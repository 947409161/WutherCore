//! URLTest（节点测速）。
//!
//! ## 关键特性
//!
//! * **节点协议无关**：探测连接由统一 `OutboundAdapter` 建立，因此所有支持
//!   TCP 的出站协议共用一套 HTTP/HTTPS 测速。
//! * **expected_status**：解析 `"200/204/401-429"` 等 mihomo 风格表达式；
//!   响应状态码必须命中范围才算 alive。空集合（`""` / `"*"`）跳过校验。
//! * **unified_delay**：第一次 HEAD 后立刻在同一连接（keep-alive）再 HEAD 一次，
//!   仅以第二次的耗时为准，历史同时保留 connect、TLS handshake、response 分项。
//! * **跨 URL 的 per-(node, url) 状态**：`alive` 原子位 + 历史 ring；
//!   `last_delay_for_url(node, url)` 死节点返回 `u32::MAX`（与 mihomo
//!   `LastDelayForTestUrl` 返回 `0xFFFF` 等价的语义，宽度扩为 u32 适应 ms）。
//! * **fast() + tolerance + single-flight**：[`UrlTester::pick_fast`] 取
//!   `last_delay_for_url` 最小者；当且仅当
//!   `current.delay > new_min + tolerance` 时切换；10s `single_flight` window
//!   防止热路径反复扫描。
//! * **低开销调度**：只运行活跃组，闲置自动停表；批量 future 惰性构造，全局
//!   semaphore 限流，同一 node/url 并发合并，失败指数退避。

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::AHashSet;
use core_outbound::adapter::{BoxedStream, DialContext};
use dashmap::DashMap;
use futures::{StreamExt, stream};
use parking_lot::{Mutex, RwLock};
use rustls::{ClientConfig, pki_types::ServerName};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufStream},
    sync::{Mutex as AsyncMutex, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::{engine::Runtime, int_ranges::IntRanges};

/// `LastDelayForTestUrl` 死节点返回值；与 mihomo `0xFFFF` 等价语义但宽度扩为 u32。
pub const DEAD_DELAY: u32 = u32::MAX;
/// 单个节点最多保留多少条历史（与 mihomo `defaultHistoriesNum = 10`）。
pub const HISTORY_CAP: usize = 10;
/// `single_flight` 缓存窗口（与 mihomo `singledo.NewSingle(time.Second * 10)`）。
pub const FAST_PICK_TTL: Duration = Duration::from_secs(10);
/// 默认 tolerance（与 mihomo `URLTest tolerance` 默认 0；这里给一个保守值）。
pub const DEFAULT_TOLERANCE_MS: u32 = 50;
const MAX_URLS_PER_NODE: usize = 16;
const FAILURE_RETRY_MIN: Duration = Duration::from_secs(5);
const FAILURE_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const SCHEDULER_TICK: Duration = Duration::from_secs(1);
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Error, Clone)]
pub enum DelayError {
    #[error("节点未注册: {0}")]
    UnknownNode(String),
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("dial 失败: {0}")]
    Dial(String),
    #[error("HTTP 失败: {0}")]
    Http(String),
    #[error("TLS 失败: {0}")]
    Tls(String),
    #[error("expected_status 不命中: {0}")]
    StatusMismatch(u16),
    #[error("超时")]
    Timeout,
    #[error("连接已关闭")]
    Closed,
}

/// 默认配置。
#[derive(Debug, Clone)]
pub struct UrlTestConfig {
    pub default_url: String,
    pub default_timeout: Duration,
    pub max_parallel: usize,
    /// 单个批次同时被 poll 的 future 数。与全局 semaphore 分离，避免一次
    /// 万节点组占满所有 URLTest 槽位。
    pub batch_parallel: usize,
    /// 默认 expected_status —— mihomo 默认空集（任何状态都算 alive）。
    pub default_expected_status: IntRanges,
    /// 默认 unified_delay —— mihomo `UnifiedDelay` 默认 false。
    pub default_unified_delay: bool,
}

impl Default for UrlTestConfig {
    fn default() -> Self {
        Self {
            // 与 mihomo 一致：默认 HTTPS generate_204（防 ISP 劫持）。
            default_url: "https://www.gstatic.com/generate_204".into(),
            default_timeout: Duration::from_secs(5),
            max_parallel: 24,
            batch_parallel: 10,
            default_expected_status: IntRanges::empty(),
            default_unified_delay: false,
        }
    }
}

/// 单次测试的可选项 —— 与 mihomo `URLTest(ctx, url, expectedStatus)` + 隐藏的
/// `UnifiedDelay` 全局开关合并到一个结构。
#[derive(Debug, Clone, Default)]
pub struct UrlTestOpts {
    pub url: Option<String>,
    pub timeout: Option<Duration>,
    pub expected_status: Option<IntRanges>,
    pub unified_delay: Option<bool>,
}

/* ========================================================================
Per-(node, url) statistics —— 对齐 mihomo `Proxy.extra` map。
======================================================================== */

#[derive(Debug)]
pub struct NodeUrlStats {
    pub alive: AtomicBool,
    pub last_delay_ms: AtomicU32, // 0 = 未测；DEAD_DELAY = 死
    pub last_seen_ms: AtomicU64,
    pub next_due_ms: AtomicU64,
    pub consecutive_failures: AtomicU32,
    requested_interval_ms: AtomicU64,
    /// 精确的探测结果世代。不能用毫秒时间判断 single-flight 是否已经完成，
    /// 因为同一毫秒内连续完成的探测会产生 ABA。
    probe_generation: AtomicU64,
    /// 最近完成探测的完整语义签名。仅当探测参数全部一致时，
    /// 等待者才能复用 single-flight 结果。
    probe_signature: AtomicU64,
    /// 同一 (node,url) 的 single-flight 门。等待者复用先完成者的结果。
    probe_lock: AsyncMutex<()>,
    last_error: Mutex<Option<DelayError>>,
    history: Mutex<std::collections::VecDeque<HistoryEntry>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub time_ms: u64,
    pub delay_ms: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub connect_ms: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub handshake_ms: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub response_ms: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub unified: bool,
}

impl Default for NodeUrlStats {
    fn default() -> Self {
        Self {
            alive: AtomicBool::new(true),
            last_delay_ms: AtomicU32::new(0),
            last_seen_ms: AtomicU64::new(0),
            next_due_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            requested_interval_ms: AtomicU64::new(u64::MAX),
            probe_generation: AtomicU64::new(0),
            probe_signature: AtomicU64::new(0),
            probe_lock: AsyncMutex::new(()),
            last_error: Mutex::new(None),
            history: Mutex::new(std::collections::VecDeque::with_capacity(HISTORY_CAP)),
        }
    }
}

impl NodeUrlStats {
    pub fn record(&self, delay_ms: u32, alive: bool) {
        self.record_timing(
            ProbeTiming {
                delay_ms,
                ..ProbeTiming::default()
            },
            alive,
            Duration::from_secs(60),
            None,
            0,
        );
    }

    fn record_timing(
        &self,
        timing: ProbeTiming,
        alive: bool,
        interval: Duration,
        error: Option<DelayError>,
        probe_signature: u64,
    ) {
        let now = now_ms();
        self.alive.store(alive, Ordering::Release);
        self.last_delay_ms.store(
            if alive { timing.delay_ms } else { DEAD_DELAY },
            Ordering::Release,
        );
        self.last_seen_ms.store(now, Ordering::Release);
        let failures = if alive {
            self.consecutive_failures.store(0, Ordering::Release);
            0
        } else {
            self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1
        };
        let requested_interval = self.requested_interval_ms.load(Ordering::Acquire);
        let interval = if requested_interval == u64::MAX {
            interval
        } else {
            interval.min(Duration::from_millis(requested_interval))
        };
        let retry = if alive {
            interval.max(SCHEDULER_TICK)
        } else {
            failure_retry_delay(failures, interval)
        };
        self.next_due_ms.store(
            now.saturating_add(retry.as_millis().min(u64::MAX as u128) as u64),
            Ordering::Release,
        );
        *self.last_error.lock() = error;
        let mut g = self.history.lock();
        g.push_back(HistoryEntry {
            time_ms: now,
            delay_ms: if alive { timing.delay_ms } else { 0 },
            connect_ms: timing.connect_ms,
            handshake_ms: timing.handshake_ms,
            response_ms: timing.response_ms,
            unified: timing.unified,
        });
        while g.len() > HISTORY_CAP {
            g.pop_front();
        }
        drop(g);
        self.probe_signature
            .store(probe_signature, Ordering::Release);
        self.probe_generation.fetch_add(1, Ordering::Release);
    }

    fn request_interval(&self, interval: Duration, now_ms: u64) {
        let interval_ms = interval
            .max(SCHEDULER_TICK)
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self.requested_interval_ms
            .fetch_min(interval_ms, Ordering::AcqRel);
        let current_due = self.next_due_ms.load(Ordering::Acquire);
        if current_due != 0 {
            self.next_due_ms
                .fetch_min(now_ms.saturating_add(interval_ms), Ordering::AcqRel);
        }
    }
    pub fn last_delay(&self) -> u32 {
        if self.alive.load(Ordering::Acquire) {
            self.last_delay_ms.load(Ordering::Acquire)
        } else {
            DEAD_DELAY
        }
    }
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.history.lock().iter().cloned().collect()
    }

    fn is_due(&self, now: u64) -> bool {
        self.next_due_ms.load(Ordering::Acquire) <= now
    }

    fn cached_result(&self) -> Result<u32, DelayError> {
        if self.is_alive() {
            let delay = self.last_delay_ms.load(Ordering::Acquire);
            if delay != 0 && delay != DEAD_DELAY {
                return Ok(delay);
            }
        }
        Err(self
            .last_error
            .lock()
            .clone()
            .unwrap_or(DelayError::Timeout))
    }
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, Default)]
struct ProbeTiming {
    delay_ms: u32,
    connect_ms: u32,
    handshake_ms: u32,
    response_ms: u32,
    unified: bool,
}

#[derive(Debug)]
struct GroupSchedule {
    revision: u64,
    members: Arc<[String]>,
    url: String,
    expected_raw: String,
    unified_delay: Option<bool>,
    interval: Duration,
    idle_timeout: Duration,
    active_until_ms: AtomicU64,
    next_run_ms: AtomicU64,
}

impl GroupSchedule {
    fn touch(&self, now: u64) {
        self.active_until_ms.store(
            now.saturating_add(self.idle_timeout.as_millis().min(u64::MAX as u128) as u64),
            Ordering::Release,
        );
    }
}

/* ========================================================================
FastPickCache —— mihomo singledo.Single 的最小复刻。
======================================================================== */

#[derive(Debug, Clone)]
struct FastPickResult {
    node: String,
    delay: u32,
}

#[derive(Debug, Default)]
struct FastPickEntry {
    last: Option<(Instant, FastPickResult)>,
}

/* ========================================================================
UrlTester
======================================================================== */

#[derive(Debug)]
pub struct UrlTester {
    pub cfg: RwLock<UrlTestConfig>,
    pub sem: Arc<Semaphore>,
    /// (node, url) → stats
    stats: DashMap<String, Arc<DashMap<String, Arc<NodeUrlStats>>>>,
    /// group_name → cached fast-pick
    fast_pick: DashMap<String, FastPickEntry>,
    schedules: DashMap<String, Arc<GroupSchedule>>,
}

impl UrlTester {
    pub fn new(cfg: UrlTestConfig) -> Arc<Self> {
        let sem = Arc::new(Semaphore::new(cfg.max_parallel));
        Arc::new(Self {
            cfg: RwLock::new(cfg),
            sem,
            stats: DashMap::new(),
            fast_pick: DashMap::new(),
            schedules: DashMap::new(),
        })
    }

    pub fn current_config(&self) -> UrlTestConfig {
        self.cfg.read().clone()
    }

    /// 取（或新建）一条 (node, url) stats。
    pub fn ensure_stats(&self, node: &str, url: &str) -> Arc<NodeUrlStats> {
        let urls = self
            .stats
            .entry(node.to_string())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();
        urls.entry(url.to_string())
            .or_insert_with(|| Arc::new(NodeUrlStats::default()))
            .clone()
    }

    /// `LastDelayForTestUrl(node, url)` —— 与 mihomo 同名方法语义。
    pub fn last_delay_for_url(&self, node: &str, url: &str) -> u32 {
        self.stats
            .get(node)
            .and_then(|urls| urls.get(url).map(|stats| stats.last_delay()))
            .unwrap_or(DEAD_DELAY)
    }

    pub fn alive_for_url(&self, node: &str, url: &str) -> bool {
        self.stats
            .get(node)
            .and_then(|urls| urls.get(url).map(|stats| stats.is_alive()))
            .unwrap_or(true)
    }

    pub fn history(&self, node: &str, url: &str) -> Vec<HistoryEntry> {
        self.stats
            .get(node)
            .and_then(|urls| urls.get(url).map(|stats| stats.history()))
            .unwrap_or_default()
    }

    /// 被动拨号失败反馈。立即把该 URL 下的节点标记为不可用并安排短延迟
    /// 重测，使一次请求内的自动策略重试可以避开刚失败的节点。
    pub fn mark_runtime_failure(&self, node: &str, url: &str, reason: impl Into<String>) {
        let error = DelayError::Dial(reason.into());
        self.ensure_stats(node, url).record_timing(
            ProbeTiming::default(),
            false,
            FAILURE_RETRY_MIN,
            Some(error),
            0,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn activate_group(
        &self,
        group: &str,
        revision: u64,
        members: &[String],
        url: &str,
        expected_status: &str,
        unified_delay: Option<bool>,
        interval: Duration,
        idle_timeout: Duration,
    ) {
        let now = now_ms();
        if let Some(schedule) = self.schedules.get(group) {
            if schedule.revision == revision {
                schedule.touch(now);
                return;
            }
        }
        for member in members {
            self.ensure_stats(member, url)
                .request_interval(interval, now);
        }
        let schedule = Arc::new(GroupSchedule {
            revision,
            members: Arc::from(members.to_vec()),
            url: url.to_string(),
            expected_raw: expected_status.to_string(),
            unified_delay,
            interval: interval.max(SCHEDULER_TICK),
            idle_timeout: idle_timeout.max(interval).max(SCHEDULER_TICK),
            active_until_ms: AtomicU64::new(0),
            next_run_ms: AtomicU64::new(now),
        });
        schedule.touch(now);
        self.schedules.insert(group.to_string(), schedule);
    }

    /// 兼容旧调用：测一个节点，仅按 url+timeout。返回 ms。
    pub async fn test_node(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        url: Option<&str>,
        to: Option<Duration>,
    ) -> Result<u32, DelayError> {
        self.test_node_with(
            runtime,
            node,
            UrlTestOpts {
                url: url.map(|s| s.to_string()),
                timeout: to,
                ..Default::default()
            },
        )
        .await
    }

    /// 与 mihomo `Proxy.URLTest(ctx, url, expectedStatus)` 等价。
    pub async fn test_node_with(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        opts: UrlTestOpts,
    ) -> Result<u32, DelayError> {
        self.test_node_internal(runtime, node, opts, DEFAULT_PROBE_INTERVAL, true)
            .await
    }

    async fn test_node_internal(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        opts: UrlTestOpts,
        schedule_interval: Duration,
        force: bool,
    ) -> Result<u32, DelayError> {
        let cfg = self.cfg.read().clone();
        let url = opts.url.unwrap_or_else(|| cfg.default_url.clone());
        let limit = opts.timeout.unwrap_or(cfg.default_timeout);
        let expected = opts
            .expected_status
            .unwrap_or(cfg.default_expected_status.clone());
        let unified = opts.unified_delay.unwrap_or(cfg.default_unified_delay);

        let parsed = parse_test_url(&url)?;
        let probe_signature = {
            let mut hasher = DefaultHasher::new();
            url.hash(&mut hasher);
            limit.hash(&mut hasher);
            expected.hash(&mut hasher);
            unified.hash(&mut hasher);
            hasher.finish()
        };
        let stats = self.ensure_stats(node, &url);
        let observed = stats.probe_generation.load(Ordering::Acquire);
        let _single_flight = stats.probe_lock.lock().await;
        let current_generation = stats.probe_generation.load(Ordering::Acquire);
        if current_generation != observed
            && stats.probe_signature.load(Ordering::Acquire) == probe_signature
        {
            return stats.cached_result();
        }
        if !force && !stats.is_due(now_ms()) {
            return stats.cached_result();
        }

        let ob = runtime
            .outbounds
            .read()
            .get(node)
            .ok_or_else(|| DelayError::UnknownNode(node.to_string()))?;

        let _permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DelayError::Closed)?;

        let started = Instant::now();
        let result = timeout(limit, async {
            let dial_ctx = DialContext::tcp(parsed.host.clone(), parsed.port);
            let connect_started = Instant::now();
            let stream = ob
                .dial_tcp(dial_ctx)
                .await
                .map_err(|e| DelayError::Dial(e.to_string()))?;
            let connect_ms = elapsed_ms(connect_started);
            run_probe(stream, &parsed, &expected, unified, started, connect_ms).await
        })
        .await;

        let timing = match result {
            Err(_) => Err(DelayError::Timeout),
            Ok(r) => r,
        };

        match &timing {
            Ok(timing) => {
                stats.record_timing(*timing, true, schedule_interval, None, probe_signature);
                runtime
                    .smart
                    .record_probe_for(node, Duration::from_millis(timing.delay_ms as u64));
                debug!(
                    target: "urltest",
                    node,
                    url,
                    ms = timing.delay_ms,
                    connect_ms = timing.connect_ms,
                    handshake_ms = timing.handshake_ms,
                    response_ms = timing.response_ms,
                    unified = timing.unified,
                    "probe ok"
                );
            }
            Err(e) => {
                stats.record_timing(
                    ProbeTiming::default(),
                    false,
                    schedule_interval,
                    Some(e.clone()),
                    probe_signature,
                );
                runtime.smart.record_probe_failure_for(node, e.to_string());
                debug!(target: "urltest", node, url, error = %e, "probe failed");
            }
        }
        self.prune_node_urls(node, &url);

        timing.map(|timing| timing.delay_ms)
    }

    /// 并行测一组节点；按节点名返回结果。结果顺序与 nodes 一致。
    pub async fn test_many(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        self.test_many_with(
            runtime,
            nodes,
            UrlTestOpts {
                url,
                timeout: to,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn test_many_with(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        opts: UrlTestOpts,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let limit = self.cfg.read().batch_parallel;
        self.test_many_with_limit(runtime, nodes, opts, limit).await
    }

    /// 惰性有界批量测速。`buffered` 只构造并 poll `limit` 个 future，不会像
    /// `JoinSet` 那样为海量节点一次性创建同等数量 Tokio 任务。
    pub async fn test_many_with_limit(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        opts: UrlTestOpts,
        limit: usize,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let interval = DEFAULT_PROBE_INTERVAL;
        self.test_many_internal(runtime, nodes, opts, limit, interval, true)
            .await
    }

    async fn test_many_internal(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        opts: UrlTestOpts,
        limit: usize,
        interval: Duration,
        force: bool,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let mut seen = AHashSet::with_capacity(nodes.len());
        let unique: Vec<String> = nodes
            .iter()
            .filter(|node| seen.insert(node.as_str()))
            .cloned()
            .collect();
        stream::iter(unique)
            .map(|node| {
                let tester = self.clone();
                let runtime = runtime.clone();
                let opts = opts.clone();
                async move {
                    let result = tester
                        .test_node_internal(&runtime, &node, opts, interval, force)
                        .await;
                    (node, result)
                }
            })
            .buffered(limit.max(1))
            .collect()
            .await
    }

    pub async fn test_all(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let names: Vec<String> = runtime
            .outbounds
            .read()
            .names()
            .filter(|n| *n != "DIRECT" && *n != "BLOCK")
            .map(|s| s.to_string())
            .collect();
        self.test_many(runtime, &names, url, to).await
    }

    async fn test_due_schedules(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let now = now_ms();
        let mut inactive = Vec::new();
        let mut due = Vec::new();
        for entry in &self.schedules {
            let schedule = entry.value();
            if schedule.active_until_ms.load(Ordering::Acquire) < now {
                inactive.push(entry.key().clone());
                continue;
            }
            let next = schedule.next_run_ms.load(Ordering::Acquire);
            if next > now {
                continue;
            }
            let interval_ms = schedule.interval.as_millis().min(u64::MAX as u128) as u64;
            let jitter = deterministic_jitter_ms(entry.key(), interval_ms / 10);
            let next_run = now.saturating_add(interval_ms).saturating_add(jitter);
            if schedule
                .next_run_ms
                .compare_exchange(next, next_run, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                due.push(schedule.clone());
            }
        }
        for group in inactive {
            self.schedules.remove(&group);
        }

        let mut all_results = Vec::new();
        for schedule in due {
            let expected = if schedule.expected_raw.trim().is_empty() {
                None
            } else {
                match IntRanges::parse(&schedule.expected_raw) {
                    Ok(expected) => Some(expected),
                    Err(error) => {
                        warn!(
                            target: "urltest",
                            expected_status = %schedule.expected_raw,
                            error = %error,
                            "invalid group expected-status; using global default"
                        );
                        None
                    }
                }
            };
            let due_nodes: Vec<String> = schedule
                .members
                .iter()
                .filter(|node| self.ensure_stats(node, &schedule.url).is_due(now))
                .cloned()
                .collect();
            if due_nodes.is_empty() {
                continue;
            }
            let opts = UrlTestOpts {
                url: Some(schedule.url.clone()),
                timeout: None,
                expected_status: expected,
                unified_delay: schedule.unified_delay,
            };
            let limit = self.cfg.read().batch_parallel;
            let mut results = self
                .test_many_internal(runtime, &due_nodes, opts, limit, schedule.interval, false)
                .await;
            all_results.append(&mut results);
        }
        all_results
    }

    /* ====================================================================
    fast() —— mihomo URLTest 选点逻辑 + tolerance + 10s singledo 缓存。
    ==================================================================== */

    /// 在已知 last_delay 表中按 `tolerance` 选最快节点。
    /// 与 mihomo `urltest.go fast(touch)` 行为一致：
    /// * 当前 fast 死了 / 不在候选 / 当前延迟比最小者大 `> tolerance` → 切换；
    /// * 否则保持。
    /// `singledo` 窗口：10s 内重复调用同 group 直接复用上次结果。
    pub fn pick_fast(
        &self,
        group: &str,
        members: &[String],
        url: &str,
        tolerance: u32,
    ) -> Option<String> {
        // 1. singledo 命中？
        if let Some(entry) = self.fast_pick.get(group) {
            if let Some((when, ref result)) = entry.last {
                if when.elapsed() < FAST_PICK_TTL
                    && members.iter().any(|member| member == &result.node)
                {
                    return Some(result.node.clone());
                }
            }
        }

        // 2. 全表扫描
        let mut best: Option<(String, u32)> = None;
        for m in members {
            let d = self.last_delay_for_url(m, url);
            if d == DEAD_DELAY {
                continue;
            }
            match &best {
                None => best = Some((m.clone(), d)),
                Some((_, bd)) => {
                    if d < *bd {
                        best = Some((m.clone(), d));
                    }
                }
            }
        }

        // 3. tolerance：保留旧 fast 如果新最优只是略快。
        let mut entry = self.fast_pick.entry(group.to_string()).or_default();
        let (final_node, final_delay) = match (entry.last.as_ref().map(|(_, r)| r.clone()), best) {
            (Some(prev), Some((_nb, nd)))
                if members.iter().any(|m| m == &prev.node)
                    && self.alive_for_url(&prev.node, url)
                    && prev.delay <= nd.saturating_add(tolerance) =>
            {
                (prev.node, prev.delay)
            }
            (_, Some((nb, nd))) => (nb, nd),
            (Some(prev), None) => return Some(prev.node), // 全 dead 时保留上一个
            (None, None) => return None,
        };
        entry.last = Some((
            Instant::now(),
            FastPickResult {
                node: final_node.clone(),
                delay: final_delay,
            },
        ));
        Some(final_node)
    }

    /// 强制让下一次 `pick_fast` 重新扫描（mihomo `fastSingle.Reset()` 等价）。
    pub fn invalidate_fast_pick(&self, group: &str) {
        self.fast_pick.remove(group);
    }

    pub fn remove_group_schedule(&self, group: &str) {
        self.schedules.remove(group);
        self.fast_pick.remove(group);
    }

    pub fn remove_nodes<'a>(&self, nodes: impl IntoIterator<Item = &'a str>) {
        for node in nodes {
            self.stats.remove(node);
        }
    }

    fn prune_node_urls(&self, node: &str, keep_url: &str) {
        let Some(urls) = self.stats.get(node) else {
            return;
        };
        if urls.len() <= MAX_URLS_PER_NODE {
            return;
        }
        let mut candidates: Vec<(String, u64)> = urls
            .iter()
            .filter(|entry| entry.key().as_str() != keep_url)
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().last_seen_ms.load(Ordering::Acquire),
                )
            })
            .collect();
        candidates.sort_unstable_by_key(|(_, last_seen)| *last_seen);
        let remove = urls.len().saturating_sub(MAX_URLS_PER_NODE);
        for (url, _) in candidates.into_iter().take(remove) {
            urls.remove(&url);
        }
    }
}

/// 后台周期任务。只执行被真实选路 touch 且仍在 idle-timeout 内的组。
pub fn spawn_periodic(
    tester: Arc<UrlTester>,
    runtime: Arc<Runtime>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let tick = SCHEDULER_TICK.min(interval).max(Duration::from_millis(100));
        let mut ticker = tokio::time::interval(tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let started = Instant::now();
            let results = tester.test_due_schedules(&runtime).await;
            if results.is_empty() {
                continue;
            }
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            info!(
                target: "urltest",
                tested = results.len(),
                ok,
                ms = started.elapsed().as_millis() as u64,
                "url test round finished"
            );
        }
    })
}

/* ========================================================================
URL 解析 + HTTP/HTTPS 探测
======================================================================== */

#[derive(Debug, Clone)]
struct ParsedTestUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

fn parse_test_url(s: &str) -> Result<ParsedTestUrl, DelayError> {
    let parsed = url::Url::parse(s).map_err(|error| DelayError::BadUrl(error.to_string()))?;
    let (scheme, default_port) = match parsed.scheme() {
        "http" => (Scheme::Http, 80),
        "https" => (Scheme::Https, 443),
        scheme => {
            return Err(DelayError::BadUrl(format!(
                "only http(s):// supported, got {scheme}"
            )));
        }
    };
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) if !host.is_empty() => host.to_string(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => host.to_string(),
        _ => return Err(DelayError::BadUrl("missing host".into())),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| DelayError::BadUrl("missing port".into()))?;
    let mut path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    let host_for_header = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let authority = if port == default_port && parsed.port().is_none() {
        host_for_header
    } else {
        format!("{host_for_header}:{port}")
    };
    Ok(ParsedTestUrl {
        scheme,
        host,
        port,
        path,
        authority,
    })
}

async fn run_probe(
    stream: BoxedStream,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
    connect_ms: u32,
) -> Result<ProbeTiming, DelayError> {
    match url.scheme {
        Scheme::Http => {
            probe_stream(stream, url, expected, unified_delay, started, connect_ms, 0).await
        }
        Scheme::Https => probe_tls(stream, url, expected, unified_delay, started, connect_ms).await,
    }
}

async fn probe_stream<S>(
    stream: S,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
    connect_ms: u32,
    handshake_ms: u32,
) -> Result<ProbeTiming, DelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    let mut stream = BufStream::new(stream);
    let response_started = Instant::now();
    let first = send_head_recv_status(&mut stream, &url.authority, &url.path, expected).await?;
    let response_ms = elapsed_ms(response_started);
    if unified_delay && first.reusable {
        let steady_started = Instant::now();
        if send_head_recv_status(&mut stream, &url.authority, &url.path, expected)
            .await
            .is_ok()
        {
            return Ok(ProbeTiming {
                delay_ms: elapsed_ms(steady_started),
                connect_ms,
                handshake_ms,
                response_ms,
                unified: true,
            });
        }
    }
    Ok(ProbeTiming {
        delay_ms: elapsed_ms(started),
        connect_ms,
        handshake_ms,
        response_ms,
        unified: false,
    })
}

async fn probe_tls(
    inner: BoxedStream,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
    connect_ms: u32,
) -> Result<ProbeTiming, DelayError> {
    let cfg = build_client_config();
    let connector = TlsConnector::from(cfg);
    let server_name = ServerName::try_from(url.host.clone())
        .map_err(|e| DelayError::Tls(format!("invalid SNI '{}': {e}", url.host)))?;
    let handshake_started = Instant::now();
    let tls = connector
        .connect(server_name, inner)
        .await
        .map_err(|e| DelayError::Tls(e.to_string()))?;
    let handshake_ms = elapsed_ms(handshake_started);
    probe_stream(
        tls,
        url,
        expected,
        unified_delay,
        started,
        connect_ms,
        handshake_ms,
    )
    .await
}

#[derive(Debug, Clone, Copy)]
struct ProbeResponse {
    reusable: bool,
}

/// 发送 HEAD 并完整消费响应头。使用 `BufStream` 保留 read-ahead 数据，第二次
/// unified probe 不会把第一次剩余 header 当作新的状态行。
async fn send_head_recv_status<S>(
    stream: &mut BufStream<S>,
    host_header: &str,
    path: &str,
    expected: &IntRanges,
) -> Result<ProbeResponse, DelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    // HEAD + keep-alive：unified_delay 复用同一连接做第二次。
    let req = format!(
        "HEAD {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: wuthercore-urltest/1.0\r\n\
         Connection: keep-alive\r\n\
         Accept: */*\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;

    const MAX_HEADER_BYTES: usize = 32 * 1024;
    let mut status_line = Vec::with_capacity(64);
    let read = stream
        .read_until(b'\n', &mut status_line)
        .await
        .map_err(|error| DelayError::Http(error.to_string()))?;
    if read == 0 {
        return Err(DelayError::Closed);
    }
    let line = std::str::from_utf8(&status_line).unwrap_or("");
    if !(line.starts_with("HTTP/1.0") || line.starts_with("HTTP/1.1")) {
        return Err(DelayError::Http(format!(
            "non-HTTP reply: {:?}",
            &line[..line.len().min(40)]
        )));
    }
    let code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            DelayError::Http(format!(
                "bad status line: {:?}",
                &line[..line.len().min(40)]
            ))
        })?;
    if !expected.check(code) {
        return Err(DelayError::StatusMismatch(code));
    }

    let mut total = status_line.len();
    let mut reusable = line.starts_with("HTTP/1.1");
    loop {
        let mut header = Vec::with_capacity(96);
        let read = stream
            .read_until(b'\n', &mut header)
            .await
            .map_err(|error| DelayError::Http(error.to_string()))?;
        if read == 0 {
            return Err(DelayError::Closed);
        }
        total = total.saturating_add(read);
        if total > MAX_HEADER_BYTES {
            return Err(DelayError::Http("response headers exceed 32 KiB".into()));
        }
        if header == b"\r\n" || header == b"\n" {
            break;
        }
        if let Ok(header) = std::str::from_utf8(&header) {
            if let Some((name, value)) = header.split_once(':') {
                if name.trim().eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                {
                    reusable = false;
                }
            }
        }
    }
    Ok(ProbeResponse { reusable })
}

/// 构建 TLS 客户端 cfg —— webpki-roots 内置 CA。
/// 显式指定 ring CryptoProvider，避免 rustls 0.23 多依赖时 builder() 全局歧义 panic。
fn build_client_config() -> Arc<ClientConfig> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("rustls ring default protocols")
            .with_root_certificates(roots)
            .with_no_client_auth();
            // 手写 probe 是 HTTP/1.1，显式阻止服务端协商 h2。
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn elapsed_ms(started: Instant) -> u32 {
    started.elapsed().as_millis().min(u32::MAX as u128) as u32
}

fn failure_retry_delay(failures: u32, configured_interval: Duration) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    let multiplier = 1u32 << shift;
    FAILURE_RETRY_MIN
        .saturating_mul(multiplier)
        .min(configured_interval.max(FAILURE_RETRY_MIN))
        .min(FAILURE_RETRY_MAX)
}

fn deterministic_jitter_ms(key: &str, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    key.hash(&mut hasher);
    hasher.finish() % max.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use core_outbound::adapter::{BoxedUdp, Capabilities, OutboundAdapter, SharedOutbound};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    struct ProbeOutbound {
        name: String,
        protocol: &'static str,
    }

    #[async_trait]
    impl OutboundAdapter for ProbeOutbound {
        fn name(&self) -> &str {
            &self.name
        }

        fn protocol(&self) -> &'static str {
            self.protocol
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                ..Capabilities::default()
            }
        }

        async fn dial_tcp(&self, _ctx: DialContext) -> std::io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut server, &mut request).await;
                let _ = server
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
            Ok(Box::pin(client))
        }

        async fn dial_udp(&self, _ctx: DialContext) -> std::io::Result<BoxedUdp> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test adapter has no UDP",
            ))
        }
    }

    #[test]
    fn parse_https_url_default_port() {
        let p = parse_test_url("https://www.gstatic.com/generate_204").unwrap();
        assert_eq!(p.scheme, Scheme::Https);
        assert_eq!(p.host, "www.gstatic.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.path, "/generate_204");
    }

    #[test]
    fn parse_http_url_explicit_port_root_path() {
        let p = parse_test_url("http://10.0.0.1:8080").unwrap();
        assert_eq!(p.scheme, Scheme::Http);
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_url_preserves_ipv6_authority_and_query() {
        let p = parse_test_url("http://[2001:db8::1]:8080/check?a=1&b=2").unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.authority, "[2001:db8::1]:8080");
        assert_eq!(p.path, "/check?a=1&b=2");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(parse_test_url("ws://x").is_err());
    }

    #[test]
    fn fast_pick_tolerance_keeps_current() {
        // 构造一个独立 UrlTester（不需要 Runtime）做 pick 测试。
        let t = UrlTester::new(UrlTestConfig::default());
        // 手工种 stats：a=200ms (alive), b=190ms (alive)
        let url = "https://t.example/";
        t.ensure_stats("a", url).record(200, true);
        t.ensure_stats("b", url).record(190, true);
        // 第一次：选最小 b
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "b");
        // 把 a 降到 175 —— tolerance=50，现 fast=b(190) vs new=a(175)，差 15 < 50，应保持 b。
        t.ensure_stats("a", url).record(175, true);
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "b");
        // 显式 invalidate 后才会换。
        t.invalidate_fast_pick("g");
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "a");
    }

    #[test]
    fn fast_pick_skips_dead_nodes() {
        let t = UrlTester::new(UrlTestConfig::default());
        let url = "https://t/";
        t.ensure_stats("dead", url).record(0, false);
        t.ensure_stats("ok", url).record(300, true);
        let pick = t
            .pick_fast("g", &["dead".into(), "ok".into()], url, 0)
            .unwrap();
        assert_eq!(pick, "ok");
    }

    #[test]
    fn last_delay_for_url_returns_dead_when_marked_dead() {
        let t = UrlTester::new(UrlTestConfig::default());
        t.ensure_stats("n", "u").record(0, false);
        assert_eq!(t.last_delay_for_url("n", "u"), DEAD_DELAY);
        t.ensure_stats("n", "u").record(123, true);
        assert_eq!(t.last_delay_for_url("n", "u"), 123);
    }

    #[test]
    fn singledo_window_returns_same_pick() {
        let t = UrlTester::new(UrlTestConfig::default());
        let url = "https://t/";
        t.ensure_stats("a", url).record(100, true);
        t.ensure_stats("b", url).record(200, true);
        let p1 = t.pick_fast("g", &["a".into(), "b".into()], url, 0).unwrap();
        // 即便此时 b 变得更快，10s 内仍返回 a（singledo TTL）。
        t.ensure_stats("b", url).record(50, true);
        let p2 = t.pick_fast("g", &["a".into(), "b".into()], url, 0).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p2, "a");
    }

    #[test]
    fn failure_backoff_is_bounded_and_exponential() {
        let interval = Duration::from_secs(60);
        assert_eq!(failure_retry_delay(1, interval), Duration::from_secs(5));
        assert_eq!(failure_retry_delay(2, interval), Duration::from_secs(10));
        assert_eq!(failure_retry_delay(4, interval), Duration::from_secs(40));
        assert_eq!(failure_retry_delay(9, interval), interval);
        assert_eq!(
            failure_retry_delay(20, Duration::from_secs(3600)),
            FAILURE_RETRY_MAX
        );
    }

    #[test]
    fn shared_node_uses_the_shortest_requested_group_interval() {
        let stats = NodeUrlStats::default();
        let now = now_ms();
        stats.request_interval(Duration::from_secs(60), now);
        stats.record(20, true);
        let long_due = stats.next_due_ms.load(Ordering::Acquire);
        stats.request_interval(Duration::from_secs(10), now);
        let short_due = stats.next_due_ms.load(Ordering::Acquire);
        assert!(short_due < long_due);
        assert!(short_due <= now.saturating_add(10_000));
    }

    #[test]
    fn per_node_url_history_is_bounded() {
        let tester = UrlTester::new(UrlTestConfig::default());
        for index in 0..32 {
            let url = format!("https://probe-{index}.invalid/");
            tester.ensure_stats("node", &url).record(10, true);
            tester.prune_node_urls("node", &url);
        }
        assert!(tester.stats.get("node").unwrap().len() <= MAX_URLS_PER_NODE);
        assert!(
            tester
                .stats
                .get("node")
                .unwrap()
                .contains_key("https://probe-31.invalid/")
        );
    }

    #[tokio::test]
    async fn unified_probe_consumes_complete_large_headers_before_reuse() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            for _ in 0..2 {
                loop {
                    let mut line = String::new();
                    let read = server.read_line(&mut line).await.unwrap();
                    assert_ne!(read, 0);
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let padding = "x".repeat(8 * 1024);
                let response = format!(
                    "HTTP/1.1 204 No Content\r\nX-Padding: {padding}\r\nConnection: keep-alive\r\n\r\n"
                );
                server
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                server.get_mut().flush().await.unwrap();
            }
        });
        let parsed = parse_test_url("http://example.com/check").unwrap();
        let result = probe_stream(
            client,
            &parsed,
            &IntRanges::empty(),
            true,
            Instant::now(),
            0,
            0,
        )
        .await
        .unwrap();
        assert!(result.unified);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_is_adapter_agnostic_across_protocol_families() {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: false
route:
  preset: direct
"#,
        )
        .unwrap();
        let runtime = Arc::new(Runtime::build(plan).unwrap());
        for protocol in [
            "http",
            "socks5",
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria2",
            "tuic",
            "wireguard",
        ] {
            let node = format!("probe-{protocol}");
            let outbound: SharedOutbound = Arc::new(ProbeOutbound {
                name: node.clone(),
                protocol,
            });
            runtime.outbounds.write().insert(node.clone(), outbound);
        }
        let tester = UrlTester::new(UrlTestConfig::default());
        for protocol in [
            "http",
            "socks5",
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria2",
            "tuic",
            "wireguard",
        ] {
            let node = format!("probe-{protocol}");
            let delay = tester
                .test_node(
                    &runtime,
                    &node,
                    Some("http://probe.invalid/generate_204"),
                    Some(Duration::from_secs(1)),
                )
                .await;
            assert!(delay.is_ok(), "{protocol}: {delay:?}");
        }
    }

    #[test]
    fn group_health_schedule_starts_on_real_selection_not_runtime_start() {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes: ["direct://0.0.0.0:0#node-a"]
groups:
  main:
    choose: fast
    use: [nodes]
route:
  preset: global
  final: main
"#,
        )
        .unwrap();
        let runtime = Runtime::build(plan).unwrap();
        let tester = UrlTester::new(UrlTestConfig::default());
        runtime.set_urltest(tester.clone());
        assert!(tester.schedules.is_empty());
        let _ = runtime.pick_outbound("example.com", 443, core_route::NetworkKind::Tcp);
        assert!(tester.schedules.contains_key("main"));
    }
}
