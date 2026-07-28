//! Smart 选择器。
//!
//! 热路径采用两次线性扫描，不排序、不生成解释字符串：
//! 第一次建立吞吐 P90 的固定桶参考值，第二次计算候选分数。`/smart/why`
//! 才构造并排序完整解释。相较单纯的延迟最小值，评分同时使用真实延迟分位数、
//! 抖动、短窗失败率、退化基线、被动吞吐和活跃连接数。

use std::{
    collections::VecDeque,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ahash::AHasher;
use core_config::model::{SmartGoal, SmartSticky};
use core_observe::ConnectionObserver;
use core_store::{
    AsyncWriter, Store,
    blobs::{DomainBestBlob, NegativeBlob},
    schema::{SMART_DOMAIN_BEST, SMART_NEGATIVE, SMART_NODE_STATS, SMART_PIN},
    store::BatchOp,
};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};

use crate::{
    cache::{DomainBest, NegativeCache},
    explain::{ChoiceExplain, NodeScore},
    metrics::{NodeFlowObserver, NodeStatSnapshot, NodeStats},
};

const NODE_PERSIST_INTERVAL: Duration = Duration::from_secs(30);
const SWITCH_TOLERANCE: f64 = 4.0;
const EXPLAIN_LOG_CAP: usize = 256;
const SPEED_FLOOR_BPS: f64 = 4.0 * 1024.0 * 1024.0;
const SPEED_CEILING_BPS: f64 = 64.0 * 1024.0 * 1024.0;

#[derive(Debug, Clone)]
pub struct SmartContext {
    pub group: String,
    pub host: String,
    pub prefer: Vec<String>,
    pub avoid: Vec<String>,
    /// 策略组当前有效节点，用于评分迟滞。
    pub current: Option<String>,
    /// 组级 sticky 覆盖；None 继承全局 Smart 配置。
    pub sticky: Option<SmartSticky>,
    /// session 模式的稳定键，由运行时按入站来源、目标和网络生成。
    pub session_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SmartChoice {
    pub node: String,
    pub explain: ChoiceExplain,
}

#[derive(Debug, Clone, Copy)]
struct Weights {
    latency: f64,
    success: f64,
    stability: f64,
    throughput: f64,
    site_memory: f64,
    load: f64,
    preference: f64,
    cost: f64,
}

impl Weights {
    fn for_goal(goal: SmartGoal) -> Self {
        match goal {
            SmartGoal::Speed => Self {
                latency: 0.30,
                success: 0.12,
                stability: 0.08,
                throughput: 0.32,
                site_memory: 0.06,
                load: 0.08,
                preference: 0.03,
                cost: 0.01,
            },
            SmartGoal::Stability => Self {
                latency: 0.18,
                success: 0.29,
                stability: 0.25,
                throughput: 0.08,
                site_memory: 0.08,
                load: 0.06,
                preference: 0.04,
                cost: 0.02,
            },
            SmartGoal::LowCost => Self {
                latency: 0.15,
                success: 0.18,
                stability: 0.12,
                throughput: 0.08,
                site_memory: 0.05,
                load: 0.04,
                preference: 0.03,
                cost: 0.35,
            },
            SmartGoal::Privacy => Self {
                latency: 0.22,
                success: 0.27,
                stability: 0.20,
                throughput: 0.10,
                site_memory: 0.02,
                load: 0.08,
                preference: 0.08,
                cost: 0.03,
            },
            SmartGoal::Balanced => Self {
                latency: 0.24,
                success: 0.22,
                stability: 0.17,
                throughput: 0.18,
                site_memory: 0.08,
                load: 0.06,
                preference: 0.04,
                cost: 0.01,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ScoreParts {
    total: f64,
    latency: f64,
    success: f64,
    stability: f64,
    throughput: f64,
    site_memory: f64,
    load: f64,
    preference: f64,
    cost: f64,
    cooldown_penalty: f64,
    degraded_penalty: f64,
}

pub struct SmartSelector {
    nodes: DashMap<String, Arc<NodeStats>>,
    domain_best: DomainBest,
    negative: NegativeCache,
    goal: RwLock<SmartGoal>,
    sticky: RwLock<SmartSticky>,
    explain_log: Mutex<VecDeque<ChoiceExplain>>,
    writer: Option<Arc<AsyncWriter>>,
}

impl std::fmt::Debug for SmartSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmartSelector")
            .field("nodes", &self.nodes.len())
            .field("goal", &*self.goal.read())
            .finish()
    }
}

impl SmartSelector {
    pub fn new(goal: SmartGoal, sticky: SmartSticky) -> Self {
        Self {
            nodes: DashMap::new(),
            domain_best: DomainBest::new(Duration::from_secs(10 * 60)),
            negative: NegativeCache::new(),
            goal: RwLock::new(goal),
            sticky: RwLock::new(sticky),
            explain_log: Mutex::new(VecDeque::with_capacity(EXPLAIN_LOG_CAP)),
            writer: None,
        }
    }

    pub async fn with_store(goal: SmartGoal, sticky: SmartSticky, store: Arc<Store>) -> Self {
        let mut selector = Self::new(goal, sticky);
        if let Ok(rows) = store
            .iter_json::<core_store::NodeStatsBlob>(SMART_NODE_STATS)
            .await
        {
            for (name, blob) in rows {
                selector
                    .nodes
                    .insert(name, Arc::new(NodeStats::from_blob(&blob)));
            }
        }
        if let Ok(rows) = store.iter_json::<DomainBestBlob>(SMART_DOMAIN_BEST).await {
            let now = unix_now();
            for (key, blob) in rows {
                if now.saturating_sub(blob.set_at_secs) <= 60 * 60 {
                    selector.domain_best.put(&key, &blob.node);
                }
            }
        }
        // 旧版 `/smart/pin` 使用独立字符串命名空间；把它并入 domain memory。
        if let Ok(rows) = store.iter_string(SMART_PIN).await {
            for (key, node) in rows {
                if !node.is_empty() {
                    selector.domain_best.put(&key, &node);
                }
            }
        }
        if let Ok(rows) = store.iter_json::<NegativeBlob>(SMART_NEGATIVE).await {
            let now = unix_now();
            for (node, blob) in rows {
                if blob.until_secs > now {
                    selector.negative.cool(
                        &node,
                        Duration::from_secs(blob.until_secs - now),
                        blob.reason,
                    );
                }
            }
        }
        selector.writer = Some(AsyncWriter::spawn(store));
        selector
    }

    pub async fn shutdown(&self) {
        if let Some(writer) = &self.writer {
            let operations: Vec<BatchOp> = self
                .nodes
                .iter()
                .map(|entry| BatchOp::PutNodeStats(entry.key().clone(), entry.value().to_blob()))
                .collect();
            if !operations.is_empty() {
                let _ = writer.enqueue_batch(operations);
            }
            writer.shutdown().await;
        }
    }

    pub fn set_goal(&self, goal: SmartGoal) {
        *self.goal.write() = goal;
    }

    pub fn ensure_node(&self, name: &str) -> Arc<NodeStats> {
        if let Some(stats) = self.nodes.get(name) {
            return stats.clone();
        }
        let stats = Arc::new(NodeStats::new());
        self.nodes.insert(name.to_string(), stats.clone());
        stats
    }

    pub fn open_flow(&self, node: &str) -> Arc<dyn ConnectionObserver> {
        NodeFlowObserver::new(self.ensure_node(node))
    }

    pub fn record_success(&self, node: &str, latency: Duration) {
        let stats = self.ensure_node(node);
        stats.record_success(latency);
        self.persist_node_if_due(node, &stats);
    }

    pub fn record_failure(&self, node: &str, reason: impl Into<String>) {
        let reason = reason.into();
        let stats = self.ensure_node(node);
        stats.record_failure(reason.clone());
        self.negative
            .cool(node, Duration::from_secs(30), reason.clone());
        if let Some(writer) = &self.writer {
            let _ = writer.enqueue_batch(vec![
                BatchOp::PutNodeStats(node.to_string(), stats.to_blob()),
                BatchOp::PutNegative(
                    node.to_string(),
                    NegativeBlob {
                        until_secs: unix_now() + 30,
                        reason,
                    },
                ),
            ]);
        }
    }

    pub fn record_probe_for(&self, node: &str, latency: Duration) {
        let stats = self.ensure_node(node);
        stats.record_probe(latency);
        self.persist_node_if_due(node, &stats);
    }

    pub fn record_probe_failure_for(&self, node: &str, reason: impl Into<String>) {
        let reason = reason.into();
        let stats = self.ensure_node(node);
        stats.record_probe_failure(reason.clone());
        self.negative
            .cool(node, Duration::from_secs(30), reason.clone());
        if let Some(writer) = &self.writer {
            let _ = writer.enqueue_batch(vec![
                BatchOp::PutNodeStats(node.to_string(), stats.to_blob()),
                BatchOp::PutNegative(
                    node.to_string(),
                    NegativeBlob {
                        until_secs: unix_now() + 30,
                        reason,
                    },
                ),
            ]);
        }
    }

    fn persist_node_if_due(&self, node: &str, stats: &NodeStats) {
        if !stats.should_persist(NODE_PERSIST_INTERVAL) {
            return;
        }
        if let Some(writer) = &self.writer {
            let _ = writer.enqueue(BatchOp::PutNodeStats(node.to_string(), stats.to_blob()));
        }
    }

    pub fn pin(&self, host: &str, group: &str, node: &str) {
        let key = DomainBest::key(group, &registrable_domain(host));
        self.domain_best.put(&key, node);
        if let Some(writer) = &self.writer {
            let _ = writer.enqueue_batch(vec![
                BatchOp::PutDomainBest(
                    key.clone(),
                    DomainBestBlob {
                        node: node.to_string(),
                        set_at_secs: unix_now(),
                    },
                ),
                BatchOp::PutPin(key, node.to_string()),
            ]);
        }
    }

    /// 路由热路径，只返回节点，不构造解释和排序。
    pub fn choose_node(&self, context: &SmartContext, members: &[String]) -> String {
        self.rank(context, members, false).0
    }

    /// 管理 API 路径，返回完整可解释评分。
    pub fn choose(&self, context: &SmartContext, members: &[String]) -> SmartChoice {
        let (node, mut scores) = self.rank(context, members, true);
        scores.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let cache_hit = self.cache_hit(context);
        let explain = ChoiceExplain {
            group: context.group.clone(),
            host: context.host.clone(),
            picked: node.clone(),
            cache_hit,
            scores,
        };
        let mut log = self.explain_log.lock();
        if log.len() >= EXPLAIN_LOG_CAP {
            log.pop_front();
        }
        log.push_back(explain.clone());
        SmartChoice { node, explain }
    }

    pub fn recent_explains(&self) -> Vec<ChoiceExplain> {
        self.explain_log.lock().iter().cloned().collect()
    }

    fn rank(
        &self,
        context: &SmartContext,
        members: &[String],
        explain: bool,
    ) -> (String, Vec<NodeScore>) {
        if members.is_empty() {
            return (String::new(), Vec::new());
        }
        let candidate = |name: &&String| {
            !context
                .avoid
                .iter()
                .any(|avoid| name.contains(avoid.as_str()))
        };
        let mut candidate_count = members.iter().filter(candidate).count();
        let use_all = candidate_count == 0;
        if use_all {
            candidate_count = members.len();
        }

        let mut cold_count = 0usize;
        let mut speed_histogram = [0u32; 64];
        let mut speed_samples = 0u32;
        for name in members.iter().filter(|name| use_all || candidate(name)) {
            let stats = self.ensure_node(name);
            if stats.sample_count() == 0 {
                cold_count += 1;
            }
            let throughput = stats.throughput_hint_bps();
            if throughput > 0.0 {
                let bucket = speed_bucket(throughput);
                speed_histogram[bucket] = speed_histogram[bucket].saturating_add(1);
                speed_samples = speed_samples.saturating_add(1);
            }
        }
        let speed_reference = speed_reference(&speed_histogram, speed_samples);

        let cache_hit = self.cache_hit(context);
        // 全部候选尚未探测时按站点稳定散列，避免所有冷启动流量压到首节点。
        // 一旦已有任何测量，就只用评分结果，不拿真实用户流量做随机探索。
        let explore_cold =
            cold_count == candidate_count && context.current.is_none() && cache_hit.is_none();
        let cold_target = if cold_count == 0 {
            0
        } else {
            stable_context_hash(context) as usize % cold_count
        };

        let weights = Weights::for_goal(*self.goal.read());
        let mut best: Option<(String, ScoreParts)> = None;
        let mut current: Option<(String, ScoreParts)> = None;
        let mut cold_index = 0usize;
        let mut cold_pick = None;
        let mut explanations = if explain {
            Vec::with_capacity(candidate_count)
        } else {
            Vec::new()
        };
        let snapshot_clock_ms = unix_now_ms();

        for name in members.iter().filter(|name| use_all || candidate(name)) {
            let snapshot = self
                .ensure_node(name)
                .snapshot_for_scoring(snapshot_clock_ms, explain);
            let parts = self.score(
                name,
                context,
                &snapshot,
                &weights,
                cache_hit.as_deref(),
                speed_reference,
            );
            if explore_cold && snapshot.samples == 0 {
                if cold_index == cold_target {
                    cold_pick = Some(name.clone());
                }
                cold_index += 1;
            }
            if context.current.as_deref() == Some(name.as_str()) {
                current = Some((name.clone(), parts));
            }
            if best
                .as_ref()
                .map(|(_, best)| parts.total > best.total)
                .unwrap_or(true)
            {
                best = Some((name.clone(), parts));
            }
            if explain {
                explanations.push(to_node_score(
                    name,
                    &snapshot,
                    parts,
                    cache_hit.as_deref(),
                    &context.prefer,
                ));
            }
        }

        let mut selected = if let Some(cold) = cold_pick {
            cold
        } else {
            let (best_name, best_parts) = best.unwrap_or_else(|| {
                (
                    members[0].clone(),
                    ScoreParts {
                        total: 0.0,
                        latency: 0.0,
                        success: 0.0,
                        stability: 0.0,
                        throughput: 0.0,
                        site_memory: 0.0,
                        load: 0.0,
                        preference: 0.0,
                        cost: 0.0,
                        cooldown_penalty: 0.0,
                        degraded_penalty: 0.0,
                    },
                )
            });
            if let Some((current_name, current_parts)) = current {
                if current_parts.degraded_penalty == 0.0
                    && current_parts.cooldown_penalty == 0.0
                    && current_parts.total + SWITCH_TOLERANCE >= best_parts.total
                {
                    current_name
                } else {
                    best_name
                }
            } else {
                best_name
            }
        };
        if selected.is_empty() {
            selected = members[0].clone();
        }
        self.remember_selection(context, &selected);
        (selected, explanations)
    }

    fn score(
        &self,
        name: &str,
        context: &SmartContext,
        stats: &NodeStatSnapshot,
        weights: &Weights,
        cache_hit: Option<&str>,
        speed_reference: f64,
    ) -> ScoreParts {
        let confidence = (stats.samples as f64 / 5.0).min(1.0);
        let latency = if stats.samples == 0 {
            50.0
        } else {
            100.0 * (1.0 - (1.0 + stats.p50_latency_ms.min(3000.0)).ln() / 3001.0f64.ln())
        };
        let success = (stats.success_rate * confidence + 0.5 * (1.0 - confidence)) * 100.0;
        let tail = (stats.p90_latency_ms - stats.p50_latency_ms).max(0.0);
        let stability = clamp(
            100.0
                - stats.jitter_ms.min(500.0) / 5.0
                - tail.min(1000.0) / 10.0
                - stats.timeout_rate * 70.0,
            0.0,
            100.0,
        );
        let throughput = if stats.throughput_bps <= 0.0 {
            50.0
        } else {
            clamp(
                stats.throughput_bps.ln_1p() / speed_reference.ln_1p() * 100.0,
                0.0,
                100.0,
            )
        };
        let site_memory = if cache_hit == Some(name) { 100.0 } else { 50.0 };
        let load = 100.0 / (1.0 + stats.active_conn as f64 / 8.0);
        let preference = if context
            .prefer
            .iter()
            .any(|preference| name.contains(preference))
        {
            90.0
        } else {
            50.0
        };
        let cost = 50.0;
        let cooldown_penalty = if self.negative.is_cool(name).is_some() {
            55.0
        } else {
            0.0
        };
        let degraded_penalty = if stats.degraded { 28.0 } else { 0.0 };
        let total = weights.latency * latency
            + weights.success * success
            + weights.stability * stability
            + weights.throughput * throughput
            + weights.site_memory * site_memory
            + weights.load * load
            + weights.preference * preference
            + weights.cost * cost
            - cooldown_penalty
            - degraded_penalty;
        ScoreParts {
            total,
            latency,
            success,
            stability,
            throughput,
            site_memory,
            load,
            preference,
            cost,
            cooldown_penalty,
            degraded_penalty,
        }
    }

    fn cache_hit(&self, context: &SmartContext) -> Option<String> {
        self.cache_key(context)
            .and_then(|key| self.domain_best.get(&key))
    }

    fn remember_selection(&self, context: &SmartContext, node: &str) {
        let Some(key) = self.cache_key(context) else {
            return;
        };
        if !self.domain_best.put_if_changed(&key, node) {
            return;
        }
        if let Some(writer) = &self.writer {
            let _ = writer.enqueue(BatchOp::PutDomainBest(
                key,
                DomainBestBlob {
                    node: node.to_string(),
                    set_at_secs: unix_now(),
                },
            ));
        }
    }

    fn cache_key(&self, context: &SmartContext) -> Option<String> {
        match context.sticky.unwrap_or_else(|| *self.sticky.read()) {
            SmartSticky::Off => None,
            SmartSticky::Site => Some(DomainBest::key(
                &context.group,
                &registrable_domain(&context.host),
            )),
            SmartSticky::Session => Some(DomainBest::key(
                &context.group,
                context
                    .session_key
                    .as_deref()
                    .unwrap_or(context.host.as_str()),
            )),
        }
    }
}

fn to_node_score(
    name: &str,
    stats: &NodeStatSnapshot,
    parts: ScoreParts,
    cache_hit: Option<&str>,
    prefer: &[String],
) -> NodeScore {
    let mut reasons = Vec::with_capacity(5);
    if cache_hit == Some(name) {
        reasons.push("site memory".to_string());
    }
    if prefer.iter().any(|item| name.contains(item)) {
        reasons.push("preferred".to_string());
    }
    reasons.push(format!(
        "p50={:.0}ms p90={:.0}ms success={:.0}% speed={:.1}MiB/s",
        stats.p50_latency_ms,
        stats.p90_latency_ms,
        stats.success_rate * 100.0,
        stats.throughput_bps / 1024.0 / 1024.0,
    ));
    if stats.degraded {
        reasons.push("degraded".to_string());
    }
    if let Some(error) = &stats.last_error {
        reasons.push(format!("last failure: {error}"));
    }
    NodeScore {
        node: name.to_string(),
        score: parts.total,
        latency_score: parts.latency,
        success_score: parts.success,
        stability_score: parts.stability,
        throughput_score: parts.throughput,
        site_memory_score: parts.site_memory,
        load_score: parts.load,
        preference_score: parts.preference,
        cost_score: parts.cost,
        cooldown_penalty: parts.cooldown_penalty,
        capability_penalty: 0.0,
        degraded_penalty: parts.degraded_penalty,
        reason: reasons.join("; "),
    }
}

fn speed_bucket(bytes_per_second: f64) -> usize {
    if bytes_per_second <= 1.0 {
        return 0;
    }
    (bytes_per_second.log2().floor() as usize).min(63)
}

fn speed_reference(histogram: &[u32; 64], samples: u32) -> f64 {
    if samples < 3 {
        return SPEED_FLOOR_BPS;
    }
    let target = samples.saturating_mul(9).div_ceil(10);
    let mut seen = 0u32;
    for (bucket, count) in histogram.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= target {
            return 2f64
                .powi(bucket as i32)
                .clamp(SPEED_FLOOR_BPS, SPEED_CEILING_BPS);
        }
    }
    SPEED_CEILING_BPS
}

fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map(str::to_owned).unwrap_or(host)
}

fn stable_context_hash(context: &SmartContext) -> u64 {
    let mut hasher = AHasher::default();
    context.group.hash(&mut hasher);
    registrable_domain(&context.host).hash(&mut hasher);
    hasher.finish()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn clamp(value: f64, minimum: f64, maximum: f64) -> f64 {
    value.max(minimum).min(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> SmartContext {
        SmartContext {
            group: "main".into(),
            host: "www.example.co.uk".into(),
            prefer: vec![],
            avoid: vec![],
            current: None,
            sticky: None,
            session_key: None,
        }
    }

    #[test]
    fn balanced_picks_lower_latency() {
        let selector = SmartSelector::new(SmartGoal::Balanced, SmartSticky::Site);
        for _ in 0..4 {
            selector.record_success("HK-1", Duration::from_millis(50));
            selector.record_success("US-1", Duration::from_millis(300));
        }
        let choice = selector.choose(&context(), &["HK-1".into(), "US-1".into()]);
        assert_eq!(choice.node, "HK-1");
        assert_eq!(choice.explain.scores.len(), 2);
    }

    #[test]
    fn cooldown_pushes_node_down() {
        let selector = SmartSelector::new(SmartGoal::Balanced, SmartSticky::Site);
        selector.record_success("HK-1", Duration::from_millis(50));
        selector.record_failure("HK-1", "tcp reset");
        selector.record_success("US-1", Duration::from_millis(300));
        let choice = selector.choose(&context(), &["HK-1".into(), "US-1".into()]);
        assert_eq!(choice.node, "US-1");
    }

    #[test]
    fn public_suffix_uses_real_registrable_domain() {
        assert_eq!(registrable_domain("www.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn group_sticky_modes_have_distinct_scopes() {
        let selector = SmartSelector::new(SmartGoal::Balanced, SmartSticky::Site);
        let mut first = context();
        first.sticky = Some(SmartSticky::Session);
        first.session_key = Some("client-a|example.co.uk|443|tcp".into());
        let mut second = first.clone();
        second.session_key = Some("client-b|example.co.uk|443|tcp".into());
        assert_ne!(selector.cache_key(&first), selector.cache_key(&second));

        first.sticky = Some(SmartSticky::Site);
        second.sticky = Some(SmartSticky::Site);
        second.host = "api.example.co.uk".into();
        assert_eq!(selector.cache_key(&first), selector.cache_key(&second));

        first.sticky = Some(SmartSticky::Off);
        assert!(selector.cache_key(&first).is_none());
    }

    #[tokio::test]
    async fn stats_persist_across_restart() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-smart-store-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let store = core_store::Store::open(&path).await.unwrap();
            let selector =
                SmartSelector::with_store(SmartGoal::Balanced, SmartSticky::Site, store).await;
            selector.record_success("HK-1", Duration::from_millis(80));
            selector.record_success("HK-1", Duration::from_millis(60));
            selector.record_failure("US-1", "timeout");
            selector.shutdown().await;
        }
        let store = core_store::Store::open(&path).await.unwrap();
        let selector =
            SmartSelector::with_store(SmartGoal::Balanced, SmartSticky::Site, store).await;
        assert!(selector.ensure_node("HK-1").snapshot().samples >= 2);
        assert!(selector.ensure_node("US-1").snapshot().last_error.is_some());
    }
}
