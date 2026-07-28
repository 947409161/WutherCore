//! 策略组运行时。
//!
//! | mihomo type           | WutherCore ChooseStrategy        | 行为                                                 |
//! |-----------------------|--------------------------------|------------------------------------------------------|
//! | `select`              | `Manual`                       | 用户/API 选择；alive fallback                        |
//! | `url-test`            | `Smart` / `Fast`               | URLTest 最低延迟 + tolerance + singledo              |
//! | `fallback`            | `Stable`                       | 顺序找首个 alive；fixed 选择优先                     |
//! | `load-balance`        | `Spread`                       | consistent-hashing / round-robin / sticky-sessions   |
//! | `relay` (chain)       | `Chain`                        | 配置编译期拒绝，避免静默退化为单跳                   |
//!
//! ## 关键能力
//!
//! * `filter` / `exclude_filter` 正则数组（多条用 backtick 分隔）
//! * `exclude_type` 协议黑名单（`http|https`）
//! * 每流 `FlowMeta { host, src_ip, dst_ip }` 用作 LB key（src+dst 哈希）
//! * `onDialFailed` / `onDialSuccess` —— 累计 `failed_times`，超过 `max_failed_times`
//!   且时间窗内 → 触发 `health_check_now()`（外部 URLTester 接管）
//! * 死节点感知：所有策略统一调 `tester.alive_for_url()` 跳过 dead
//! * `MarshalJSON`：与 Clash dashboard `/proxies/<group>` 一致字段
//!   `{ type, now, all, testUrl, expectedStatus, fixed, hidden, icon, strategy? }`

use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::AHasher;
use core_config::{
    model::{ChooseStrategy, SmartSticky},
    runtime_plan::GroupPlan,
};
use core_smart::{SmartContext, SmartSelector};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use tracing::debug;

use crate::health::UrlTester;

/* ============================================================
FlowMeta：策略组选点的输入上下文
============================================================ */

/// 一次 dial 的元数据 —— LoadBalance / Smart 等需要 host / src 用作 hash key。
#[derive(Debug, Clone, Default)]
pub struct FlowMeta {
    /// 目标 host（域名优先；纯 IP 时退化为 IP literal）
    pub host: String,
    /// 已解析过的 IP literal（fake-ip / 真实 IP 都行）；可选
    pub dst_ip: Option<std::net::IpAddr>,
    /// 入站客户端来源（用于 sticky-sessions）；可选
    pub src_ip: Option<std::net::IpAddr>,
    /// 目标端口
    pub port: u16,
    /// "tcp" / "udp"
    pub network: &'static str,
}

impl FlowMeta {
    pub fn for_host(host: impl Into<String>, port: u16, network: &'static str) -> Self {
        Self {
            host: host.into(),
            dst_ip: None,
            src_ip: None,
            port,
            network,
        }
    }
    /// 用于 LB key —— mihomo `getKey(metadata)`：host 是 IP 取 IP；
    /// 否则取 eTLD+1（这里简化为最后两段 dot 子串）。
    pub fn lb_key(&self) -> String {
        if self.host.is_empty() {
            return self.dst_ip.map(|i| i.to_string()).unwrap_or_default();
        }
        if self.host.parse::<std::net::IpAddr>().is_ok() {
            return self.host.clone();
        }
        etld_plus_one(&self.host)
    }
    /// 用于 sticky-sessions key —— mihomo `getKeyWithSrcAndDst`：src+dst。
    pub fn lb_key_sticky(&self) -> String {
        let dst = self.lb_key();
        let src = self.src_ip.map(|i| i.to_string()).unwrap_or_default();
        format!("{src}{dst}")
    }
}

fn etld_plus_one(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map(str::to_owned).unwrap_or(host)
}

/* ============================================================
GroupOptions：扩展 GroupPlan 用不上的 mihomo 选项
============================================================ */

/// 与 mihomo `GroupCommonOption` 同语义的运行期选项。
/// 从 `GroupPlan` 派生 dashboard 展示字段，其余运行期选项使用默认值。
#[derive(Debug, Clone)]
pub struct GroupOptions {
    /// 默认探测 URL（覆盖 UrlTester::default_url 用）
    pub url: Option<String>,
    /// expected-status 表达式（"200/204/401-429"），空则任意
    pub expected_status: String,
    /// LoadBalance 策略：`consistent-hashing` / `round-robin` / `sticky-sessions`
    pub lb_strategy: LbStrategy,
    /// URLTest tolerance（毫秒）
    pub tolerance: u32,
    /// 活跃组的健康检查间隔。
    pub interval: Duration,
    /// 组无流量后停止周期探活的时间。
    pub idle_timeout: Duration,
    /// None 表示继承全局 unified-delay。
    pub unified_delay: Option<bool>,
    /// 节点名 filter 正则；多条用 backtick "`" 分隔
    pub filter: String,
    /// 节点名 exclude_filter 正则
    pub exclude_filter: String,
    /// 协议黑名单：`http|https|direct`
    pub exclude_type: String,
    /// `onDialFailed` 累计阈值
    pub max_failed_times: u32,
    /// 累计失败时间窗（毫秒）
    pub test_timeout_ms: u64,
    /// 是否禁用 UDP（disable-udp）
    pub disable_udp: bool,
    /// 仅 dashboard 显示用
    pub hidden: bool,
    pub icon: String,
}

impl Default for GroupOptions {
    fn default() -> Self {
        Self {
            url: None,
            expected_status: String::new(),
            lb_strategy: LbStrategy::ConsistentHashing,
            tolerance: 50,
            interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(10 * 60),
            unified_delay: None,
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            max_failed_times: 5,
            test_timeout_ms: 5_000,
            disable_udp: false,
            hidden: false,
            icon: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

impl LbStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "consistent-hashing" | "consistent_hashing" => Some(Self::ConsistentHashing),
            "round-robin" | "round_robin" => Some(Self::RoundRobin),
            "sticky-sessions" | "sticky_sessions" => Some(Self::StickySessions),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConsistentHashing => "consistent-hashing",
            Self::RoundRobin => "round-robin",
            Self::StickySessions => "sticky-sessions",
        }
    }
}

/* ============================================================
GroupBase：成员过滤 + onDialFailed/Success + healthCheck 调度
============================================================ */

#[derive(Debug, Default)]
struct FailureWindow {
    times: AtomicI32,
    first_at_ms: parking_lot::Mutex<Option<Instant>>,
    health_checking: parking_lot::Mutex<bool>,
}

/// LB 状态机 —— round-robin 索引、sticky-sessions LRU。
#[derive(Debug)]
struct LbState {
    rr: AtomicUsize,
    /// (key_hash → member_index) + 最近 N 次访问时间，简易 LRU。
    sticky: Mutex<StickyLru>,
}

#[derive(Debug)]
struct StickyLru {
    ttl: Duration,
    map: LruCache<u64, (usize, Instant)>,
}

impl StickyLru {
    fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            map: LruCache::new(NonZeroUsize::new(cap.max(1)).expect("non-zero lru capacity")),
        }
    }
    fn get(&mut self, k: u64) -> Option<usize> {
        let now = Instant::now();
        if let Some((idx, when)) = self.map.get(&k).copied() {
            if now.duration_since(when) < self.ttl {
                self.map.put(k, (idx, now));
                return Some(idx);
            }
            self.map.pop(&k);
        }
        None
    }
    fn put(&mut self, k: u64, idx: usize) {
        self.map.put(k, (idx, Instant::now()));
    }
}

impl Default for LbState {
    fn default() -> Self {
        Self {
            rr: AtomicUsize::new(0),
            sticky: Mutex::new(StickyLru::new(1024, Duration::from_secs(600))),
        }
    }
}

/* ============================================================
GroupSelector
============================================================ */

#[derive(Debug)]
pub struct GroupSelector {
    plan: GroupPlan,
    opts: RwLock<GroupOptions>,
    /// 编译后的 filter 正则（多条 OR）
    filter_regs: RwLock<Vec<Regex>>,
    exclude_filter_regs: RwLock<Vec<Regex>>,
    exclude_type_set: RwLock<Vec<String>>,
    health_revision: AtomicU64,
    /// 所有组类型共享的用户固定选择。
    pin: RwLock<Option<GroupPin>>,
    /// 下一个 pin 世代。独立于时间，避免同毫秒更新产生 ABA。
    pin_generation: AtomicU64,
    /// 失败窗口
    failure: FailureWindow,
    /// LB 状态
    lb: LbState,
    /// "上次选择"持久 cache，便于 Now() 不抖动 —— sticky 场景。
    last_pick: RwLock<Option<String>>,
}

impl GroupSelector {
    pub fn new(plan: GroupPlan) -> Self {
        let opts = GroupOptions {
            url: plan.check.clone(),
            expected_status: plan.expected_status.clone(),
            lb_strategy: LbStrategy::parse(&plan.strategy).unwrap_or(LbStrategy::ConsistentHashing),
            tolerance: plan.tolerance,
            interval: plan.interval,
            idle_timeout: plan.idle_timeout,
            unified_delay: plan.unified_delay,
            filter: plan.filter.clone(),
            exclude_filter: plan.exclude_filter.clone(),
            exclude_type: plan.exclude_type.clone(),
            max_failed_times: plan.max_failed_times,
            test_timeout_ms: plan.test_timeout.as_millis().min(u64::MAX as u128) as u64,
            disable_udp: plan.disable_udp,
            hidden: plan.hidden,
            icon: plan.icon.clone(),
        };
        Self::with_options(plan, opts)
    }

    pub fn with_options(plan: GroupPlan, opts: GroupOptions) -> Self {
        let me = Self {
            plan,
            opts: RwLock::new(GroupOptions::default()),
            filter_regs: RwLock::new(Vec::new()),
            exclude_filter_regs: RwLock::new(Vec::new()),
            exclude_type_set: RwLock::new(Vec::new()),
            health_revision: AtomicU64::new(0),
            pin: RwLock::new(None),
            pin_generation: AtomicU64::new(0),
            failure: FailureWindow::default(),
            lb: LbState::default(),
            last_pick: RwLock::new(None),
        };
        me.set_options(opts);
        me
    }

    pub fn name(&self) -> &str {
        &self.plan.name
    }
    pub fn plan(&self) -> &GroupPlan {
        &self.plan
    }
    pub fn members(&self) -> &[String] {
        &self.plan.members
    }
    pub fn options(&self) -> GroupOptions {
        self.opts.read().clone()
    }

    /// 热改 GroupOptions —— `/configs PUT` 或 dashboard 修改 strategy/filter 时调。
    pub fn set_options(&self, opts: GroupOptions) {
        let filter_regs = compile_regs_backtick(&opts.filter);
        let exclude_regs = compile_regs_backtick(&opts.exclude_filter);
        let etypes: Vec<String> = if opts.exclude_type.is_empty() {
            Vec::new()
        } else {
            opts.exclude_type
                .split('|')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        *self.filter_regs.write() = filter_regs;
        *self.exclude_filter_regs.write() = exclude_regs;
        *self.exclude_type_set.write() = etypes;
        self.health_revision
            .store(group_health_revision(&self.plan, &opts), Ordering::Release);
        *self.opts.write() = opts;
    }

    /// 应用 filter / exclude_filter / exclude_type 后的成员快照。
    /// `protocol_of` 闭包用于查询 outbound 协议名（运行时有 OutboundRegistry）；
    /// 测试场景可以传 `|_| ""`。
    pub fn filtered_members(&self, protocol_of: impl Fn(&str) -> String) -> Vec<String> {
        let filt = self.filter_regs.read();
        let excl = self.exclude_filter_regs.read();
        let etypes = self.exclude_type_set.read();
        let mut out: Vec<String> = self
            .plan
            .members
            .iter()
            .filter(|n| {
                if !etypes.is_empty() {
                    let proto = protocol_of(n).to_lowercase();
                    if etypes.iter().any(|e| *e == proto) {
                        return false;
                    }
                }
                if !filt.is_empty() && !filt.iter().any(|r| r.is_match(n)) {
                    return false;
                }
                if !excl.is_empty() && excl.iter().any(|r| r.is_match(n)) {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        if out.is_empty() {
            // 兼容 mihomo："filter 空命中时回退原 members"（不会让 group 完全不可用）。
            out = self.plan.members.clone();
        }
        out
    }

    pub fn has_unresolved_feed_placeholders(&self) -> bool {
        self.plan.members.iter().any(|m| is_feed_placeholder(m))
    }

    pub fn set_pin(&self, node: impl Into<String>, source: PinSource) -> GroupPin {
        let node = node.into();
        let generation = self.pin_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let pin = GroupPin {
            node: node.clone(),
            generation,
            created_at_ms: now_ms(),
            source,
        };
        *self.last_pick.write() = Some(node);
        *self.pin.write() = Some(pin.clone());
        pin
    }

    pub fn restore_pin(&self, mut pin: GroupPin) {
        pin.source = PinSource::Restored;
        self.pin_generation
            .fetch_max(pin.generation, Ordering::AcqRel);
        *self.last_pick.write() = Some(pin.node.clone());
        *self.pin.write() = Some(pin);
    }

    /// 清除当前固定选择。`last_pick` 保留，自动策略下一次选点会以它作为
    /// 迟滞参考，但不会继续强制路由到该节点。
    pub fn clear_pin(&self) -> Option<GroupPin> {
        self.pin.write().take()
    }

    pub fn current_pin(&self) -> Option<GroupPin> {
        self.pin.read().clone()
    }

    pub(crate) fn restore_pin_after_failed_commit(
        &self,
        pin: Option<GroupPin>,
        last_pick: Option<String>,
    ) {
        *self.pin.write() = pin;
        *self.last_pick.write() = last_pick;
    }

    /// 兼容旧内部调用。新代码应使用 [`Self::set_pin`]。
    pub fn set_manual(&self, node: impl Into<String>) {
        self.set_pin(node, PinSource::Restored);
    }

    pub fn clear_manual(&self) {
        self.clear_pin();
    }

    pub fn current_manual(&self) -> Option<String> {
        self.current_pin().map(|pin| pin.node)
    }

    pub fn last_pick(&self) -> Option<String> {
        self.last_pick.read().clone()
    }

    pub fn begin_manual_probe(&self) -> ManualProbeToken {
        ManualProbeToken {
            generation: self.pin.read().as_ref().map(|pin| pin.generation),
            // Selector 的测速只刷新健康状态，不改变用户的持久选择。
            release_after_success: !matches!(self.plan.choose, ChooseStrategy::Manual),
        }
    }

    /// 在一次 Clash 手动组测速成功后解除自动策略的旧 pin。
    ///
    /// 返回 true 表示确实发生了解锁。至少有一个候选探活成功才允许解锁，
    /// 避免网络整体中断时丢掉用户意图。
    pub fn complete_manual_probe(&self, token: ManualProbeToken, any_success: bool) -> bool {
        if !any_success || !token.release_after_success {
            return false;
        }
        let Some(generation) = token.generation else {
            return false;
        };
        let mut pin = self.pin.write();
        if pin.as_ref().map(|pin| pin.generation) != Some(generation) {
            return false;
        }
        pin.take();
        true
    }

    /* ====================================================================
    核心选点入口 —— 与 mihomo `Unwrap(metadata, touch)` 等价。
    ==================================================================== */

    /// 选出一个节点；策略全量分支。
    pub fn pick(
        &self,
        meta: &FlowMeta,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        self.pick_eligible(meta, smart, tester, |_| true)
    }

    /// 选出一个满足额外能力约束的节点。
    ///
    /// TUN UDP 会用这个入口过滤不支持 UDP relay 的 outbound。这里不把
    /// unsupported 节点留给后续 dial 再 fallback，避免 UDP 流量静默绕到 DIRECT。
    pub fn pick_eligible(
        &self,
        meta: &FlowMeta,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
        eligible: impl Fn(&str) -> bool,
    ) -> Option<String> {
        self.pick_eligible_with_protocol(meta, smart, tester, eligible, |_| String::new())
    }

    pub fn pick_eligible_with_protocol(
        &self,
        meta: &FlowMeta,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
        eligible: impl Fn(&str) -> bool,
        protocol_of: impl Fn(&str) -> String,
    ) -> Option<String> {
        if meta.network == "udp" && self.opts.read().disable_udp {
            tracing::debug!(
                target: "group::pick",
                group = %self.plan.name,
                "UDP rejected by group disable-udp"
            );
            return None;
        }
        let mut members = self.filtered_members(protocol_of);
        let unresolved_feeds = members.iter().filter(|m| is_feed_placeholder(m)).count();
        if unresolved_feeds > 0 {
            members.retain(|m| !is_feed_placeholder(m));
        }
        let before_eligibility = members.len();
        members.retain(|m| eligible(m));
        if members.is_empty() {
            tracing::warn!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                unresolved_feeds,
                candidates_before_eligibility = before_eligibility,
                network = meta.network,
                "no selectable members after filter/provider expansion -> caller will fall back",
            );
            return None;
        }
        let url = self.opts.read().url.clone().unwrap_or_else(|| {
            tester
                .map(|t| t.current_config().default_url)
                .unwrap_or_default()
        });
        if let Some(tester) = tester {
            let opts = self.opts.read().clone();
            tester.activate_group(
                self.name(),
                self.health_revision.load(Ordering::Acquire),
                &members,
                &url,
                &opts.expected_status,
                opts.unified_delay,
                opts.interval,
                opts.idle_timeout,
            );
        }
        let started = std::time::Instant::now();
        let chosen = self
            .pick_pin(&members, &url, tester.map(|tester| tester.as_ref()))
            .or_else(|| match self.plan.choose {
                ChooseStrategy::Manual => self.pick_manual(&members),
                ChooseStrategy::Smart => self.pick_smart(meta, &members, smart),
                ChooseStrategy::Fast => self.pick_url_test(&members, &url, tester),
                ChooseStrategy::Stable => self.pick_fallback(&members, &url, tester),
                ChooseStrategy::Spread => self.pick_load_balance(meta, &members, &url, tester),
                ChooseStrategy::Chain => self.pick_chain(&members),
            });
        match &chosen {
            Some(n) => tracing::debug!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                candidates = members.len(),
                picked = %n,
                fixed = ?self.current_manual(),
                elapsed_us = started.elapsed().as_micros() as u64,
                "decided",
            ),
            None => tracing::warn!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                candidates = members.len(),
                "no node chosen",
            ),
        }
        if let Some(ref n) = chosen {
            let needs_update = self.last_pick.read().as_deref() != Some(n.as_str());
            if needs_update {
                *self.last_pick.write() = Some(n.clone());
            }
        }
        chosen
    }

    /// 兼容旧签名：仅按 host 选点。
    pub fn pick_by_host(
        &self,
        host: &str,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let meta = FlowMeta::for_host(host, 443, "tcp");
        self.pick(&meta, smart, tester)
    }

    /* ====================================================================
    Selector / Manual —— mihomo selector.go
    ==================================================================== */

    fn pick_pin(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&UrlTester>,
    ) -> Option<String> {
        let pin = self.pin.read().clone()?;
        if !members.iter().any(|member| member == &pin.node) {
            // provider 暂时移除节点时保留 pin 意图；节点重新出现后会自动恢复。
            return None;
        }
        if matches!(self.plan.choose, ChooseStrategy::Manual)
            || tester
                .map(|tester| tester.alive_for_url(&pin.node, url))
                .unwrap_or(true)
        {
            return Some(pin.node);
        }
        // 自动策略固定节点失活时只做运行时故障转移，不删除持久 pin。
        None
    }

    /// 启动与 provider 刷新时预热一次组健康计划。
    pub fn activate_health(&self, tester: &Arc<UrlTester>) {
        self.activate_health_with_protocol(tester, |_| String::new());
    }

    /// 使用真实 outbound 协议过滤后预热健康计划，确保 `exclude-type` 不会为
    /// 已排除的海量节点创建无效探测。
    pub fn activate_health_with_protocol(
        &self,
        tester: &Arc<UrlTester>,
        protocol_of: impl Fn(&str) -> String,
    ) {
        let members = self.filtered_members(protocol_of);
        let opts = self.opts.read().clone();
        let url = opts
            .url
            .clone()
            .unwrap_or_else(|| tester.current_config().default_url);
        tester.activate_group(
            self.name(),
            self.health_revision.load(Ordering::Acquire),
            &members,
            &url,
            &opts.expected_status,
            opts.unified_delay,
            opts.interval,
            opts.idle_timeout,
        );
    }

    fn pick_manual(&self, members: &[String]) -> Option<String> {
        members.first().cloned()
    }

    /* ====================================================================
    URLTest / Fast —— mihomo urltest.go fast(touch)
    ==================================================================== */

    fn pick_url_test(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let opts = self.opts.read();
        let tol = opts.tolerance;
        if let Some(t) = tester {
            let primary = self.non_avoided_members(members, url, Some(t));
            let candidates: Cow<'_, [String]> = if self.plan.prefer.is_empty() {
                primary
            } else {
                let fastest = primary
                    .iter()
                    .map(|node| t.last_delay_for_url(node, url))
                    .filter(|delay| *delay != crate::health::DEAD_DELAY)
                    .min();
                let preferred: Vec<String> = primary
                    .iter()
                    .filter(|node| self.is_preferred(node))
                    .cloned()
                    .collect();
                let preferred_fastest = preferred
                    .iter()
                    .map(|node| t.last_delay_for_url(node, url))
                    .filter(|delay| *delay != crate::health::DEAD_DELAY)
                    .min();
                if matches!(
                    (fastest, preferred_fastest),
                    (Some(fastest), Some(preferred))
                        if preferred <= fastest.saturating_add(tol)
                ) {
                    Cow::Owned(preferred)
                } else {
                    primary
                }
            };
            if let Some(p) = t.pick_fast(self.name(), candidates.as_ref(), url, tol) {
                return Some(p);
            }
        }
        // 没有 tester / 全 dead → 退回成员首位
        members.first().cloned()
    }

    /* ====================================================================
    Fallback / Stable —— mihomo fallback.go findAliveProxy
    ==================================================================== */

    fn pick_fallback(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        // prefer 是稳定优先级，avoid 只在其它候选全部失活时兜底。
        for tier in 0..3 {
            for member in members {
                let preferred = self.is_preferred(member);
                let avoided = self.is_avoided(member);
                let in_tier = match tier {
                    0 => preferred && !avoided,
                    1 => !preferred && !avoided,
                    _ => avoided,
                };
                if in_tier
                    && tester
                        .map(|tester| tester.alive_for_url(member, url))
                        .unwrap_or(true)
                {
                    return Some(member.clone());
                }
            }
        }
        members.first().cloned()
    }

    /* ====================================================================
    LoadBalance / Spread —— mihomo loadbalance.go
    ==================================================================== */

    fn pick_load_balance(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let candidates = self.non_avoided_members(members, url, tester.map(Arc::as_ref));
        let strat = self.opts.read().lb_strategy;
        match strat {
            LbStrategy::ConsistentHashing => {
                self.lb_consistent_hashing(meta, candidates.as_ref(), url, tester)
            }
            LbStrategy::RoundRobin => self.lb_round_robin(candidates.as_ref(), url, tester),
            LbStrategy::StickySessions => self.lb_sticky(meta, candidates.as_ref(), url, tester),
        }
    }

    fn is_preferred(&self, node: &str) -> bool {
        self.plan
            .prefer
            .iter()
            .any(|pattern| !pattern.is_empty() && node.contains(pattern))
    }

    fn is_avoided(&self, node: &str) -> bool {
        self.plan
            .avoid
            .iter()
            .any(|pattern| !pattern.is_empty() && node.contains(pattern))
    }

    fn non_avoided_members<'a>(
        &self,
        members: &'a [String],
        url: &str,
        tester: Option<&UrlTester>,
    ) -> Cow<'a, [String]> {
        if self.plan.avoid.is_empty() {
            return Cow::Borrowed(members);
        }
        let primary: Vec<String> = members
            .iter()
            .filter(|member| !self.is_avoided(member))
            .filter(|member| {
                tester
                    .map(|tester| tester.alive_for_url(member, url))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if primary.is_empty() {
            Cow::Borrowed(members)
        } else {
            Cow::Owned(primary)
        }
    }

    fn lb_consistent_hashing(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let key = hash_str(&meta.lb_key());
        let buckets = members.len() as i32;
        if buckets <= 0 {
            return None;
        }
        // 与 mihomo jumpHash 同算法。
        let mut k = key;
        for _ in 0..5 {
            let idx = jump_hash(k, buckets) as usize;
            let m = &members[idx];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
            k = k.wrapping_add(1);
        }
        // 全数遍历回退
        for m in members {
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
        }
        members.first().cloned()
    }

    fn lb_round_robin(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let n = members.len();
        if n == 0 {
            return None;
        }
        let start = self.lb.rr.fetch_add(1, Ordering::Relaxed) % n;
        for off in 0..n {
            let i = (start + off) % n;
            let m = &members[i];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
        }
        members.first().cloned()
    }

    fn lb_sticky(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let key = hash_str(&meta.lb_key_sticky());
        let n = members.len();
        if n == 0 {
            return None;
        }
        let mut g = self.lb.sticky.lock();
        // 1. LRU 命中
        if let Some(idx) = g.get(key) {
            if idx < n {
                let m = &members[idx];
                if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                    return Some(m.clone());
                }
            }
        }
        // 2. jumpHash 重选
        let mut k = key.wrapping_add(now_nanos());
        for _ in 0..5 {
            let idx = jump_hash(k, n as i32) as usize;
            let m = &members[idx];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                g.put(key, idx);
                return Some(m.clone());
            }
            k = k.wrapping_add(1);
        }
        // 3. 全 dead → first
        g.put(key, 0);
        members.first().cloned()
    }

    /* ====================================================================
    Smart —— 走 SmartSelector
    ==================================================================== */

    fn pick_smart(
        &self,
        meta: &FlowMeta,
        members: &[String],
        smart: &Arc<SmartSelector>,
    ) -> Option<String> {
        let sticky = self.plan.sticky.as_deref().and_then(|sticky| match sticky {
            "off" => Some(SmartSticky::Off),
            "site" => Some(SmartSticky::Site),
            "session" => Some(SmartSticky::Session),
            _ => None,
        });
        let session_key = matches!(sticky, Some(SmartSticky::Session)).then(|| {
            format!(
                "{}|{}|{}|{}",
                meta.src_ip
                    .map(|address| address.to_string())
                    .unwrap_or_default(),
                meta.host,
                meta.port,
                meta.network
            )
        });
        let ctx = SmartContext {
            group: self.plan.name.clone(),
            host: meta.host.clone(),
            prefer: self.plan.prefer.clone(),
            avoid: self.plan.avoid.clone(),
            current: self.last_pick(),
            sticky,
            session_key,
        };
        Some(smart.choose_node(&ctx, members))
    }

    /* ====================================================================
    Chain / Relay
    ==================================================================== */

    fn pick_chain(&self, members: &[String]) -> Option<String> {
        // chain 第一跳 = path[0]；具体 outbound 拼接由 dispatcher / runtime.dial 完成。
        self.plan
            .path
            .first()
            .cloned()
            .or_else(|| members.first().cloned())
    }

    /* ====================================================================
    Health-check 反馈：与 mihomo onDialFailed/onDialSuccess 等价。
    ==================================================================== */

    /// 一次成功 dial —— 重置失败计数。
    pub fn on_dial_success(&self) {
        self.failure.times.store(0, Ordering::Release);
        *self.failure.first_at_ms.lock() = None;
    }

    /// 一次失败 dial。`trigger_health_check` 在窗口内累计达到阈值时被回调；
    /// 调用方一般传 `|| tester.test_many(...)` 触发 URLTest。
    pub fn on_dial_failed(&self, _err: &str, mut trigger_health_check: impl FnMut()) {
        let opts = self.opts.read();
        let max = opts.max_failed_times.max(1);
        let window = Duration::from_millis(opts.test_timeout_ms.max(1));
        drop(opts);

        // 立刻进健康检查的特殊情况：错误是 connection refused —— 这里不解析错误内容，
        // 始终走计数路径。
        let prev = self.failure.times.fetch_add(1, Ordering::AcqRel);
        let now = Instant::now();
        if prev == 0 {
            *self.failure.first_at_ms.lock() = Some(now);
        } else {
            let first = *self.failure.first_at_ms.lock();
            if let Some(first) = first {
                if now.duration_since(first) > window {
                    // 超窗 → reset 计数
                    self.failure.times.store(1, Ordering::Release);
                    *self.failure.first_at_ms.lock() = Some(now);
                    return;
                }
            }
        }
        let cur = (prev as u32) + 1;
        if cur >= max {
            // 防重入：同一时刻只触发一次健康检查。
            let mut hc = self.failure.health_checking.lock();
            if !*hc {
                *hc = true;
                drop(hc);
                debug!(
                    target: "group::health",
                    group = %self.plan.name,
                    failed = cur,
                    "max_failed_times reached, trigger health-check"
                );
                trigger_health_check();
                let mut hc = self.failure.health_checking.lock();
                *hc = false;
                self.failure.times.store(0, Ordering::Release);
                *self.failure.first_at_ms.lock() = None;
            }
        }
    }

    /// 强制触发一次健康检查（dashboard `PUT /providers/proxies/<group>` / 调试用）。
    pub fn force_invalidate_pick_cache(&self, tester: &Arc<UrlTester>) {
        tester.invalidate_fast_pick(self.name());
    }

    pub fn mark_member_failed(&self, node: &str, tester: &Arc<UrlTester>, error: &str) {
        let url = self
            .opts
            .read()
            .url
            .clone()
            .unwrap_or_else(|| tester.current_config().default_url);
        tester.mark_runtime_failure(node, &url, error);
        tester.invalidate_fast_pick(self.name());
    }

    /// Clash 手动组测速解除自动 pin 后，立即用刚写入的健康数据恢复自动选择，
    /// 使 API 的 `now` 与下一条真实流量保持一致。
    pub fn reselect_after_manual_probe(
        &self,
        members: &[String],
        tested_url: &str,
        smart: &Arc<SmartSelector>,
        tester: &Arc<UrlTester>,
    ) -> Option<String> {
        if matches!(self.plan.choose, ChooseStrategy::Manual) || self.current_pin().is_some() {
            return self.last_pick();
        }
        let (host, port) = url::Url::parse(tested_url)
            .ok()
            .map(|url| {
                (
                    url.host_str().unwrap_or_default().to_owned(),
                    url.port_or_known_default().unwrap_or(443),
                )
            })
            .unwrap_or_default();
        let meta = FlowMeta::for_host(host, port, "tcp");
        tester.invalidate_fast_pick(self.name());
        let selected = match self.plan.choose {
            ChooseStrategy::Manual => None,
            ChooseStrategy::Smart => self.pick_smart(&meta, members, smart),
            ChooseStrategy::Fast => self.pick_url_test(members, tested_url, Some(tester)),
            ChooseStrategy::Stable => self.pick_fallback(members, tested_url, Some(tester)),
            ChooseStrategy::Spread => {
                self.pick_load_balance(&meta, members, tested_url, Some(tester))
            }
            ChooseStrategy::Chain => self.pick_chain(members),
        };
        if let Some(node) = selected.as_ref() {
            *self.last_pick.write() = Some(node.clone());
        }
        selected
    }

    /* ====================================================================
    Dashboard JSON —— 对齐 Clash `/proxies/:name` 字段
    ==================================================================== */

    pub fn to_clash_json(&self) -> serde_json::Value {
        let opts = self.opts.read();
        let strategy = match self.plan.choose {
            ChooseStrategy::Manual => "Selector",
            ChooseStrategy::Smart => "Smart",
            ChooseStrategy::Fast => "URLTest",
            ChooseStrategy::Stable => "Fallback",
            ChooseStrategy::Spread => "LoadBalance",
            ChooseStrategy::Chain => "Relay",
        };
        let now = self
            .last_pick
            .read()
            .clone()
            .filter(|node| self.plan.members.iter().any(|member| member == node))
            .or_else(|| self.current_manual())
            .filter(|node| self.plan.members.iter().any(|member| member == node))
            .unwrap_or_else(|| self.plan.members.first().cloned().unwrap_or_default());
        let pin = self.current_pin();
        let mut body = serde_json::json!({
            "type": strategy,
            "name": self.plan.name,
            "now": now,
            "all": self.plan.members,
            "udp": !opts.disable_udp,
            "alive": true,
            "history": [],
            "extra": {},
            "hidden": opts.hidden,
            "icon": opts.icon,
            "fixed": pin.as_ref().map(|pin| pin.node.clone()).unwrap_or_default(),
            "pin": pin.as_ref().map(|pin| serde_json::json!({
                "node": pin.node,
                "generation": pin.generation,
                "createdAt": pin.created_at_ms,
                "source": pin.source.as_str(),
                "persistent": true,
                "available": self.plan.members.iter().any(|member| member == &pin.node),
            })),
            "expectedStatus": opts.expected_status,
            "testUrl": opts.url.clone().unwrap_or_default(),
        });
        if matches!(self.plan.choose, ChooseStrategy::Spread) {
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "strategy".into(),
                    serde_json::Value::String(opts.lb_strategy.as_str().into()),
                );
            }
        }
        body
    }
}

/* ============================================================
utils
============================================================ */

fn compile_regs_backtick(s: &str) -> Vec<Regex> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('`')
        .filter(|p| !p.is_empty())
        .filter_map(|p| Regex::new(p).ok())
        .collect()
}

fn is_feed_placeholder(name: &str) -> bool {
    name.strip_prefix("feed:")
        .map(|rest| !rest.trim().is_empty())
        .unwrap_or(false)
}

fn hash_str(s: &str) -> u64 {
    let mut h = AHasher::default();
    s.hash(&mut h);
    h.finish()
}

/// jumpHash —— Jump Consistent Hash（与 mihomo `jumpHash` 实现一致）。
fn jump_hash(mut key: u64, buckets: i32) -> i32 {
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        let next = ((b + 1) as f64) * ((1u64 << 31) as f64) / (((key >> 33) + 1) as f64);
        j = next as i64;
    }
    b as i32
}

fn now_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use core_config::{model::ChooseStrategy, runtime_plan::GroupPlan};

    use super::*;

    fn plan(choose: ChooseStrategy, members: &[&str]) -> GroupPlan {
        GroupPlan {
            name: "g".into(),
            choose,
            members: members.iter().map(|s| s.to_string()).collect(),
            prefer: vec![],
            avoid: vec![],
            check: None,
            expected_status: String::new(),
            interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(600),
            tolerance: 50,
            unified_delay: None,
            strategy: "consistent-hashing".into(),
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            max_failed_times: 5,
            test_timeout: Duration::from_secs(5),
            disable_udp: false,
            sticky: None,
            path: vec![],
            hidden: false,
            icon: String::new(),
        }
    }

    fn smart() -> Arc<SmartSelector> {
        Arc::new(SmartSelector::new(
            core_config::model::SmartGoal::Balanced,
            core_config::model::SmartSticky::Off,
        ))
    }

    fn meta(host: &str) -> FlowMeta {
        FlowMeta::for_host(host, 443, "tcp")
    }

    #[test]
    fn manual_first_then_picked() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b", "c"]));
        let s = smart();
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("a"));
        g.set_manual("c");
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("c"));
    }

    #[test]
    fn manual_invalid_pick_falls_back_to_first() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        let s = smart();
        g.set_manual("ghost");
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("a"));
    }

    #[test]
    fn unresolved_feed_placeholder_is_not_selectable() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["feed:primary", "node-a"]));
        let s = smart();

        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("node-a"));
        assert!(g.has_unresolved_feed_placeholders());
    }

    #[test]
    fn all_unresolved_feed_placeholders_return_none() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["feed:primary"]));
        let s = smart();

        assert_eq!(g.pick(&meta("x"), &s, None), None);
    }

    #[test]
    fn url_test_uses_fast_pick_when_tester_present() {
        let g = GroupSelector::new(plan(ChooseStrategy::Fast, &["a", "b", "c"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        // 种 stats：a=300, b=100, c=200
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(300, true);
        tester.ensure_stats("b", &url).record(100, true);
        tester.ensure_stats("c", &url).record(200, true);
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "b");
    }

    #[test]
    fn fallback_skips_dead_and_finds_first_alive() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a", "b", "c"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(0, false);
        tester.ensure_stats("b", &url).record(0, false);
        tester.ensure_stats("c", &url).record(150, true);
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "c");
    }

    #[test]
    fn stable_honors_prefer_and_uses_avoid_only_as_fallback() {
        let mut group_plan = plan(ChooseStrategy::Stable, &["regular", "premium", "expired"]);
        group_plan.prefer = vec!["premium".into()];
        group_plan.avoid = vec!["expired".into()];
        let g = GroupSelector::new(group_plan);
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        for node in ["regular", "premium", "expired"] {
            tester.ensure_stats(node, &url).record(50, true);
        }
        assert_eq!(
            g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
            Some("premium")
        );
        tester.ensure_stats("premium", &url).record(0, false);
        assert_eq!(
            g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
            Some("regular")
        );
        tester.ensure_stats("regular", &url).record(0, false);
        assert_eq!(
            g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
            Some("expired")
        );
    }

    #[test]
    fn fast_prefer_wins_only_inside_tolerance() {
        let mut group_plan = plan(ChooseStrategy::Fast, &["regular", "premium"]);
        group_plan.prefer = vec!["premium".into()];
        group_plan.tolerance = 50;
        let g = GroupSelector::new(group_plan);
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("regular", &url).record(100, true);
        tester.ensure_stats("premium", &url).record(130, true);
        assert_eq!(
            g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
            Some("premium")
        );
        tester.invalidate_fast_pick("g");
        tester.ensure_stats("premium", &url).record(200, true);
        assert_eq!(
            g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
            Some("regular")
        );
    }

    #[test]
    fn automatic_group_fails_over_without_losing_durable_pin() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a", "b"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(0, false);
        tester.ensure_stats("b", &url).record(150, true);
        g.set_manual("a");
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "b");
        assert_eq!(g.current_manual().as_deref(), Some("a"));

        tester.ensure_stats("a", &url).record(80, true);
        assert_eq!(g.pick(&meta("x"), &s, Some(&tester)).as_deref(), Some("a"));
    }

    #[test]
    fn every_strategy_honors_a_live_pin() {
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(20, true);
        tester.ensure_stats("b", &url).record(10, true);
        let s = smart();

        for strategy in [
            ChooseStrategy::Manual,
            ChooseStrategy::Smart,
            ChooseStrategy::Fast,
            ChooseStrategy::Stable,
            ChooseStrategy::Spread,
            ChooseStrategy::Chain,
        ] {
            let g = GroupSelector::new(plan(strategy, &["a", "b"]));
            g.set_pin("a", PinSource::ClashApi);
            assert_eq!(
                g.pick(&meta("x"), &s, Some(&tester)).as_deref(),
                Some("a"),
                "{strategy:?} ignored its pin"
            );
        }
    }

    #[test]
    fn successful_manual_probe_unlocks_only_automatic_groups() {
        for strategy in [
            ChooseStrategy::Smart,
            ChooseStrategy::Fast,
            ChooseStrategy::Stable,
            ChooseStrategy::Spread,
            ChooseStrategy::Chain,
        ] {
            let g = GroupSelector::new(plan(strategy, &["a", "b"]));
            g.set_pin("a", PinSource::ClashApi);
            let token = g.begin_manual_probe();
            assert!(g.complete_manual_probe(token, true), "{strategy:?}");
            assert!(g.current_pin().is_none(), "{strategy:?}");
        }

        let manual = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        manual.set_pin("a", PinSource::ClashApi);
        let token = manual.begin_manual_probe();
        assert!(!manual.complete_manual_probe(token, true));
        assert_eq!(manual.current_manual().as_deref(), Some("a"));
    }

    #[test]
    fn failed_or_stale_manual_probe_never_clears_pin() {
        let g = GroupSelector::new(plan(ChooseStrategy::Fast, &["a", "b"]));
        g.set_pin("a", PinSource::ClashApi);
        let failed = g.begin_manual_probe();
        assert!(!g.complete_manual_probe(failed, false));
        assert_eq!(g.current_manual().as_deref(), Some("a"));

        let stale = g.begin_manual_probe();
        let replacement = g.set_pin("b", PinSource::NativeApi);
        assert!(!g.complete_manual_probe(stale, true));
        assert_eq!(g.current_pin(), Some(replacement));
    }

    #[test]
    fn loadbalance_consistent_hashing_is_stable_per_host() {
        let mut p = plan(ChooseStrategy::Spread, &["a", "b", "c", "d"]);
        p.choose = ChooseStrategy::Spread;
        let g = GroupSelector::new(p);
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::ConsistentHashing,
            ..GroupOptions::default()
        });
        let s = smart();
        let p1 = g.pick(&meta("example.com"), &s, None).unwrap();
        let p2 = g.pick(&meta("example.com"), &s, None).unwrap();
        let p3 = g.pick(&meta("example.com"), &s, None).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn loadbalance_round_robin_cycles() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a", "b", "c"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::RoundRobin,
            ..GroupOptions::default()
        });
        let s = smart();
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(g.pick(&meta("h"), &s, None).unwrap());
        }
        // 至少包含全部 a,b,c
        assert!(seen.contains(&"a".to_string()));
        assert!(seen.contains(&"b".to_string()));
        assert!(seen.contains(&"c".to_string()));
    }

    #[test]
    fn disable_udp_is_enforced_by_the_selection_path() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a"]));
        g.set_options(GroupOptions {
            disable_udp: true,
            ..GroupOptions::default()
        });
        let s = smart();
        let udp = FlowMeta::for_host("example.com", 53, "udp");
        assert!(g.pick(&udp, &s, None).is_none());
        let tcp = FlowMeta::for_host("example.com", 443, "tcp");
        assert_eq!(g.pick(&tcp, &s, None).as_deref(), Some("a"));
    }

    #[test]
    fn loadbalance_sticky_returns_same_for_same_src_dst() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a", "b", "c", "d"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::StickySessions,
            ..GroupOptions::default()
        });
        let s = smart();
        let mut m = FlowMeta::for_host("h", 443, "tcp");
        m.src_ip = Some("10.0.0.1".parse().unwrap());
        let p1 = g.pick(&m, &s, None).unwrap();
        let p2 = g.pick(&m, &s, None).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn chain_returns_path_first() {
        let mut p = plan(ChooseStrategy::Chain, &["a", "b"]);
        p.path = vec!["hop1".into(), "hop2".into()];
        let g = GroupSelector::new(p);
        let s = smart();
        assert_eq!(g.pick(&meta("h"), &s, None).as_deref(), Some("hop1"));
    }

    #[test]
    fn filter_regex_keeps_matched() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["HK-1", "JP-2", "US-3"]));
        g.set_options(GroupOptions {
            filter: "^HK".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| String::new());
        assert_eq!(mems, vec!["HK-1".to_string()]);
    }

    #[test]
    fn exclude_filter_drops_matched() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["HK-1", "JP-2", "US-3"]));
        g.set_options(GroupOptions {
            exclude_filter: "JP".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| String::new());
        assert_eq!(mems, vec!["HK-1".to_string(), "US-3".to_string()]);
    }

    #[test]
    fn exclude_type_drops_protocol() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        g.set_options(GroupOptions {
            exclude_type: "ss|http".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|n| {
            if n == "a" {
                "ss".to_string()
            } else {
                "vmess".to_string()
            }
        });
        assert_eq!(mems, vec!["b".to_string()]);
    }

    #[test]
    fn filter_empty_match_falls_back_to_full_members() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        g.set_options(GroupOptions {
            filter: "^never_match$".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| String::new());
        assert_eq!(mems, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn on_dial_failed_triggers_after_max() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a"]));
        g.set_options(GroupOptions {
            max_failed_times: 3,
            test_timeout_ms: 10_000,
            ..GroupOptions::default()
        });
        let triggered = std::sync::atomic::AtomicUsize::new(0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(triggered.load(std::sync::atomic::Ordering::SeqCst), 0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(triggered.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn on_dial_success_resets_window() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a"]));
        g.set_options(GroupOptions {
            max_failed_times: 2,
            ..GroupOptions::default()
        });
        let triggered = std::sync::atomic::AtomicUsize::new(0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, Ordering::SeqCst);
        });
        g.on_dial_success();
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, Ordering::SeqCst);
        });
        // 仍未触发：第一次失败窗口已被 success 重置。
        assert_eq!(triggered.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn jump_hash_is_consistent() {
        // 改变桶数时只有 1/N 流量会"换桶"——这里只验证同 key 同 buckets 必回相同 idx。
        let k = hash_str("example.com");
        assert_eq!(jump_hash(k, 8), jump_hash(k, 8));
    }

    #[test]
    fn etld_plus_one_basic() {
        assert_eq!(etld_plus_one("a.b.example.com"), "example.com");
        assert_eq!(etld_plus_one("example.com"), "example.com");
        assert_eq!(etld_plus_one("localhost"), "localhost");
    }

    #[test]
    fn to_clash_json_includes_strategy_for_loadbalance() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::StickySessions,
            ..GroupOptions::default()
        });
        let v = g.to_clash_json();
        assert_eq!(v["type"], "LoadBalance");
        assert_eq!(v["strategy"], "sticky-sessions");
    }

    #[test]
    fn to_clash_json_uses_group_hidden_and_icon() {
        let mut group_plan = plan(ChooseStrategy::Manual, &["a"]);
        group_plan.hidden = true;
        group_plan.icon = "data:image/png;base64,iVBORw0KGgo=".into();
        let group = GroupSelector::new(group_plan);
        let value = group.to_clash_json();
        assert_eq!(value["hidden"], true);
        assert_eq!(value["icon"], "data:image/png;base64,iVBORw0KGgo=");
    }
}

fn group_health_revision(plan: &GroupPlan, opts: &GroupOptions) -> u64 {
    let mut hasher = AHasher::default();
    plan.name.hash(&mut hasher);
    plan.members.hash(&mut hasher);
    opts.url.hash(&mut hasher);
    opts.expected_status.hash(&mut hasher);
    opts.unified_delay.hash(&mut hasher);
    opts.interval.hash(&mut hasher);
    opts.idle_timeout.hash(&mut hasher);
    opts.filter.hash(&mut hasher);
    opts.exclude_filter.hash(&mut hasher);
    opts.exclude_type.hash(&mut hasher);
    hasher.finish()
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// API 固定节点的来源。来源只用于观测，不参与选择语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    ClashApi,
    NativeApi,
    Restored,
}

impl PinSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClashApi => "clash_api",
            Self::NativeApi => "native_api",
            Self::Restored => "restored",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "native_api" => Self::NativeApi,
            "restored" => Self::Restored,
            _ => Self::ClashApi,
        }
    }
}

/// 一个持久化 pin 的内存状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPin {
    pub node: String,
    pub generation: u64,
    pub created_at_ms: u64,
    pub source: PinSource,
}

/// 手动组测速的并发令牌。
///
/// 测速完成时必须携带开始时看到的世代。用户在测速期间重新选择节点后，
/// 旧令牌不能解除新的 pin。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualProbeToken {
    generation: Option<u64>,
    release_after_success: bool,
}
