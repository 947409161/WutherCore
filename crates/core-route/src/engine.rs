//! 路由匹配引擎。
//!
//! 输入：[`FlowContext`] —— 一次连接的目标（域名/IP/端口/网络/进程）。
//! 输出：[`RouteDecision`] —— direct / block / group("xxx")。

use std::{net::IpAddr, sync::Arc};

use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use arc_swap::ArcSwap;
use core_config::runtime_plan::{RouteAction, RouteMatcher, RoutePlan};
use core_ruleset::{
    RulesetIndex, RulesetInterfaceAddress, RulesetMatchContext, RulesetMatchOutcome,
    compile_mihomo_domain_regex,
};
use fancy_regex::Regex as FancyRegex;
use globset::{GlobBuilder, GlobMatcher};
use ipnet::IpNet;

use crate::builtin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

impl NetworkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// sing-box 规则集可选元数据。
///
/// 这些值只在调用方确实掌握时填写；`None`/空集合不会回退到连接协议、
/// 目标地址或其他近似字段，对应 predicate 会安全地返回 false。
#[derive(Debug, Clone)]
pub struct FlowRulesetMetadata {
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub inbound_port: Option<u16>,
    pub inbound_type: Option<String>,
    pub inbound_user: Option<String>,
    pub inbound_name: Option<String>,
    pub uid: Option<u32>,
    pub dscp: Option<u8>,
    pub source_geoip: Vec<String>,
    pub destination_geoip: Vec<String>,
    pub destination_geosite: Vec<String>,
    pub source_asn: Option<u32>,
    pub destination_asn: Option<u32>,
    pub rematch_names: Vec<String>,
    pub query_type: Option<u16>,
    pub process_path: Option<String>,
    pub package_names: Vec<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_type: Option<u8>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub network_interface_addresses: Vec<RulesetInterfaceAddress>,
    pub default_interface_addresses: Vec<IpNet>,
}

impl Default for FlowRulesetMetadata {
    fn default() -> Self {
        Self {
            source_ip: None,
            source_port: None,
            inbound_port: None,
            inbound_type: None,
            inbound_user: None,
            inbound_name: None,
            uid: None,
            dscp: None,
            source_geoip: Vec::new(),
            destination_geoip: Vec::new(),
            destination_geosite: Vec::new(),
            source_asn: None,
            destination_asn: None,
            rematch_names: Vec::new(),
            query_type: None,
            process_path: None,
            package_names: Vec::new(),
            wifi_ssid: None,
            wifi_bssid: None,
            network_type: None,
            network_is_expensive: None,
            network_is_constrained: None,
            network_interface_addresses: Vec::new(),
            default_interface_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: NetworkKind,
    pub process: Option<String>,
    /// sing-box 规则集专用的、可选的系统/连接元数据。
    pub ruleset: FlowRulesetMetadata,
    /// L7 协议指纹 —— 由 inbound/capture 嗅探首包后写入；用于 `proto:` 规则。
    pub protocol: Option<crate::sniff::L7Proto>,
}

impl FlowContext {
    pub fn for_domain(host: impl Into<String>, port: u16, network: NetworkKind) -> Self {
        Self {
            host: host.into(),
            ip: None,
            port,
            network,
            process: None,
            ruleset: FlowRulesetMetadata::default(),
            protocol: None,
        }
    }

    pub fn for_ip(ip: IpAddr, port: u16, network: NetworkKind) -> Self {
        Self {
            host: ip.to_string(),
            ip: Some(ip),
            port,
            network,
            process: None,
            ruleset: FlowRulesetMetadata::default(),
            protocol: None,
        }
    }

    fn ruleset_match_context(&self) -> RulesetMatchContext<'_> {
        RulesetMatchContext {
            dst_host: &self.host,
            dst_ip: self.ip,
            dst_port: Some(self.port),
            src_ip: self.ruleset.source_ip,
            src_port: self.ruleset.source_port,
            network: Some(self.network.as_str()),
            process_name: self.process.as_deref(),
            query_type: self.ruleset.query_type,
            process_path: self.ruleset.process_path.as_deref(),
            inbound_port: self.ruleset.inbound_port,
            inbound_type: self.ruleset.inbound_type.as_deref(),
            inbound_user: self.ruleset.inbound_user.as_deref(),
            inbound_name: self.ruleset.inbound_name.as_deref(),
            uid: self.ruleset.uid,
            dscp: self.ruleset.dscp,
            destination_geoip: &self.ruleset.destination_geoip,
            source_geoip: &self.ruleset.source_geoip,
            destination_geosite: &self.ruleset.destination_geosite,
            destination_asn: self.ruleset.destination_asn,
            source_asn: self.ruleset.source_asn,
            rematch_names: &self.ruleset.rematch_names,
            package_names: &self.ruleset.package_names,
            wifi_ssid: self.ruleset.wifi_ssid.as_deref(),
            wifi_bssid: self.ruleset.wifi_bssid.as_deref(),
            network_type: self.ruleset.network_type,
            network_is_expensive: self.ruleset.network_is_expensive,
            network_is_constrained: self.ruleset.network_is_constrained,
            network_interface_addresses: &self.ruleset.network_interface_addresses,
            default_interface_addresses: &self.ruleset.default_interface_addresses,
        }
    }

    /// 链式：附加嗅探到的协议；SNI 场景自动把 host 同步为 SNI 域名。
    pub fn with_protocol(mut self, p: crate::sniff::L7Proto) -> Self {
        if let crate::sniff::L7Proto::Sni(sni) = &p {
            if !sni.is_empty() && self.host.parse::<std::net::IpAddr>().is_ok() {
                self.host = sni.clone();
            }
        }
        self.protocol = Some(p);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Block,
    Group(String),
}

impl RouteDecision {
    pub fn from_action(a: &RouteAction) -> Self {
        match a {
            RouteAction::Direct => RouteDecision::Direct,
            RouteAction::Block => RouteDecision::Block,
            RouteAction::Group(g) => RouteDecision::Group(g.clone()),
            RouteAction::Pass | RouteAction::PassRule | RouteAction::SubRule(_) => {
                debug_assert!(false, "control-flow action must not produce a decision");
                RouteDecision::Direct
            }
        }
    }
}

/// 一次路由命中的完整、稳定描述。
///
/// `rule` / `payload` 与 Mihomo connection API 的顶层字段一一对应；
/// `index`、`source`、`action` 供原生连接表和兼容 API 展示完整命中上下文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRuleHit {
    pub index: Option<usize>,
    pub rule: String,
    pub payload: String,
    pub source: String,
    pub action: String,
    pub no_resolve: bool,
    pub no_log: bool,
    pub no_track: bool,
}

impl RouteRuleHit {
    fn fallback() -> Self {
        Self {
            index: None,
            rule: "MATCH".into(),
            payload: String::new(),
            source: "implicit-direct".into(),
            action: "DIRECT".into(),
            no_resolve: false,
            no_log: false,
            no_track: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedRouteDecision {
    pub decision: RouteDecision,
    pub matcher: &'static str,
    pub hit: RouteRuleHit,
}

#[derive(Debug)]
enum PreparedDomainRegex {
    Fast(regex::Regex),
    Fancy(FancyRegex),
}

#[derive(Debug, Default)]
struct PreparedMatchers {
    normalized_values: AHashMap<String, String>,
    destination_cidrs: AHashMap<String, IpNet>,
    source_cidrs: AHashMap<String, IpNet>,
    domain_regexes: AHashMap<String, PreparedDomainRegex>,
    domain_wildcards: AHashMap<String, GlobMatcher>,
    process_regexes: AHashMap<String, regex::Regex>,
    process_wildcards: AHashMap<String, GlobMatcher>,
    destination_ip_suffixes: AHashMap<String, PreparedIpSuffix>,
    source_ip_suffixes: AHashMap<String, PreparedIpSuffix>,
    geosite_aliases: AHashMap<String, Vec<String>>,
    geoip_aliases: AHashMap<String, Vec<String>>,
    asn_aliases: AHashMap<u32, Vec<String>>,
    keyword_ids: AHashMap<String, usize>,
    keyword_unique_ids: AHashMap<String, usize>,
    keyword_patterns: Vec<String>,
    keyword_automaton: Option<AhoCorasick>,
}

#[derive(Debug, Clone, Copy)]
struct PreparedIpSuffix {
    address: IpAddr,
    bits: u8,
}

impl PreparedMatchers {
    fn compile(plan: &RoutePlan) -> Self {
        fn collect(matcher: &RouteMatcher, prepared: &mut PreparedMatchers) {
            match matcher {
                RouteMatcher::Domain(value) | RouteMatcher::Suffix(value) => {
                    prepared
                        .normalized_values
                        .entry(value.clone())
                        .or_insert_with(|| normalize_route_domain(value));
                }
                RouteMatcher::Process(value)
                | RouteMatcher::ProcessPath(value)
                | RouteMatcher::InUser(value)
                | RouteMatcher::InName(value)
                | RouteMatcher::InType(value)
                | RouteMatcher::RematchName(value) => {
                    prepared
                        .normalized_values
                        .entry(value.clone())
                        .or_insert_with(|| value.to_lowercase());
                }
                RouteMatcher::Keyword(value) => {
                    let normalized = value.to_ascii_lowercase();
                    let id = match prepared.keyword_unique_ids.get(&normalized).copied() {
                        Some(id) => id,
                        None => {
                            let id = prepared.keyword_patterns.len();
                            prepared.keyword_patterns.push(normalized.clone());
                            prepared.keyword_unique_ids.insert(normalized, id);
                            id
                        }
                    };
                    prepared.keyword_ids.insert(value.clone(), id);
                }
                RouteMatcher::DomainRegex(pattern) => {
                    prepared
                        .domain_regexes
                        .entry(pattern.clone())
                        .or_insert_with(|| {
                            let mut builder = regex::RegexBuilder::new(pattern);
                            builder.case_insensitive(true);
                            match builder.build() {
                                Ok(regex) => PreparedDomainRegex::Fast(regex),
                                Err(_) => PreparedDomainRegex::Fancy(
                                    compile_mihomo_domain_regex(pattern)
                                        .expect("route regex was validated during config compile"),
                                ),
                            }
                        });
                }
                RouteMatcher::DomainWildcard(pattern) => {
                    prepared
                        .domain_wildcards
                        .entry(pattern.clone())
                        .or_insert_with(|| compile_glob(&normalize_route_domain_pattern(pattern)));
                }
                RouteMatcher::ProcessRegex(pattern) | RouteMatcher::ProcessPathRegex(pattern) => {
                    prepared
                        .process_regexes
                        .entry(pattern.clone())
                        .or_insert_with(|| {
                            regex::Regex::new(pattern)
                                .expect("process regex was validated during config compile")
                        });
                }
                RouteMatcher::ProcessWildcard(pattern)
                | RouteMatcher::ProcessPathWildcard(pattern) => {
                    prepared
                        .process_wildcards
                        .entry(pattern.clone())
                        .or_insert_with(|| compile_glob(pattern));
                }
                RouteMatcher::Cidr(value) => {
                    if let Ok(network) = value.parse() {
                        prepared.destination_cidrs.insert(value.clone(), network);
                    }
                }
                RouteMatcher::SrcCidr(value) => {
                    if let Ok(network) = value.parse() {
                        prepared.source_cidrs.insert(value.clone(), network);
                    }
                }
                RouteMatcher::IpSuffix(value) => {
                    if let Some(suffix) = parse_ip_suffix(value) {
                        prepared
                            .destination_ip_suffixes
                            .insert(value.clone(), suffix);
                    }
                }
                RouteMatcher::SrcIpSuffix(value) => {
                    if let Some(suffix) = parse_ip_suffix(value) {
                        prepared.source_ip_suffixes.insert(value.clone(), suffix);
                    }
                }
                RouteMatcher::GeoSite(value) => {
                    prepared
                        .geosite_aliases
                        .insert(value.clone(), ruleset_name_candidates("geosite", value));
                }
                RouteMatcher::GeoIp(value) | RouteMatcher::SrcGeoIp(value) => {
                    prepared
                        .geoip_aliases
                        .insert(value.clone(), ruleset_name_candidates("geoip", value));
                }
                RouteMatcher::IpAsn(asn) | RouteMatcher::SrcIpAsn(asn) => {
                    prepared
                        .asn_aliases
                        .insert(*asn, ruleset_name_candidates("asn", &asn.to_string()));
                }
                RouteMatcher::And(parts) | RouteMatcher::Or(parts) => {
                    for part in parts {
                        collect(part, prepared);
                    }
                }
                RouteMatcher::Not(part) | RouteMatcher::NoResolve(part) => collect(part, prepared),
                _ => {}
            }
        }

        let mut prepared = Self::default();
        for step in &plan.steps {
            collect(&step.matcher, &mut prepared);
        }
        for steps in plan.sub_rules.values() {
            for step in steps {
                collect(&step.matcher, &mut prepared);
            }
        }
        if !prepared.keyword_patterns.is_empty() {
            prepared.keyword_automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&prepared.keyword_patterns)
                .ok();
        }
        prepared
    }
}

struct MatchInput<'a> {
    context: &'a FlowContext,
    normalized_host: String,
    unicode_host: String,
    resolved_ip: Option<IpAddr>,
    keyword_hits: Option<Vec<bool>>,
}

impl<'a> MatchInput<'a> {
    fn new(context: &'a FlowContext) -> Self {
        let unicode_host = context.host.trim().trim_end_matches('.').to_lowercase();
        Self {
            context,
            normalized_host: normalize_route_domain(&unicode_host),
            unicode_host,
            resolved_ip: context.ip.or_else(|| context.host.parse().ok()),
            keyword_hits: None,
        }
    }

    fn keyword_matches(&mut self, prepared: &PreparedMatchers, pattern_id: usize) -> bool {
        if self.keyword_hits.is_none() {
            let mut hits = vec![false; prepared.keyword_patterns.len()];
            if let Some(automaton) = &prepared.keyword_automaton {
                for matched in automaton.find_overlapping_iter(&self.normalized_host) {
                    hits[matched.pattern().as_usize()] = true;
                }
                if self.unicode_host != self.normalized_host {
                    for matched in automaton.find_overlapping_iter(&self.unicode_host) {
                        hits[matched.pattern().as_usize()] = true;
                    }
                }
            }
            self.keyword_hits = Some(hits);
        }
        self.keyword_hits
            .as_ref()
            .and_then(|hits| hits.get(pattern_id))
            .copied()
            .unwrap_or(false)
    }
}

/// 路由引擎；按 [`RoutePlan::steps`] 顺序匹配。
#[derive(Debug, Clone)]
pub struct RouteEngine {
    plan: Arc<RoutePlan>,
    extra_cidrs: Vec<IpNet>,
    rulesets: Option<Arc<RulesetIndex>>,
    prepared: Arc<PreparedMatchers>,
    disabled_rules: Arc<ArcSwap<Vec<bool>>>,
    disabled_update: Arc<parking_lot::Mutex<()>>,
}

impl RouteEngine {
    pub fn new(plan: RoutePlan) -> Self {
        let prepared = Arc::new(PreparedMatchers::compile(&plan));
        let disabled = vec![false; plan.steps.len()];
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: None,
            prepared,
            disabled_rules: Arc::new(ArcSwap::from_pointee(disabled)),
            disabled_update: Arc::new(parking_lot::Mutex::new(())),
        }
    }

    pub fn with_rulesets(plan: RoutePlan, rulesets: Arc<RulesetIndex>) -> Self {
        let prepared = Arc::new(PreparedMatchers::compile(&plan));
        let disabled = vec![false; plan.steps.len()];
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: Some(rulesets),
            prepared,
            disabled_rules: Arc::new(ArcSwap::from_pointee(disabled)),
            disabled_update: Arc::new(parking_lot::Mutex::new(())),
        }
    }

    pub fn plan(&self) -> &RoutePlan {
        &self.plan
    }

    pub fn rulesets(&self) -> Option<Arc<RulesetIndex>> {
        self.rulesets.clone()
    }

    /// Mihomo `PATCH /rules/disable` compatible runtime rule switch.
    pub fn set_rule_disabled(&self, index: usize, disabled: bool) -> bool {
        if index >= self.plan.steps.len() {
            return false;
        }
        let _update = self.disabled_update.lock();
        let current = self.disabled_rules.load_full();
        let mut next = (*current).clone();
        next[index] = disabled;
        self.disabled_rules.store(Arc::new(next));
        true
    }

    pub fn rule_disabled(&self, index: usize) -> bool {
        self.disabled_rules
            .load()
            .get(index)
            .copied()
            .unwrap_or(false)
    }

    /// Return the exact descriptors used by routing and connection tracking.
    /// Keeping `/rules`, `/connections` and the data plane on this single
    /// formatter prevents rule-type and payload drift.
    pub fn rule_descriptions(&self) -> Vec<(RouteRuleHit, bool)> {
        self.plan
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                (
                    describe_route_step(Some(index), step),
                    self.rule_disabled(index),
                )
            })
            .collect()
    }

    pub fn decide(&self, ctx: &FlowContext) -> (RouteDecision, &'static str, String) {
        let detailed = self.decide_detailed(ctx);
        (detailed.decision, detailed.matcher, detailed.hit.source)
    }

    pub fn decide_detailed(&self, ctx: &FlowContext) -> DetailedRouteDecision {
        let disabled = self.disabled_rules.load();
        let mut input = MatchInput::new(ctx);
        let destination_ip_resolved = input.resolved_ip.is_some();
        if let StepFlow::Result(decision) = self.evaluate_steps(
            &self.plan.steps,
            &mut input,
            true,
            destination_ip_resolved,
            Some(&disabled),
            0,
        ) {
            return decision;
        }
        DetailedRouteDecision {
            decision: RouteDecision::Direct,
            matcher: "fallback",
            hit: RouteRuleHit::fallback(),
        }
    }

    /// Return whether route evaluation has actually reached a rule whose
    /// answer depends on process/package metadata.
    ///
    /// This mirrors mihomo's Strict mode: rules before the first process rule
    /// retain normal first-match and logical short-circuit behavior.
    pub fn needs_process(&self, ctx: &FlowContext) -> bool {
        let disabled = self.disabled_rules.load();
        let mut input = MatchInput::new(ctx);
        let destination_ip_resolved = input.resolved_ip.is_some();
        matches!(
            self.first_requirement(
                &self.plan.steps,
                &mut input,
                false,
                destination_ip_resolved,
                Some(&disabled),
                0,
            ),
            StepFlow::Result(MatchState::Deferred { process: true, .. })
        )
    }

    /// Return whether ordered evaluation has reached a destination-IP rule
    /// while the target is still a domain. The async runtime resolves only in
    /// that case, so domain-only rule sets never pay a DNS cost.
    pub fn needs_destination_ip(&self, ctx: &FlowContext) -> bool {
        if ctx.ip.is_some() || ctx.host.parse::<IpAddr>().is_ok() {
            return false;
        }
        let disabled = self.disabled_rules.load();
        let mut input = MatchInput::new(ctx);
        matches!(
            self.first_requirement(
                &self.plan.steps,
                &mut input,
                true,
                false,
                Some(&disabled),
                0,
            ),
            StepFlow::Result(MatchState::Deferred {
                destination_ip: true,
                ..
            })
        )
    }

    fn evaluate_steps(
        &self,
        steps: &[core_config::runtime_plan::RouteStep],
        input: &mut MatchInput<'_>,
        process_resolved: bool,
        destination_ip_resolved: bool,
        disabled: Option<&[bool]>,
        depth: usize,
    ) -> StepFlow<DetailedRouteDecision> {
        if depth > self.plan.sub_rules.len() {
            return StepFlow::Exhausted;
        }
        for (index, step) in steps.iter().enumerate() {
            if disabled.is_some_and(|flags| flags.get(index).copied().unwrap_or(false)) {
                continue;
            }
            if !step_matches(
                &step.matcher,
                input,
                &self.extra_cidrs,
                self.rulesets.as_ref(),
                &self.prepared,
                process_resolved,
                destination_ip_resolved || step.options.no_resolve,
            ) {
                continue;
            }
            if let RouteAction::SubRule(name) = &step.action {
                if let Some(branch) = self.plan.sub_rules.get(name) {
                    match self.evaluate_steps(
                        branch,
                        input,
                        process_resolved,
                        destination_ip_resolved,
                        None,
                        depth + 1,
                    ) {
                        StepFlow::Result(decision) => return StepFlow::Result(decision),
                        // PASS always exits the complete SUB-RULE call chain.
                        // The main rule list consumes the signal and resumes
                        // immediately after its top-level SUB-RULE entry.
                        StepFlow::ContinueMain if depth == 0 => continue,
                        StepFlow::ContinueMain => return StepFlow::ContinueMain,
                        StepFlow::Exhausted => {}
                    }
                }
                continue;
            }
            if matches!(&step.action, RouteAction::Pass | RouteAction::PassRule) {
                if matches!(&step.action, RouteAction::Pass) && depth > 0 {
                    return StepFlow::ContinueMain;
                }
                continue;
            }
            return StepFlow::Result(DetailedRouteDecision {
                decision: RouteDecision::from_action(&step.action),
                matcher: matcher_kind(&step.matcher),
                hit: describe_route_step(disabled.map(|_| index), step),
            });
        }
        StepFlow::Exhausted
    }

    fn first_requirement(
        &self,
        steps: &[core_config::runtime_plan::RouteStep],
        input: &mut MatchInput<'_>,
        process_resolved: bool,
        destination_ip_resolved: bool,
        disabled: Option<&[bool]>,
        depth: usize,
    ) -> StepFlow<MatchState> {
        if depth > self.plan.sub_rules.len() {
            return StepFlow::Exhausted;
        }
        for (index, step) in steps.iter().enumerate() {
            if disabled.is_some_and(|flags| flags.get(index).copied().unwrap_or(false)) {
                continue;
            }
            let state = step_match_state(
                &step.matcher,
                input,
                &self.extra_cidrs,
                self.rulesets.as_ref(),
                &self.prepared,
                process_resolved,
                destination_ip_resolved || step.options.no_resolve,
            );
            match state {
                MatchState::NotMatched => {}
                MatchState::Matched => {
                    if let RouteAction::SubRule(name) = &step.action {
                        if let Some(branch) = self.plan.sub_rules.get(name) {
                            match self.first_requirement(
                                branch,
                                input,
                                process_resolved,
                                destination_ip_resolved,
                                None,
                                depth + 1,
                            ) {
                                StepFlow::Result(result) => return StepFlow::Result(result),
                                StepFlow::ContinueMain if depth == 0 => continue,
                                StepFlow::ContinueMain => return StepFlow::ContinueMain,
                                StepFlow::Exhausted => {}
                            }
                        }
                        continue;
                    }
                    if matches!(&step.action, RouteAction::Pass | RouteAction::PassRule) {
                        if matches!(&step.action, RouteAction::Pass) && depth > 0 {
                            return StepFlow::ContinueMain;
                        }
                        continue;
                    }
                    return StepFlow::Result(MatchState::Matched);
                }
                deferred => return StepFlow::Result(deferred),
            }
        }
        StepFlow::Exhausted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepFlow<T> {
    Result(T),
    ContinueMain,
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchState {
    Matched,
    NotMatched,
    Deferred { process: bool, destination_ip: bool },
}

impl MatchState {
    fn deferred(process: bool, destination_ip: bool) -> Self {
        if process || destination_ip {
            Self::Deferred {
                process,
                destination_ip,
            }
        } else {
            Self::NotMatched
        }
    }

    fn requirements(self) -> (bool, bool) {
        match self {
            Self::Deferred {
                process,
                destination_ip,
            } => (process, destination_ip),
            Self::Matched | Self::NotMatched => (false, false),
        }
    }
}

fn describe_route_step(
    index: Option<usize>,
    step: &core_config::runtime_plan::RouteStep,
) -> RouteRuleHit {
    let (rule, payload) = if matches!(step.action, RouteAction::SubRule(_)) {
        (
            "SUB-RULE",
            format!("({})", matcher_expression(&step.matcher)),
        )
    } else {
        describe_matcher(&step.matcher)
    };
    RouteRuleHit {
        index,
        rule: rule.into(),
        payload,
        source: step.source.clone(),
        action: describe_action(&step.action),
        no_resolve: step.options.no_resolve,
        no_log: step.options.no_log,
        no_track: step.options.no_track,
    }
}

fn describe_action(action: &RouteAction) -> String {
    match action {
        RouteAction::Direct => "DIRECT".into(),
        RouteAction::Block => "REJECT".into(),
        RouteAction::Group(group) => group.clone(),
        RouteAction::Pass => "PASS".into(),
        RouteAction::PassRule => "PASS-RULE".into(),
        RouteAction::SubRule(name) => name.clone(),
    }
}

fn describe_matcher(matcher: &RouteMatcher) -> (&'static str, String) {
    match matcher {
        RouteMatcher::Any => ("MATCH", String::new()),
        RouteMatcher::Home => ("HOME", String::new()),
        RouteMatcher::Cn => ("GEOIP", "CN".into()),
        RouteMatcher::Ads => ("ADS", String::new()),
        RouteMatcher::Service(service) => ("SERVICE", service.clone()),
        RouteMatcher::Domain(domain) => ("DOMAIN", domain.clone()),
        RouteMatcher::Suffix(suffix) => ("DOMAIN-SUFFIX", suffix.clone()),
        RouteMatcher::Keyword(keyword) => ("DOMAIN-KEYWORD", keyword.clone()),
        RouteMatcher::DomainRegex(pattern) => ("DOMAIN-REGEX", pattern.clone()),
        RouteMatcher::DomainWildcard(pattern) => ("DOMAIN-WILDCARD", pattern.clone()),
        RouteMatcher::GeoSite(code) => ("GEOSITE", code.clone()),
        RouteMatcher::Cidr(cidr) => ("IP-CIDR", cidr.clone()),
        RouteMatcher::SrcCidr(cidr) => ("SRC-IP-CIDR", cidr.clone()),
        RouteMatcher::IpSuffix(suffix) => ("IP-SUFFIX", suffix.clone()),
        RouteMatcher::SrcIpSuffix(suffix) => ("SRC-IP-SUFFIX", suffix.clone()),
        RouteMatcher::GeoIp(code) => ("GEOIP", code.clone()),
        RouteMatcher::SrcGeoIp(code) => ("SRC-GEOIP", code.clone()),
        RouteMatcher::IpAsn(asn) => ("IP-ASN", asn.to_string()),
        RouteMatcher::SrcIpAsn(asn) => ("SRC-IP-ASN", asn.to_string()),
        RouteMatcher::Port(port) => ("DST-PORT", port.to_string()),
        RouteMatcher::PortRange(low, high) => ("DST-PORT", format!("{low}-{high}")),
        RouteMatcher::SrcPort(port) => ("SRC-PORT", port.to_string()),
        RouteMatcher::SrcPortRange(low, high) => ("SRC-PORT", format!("{low}-{high}")),
        RouteMatcher::InPort(port) => ("IN-PORT", port.to_string()),
        RouteMatcher::InPortRange(low, high) => ("IN-PORT", format!("{low}-{high}")),
        RouteMatcher::Network(network) => ("NETWORK", network.clone()),
        RouteMatcher::Dscp(dscp) => ("DSCP", dscp.to_string()),
        RouteMatcher::InUser(user) => ("IN-USER", user.clone()),
        RouteMatcher::InName(name) => ("IN-NAME", name.clone()),
        RouteMatcher::InType(kind) => ("IN-TYPE", kind.clone()),
        RouteMatcher::Uid(uid) => ("UID", uid.to_string()),
        RouteMatcher::RematchName(name) => ("REMATCH-NAME", name.clone()),
        RouteMatcher::Process(process) => ("PROCESS-NAME", process.clone()),
        RouteMatcher::ProcessPath(path) => ("PROCESS-PATH", path.clone()),
        RouteMatcher::ProcessRegex(pattern) => ("PROCESS-NAME-REGEX", pattern.clone()),
        RouteMatcher::ProcessPathRegex(pattern) => ("PROCESS-PATH-REGEX", pattern.clone()),
        RouteMatcher::ProcessWildcard(pattern) => ("PROCESS-NAME-WILDCARD", pattern.clone()),
        RouteMatcher::ProcessPathWildcard(pattern) => ("PROCESS-PATH-WILDCARD", pattern.clone()),
        RouteMatcher::Set(name) => ("RULE-SET", name.clone()),
        RouteMatcher::SrcSet(name) => ("RULE-SET", format!("{name},src")),
        RouteMatcher::Proto(protocol) => ("PROTOCOL", protocol.clone()),
        RouteMatcher::And(parts) => ("AND", describe_compound(parts)),
        RouteMatcher::Or(parts) => ("OR", describe_compound(parts)),
        RouteMatcher::Not(part) => {
            let (rule, payload) = describe_matcher(part);
            let inner = if payload.is_empty() {
                format!("({rule})")
            } else {
                format!("({rule},{payload})")
            };
            ("NOT", inner)
        }
        RouteMatcher::NoResolve(part) => {
            let (rule, mut payload) = describe_matcher(part);
            if !payload.is_empty() {
                payload.push(',');
            }
            payload.push_str("no-resolve");
            (rule, payload)
        }
    }
}

fn matcher_expression(matcher: &RouteMatcher) -> String {
    let (rule, payload) = describe_matcher(matcher);
    if payload.is_empty() {
        rule.into()
    } else {
        format!("{rule},{payload}")
    }
}

fn describe_compound(parts: &[RouteMatcher]) -> String {
    let mut output = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let (rule, payload) = describe_matcher(part);
        output.push('(');
        output.push_str(rule);
        if !payload.is_empty() {
            output.push(',');
            output.push_str(&payload);
        }
        output.push(')');
    }
    output
}

fn matcher_kind(m: &RouteMatcher) -> &'static str {
    match m {
        RouteMatcher::Any => "any",
        RouteMatcher::Home => "home",
        RouteMatcher::Cn => "cn",
        RouteMatcher::Ads => "ads",
        RouteMatcher::Service(_) => "service",
        RouteMatcher::Domain(_) => "domain",
        RouteMatcher::Suffix(_) => "suffix",
        RouteMatcher::Keyword(_) => "keyword",
        RouteMatcher::DomainRegex(_) => "domain_regex",
        RouteMatcher::DomainWildcard(_) => "domain_wildcard",
        RouteMatcher::GeoSite(_) => "geosite",
        RouteMatcher::Cidr(_) => "ip",
        RouteMatcher::SrcCidr(_) => "src_ip",
        RouteMatcher::IpSuffix(_) => "ip_suffix",
        RouteMatcher::SrcIpSuffix(_) => "src_ip_suffix",
        RouteMatcher::GeoIp(_) => "geoip",
        RouteMatcher::SrcGeoIp(_) => "src_geoip",
        RouteMatcher::IpAsn(_) => "ip_asn",
        RouteMatcher::SrcIpAsn(_) => "src_ip_asn",
        RouteMatcher::Port(_) => "port",
        RouteMatcher::PortRange(_, _) => "port_range",
        RouteMatcher::SrcPort(_) => "src_port",
        RouteMatcher::SrcPortRange(_, _) => "src_port_range",
        RouteMatcher::InPort(_) => "in_port",
        RouteMatcher::InPortRange(_, _) => "in_port_range",
        RouteMatcher::And(_) => "and",
        RouteMatcher::Or(_) => "or",
        RouteMatcher::Not(_) => "not",
        RouteMatcher::NoResolve(part) => matcher_kind(part),
        RouteMatcher::Network(_) => "network",
        RouteMatcher::Dscp(_) => "dscp",
        RouteMatcher::InUser(_) => "in_user",
        RouteMatcher::InName(_) => "in_name",
        RouteMatcher::InType(_) => "in_type",
        RouteMatcher::Uid(_) => "uid",
        RouteMatcher::RematchName(_) => "rematch_name",
        RouteMatcher::Process(_) => "process",
        RouteMatcher::ProcessPath(_) => "process_path",
        RouteMatcher::ProcessRegex(_) => "process_regex",
        RouteMatcher::ProcessPathRegex(_) => "process_path_regex",
        RouteMatcher::ProcessWildcard(_) => "process_wildcard",
        RouteMatcher::ProcessPathWildcard(_) => "process_path_wildcard",
        RouteMatcher::Set(_) => "set",
        RouteMatcher::SrcSet(_) => "src_set",
        RouteMatcher::Proto(_) => "proto",
    }
}

fn step_matches(
    m: &RouteMatcher,
    input: &mut MatchInput<'_>,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
    prepared: &PreparedMatchers,
    process_resolved: bool,
    destination_ip_resolved: bool,
) -> bool {
    step_match_state(
        m,
        input,
        extra_cidrs,
        rulesets,
        prepared,
        process_resolved,
        destination_ip_resolved,
    ) == MatchState::Matched
}

fn step_match_state(
    m: &RouteMatcher,
    input: &mut MatchInput<'_>,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
    prepared: &PreparedMatchers,
    process_resolved: bool,
    destination_ip_resolved: bool,
) -> MatchState {
    use MatchState::{Matched, NotMatched};
    let ctx = input.context;

    match m {
        RouteMatcher::Any => Matched,
        RouteMatcher::Home if !destination_ip_resolved && !match_home_domain(input) => {
            MatchState::deferred(false, true)
        }
        RouteMatcher::Home => bool_state(match_home(input)),
        RouteMatcher::Cn if !destination_ip_resolved && !match_cn_domain(input) => {
            MatchState::deferred(false, true)
        }
        RouteMatcher::Cn => bool_state(match_cn(input)),
        RouteMatcher::Ads => bool_state(match_suffix_list(
            &input.normalized_host,
            builtin::ADS_SUFFIXES,
        )),
        RouteMatcher::Service(name) => bool_state(match_suffix_list(
            &input.normalized_host,
            builtin::service_suffixes(name),
        )),
        RouteMatcher::Domain(domain) => {
            let normalized = prepared
                .normalized_values
                .get(domain)
                .map(String::as_str)
                .unwrap_or(domain);
            bool_state(input.normalized_host == normalized)
        }
        RouteMatcher::Suffix(suffix) => {
            let normalized = prepared
                .normalized_values
                .get(suffix)
                .map(String::as_str)
                .unwrap_or(suffix);
            bool_state(host_suffix_normalized(&input.normalized_host, normalized))
        }
        RouteMatcher::Keyword(keyword) => {
            let matched = prepared
                .keyword_ids
                .get(keyword)
                .map(|id| input.keyword_matches(prepared, *id))
                .unwrap_or_else(|| {
                    input
                        .normalized_host
                        .contains(&keyword.to_ascii_lowercase())
                });
            bool_state(matched)
        }
        RouteMatcher::DomainRegex(pattern) => {
            let matched = match prepared.domain_regexes.get(pattern) {
                Some(PreparedDomainRegex::Fast(regex)) => {
                    regex.is_match(&input.normalized_host)
                        || (input.unicode_host != input.normalized_host
                            && regex.is_match(&input.unicode_host))
                }
                Some(PreparedDomainRegex::Fancy(regex)) => {
                    regex.is_match(&input.normalized_host).unwrap_or(false)
                        || (input.unicode_host != input.normalized_host
                            && regex.is_match(&input.unicode_host).unwrap_or(false))
                }
                None => false,
            };
            bool_state(matched)
        }
        RouteMatcher::DomainWildcard(pattern) => bool_state(
            prepared
                .domain_wildcards
                .get(pattern)
                .is_some_and(|matcher| {
                    matcher.is_match(&input.normalized_host)
                        || (input.unicode_host != input.normalized_host
                            && matcher.is_match(&input.unicode_host))
                }),
        ),
        RouteMatcher::GeoSite(code) => match_ruleset_alias(
            prepared.geosite_aliases.get(code),
            input,
            rulesets,
            process_resolved,
            destination_ip_resolved,
            false,
        ),
        RouteMatcher::Cidr(_) if !destination_ip_resolved => MatchState::deferred(false, true),
        RouteMatcher::Cidr(cidr) => bool_state(match_cidr(
            input,
            prepared.destination_cidrs.get(cidr),
            extra_cidrs,
        )),
        RouteMatcher::SrcCidr(cidr) => {
            bool_state(match_source_cidr(ctx, prepared.source_cidrs.get(cidr)))
        }
        RouteMatcher::IpSuffix(_) if !destination_ip_resolved => MatchState::deferred(false, true),
        RouteMatcher::IpSuffix(suffix) => bool_state(
            prepared
                .destination_ip_suffixes
                .get(suffix)
                .is_some_and(|suffix| {
                    input
                        .resolved_ip
                        .is_some_and(|ip| ip_suffix_matches(ip, *suffix))
                }),
        ),
        RouteMatcher::SrcIpSuffix(suffix) => bool_state(
            prepared
                .source_ip_suffixes
                .get(suffix)
                .is_some_and(|suffix| {
                    ctx.ruleset
                        .source_ip
                        .is_some_and(|ip| ip_suffix_matches(ip, *suffix))
                }),
        ),
        RouteMatcher::GeoIp(code)
            if !destination_ip_resolved
                && !metadata_code_matches(&ctx.ruleset.destination_geoip, code) =>
        {
            MatchState::deferred(false, true)
        }
        RouteMatcher::GeoIp(code) => {
            if metadata_code_matches(&ctx.ruleset.destination_geoip, code) {
                Matched
            } else {
                match_ruleset_alias(
                    prepared.geoip_aliases.get(code),
                    input,
                    rulesets,
                    process_resolved,
                    destination_ip_resolved,
                    false,
                )
            }
        }
        RouteMatcher::SrcGeoIp(code) => {
            if metadata_code_matches(&ctx.ruleset.source_geoip, code) {
                Matched
            } else {
                match_ruleset_alias(
                    prepared.geoip_aliases.get(code),
                    input,
                    rulesets,
                    process_resolved,
                    true,
                    true,
                )
            }
        }
        RouteMatcher::IpAsn(asn)
            if !destination_ip_resolved && ctx.ruleset.destination_asn != Some(*asn) =>
        {
            MatchState::deferred(false, true)
        }
        RouteMatcher::IpAsn(asn) => {
            if ctx.ruleset.destination_asn == Some(*asn) {
                Matched
            } else {
                match_ruleset_alias(
                    prepared.asn_aliases.get(asn),
                    input,
                    rulesets,
                    process_resolved,
                    destination_ip_resolved,
                    false,
                )
            }
        }
        RouteMatcher::SrcIpAsn(asn) => {
            if ctx.ruleset.source_asn == Some(*asn) {
                Matched
            } else {
                match_ruleset_alias(
                    prepared.asn_aliases.get(asn),
                    input,
                    rulesets,
                    process_resolved,
                    true,
                    true,
                )
            }
        }
        RouteMatcher::Port(p) => bool_state(ctx.port == *p),
        RouteMatcher::PortRange(lo, hi) => bool_state(ctx.port >= *lo && ctx.port <= *hi),
        RouteMatcher::SrcPort(p) => bool_state(ctx.ruleset.source_port == Some(*p)),
        RouteMatcher::SrcPortRange(lo, hi) => bool_state(
            ctx.ruleset
                .source_port
                .map(|port| port >= *lo && port <= *hi)
                .unwrap_or(false),
        ),
        RouteMatcher::InPort(port) => bool_state(ctx.ruleset.inbound_port == Some(*port)),
        RouteMatcher::InPortRange(lo, hi) => bool_state(
            ctx.ruleset
                .inbound_port
                .is_some_and(|port| port >= *lo && port <= *hi),
        ),
        RouteMatcher::Network(n) => bool_state(n.eq_ignore_ascii_case(ctx.network.as_str())),
        RouteMatcher::Dscp(dscp) => bool_state(ctx.ruleset.dscp == Some(*dscp)),
        RouteMatcher::InUser(users) => bool_state(option_matches_list(
            ctx.ruleset.inbound_user.as_deref(),
            users,
        )),
        RouteMatcher::InName(names) => bool_state(option_matches_list(
            ctx.ruleset.inbound_name.as_deref(),
            names,
        )),
        RouteMatcher::InType(types) => bool_state(option_matches_list(
            ctx.ruleset.inbound_type.as_deref(),
            types,
        )),
        RouteMatcher::Uid(uid) => bool_state(ctx.ruleset.uid == Some(*uid)),
        RouteMatcher::RematchName(names) => bool_state(
            ctx.ruleset
                .rematch_names
                .iter()
                .any(|actual| value_matches_list(actual, names)),
        ),
        RouteMatcher::Process(_)
        | RouteMatcher::ProcessPath(_)
        | RouteMatcher::ProcessRegex(_)
        | RouteMatcher::ProcessPathRegex(_)
        | RouteMatcher::ProcessWildcard(_)
        | RouteMatcher::ProcessPathWildcard(_)
            if !process_resolved =>
        {
            MatchState::deferred(true, false)
        }
        RouteMatcher::Process(name) => bool_state(
            ctx.process
                .as_ref()
                .map(|p| text_eq_ignore_case(p, name))
                .unwrap_or(false)
                || ctx
                    .ruleset
                    .package_names
                    .iter()
                    .any(|package| text_eq_ignore_case(package, name)),
        ),
        RouteMatcher::ProcessPath(path) => bool_state(
            ctx.ruleset
                .process_path
                .as_deref()
                .map(|actual| text_eq_ignore_case(actual, path))
                .unwrap_or(false),
        ),
        RouteMatcher::ProcessRegex(pattern) => {
            bool_state(prepared.process_regexes.get(pattern).is_some_and(|regex| {
                ctx.process
                    .as_deref()
                    .is_some_and(|name| regex.is_match(name))
                    || ctx
                        .ruleset
                        .package_names
                        .iter()
                        .any(|name| regex.is_match(name))
            }))
        }
        RouteMatcher::ProcessPathRegex(pattern) => {
            bool_state(prepared.process_regexes.get(pattern).is_some_and(|regex| {
                ctx.ruleset
                    .process_path
                    .as_deref()
                    .is_some_and(|path| regex.is_match(path))
            }))
        }
        RouteMatcher::ProcessWildcard(pattern) => bool_state(
            prepared
                .process_wildcards
                .get(pattern)
                .is_some_and(|matcher| {
                    ctx.process
                        .as_deref()
                        .is_some_and(|name| matcher.is_match(name))
                        || ctx
                            .ruleset
                            .package_names
                            .iter()
                            .any(|name| matcher.is_match(name))
                }),
        ),
        RouteMatcher::ProcessPathWildcard(pattern) => bool_state(
            prepared
                .process_wildcards
                .get(pattern)
                .is_some_and(|matcher| {
                    ctx.ruleset
                        .process_path
                        .as_deref()
                        .is_some_and(|path| matcher.is_match(path))
                }),
        ),
        RouteMatcher::Set(name) => match rulesets {
            Some(index) => ruleset_outcome_to_state(index.matches_context_deferred(
                name,
                &ctx.ruleset_match_context(),
                process_resolved,
                destination_ip_resolved,
            )),
            None => NotMatched,
        },
        RouteMatcher::SrcSet(name) => match rulesets {
            Some(index) => ruleset_outcome_to_state(index.matches_context_deferred(
                name,
                &source_ruleset_context(ctx),
                process_resolved,
                true,
            )),
            None => NotMatched,
        },
        RouteMatcher::Proto(name) => bool_state(
            ctx.protocol
                .as_ref()
                .map(|p| crate::sniff::proto_name_matches(name, p))
                .unwrap_or(false),
        ),
        RouteMatcher::And(parts) => {
            let mut needs_process = false;
            let mut needs_destination_ip = false;
            for part in parts {
                let state = step_match_state(
                    part,
                    input,
                    extra_cidrs,
                    rulesets,
                    prepared,
                    process_resolved,
                    destination_ip_resolved,
                );
                match state {
                    NotMatched => return NotMatched,
                    Matched => {}
                    deferred => {
                        let (process, destination_ip) = deferred.requirements();
                        needs_process |= process;
                        needs_destination_ip |= destination_ip;
                    }
                }
            }
            if needs_process || needs_destination_ip {
                MatchState::deferred(needs_process, needs_destination_ip)
            } else {
                Matched
            }
        }
        RouteMatcher::Or(parts) => {
            let mut needs_process = false;
            let mut needs_destination_ip = false;
            for part in parts {
                let state = step_match_state(
                    part,
                    input,
                    extra_cidrs,
                    rulesets,
                    prepared,
                    process_resolved,
                    destination_ip_resolved,
                );
                match state {
                    Matched => return Matched,
                    NotMatched => {}
                    deferred => {
                        let (process, destination_ip) = deferred.requirements();
                        needs_process |= process;
                        needs_destination_ip |= destination_ip;
                    }
                }
            }
            MatchState::deferred(needs_process, needs_destination_ip)
        }
        RouteMatcher::Not(part) => match step_match_state(
            part,
            input,
            extra_cidrs,
            rulesets,
            prepared,
            process_resolved,
            destination_ip_resolved,
        ) {
            Matched => NotMatched,
            NotMatched => Matched,
            deferred => deferred,
        },
        RouteMatcher::NoResolve(part) => step_match_state(
            part,
            input,
            extra_cidrs,
            rulesets,
            prepared,
            process_resolved,
            true,
        ),
    }
}

fn bool_state(value: bool) -> MatchState {
    if value {
        MatchState::Matched
    } else {
        MatchState::NotMatched
    }
}

fn normalize_route_domain(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('.');
    idna::domain_to_ascii(trimmed)
        .unwrap_or_else(|_| trimmed.to_ascii_lowercase())
        .to_ascii_lowercase()
}

fn normalize_route_domain_pattern(pattern: &str) -> String {
    pattern
        .trim()
        .trim_end_matches('.')
        .split('.')
        .map(|label| {
            if label.contains('*') || label.contains('?') {
                label.to_lowercase()
            } else {
                idna::domain_to_ascii(label)
                    .unwrap_or_else(|_| label.to_lowercase())
                    .to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn compile_glob(pattern: &str) -> GlobMatcher {
    let mut builder = GlobBuilder::new(pattern);
    builder
        .case_insensitive(true)
        .literal_separator(false)
        .backslash_escape(true);
    builder
        .build()
        .expect("wildcard was validated during config compile")
        .compile_matcher()
}

fn parse_ip_suffix(value: &str) -> Option<PreparedIpSuffix> {
    let (address, bits) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let bits = bits.parse::<u8>().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    (bits <= maximum).then_some(PreparedIpSuffix { address, bits })
}

fn ip_suffix_matches(candidate: IpAddr, suffix: PreparedIpSuffix) -> bool {
    match (candidate, suffix.address) {
        (IpAddr::V4(candidate), IpAddr::V4(expected)) => {
            suffix_bits_match(&candidate.octets(), &expected.octets(), suffix.bits)
        }
        (IpAddr::V6(candidate), IpAddr::V6(expected)) => {
            suffix_bits_match(&candidate.octets(), &expected.octets(), suffix.bits)
        }
        _ => false,
    }
}

fn suffix_bits_match(candidate: &[u8], expected: &[u8], bits: u8) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    if full_bytes > 0
        && candidate[candidate.len() - full_bytes..] != expected[expected.len() - full_bytes..]
    {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let index = candidate.len() - full_bytes - 1;
    let mask = (1u8 << remaining_bits) - 1;
    candidate[index] & mask == expected[index] & mask
}

fn metadata_code_matches(values: &[String], expected: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(expected))
}

fn value_matches_list(actual: &str, expected: &str) -> bool {
    expected
        .split('/')
        .map(str::trim)
        .any(|candidate| actual.eq_ignore_ascii_case(candidate))
}

fn option_matches_list(actual: Option<&str>, expected: &str) -> bool {
    actual.is_some_and(|actual| value_matches_list(actual, expected))
}

fn ruleset_name_candidates(kind: &str, name: &str) -> Vec<String> {
    let raw = name.trim().trim_start_matches(':').to_ascii_lowercase();
    let mut candidates = Vec::with_capacity(3);
    let mut push = |candidate: String| {
        if !candidate.is_empty() && !candidates.iter().any(|old| old == &candidate) {
            candidates.push(candidate);
        }
    };
    push(raw.clone());
    push(format!("{kind}-{raw}"));
    match (kind, raw.as_str()) {
        ("geosite", "cn") => push("cn-domain".into()),
        ("geoip", "cn") => push("geoip-cn".into()),
        ("geoip", "private") => push("geoip-private".into()),
        _ => {}
    }
    candidates
}

fn source_ruleset_context(ctx: &FlowContext) -> RulesetMatchContext<'_> {
    let base = ctx.ruleset_match_context();
    RulesetMatchContext {
        dst_host: "",
        dst_ip: base.src_ip,
        dst_port: base.src_port,
        ..base
    }
}

fn ruleset_outcome_to_state(outcome: RulesetMatchOutcome) -> MatchState {
    match outcome {
        RulesetMatchOutcome::Matched => MatchState::Matched,
        RulesetMatchOutcome::NotMatched => MatchState::NotMatched,
        RulesetMatchOutcome::NeedsProcess => MatchState::deferred(true, false),
        RulesetMatchOutcome::NeedsDestinationIp => MatchState::deferred(false, true),
        RulesetMatchOutcome::NeedsProcessAndDestinationIp => MatchState::deferred(true, true),
    }
}

fn match_ruleset_alias(
    candidates: Option<&Vec<String>>,
    input: &MatchInput<'_>,
    rulesets: Option<&Arc<RulesetIndex>>,
    process_resolved: bool,
    destination_ip_resolved: bool,
    source: bool,
) -> MatchState {
    let Some(index) = rulesets else {
        return MatchState::NotMatched;
    };
    let Some(candidates) = candidates else {
        return MatchState::NotMatched;
    };
    let mut needs_process = false;
    let mut needs_destination_ip = false;
    for candidate in candidates {
        if index.get(candidate).is_none() {
            continue;
        }
        let context = if source {
            source_ruleset_context(input.context)
        } else {
            input.context.ruleset_match_context()
        };
        match ruleset_outcome_to_state(index.matches_context_deferred(
            candidate,
            &context,
            process_resolved,
            destination_ip_resolved || source,
        )) {
            MatchState::Matched => return MatchState::Matched,
            MatchState::NotMatched => {}
            deferred => {
                let (process, destination_ip) = deferred.requirements();
                needs_process |= process;
                needs_destination_ip |= destination_ip;
            }
        }
    }
    MatchState::deferred(needs_process, needs_destination_ip)
}

fn host_suffix_normalized(host: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn text_eq_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

fn match_suffix_list(host: &str, list: &[&str]) -> bool {
    list.iter()
        .any(|suffix| host_suffix_normalized(host, suffix))
}

fn match_home_domain(input: &MatchInput<'_>) -> bool {
    match_suffix_list(&input.normalized_host, builtin::HOME_SUFFIXES)
}

fn match_home(input: &MatchInput<'_>) -> bool {
    if match_home_domain(input) {
        return true;
    }
    if let Some(ip) = input.resolved_ip {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cn_domain(input: &MatchInput<'_>) -> bool {
    match_suffix_list(&input.normalized_host, builtin::CN_SUFFIXES)
}

fn match_cn(input: &MatchInput<'_>) -> bool {
    if match_cn_domain(input) {
        return true;
    }
    if let Some(ip) = input.resolved_ip {
        return builtin::CN_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cidr(input: &MatchInput<'_>, network: Option<&IpNet>, extra: &[IpNet]) -> bool {
    let Some(network) = network else {
        return false;
    };
    if let Some(ip) = input.resolved_ip {
        if network.contains(&ip) {
            return true;
        }
        return extra.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_source_cidr(ctx: &FlowContext, network: Option<&IpNet>) -> bool {
    let Some(network) = network else {
        return false;
    };
    ctx.ruleset
        .source_ip
        .map(|ip| network.contains(&ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use core_config::runtime_plan::{RoutePlan, RouteStep};
    use core_ruleset::{RulesetFormat, RulesetIndex, RulesetMatcher, parse_ruleset_compiled};

    use super::*;

    fn plan_cn_smart() -> RoutePlan {
        let mut p = RoutePlan {
            preset: "cn_smart".into(),
            r#final: "main".into(),
            steps: vec![],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Home,
            action: RouteAction::Direct,
            source: "preset:home".into(),
            options: Default::default(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Cn,
            action: RouteAction::Direct,
            source: "preset:cn".into(),
            options: Default::default(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Any,
            action: RouteAction::Group("main".into()),
            source: "preset:any".into(),
            options: Default::default(),
        });
        p
    }

    fn engine_for(matcher: RouteMatcher) -> RouteEngine {
        RouteEngine::new(RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![RouteStep {
                matcher,
                action: RouteAction::Group("matched".into()),
                source: "test".into(),
                options: Default::default(),
            }],
            sub_rules: Default::default(),
            sets: Default::default(),
        })
    }

    #[test]
    fn cn_domain_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.qq.com", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn lan_ip_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_ip("192.168.1.10".parse().unwrap(), 22, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn unknown_goes_main() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.example.org", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Group("main".into()));
    }

    #[test]
    fn host_suffix_case_insensitive() {
        assert!(super::host_suffix_normalized("mail.qq.com", "qq.com"));
        assert!(!super::host_suffix_normalized("noqq.com", "qq.com"));
    }

    #[test]
    fn mihomo_domain_regex_uses_case_insensitive_advanced_matching() {
        let engine = engine_for(RouteMatcher::DomainRegex(
            r"^(?!api0\.)(api[0-9]+)\.example\.com$".into(),
        ));
        let matched = FlowContext::for_domain("API42.EXAMPLE.COM", 443, NetworkKind::Tcp);
        assert_eq!(
            engine.decide(&matched).0,
            RouteDecision::Group("matched".into())
        );
        let excluded = FlowContext::for_domain("api0.example.com", 443, NetworkKind::Tcp);
        assert_eq!(engine.decide(&excluded).0, RouteDecision::Direct);
    }

    #[test]
    fn source_matchers_never_fall_back_to_destination() {
        let source_ip = engine_for(RouteMatcher::SrcCidr("10.0.0.0/8".into()));
        let destination_only =
            FlowContext::for_ip("10.2.3.4".parse().unwrap(), 1500, NetworkKind::Tcp);
        assert_eq!(source_ip.decide(&destination_only).0, RouteDecision::Direct);

        let mut with_source =
            FlowContext::for_ip("203.0.113.8".parse().unwrap(), 80, NetworkKind::Tcp);
        with_source.ruleset.source_ip = Some("10.2.3.4".parse().unwrap());
        assert_eq!(
            source_ip.decide(&with_source).0,
            RouteDecision::Group("matched".into())
        );

        let source_port = engine_for(RouteMatcher::SrcPortRange(1000, 2000));
        assert_eq!(
            source_port.decide(&destination_only).0,
            RouteDecision::Direct
        );
        with_source.ruleset.source_port = Some(1500);
        assert_eq!(
            source_port.decide(&with_source).0,
            RouteDecision::Group("matched".into())
        );
    }

    #[test]
    fn process_path_is_exact_case_insensitive_and_triggers_lazy_lookup() {
        let engine = engine_for(RouteMatcher::ProcessPath(
            r"C:\Program Files\Browser\browser.exe".into(),
        ));
        let mut context = FlowContext::for_domain("example.com", 443, NetworkKind::Tcp);
        assert!(engine.needs_process(&context));

        context.ruleset.process_path = Some(r"c:\program files\browser\BROWSER.EXE".into());
        assert_eq!(
            engine.decide(&context).0,
            RouteDecision::Group("matched".into())
        );

        context.ruleset.process_path = Some(r"C:\Program Files\Browser\helper.exe".into());
        assert_eq!(engine.decide(&context).0, RouteDecision::Direct);
    }

    #[test]
    fn flow_ruleset_metadata_is_mapped_without_loss() {
        let interface_address = RulesetInterfaceAddress {
            interface_type: 3,
            address: "192.168.0.0/16".parse().unwrap(),
            is_own: false,
        };
        let default_address: IpNet = "10.0.0.0/8".parse().unwrap();
        let mut flow = FlowContext::for_domain("dns.example", 53, NetworkKind::Udp);
        flow.ip = Some("203.0.113.8".parse().unwrap());
        flow.process = Some("resolver".into());
        flow.ruleset = FlowRulesetMetadata {
            source_ip: Some("192.0.2.7".parse().unwrap()),
            source_port: Some(53000),
            query_type: Some(28),
            process_path: Some("/usr/bin/resolver".into()),
            package_names: vec!["com.example.resolver".into()],
            wifi_ssid: Some("office".into()),
            wifi_bssid: Some("00:11:22:33:44:55".into()),
            network_type: Some(3),
            network_is_expensive: Some(true),
            network_is_constrained: Some(false),
            network_interface_addresses: vec![interface_address.clone()],
            default_interface_addresses: vec![default_address],
            ..Default::default()
        };

        let ruleset = flow.ruleset_match_context();
        assert_eq!(ruleset.dst_host, "dns.example");
        assert_eq!(ruleset.dst_ip, flow.ip);
        assert_eq!(ruleset.dst_port, Some(53));
        assert_eq!(ruleset.src_ip, flow.ruleset.source_ip);
        assert_eq!(ruleset.src_port, Some(53000));
        assert_eq!(ruleset.network, Some("udp"));
        assert_eq!(ruleset.process_name, Some("resolver"));
        assert_eq!(ruleset.query_type, Some(28));
        assert_eq!(ruleset.process_path, Some("/usr/bin/resolver"));
        assert_eq!(ruleset.package_names, ["com.example.resolver"]);
        assert_eq!(ruleset.wifi_ssid, Some("office"));
        assert_eq!(ruleset.wifi_bssid, Some("00:11:22:33:44:55"));
        assert_eq!(ruleset.network_type, Some(3));
        assert_eq!(ruleset.network_is_expensive, Some(true));
        assert_eq!(ruleset.network_is_constrained, Some(false));
        assert_eq!(ruleset.network_interface_addresses, [interface_address]);
        assert_eq!(ruleset.default_interface_addresses, [default_address]);
    }

    /// `Or([Port(53), Port(5353)])` 应该在端口为 53 或 5353 时命中，其它时不命中。
    /// 单条规则覆盖多个端口，避免在步表里展开成 N 条独立 step。
    #[test]
    fn or_matcher_short_circuits_on_first_match() {
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Or(vec![
                        RouteMatcher::Port(53),
                        RouteMatcher::Port(5353),
                    ]),
                    action: RouteAction::Group("hijack".into()),
                    source: "or-test".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                    options: Default::default(),
                },
            ],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let eng = RouteEngine::new(plan);
        let (d53, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Udp));
        let (d5353, _, _) = eng.decide(&FlowContext::for_domain("a.com", 5353, NetworkKind::Udp));
        let (d80, _, _) = eng.decide(&FlowContext::for_domain("a.com", 80, NetworkKind::Tcp));
        assert_eq!(d53, RouteDecision::Group("hijack".into()));
        assert_eq!(d5353, RouteDecision::Group("hijack".into()));
        assert_eq!(d80, RouteDecision::Group("main".into()));
    }

    /// `And([Port(53), Network(udp)])` 只在端口和协议同时命中时触发。
    #[test]
    fn and_matcher_requires_all_clauses() {
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::And(vec![
                        RouteMatcher::Port(53),
                        RouteMatcher::Network("udp".into()),
                    ]),
                    action: RouteAction::Group("hijack".into()),
                    source: "and-test".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                    options: Default::default(),
                },
            ],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let eng = RouteEngine::new(plan);
        // 53/udp 命中
        let (d_udp, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Udp));
        assert_eq!(d_udp, RouteDecision::Group("hijack".into()));
        // 53/tcp 不命中（端口对，网络不对）
        let (d_tcp, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Tcp));
        assert_eq!(d_tcp, RouteDecision::Group("main".into()));
        // 80/udp 不命中（网络对，端口不对）
        let (d_other, _, _) = eng.decide(&FlowContext::for_domain("a.com", 80, NetworkKind::Udp));
        assert_eq!(d_other, RouteDecision::Group("main".into()));
    }

    #[test]
    fn strict_process_lookup_follows_first_match_order_and_short_circuiting() {
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Domain("already.example".into()),
                    action: RouteAction::Direct,
                    source: "domain-first".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::And(vec![
                        RouteMatcher::Port(443),
                        RouteMatcher::Process("browser".into()),
                    ]),
                    action: RouteAction::Group("proxy".into()),
                    source: "process".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Direct,
                    source: "fallback".into(),
                    options: Default::default(),
                },
            ],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let engine = RouteEngine::new(plan);

        assert!(!engine.needs_process(&FlowContext::for_domain(
            "already.example",
            443,
            NetworkKind::Tcp,
        )));
        assert!(!engine.needs_process(&FlowContext::for_domain(
            "other.example",
            80,
            NetworkKind::Tcp,
        )));
        assert!(engine.needs_process(&FlowContext::for_domain(
            "other.example",
            443,
            NetworkKind::Tcp,
        )));
    }

    #[test]
    fn strict_ruleset_lookup_preserves_not_semantics() {
        use core_ruleset::{RulesetExpr, RulesetPredicate, RulesetProgram};

        let index = RulesetIndex::new();
        index.insert(Arc::new(RulesetMatcher::compile_semantic(
            "not-browser",
            RulesetProgram::new(
                1,
                1,
                RulesetExpr::Not(Box::new(RulesetExpr::Predicate(
                    RulesetPredicate::ProcessName(vec!["browser".into()]),
                ))),
            ),
        )));
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![RouteStep {
                matcher: RouteMatcher::Set("not-browser".into()),
                action: RouteAction::Direct,
                source: "set".into(),
                options: Default::default(),
            }],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let engine = RouteEngine::with_rulesets(plan, index);
        assert!(engine.needs_process(&FlowContext::for_domain(
            "example.com",
            443,
            NetworkKind::Tcp,
        )));
    }

    #[test]
    fn set_matcher_receives_network_context() {
        let compiled = parse_ruleset_compiled(
            RulesetFormat::SingboxJson,
            br#"{"version":1,"rules":[{"domain":"dns.example","network":"udp"}]}"#,
        )
        .unwrap();
        let index = RulesetIndex::new();
        index.insert(Arc::new(RulesetMatcher::compile_any("dns", compiled)));
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Set("dns".into()),
                    action: RouteAction::Group("hijack".into()),
                    source: "set-network".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                    options: Default::default(),
                },
            ],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let engine = RouteEngine::with_rulesets(plan, index);
        let udp = engine.decide(&FlowContext::for_domain(
            "dns.example",
            53,
            NetworkKind::Udp,
        ));
        let tcp = engine.decide(&FlowContext::for_domain(
            "dns.example",
            53,
            NetworkKind::Tcp,
        ));
        assert_eq!(udp.0, RouteDecision::Group("hijack".into()));
        assert_eq!(tcp.0, RouteDecision::Group("main".into()));
    }

    #[test]
    fn mrs_domain_and_ipcidr_are_evaluated_end_to_end() {
        let index = RulesetIndex::new();
        let domain = parse_ruleset_compiled(
            RulesetFormat::Mrs,
            include_bytes!("../../core-ruleset/tests/data/sample_domain.mrs"),
        )
        .unwrap();
        let ipcidr = parse_ruleset_compiled(
            RulesetFormat::Mrs,
            include_bytes!("../../core-ruleset/tests/data/sample_ipcidr.mrs"),
        )
        .unwrap();
        index.insert(Arc::new(RulesetMatcher::compile_any("domain-mrs", domain)));
        index.insert(Arc::new(RulesetMatcher::compile_any("ip-mrs", ipcidr)));

        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Set("domain-mrs".into()),
                    action: RouteAction::Group("domain".into()),
                    source: "RULE-SET,domain-mrs,domain".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Set("ip-mrs".into()),
                    action: RouteAction::Group("ip".into()),
                    source: "RULE-SET,ip-mrs,ip".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Direct,
                    source: "MATCH,DIRECT".into(),
                    options: Default::default(),
                },
            ],
            sub_rules: Default::default(),
            sets: Default::default(),
        };
        let engine = RouteEngine::with_rulesets(plan, index);

        let domain = FlowContext::for_domain("A.Example.COM.", 443, NetworkKind::Tcp);
        assert_eq!(
            engine.decide(&domain).0,
            RouteDecision::Group("domain".into())
        );

        let mut resolved =
            FlowContext::for_domain("resolver-result.example", 443, NetworkKind::Tcp);
        assert!(engine.needs_destination_ip(&resolved));
        resolved.ip = Some("1.1.1.1".parse().unwrap());
        assert_eq!(
            engine.decide(&resolved).0,
            RouteDecision::Group("ip".into())
        );
    }

    #[test]
    fn sub_rule_returns_inner_hit_and_falls_through_when_branch_misses() {
        let mut sub_rules = std::collections::BTreeMap::new();
        sub_rules.insert(
            "tcp-branch".into(),
            vec![RouteStep {
                matcher: RouteMatcher::Domain("inside.example".into()),
                action: RouteAction::Group("inner".into()),
                source: "DOMAIN,inside.example,inner".into(),
                options: Default::default(),
            }],
        );
        let engine = RouteEngine::new(RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Network("tcp".into()),
                    action: RouteAction::SubRule("tcp-branch".into()),
                    source: "SUB-RULE,(NETWORK,tcp),tcp-branch".into(),
                    options: Default::default(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Direct,
                    source: "MATCH,DIRECT".into(),
                    options: Default::default(),
                },
            ],
            sub_rules,
            sets: Default::default(),
        });

        let hit = engine.decide_detailed(&FlowContext::for_domain(
            "inside.example",
            443,
            NetworkKind::Tcp,
        ));
        assert_eq!(hit.decision, RouteDecision::Group("inner".into()));
        assert_eq!(hit.hit.rule, "DOMAIN");
        assert_eq!(hit.hit.index, None);

        let miss = engine.decide(&FlowContext::for_domain(
            "outside.example",
            443,
            NetworkKind::Tcp,
        ));
        assert_eq!(miss.0, RouteDecision::Direct);
    }

    #[test]
    fn pass_exits_nested_sub_rules_but_pass_rule_stays_in_current_branch() {
        let nested = |control| {
            let mut sub_rules = std::collections::BTreeMap::new();
            sub_rules.insert(
                "inner".into(),
                vec![
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: control,
                        source: "MATCH,control".into(),
                        options: Default::default(),
                    },
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: RouteAction::Group("after-control".into()),
                        source: "MATCH,after-control".into(),
                        options: Default::default(),
                    },
                ],
            );
            sub_rules.insert(
                "outer".into(),
                vec![
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: RouteAction::SubRule("inner".into()),
                        source: "SUB-RULE,(MATCH),inner".into(),
                        options: Default::default(),
                    },
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: RouteAction::Group("after-inner".into()),
                        source: "MATCH,after-inner".into(),
                        options: Default::default(),
                    },
                ],
            );
            RouteEngine::new(RoutePlan {
                preset: "custom".into(),
                r#final: "main".into(),
                steps: vec![
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: RouteAction::SubRule("outer".into()),
                        source: "SUB-RULE,(MATCH),outer".into(),
                        options: Default::default(),
                    },
                    RouteStep {
                        matcher: RouteMatcher::Any,
                        action: RouteAction::Group("main".into()),
                        source: "MATCH,main".into(),
                        options: Default::default(),
                    },
                ],
                sub_rules,
                sets: Default::default(),
            })
        };

        let context = FlowContext::for_domain("example.com", 443, NetworkKind::Tcp);
        assert_eq!(
            nested(RouteAction::Pass).decide(&context).0,
            RouteDecision::Group("main".into())
        );
        assert_eq!(
            nested(RouteAction::PassRule).decide(&context).0,
            RouteDecision::Group("after-control".into())
        );
    }

    #[test]
    fn no_resolve_inside_logical_rule_does_not_request_dns() {
        let engine = engine_for(RouteMatcher::And(vec![
            RouteMatcher::NoResolve(Box::new(RouteMatcher::Cidr("1.1.1.0/24".into()))),
            RouteMatcher::Network("tcp".into()),
        ]));
        let unresolved = FlowContext::for_domain("resolver.example", 443, NetworkKind::Tcp);
        assert!(!engine.needs_destination_ip(&unresolved));
        assert_eq!(engine.decide(&unresolved).0, RouteDecision::Direct);

        let mut already_resolved = unresolved;
        already_resolved.ip = Some("1.1.1.1".parse().unwrap());
        assert_eq!(
            engine.decide(&already_resolved).0,
            RouteDecision::Group("matched".into())
        );
    }
}
