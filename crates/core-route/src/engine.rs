//! 路由匹配引擎。
//!
//! 输入：[`FlowContext`] —— 一次连接的目标（域名/IP/端口/网络/进程）。
//! 输出：[`RouteDecision`] —— direct / block / group("xxx")。

use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use ahash::AHashMap;
use core_config::runtime_plan::{RouteAction, RouteMatcher, RoutePlan};
use core_ruleset::{
    RulesetIndex, RulesetInterfaceAddress, RulesetMatchContext, RulesetMatchOutcome,
    compile_mihomo_domain_regex,
};
use fancy_regex::Regex as FancyRegex;
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
        }
    }
}

/// 路由引擎；按 [`RoutePlan::steps`] 顺序匹配。
#[derive(Debug, Clone)]
pub struct RouteEngine {
    plan: Arc<RoutePlan>,
    extra_cidrs: Vec<IpNet>,
    rulesets: Option<Arc<RulesetIndex>>,
    domain_regexes: Arc<AHashMap<String, FancyRegex>>,
    disabled_rules: Arc<parking_lot::RwLock<BTreeSet<usize>>>,
}

impl RouteEngine {
    pub fn new(plan: RoutePlan) -> Self {
        let domain_regexes = Arc::new(compile_route_domain_regexes(&plan));
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: None,
            domain_regexes,
            disabled_rules: Arc::new(parking_lot::RwLock::new(BTreeSet::new())),
        }
    }

    pub fn with_rulesets(plan: RoutePlan, rulesets: Arc<RulesetIndex>) -> Self {
        let domain_regexes = Arc::new(compile_route_domain_regexes(&plan));
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: Some(rulesets),
            domain_regexes,
            disabled_rules: Arc::new(parking_lot::RwLock::new(BTreeSet::new())),
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
        let mut rules = self.disabled_rules.write();
        if disabled {
            rules.insert(index);
        } else {
            rules.remove(&index);
        }
        true
    }

    pub fn rule_disabled(&self, index: usize) -> bool {
        self.disabled_rules.read().contains(&index)
    }

    pub fn decide(&self, ctx: &FlowContext) -> (RouteDecision, &'static str, String) {
        let disabled = self.disabled_rules.read();
        for (index, step) in self.plan.steps.iter().enumerate() {
            if disabled.contains(&index) {
                continue;
            }
            if step_matches(
                &step.matcher,
                ctx,
                &self.extra_cidrs,
                self.rulesets.as_ref(),
                &self.domain_regexes,
            ) {
                return (
                    RouteDecision::from_action(&step.action),
                    matcher_kind(&step.matcher),
                    step.source.clone(),
                );
            }
        }
        (RouteDecision::Direct, "fallback", "implicit-direct".into())
    }

    /// Return whether route evaluation has actually reached a rule whose
    /// answer depends on process/package metadata.
    ///
    /// This mirrors mihomo's Strict mode: rules before the first process rule
    /// retain normal first-match and logical short-circuit behavior.
    pub fn needs_process(&self, ctx: &FlowContext) -> bool {
        let disabled = self.disabled_rules.read();
        for (index, step) in self.plan.steps.iter().enumerate() {
            if disabled.contains(&index) {
                continue;
            }
            match step_match_state(
                &step.matcher,
                ctx,
                &self.extra_cidrs,
                self.rulesets.as_ref(),
                &self.domain_regexes,
                false,
            ) {
                MatchState::Matched => return false,
                MatchState::NeedsProcess => return true,
                MatchState::NotMatched => {}
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchState {
    Matched,
    NotMatched,
    NeedsProcess,
}

fn compile_route_domain_regexes(plan: &RoutePlan) -> AHashMap<String, FancyRegex> {
    fn collect(matcher: &RouteMatcher, out: &mut AHashMap<String, FancyRegex>) {
        match matcher {
            RouteMatcher::DomainRegex(pattern) => {
                if !out.contains_key(pattern)
                    && let Ok(regex) = compile_mihomo_domain_regex(pattern)
                {
                    out.insert(pattern.clone(), regex);
                }
            }
            RouteMatcher::And(parts) | RouteMatcher::Or(parts) => {
                for part in parts {
                    collect(part, out);
                }
            }
            _ => {}
        }
    }

    let mut regexes = AHashMap::new();
    for step in &plan.steps {
        collect(&step.matcher, &mut regexes);
    }
    regexes
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
        RouteMatcher::Cidr(_) => "ip",
        RouteMatcher::SrcCidr(_) => "src_ip",
        RouteMatcher::Port(_) => "port",
        RouteMatcher::PortRange(_, _) => "port_range",
        RouteMatcher::SrcPort(_) => "src_port",
        RouteMatcher::SrcPortRange(_, _) => "src_port_range",
        RouteMatcher::And(_) => "and",
        RouteMatcher::Or(_) => "or",
        RouteMatcher::Network(_) => "network",
        RouteMatcher::Process(_) => "process",
        RouteMatcher::ProcessPath(_) => "process_path",
        RouteMatcher::Set(_) => "set",
        RouteMatcher::Proto(_) => "proto",
    }
}

fn step_matches(
    m: &RouteMatcher,
    ctx: &FlowContext,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
    domain_regexes: &AHashMap<String, FancyRegex>,
) -> bool {
    step_match_state(m, ctx, extra_cidrs, rulesets, domain_regexes, true) == MatchState::Matched
}

fn step_match_state(
    m: &RouteMatcher,
    ctx: &FlowContext,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
    domain_regexes: &AHashMap<String, FancyRegex>,
    process_resolved: bool,
) -> MatchState {
    use MatchState::{Matched, NeedsProcess, NotMatched};

    match m {
        RouteMatcher::Any => Matched,
        RouteMatcher::Home => bool_state(match_home(ctx)),
        RouteMatcher::Cn => bool_state(match_cn(ctx)),
        RouteMatcher::Ads => bool_state(match_suffix_list(&ctx.host, builtin::ADS_SUFFIXES)),
        RouteMatcher::Service(name) => bool_state(match_suffix_list(
            &ctx.host,
            builtin::service_suffixes(name),
        )),
        RouteMatcher::Domain(d) => bool_state(host_eq(&ctx.host, d)),
        RouteMatcher::Suffix(s) => bool_state(host_suffix(&ctx.host, s)),
        RouteMatcher::Keyword(k) => bool_state(host_contains(&ctx.host, k)),
        RouteMatcher::DomainRegex(pattern) => bool_state(
            domain_regexes
                .get(pattern)
                .and_then(|regex| regex.is_match(&ctx.host).ok())
                .unwrap_or(false),
        ),
        RouteMatcher::Cidr(s) => bool_state(match_cidr(ctx, s, extra_cidrs)),
        RouteMatcher::SrcCidr(s) => bool_state(match_source_cidr(ctx, s)),
        RouteMatcher::Port(p) => bool_state(ctx.port == *p),
        RouteMatcher::PortRange(lo, hi) => bool_state(ctx.port >= *lo && ctx.port <= *hi),
        RouteMatcher::SrcPort(p) => bool_state(ctx.ruleset.source_port == Some(*p)),
        RouteMatcher::SrcPortRange(lo, hi) => bool_state(
            ctx.ruleset
                .source_port
                .map(|port| port >= *lo && port <= *hi)
                .unwrap_or(false),
        ),
        RouteMatcher::Network(n) => bool_state(n.eq_ignore_ascii_case(ctx.network.as_str())),
        RouteMatcher::Process(_) | RouteMatcher::ProcessPath(_) if !process_resolved => {
            NeedsProcess
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
        RouteMatcher::Set(name) => match rulesets {
            Some(idx) => idx
                .get(name)
                .map(|m| {
                    match m.matches_context_lazy(&ctx.ruleset_match_context(), process_resolved) {
                        RulesetMatchOutcome::Matched => Matched,
                        RulesetMatchOutcome::NotMatched => NotMatched,
                        RulesetMatchOutcome::NeedsProcess => NeedsProcess,
                    }
                })
                .unwrap_or(NotMatched),
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
            for part in parts {
                match step_match_state(
                    part,
                    ctx,
                    extra_cidrs,
                    rulesets,
                    domain_regexes,
                    process_resolved,
                ) {
                    NotMatched => return NotMatched,
                    NeedsProcess => needs_process = true,
                    Matched => {}
                }
            }
            if needs_process { NeedsProcess } else { Matched }
        }
        RouteMatcher::Or(parts) => {
            let mut needs_process = false;
            for part in parts {
                match step_match_state(
                    part,
                    ctx,
                    extra_cidrs,
                    rulesets,
                    domain_regexes,
                    process_resolved,
                ) {
                    Matched => return Matched,
                    NeedsProcess => needs_process = true,
                    NotMatched => {}
                }
            }
            if needs_process {
                NeedsProcess
            } else {
                NotMatched
            }
        }
    }
}

fn bool_state(value: bool) -> MatchState {
    if value {
        MatchState::Matched
    } else {
        MatchState::NotMatched
    }
}

fn host_eq(host: &str, target: &str) -> bool {
    host.eq_ignore_ascii_case(target)
}

fn host_suffix(host: &str, suffix: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let s = suffix.trim_start_matches('.').to_ascii_lowercase();
    h == s || h.ends_with(&format!(".{s}"))
}

/// mihomo `DOMAIN-KEYWORD,foo` —— host 含子串 `foo`（大小写不敏感）。
fn host_contains(host: &str, keyword: &str) -> bool {
    host.to_ascii_lowercase()
        .contains(&keyword.to_ascii_lowercase())
}

fn text_eq_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

fn match_suffix_list(host: &str, list: &[&str]) -> bool {
    list.iter().any(|s| host_suffix(host, s))
}

fn match_home(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::HOME_SUFFIXES) {
        return true;
    }
    if let Some(ip) = ctx.ip {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    if let Ok(ip) = ctx.host.parse::<IpAddr>() {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cn(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::CN_SUFFIXES) {
        return true;
    }
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        return builtin::CN_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cidr(ctx: &FlowContext, cidr: &str, extra: &[IpNet]) -> bool {
    let net: IpNet = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        if net.contains(&ip) {
            return true;
        }
        return extra.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_source_cidr(ctx: &FlowContext, cidr: &str) -> bool {
    let Ok(net) = cidr.parse::<IpNet>() else {
        return false;
    };
    ctx.ruleset
        .source_ip
        .map(|ip| net.contains(&ip))
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
            sets: Default::default(),
        };
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Home,
            action: RouteAction::Direct,
            source: "preset:home".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Cn,
            action: RouteAction::Direct,
            source: "preset:cn".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Any,
            action: RouteAction::Group("main".into()),
            source: "preset:any".into(),
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
            }],
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
        assert!(super::host_suffix("Mail.QQ.com", "qq.com"));
        assert!(!super::host_suffix("noqq.com", "qq.com"));
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
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
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
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
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
                },
                RouteStep {
                    matcher: RouteMatcher::And(vec![
                        RouteMatcher::Port(443),
                        RouteMatcher::Process("browser".into()),
                    ]),
                    action: RouteAction::Group("proxy".into()),
                    source: "process".into(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Direct,
                    source: "fallback".into(),
                },
            ],
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
            }],
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
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
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
}
