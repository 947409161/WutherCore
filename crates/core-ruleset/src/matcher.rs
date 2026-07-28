//! 高速规则匹配器：编译后的 trie / set / cidr / 关键字 / 正则 复合体。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use arc_swap::ArcSwap;
use fancy_regex::Regex as FancyRegex;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ip_network_table::IpNetworkTable;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::RegexSet;
use thiserror::Error;
use tokio::sync::watch;

use crate::ir::{RulesetMatchContext, RulesetMatchOutcome, RulesetProgram};
use crate::mihomo_regex::compile_mihomo_domain_regex;

const MAX_IP_PREFIX_SNAPSHOT_ITEMS: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RulesetPrefixError {
    #[error("destination IP ranges expand beyond the snapshot limit of {limit} prefixes")]
    TooManyPrefixes { limit: usize },
    #[error("destination IP prefix snapshot allocation failed")]
    AllocationFailed,
    #[error("destination {family} range starts after its end")]
    InvalidRange { family: &'static str },
}

/// How the published prefixes relate to the ruleset's full matching semantics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RulesetIpPrefixSemantics {
    /// The ruleset itself is exactly the union of the published destination prefixes.
    Exact,
    /// Prefixes were extracted with sing-box `RuleSet.ExtractIPSet` semantics.
    ///
    /// Surrounding logical conditions, inversion and non-IP predicates are not
    /// represented. This is intentionally compatible with sing-box
    /// `route_address_set`, but consumers that require an exact set (especially
    /// exclusion/bypass paths) can reject this status.
    Extracted,
    /// The loaded ruleset contains no destination-IP set.
    #[default]
    NotIpSet,
}

pub type RulesetDestinationPrefixes = (
    RulesetIpPrefixSemantics,
    Arc<Vec<Ipv4Net>>,
    Arc<Vec<Ipv6Net>>,
);

/// Readiness and safety status for one requested ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetIpPrefixStatus {
    Ready {
        semantics: RulesetIpPrefixSemantics,
    },
    /// The manager knows this name but has not completed its first load.
    Pending,
    /// The first load failed and there is no last-known-good matcher.
    Unavailable,
    /// The name was never declared or loaded.
    Missing,
    TooManyPrefixes {
        limit: usize,
    },
    AllocationFailed,
    InvalidRange {
        family: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetIpPrefixSet {
    pub name: String,
    pub status: RulesetIpPrefixStatus,
    pub ipv4: Arc<Vec<Ipv4Net>>,
    pub ipv6: Arc<Vec<Ipv6Net>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetIpPrefixSnapshot {
    /// Monotonic index revision at which all sets in this snapshot were read.
    pub revision: u64,
    /// Requested sets in first-occurrence order. Duplicate names are removed.
    pub sets: Arc<Vec<RulesetIpPrefixSet>>,
}

/// classical 行解析后形态。
#[derive(Debug, Clone)]
pub struct ClassicalEntry {
    pub kind: ClassicalKind,
    pub value: String,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    DomainWildcard,
    GeoSite,
    GeoIp,
    SrcGeoIp,
    IpCidr,
    SrcIpCidr,
    IpSuffix,
    SrcIpSuffix,
    IpAsn,
    SrcIpAsn,
    DstPort,
    SrcPort,
    InPort,
    InType,
    InUser,
    InName,
    Dscp,
    Uid,
    ProcessName,
    ProcessPath,
    ProcessNameRegex,
    ProcessPathRegex,
    ProcessNameWildcard,
    ProcessPathWildcard,
    RematchName,
    Network,
    And,
    Or,
    Not,
    Match,
}

impl ClassicalKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "DOMAIN" => Self::Domain,
            "DOMAIN-SUFFIX" => Self::DomainSuffix,
            "DOMAIN-KEYWORD" => Self::DomainKeyword,
            "DOMAIN-REGEX" => Self::DomainRegex,
            "DOMAIN-WILDCARD" => Self::DomainWildcard,
            "GEOSITE" => Self::GeoSite,
            "GEOIP" => Self::GeoIp,
            "SRC-GEOIP" => Self::SrcGeoIp,
            "IP-CIDR" | "IP-CIDR6" => Self::IpCidr,
            "SRC-IP-CIDR" => Self::SrcIpCidr,
            "IP-SUFFIX" => Self::IpSuffix,
            "SRC-IP-SUFFIX" => Self::SrcIpSuffix,
            "IP-ASN" => Self::IpAsn,
            "SRC-IP-ASN" => Self::SrcIpAsn,
            "DST-PORT" => Self::DstPort,
            "SRC-PORT" => Self::SrcPort,
            "IN-PORT" => Self::InPort,
            "IN-TYPE" => Self::InType,
            "IN-USER" => Self::InUser,
            "IN-NAME" => Self::InName,
            "DSCP" => Self::Dscp,
            "UID" => Self::Uid,
            "PROCESS-NAME" => Self::ProcessName,
            "PROCESS-PATH" => Self::ProcessPath,
            "PROCESS-NAME-REGEX" => Self::ProcessNameRegex,
            "PROCESS-PATH-REGEX" => Self::ProcessPathRegex,
            "PROCESS-NAME-WILDCARD" => Self::ProcessNameWildcard,
            "PROCESS-PATH-WILDCARD" => Self::ProcessPathWildcard,
            "REMATCH-NAME" => Self::RematchName,
            "NETWORK" => Self::Network,
            "AND" => Self::And,
            "OR" => Self::Or,
            "NOT" => Self::Not,
            "MATCH" => Self::Match,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct IpSuffix {
    address: IpAddr,
    bits: u8,
}

#[derive(Debug)]
enum LogicalRule {
    Leaf(Box<RulesetMatcher>),
    And(Vec<LogicalRule>),
    Or(Vec<LogicalRule>),
    Not(Box<LogicalRule>),
}

#[derive(Default)]
struct PrefixTable(IpNetworkTable<()>);

impl std::fmt::Debug for PrefixTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrefixTable")
            .field("prefixes", &self.0.len())
            .finish()
    }
}

impl PrefixTable {
    fn insert(&mut self, network: IpNet) {
        if let Ok(network) = network.to_string().parse::<ip_network::IpNetwork>() {
            self.0.insert(network, ());
        }
    }

    #[inline]
    fn contains(&self, address: IpAddr) -> bool {
        self.0.longest_match(address).is_some()
    }
}

/// 单条规则集编译产物 —— 内部不可变 + 引用计数共享。
#[derive(Debug, Default)]
pub struct RulesetMatcher {
    pub name: String,
    /// 精确域名（已小写 + 去尾点）
    domains: AHashSet<String>,
    /// 后缀集合（转为反向 trie 查询）
    suffix_trie: SuffixTrie,
    /// 子串关键字
    keywords: Vec<String>,
    keyword_automaton: Option<AhoCorasick>,
    /// DOMAIN-WILDCARD patterns compiled as one globset.
    wildcard_set: Option<GlobSet>,
    /// Rust `regex` 可以无损处理的快速正则集合。
    regex_set: Option<RegexSet>,
    /// 需要 look-around / backreference 等 regexp2 语义的正则。
    fancy_regexes: Vec<FancyRegex>,
    /// CIDR：v4 与 v6 分桶
    cidr_v4: Vec<ipnet::Ipv4Net>,
    cidr_v6: Vec<ipnet::Ipv6Net>,
    destination_prefix_table: PrefixTable,
    /// source CIDR 与 destination CIDR 严格分桶。
    src_cidr_v4: Vec<ipnet::Ipv4Net>,
    src_cidr_v6: Vec<ipnet::Ipv6Net>,
    source_prefix_table: PrefixTable,
    destination_ip_suffixes: Vec<IpSuffix>,
    source_ip_suffixes: Vec<IpSuffix>,
    destination_geoip: AHashSet<String>,
    source_geoip: AHashSet<String>,
    destination_geosite: AHashSet<String>,
    destination_asn: AHashSet<u32>,
    source_asn: AHashSet<u32>,
    destination_geoip_aliases: Vec<Vec<String>>,
    source_geoip_aliases: Vec<Vec<String>>,
    destination_geosite_aliases: Vec<Vec<String>>,
    destination_asn_aliases: Vec<Vec<String>>,
    source_asn_aliases: Vec<Vec<String>>,
    destination_ip_requires_resolution: bool,
    /// 进程名（精确）
    processes: AHashSet<String>,
    /// 完整进程路径（精确，大小写不敏感）。
    process_paths: AHashSet<String>,
    process_regex_set: Option<RegexSet>,
    process_path_regex_set: Option<RegexSet>,
    process_wildcard_set: Option<GlobSet>,
    process_path_wildcard_set: Option<GlobSet>,
    rematch_names: AHashSet<String>,
    networks: AHashSet<String>,
    /// 端口（单值或区间，u16..=u16）
    ports: Vec<(u16, u16)>,
    /// source 端口，不能退化为 destination 端口。
    src_ports: Vec<(u16, u16)>,
    inbound_ports: Vec<(u16, u16)>,
    inbound_types: AHashSet<String>,
    inbound_users: AHashSet<String>,
    inbound_names: AHashSet<String>,
    dscp_values: AHashSet<u8>,
    uid_values: AHashSet<u32>,
    logical_rules: Vec<LogicalRule>,
    match_all: bool,
    /// 原始 classical 条目，便于 explain。
    pub classical_count: usize,

    /// mihomo MRS domain succinct trie —— 比 suffix_trie + domains 更紧凑、
    /// 自带 wildcard 语义，几十 MB 域名集亦能 O(|key|) 查询。
    mrs_domain_set: Option<Arc<crate::parser::mrs::MrsDomainSet>>,
    /// mihomo MRS ipcidr 闭区间 v4 列表（已按 from 升序排序，二分查找）。
    mrs_v4_ranges: Vec<(u32, u32)>,
    /// 同上，IPv6。
    mrs_v6_ranges: Vec<(u128, u128)>,
    /// MRS 原始统计（domain count 或 ipcidr range count）。
    mrs_count: usize,

    /// sing-box JSON / SRS 共享的语义规则程序。
    semantic_program: Option<RulesetProgram>,

    /// 可供 TUN `route_address_set` 原子快照的 destination-only IP 前缀。
    destination_prefixes_v4: Arc<Vec<Ipv4Net>>,
    destination_prefixes_v6: Arc<Vec<Ipv6Net>>,
    destination_prefix_semantics: RulesetIpPrefixSemantics,
    destination_prefix_error: Option<RulesetPrefixError>,
}

impl RulesetMatcher {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// 把 classical 条目集合编译为 matcher。
    pub fn compile(name: impl Into<String>, entries: Vec<ClassicalEntry>) -> Self {
        let mut m = RulesetMatcher::new(name);
        let mut regex_pats: Vec<String> = Vec::new();
        let mut wildcard_pats: Vec<String> = Vec::new();
        let mut process_regex_pats: Vec<String> = Vec::new();
        let mut process_path_regex_pats: Vec<String> = Vec::new();
        let mut process_wildcard_pats: Vec<String> = Vec::new();
        let mut process_path_wildcard_pats: Vec<String> = Vec::new();
        let mut saw_destination_prefix = false;
        let mut saw_non_destination_rule = false;
        m.classical_count = entries.len();
        for e in entries {
            let no_resolve = e
                .policy
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("no-resolve"));
            match e.kind {
                ClassicalKind::Domain => {
                    saw_non_destination_rule = true;
                    m.domains.insert(normalize_domain(&e.value));
                }
                ClassicalKind::DomainSuffix => {
                    saw_non_destination_rule = true;
                    m.suffix_trie.insert(&e.value);
                }
                ClassicalKind::DomainKeyword => {
                    saw_non_destination_rule = true;
                    m.keywords.push(e.value.to_lowercase());
                }
                ClassicalKind::DomainRegex => {
                    saw_non_destination_rule = true;
                    regex_pats.push(e.value);
                }
                ClassicalKind::DomainWildcard => {
                    saw_non_destination_rule = true;
                    wildcard_pats.push(normalize_domain_pattern(&e.value));
                }
                ClassicalKind::GeoSite => {
                    saw_non_destination_rule = true;
                    let value = e.value.to_ascii_lowercase();
                    if m.destination_geosite.insert(value.clone()) {
                        m.destination_geosite_aliases
                            .push(ruleset_alias_candidates("geosite", &value));
                    }
                }
                ClassicalKind::GeoIp => {
                    saw_non_destination_rule = true;
                    m.destination_ip_requires_resolution |= !no_resolve;
                    let value = e.value.to_ascii_lowercase();
                    if m.destination_geoip.insert(value.clone()) {
                        m.destination_geoip_aliases
                            .push(ruleset_alias_candidates("geoip", &value));
                    }
                }
                ClassicalKind::SrcGeoIp => {
                    saw_non_destination_rule = true;
                    let value = e.value.to_ascii_lowercase();
                    if m.source_geoip.insert(value.clone()) {
                        m.source_geoip_aliases
                            .push(ruleset_alias_candidates("geoip", &value));
                    }
                }
                ClassicalKind::IpCidr => {
                    if let Ok(net) = e.value.parse::<IpNet>() {
                        m.destination_ip_requires_resolution |= !no_resolve;
                        saw_destination_prefix = true;
                        match net {
                            IpNet::V4(v4) => m.cidr_v4.push(v4),
                            IpNet::V6(v6) => m.cidr_v6.push(v6),
                        }
                    } else {
                        // Parsers normally reject malformed CIDRs. If a caller
                        // constructs entries directly, never label an ignored
                        // item as an exact IP set.
                        saw_non_destination_rule = true;
                    }
                }
                ClassicalKind::SrcIpCidr => {
                    saw_non_destination_rule = true;
                    if let Ok(net) = e.value.parse::<IpNet>() {
                        match net {
                            IpNet::V4(v4) => m.src_cidr_v4.push(v4),
                            IpNet::V6(v6) => m.src_cidr_v6.push(v6),
                        }
                    }
                }
                ClassicalKind::IpSuffix => {
                    saw_non_destination_rule = true;
                    if let Some(suffix) = parse_ip_suffix(&e.value) {
                        m.destination_ip_requires_resolution |= !no_resolve;
                        m.destination_ip_suffixes.push(suffix);
                    }
                }
                ClassicalKind::SrcIpSuffix => {
                    saw_non_destination_rule = true;
                    if let Some(suffix) = parse_ip_suffix(&e.value) {
                        m.source_ip_suffixes.push(suffix);
                    }
                }
                ClassicalKind::IpAsn => {
                    saw_non_destination_rule = true;
                    if let Some(asn) = parse_asn(&e.value) {
                        m.destination_ip_requires_resolution |= !no_resolve;
                        if m.destination_asn.insert(asn) {
                            m.destination_asn_aliases
                                .push(ruleset_alias_candidates("asn", &asn.to_string()));
                        }
                    }
                }
                ClassicalKind::SrcIpAsn => {
                    saw_non_destination_rule = true;
                    if let Some(asn) = parse_asn(&e.value) {
                        if m.source_asn.insert(asn) {
                            m.source_asn_aliases
                                .push(ruleset_alias_candidates("asn", &asn.to_string()));
                        }
                    }
                }
                ClassicalKind::DstPort => {
                    saw_non_destination_rule = true;
                    if let Some(range) = parse_port_range(&e.value) {
                        m.ports.push(range);
                    }
                }
                ClassicalKind::SrcPort => {
                    saw_non_destination_rule = true;
                    if let Some(range) = parse_port_range(&e.value) {
                        m.src_ports.push(range);
                    }
                }
                ClassicalKind::InPort => {
                    saw_non_destination_rule = true;
                    if let Some(range) = parse_port_range(&e.value) {
                        m.inbound_ports.push(range);
                    }
                }
                ClassicalKind::InType => {
                    saw_non_destination_rule = true;
                    insert_slash_values(&mut m.inbound_types, &e.value);
                }
                ClassicalKind::InUser => {
                    saw_non_destination_rule = true;
                    insert_slash_values(&mut m.inbound_users, &e.value);
                }
                ClassicalKind::InName => {
                    saw_non_destination_rule = true;
                    insert_slash_values(&mut m.inbound_names, &e.value);
                }
                ClassicalKind::Dscp => {
                    saw_non_destination_rule = true;
                    if let Ok(value) = e.value.parse() {
                        m.dscp_values.insert(value);
                    }
                }
                ClassicalKind::Uid => {
                    saw_non_destination_rule = true;
                    if let Ok(value) = e.value.parse() {
                        m.uid_values.insert(value);
                    }
                }
                ClassicalKind::ProcessName => {
                    saw_non_destination_rule = true;
                    m.processes.insert(e.value.to_ascii_lowercase());
                }
                ClassicalKind::ProcessPath => {
                    saw_non_destination_rule = true;
                    m.process_paths.insert(e.value.to_lowercase());
                }
                ClassicalKind::ProcessNameRegex => {
                    saw_non_destination_rule = true;
                    process_regex_pats.push(e.value);
                }
                ClassicalKind::ProcessPathRegex => {
                    saw_non_destination_rule = true;
                    process_path_regex_pats.push(e.value);
                }
                ClassicalKind::ProcessNameWildcard => {
                    saw_non_destination_rule = true;
                    process_wildcard_pats.push(e.value);
                }
                ClassicalKind::ProcessPathWildcard => {
                    saw_non_destination_rule = true;
                    process_path_wildcard_pats.push(e.value);
                }
                ClassicalKind::RematchName => {
                    saw_non_destination_rule = true;
                    insert_slash_values(&mut m.rematch_names, &e.value);
                }
                ClassicalKind::Network => {
                    saw_non_destination_rule = true;
                    insert_slash_values(&mut m.networks, &e.value);
                }
                ClassicalKind::And | ClassicalKind::Or | ClassicalKind::Not => {
                    saw_non_destination_rule = true;
                    if let Some(rule) = compile_logical_rule(e.kind, &e.value) {
                        m.logical_rules.push(rule);
                    }
                }
                ClassicalKind::Match => {
                    saw_non_destination_rule = true;
                    m.match_all = true;
                }
            }
        }
        if !regex_pats.is_empty() {
            let mut fast = Vec::new();
            for pattern in regex_pats {
                if regex::Regex::new(&pattern).is_ok() {
                    fast.push(pattern);
                } else if let Ok(regex) = compile_mihomo_domain_regex(&pattern) {
                    m.fancy_regexes.push(regex);
                }
            }
            if !fast.is_empty()
                && let Ok(rs) = regex::RegexSetBuilder::new(&fast)
                    .case_insensitive(true)
                    .build()
            {
                m.regex_set = Some(rs);
            }
        }
        if !m.keywords.is_empty() {
            m.keyword_automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&m.keywords)
                .ok();
        }
        if !wildcard_pats.is_empty() {
            let mut set = GlobSetBuilder::new();
            for pattern in wildcard_pats {
                let mut builder = GlobBuilder::new(&pattern);
                builder
                    .case_insensitive(true)
                    .literal_separator(false)
                    .backslash_escape(true);
                if let Ok(glob) = builder.build() {
                    set.add(glob);
                }
            }
            m.wildcard_set = set.build().ok();
        }
        m.process_regex_set = compile_regex_set(&process_regex_pats);
        m.process_path_regex_set = compile_regex_set(&process_path_regex_pats);
        m.process_wildcard_set = compile_glob_set(&process_wildcard_pats);
        m.process_path_wildcard_set = compile_glob_set(&process_path_wildcard_pats);
        // 排序 CIDR 让长前缀优先（更精确）
        m.cidr_v4.sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.cidr_v6.sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.src_cidr_v4
            .sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.src_cidr_v6
            .sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        for network in m
            .cidr_v4
            .iter()
            .copied()
            .map(IpNet::V4)
            .chain(m.cidr_v6.iter().copied().map(IpNet::V6))
        {
            m.destination_prefix_table.insert(network);
        }
        for network in m
            .src_cidr_v4
            .iter()
            .copied()
            .map(IpNet::V4)
            .chain(m.src_cidr_v6.iter().copied().map(IpNet::V6))
        {
            m.source_prefix_table.insert(network);
        }
        let semantics = match (saw_destination_prefix, saw_non_destination_rule) {
            (true, false) => RulesetIpPrefixSemantics::Exact,
            (true, true) => RulesetIpPrefixSemantics::Extracted,
            (false, _) => RulesetIpPrefixSemantics::NotIpSet,
        };
        let prefixes = try_clone_prefixes(&m.cidr_v4, &m.cidr_v6)
            .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
        m.install_destination_prefixes(prefixes, semantics);
        m
    }

    /// 从纯 domain 列表（mihomo behavior=domain）编译：
    /// 项以 `+.` 开头视为后缀，否则视为精确。
    pub fn compile_domains(
        name: impl Into<String>,
        lines: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|line| crate::parser::txt::parse_domain_pattern(line.trim()).ok())
            .collect();
        Self::compile(name, entries)
    }

    pub fn compile_ipcidr(
        name: impl Into<String>,
        lines: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    return None;
                }
                Some(ClassicalEntry {
                    kind: ClassicalKind::IpCidr,
                    value: l.into(),
                    policy: None,
                })
            })
            .collect();
        Self::compile(name, entries)
    }

    /// 把 [`crate::parser::RulesetCompiled`] 编译成 matcher。
    /// `Classical` 走老 [`Self::compile`] 路径；`Mrs` 把预编译产物挂到内部字段。
    pub fn compile_any(name: impl Into<String>, compiled: crate::parser::RulesetCompiled) -> Self {
        match compiled {
            crate::parser::RulesetCompiled::Classical(entries) => Self::compile(name, entries),
            crate::parser::RulesetCompiled::Semantic(program) => {
                Self::compile_semantic(name, program)
            }
            crate::parser::RulesetCompiled::Mrs(payload) => Self::compile_mrs(name, payload),
        }
    }

    pub fn compile_semantic(name: impl Into<String>, program: RulesetProgram) -> Self {
        let mut matcher = RulesetMatcher::new(name);
        let semantics = if program.is_exact_destination_ip_set() {
            RulesetIpPrefixSemantics::Exact
        } else {
            RulesetIpPrefixSemantics::Extracted
        };
        let prefixes = collect_program_prefixes(&program)
            .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
        let semantics = match &prefixes {
            Ok((ipv4, ipv6)) if ipv4.is_empty() && ipv6.is_empty() => {
                RulesetIpPrefixSemantics::NotIpSet
            }
            _ => semantics,
        };
        matcher.install_destination_prefixes(prefixes, semantics);
        matcher.semantic_program = Some(program);
        matcher
    }

    /// 把 mihomo MRS 预编译产物挂到 matcher。
    pub fn compile_mrs(name: impl Into<String>, payload: crate::parser::mrs::MrsPayload) -> Self {
        let mut m = RulesetMatcher::new(name);
        m.mrs_count = payload.count();
        match payload {
            crate::parser::mrs::MrsPayload::Domain { set, .. } => {
                m.mrs_domain_set = Some(set);
                m.install_destination_prefixes(
                    Ok((Vec::new(), Vec::new())),
                    RulesetIpPrefixSemantics::NotIpSet,
                );
            }
            crate::parser::mrs::MrsPayload::IpCidr { set, .. } => {
                m.destination_ip_requires_resolution = true;
                // Arc<MrsIpCidrSet> → 拷贝一份排序好的 Vec 进 matcher 字段
                // （MrsIpCidrSet 内部已经排过序）。MrsIpCidrSet 不暴露所有权移动，
                // 直接 clone 出 v4/v6 ranges 即可。
                m.mrs_v4_ranges = set.v4_ranges.clone();
                m.mrs_v6_ranges = set.v6_ranges.clone();
                let prefixes = ranges_to_prefixes(&m.mrs_v4_ranges, &m.mrs_v6_ranges)
                    .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
                m.install_destination_prefixes(prefixes, RulesetIpPrefixSemantics::Exact);
            }
        }
        m
    }

    /// Return an immutable destination-prefix view for route-set consumers.
    ///
    /// The semantic label is essential: `Extracted` mirrors sing-box's
    /// `RuleSet.ExtractIPSet` compatibility behavior but is not equivalent to
    /// evaluating a conditional or inverted ruleset.
    pub fn destination_ip_prefixes(
        &self,
    ) -> Result<RulesetDestinationPrefixes, RulesetPrefixError> {
        if let Some(error) = &self.destination_prefix_error {
            return Err(error.clone());
        }
        Ok((
            self.destination_prefix_semantics,
            self.destination_prefixes_v4.clone(),
            self.destination_prefixes_v6.clone(),
        ))
    }

    fn install_destination_prefixes(
        &mut self,
        prefixes: Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError>,
        semantics: RulesetIpPrefixSemantics,
    ) {
        self.destination_prefix_semantics = semantics;
        match prefixes {
            Ok((ipv4, ipv6)) => {
                self.destination_prefixes_v4 = Arc::new(ipv4);
                self.destination_prefixes_v6 = Arc::new(ipv6);
                self.destination_prefix_error = None;
            }
            Err(error) => {
                self.destination_prefixes_v4 = Arc::new(Vec::new());
                self.destination_prefixes_v6 = Arc::new(Vec::new());
                self.destination_prefix_error = Some(error);
            }
        }
    }

    fn has_same_destination_prefixes(&self, other: &Self) -> bool {
        self.destination_prefix_semantics == other.destination_prefix_semantics
            && self.destination_prefix_error == other.destination_prefix_error
            && self.destination_prefixes_v4 == other.destination_prefixes_v4
            && self.destination_prefixes_v6 == other.destination_prefixes_v6
    }

    /// 主入口：判断 host/ip/port 是否命中。
    pub fn matches(
        &self,
        host: &str,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process: Option<&str>,
    ) -> bool {
        self.matches_context(&RulesetMatchContext {
            dst_host: host,
            dst_ip: ip,
            dst_port: port,
            process_name: process,
            ..Default::default()
        })
    }

    /// 结构化匹配入口。新调用方应优先使用它，避免混淆 source / destination。
    pub fn matches_context(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        if let Some(program) = &self.semantic_program {
            return program.matches(ctx);
        }
        if self.match_all {
            return true;
        }

        // 域名相关
        let host_unicode = ctx.dst_host.trim().trim_end_matches('.').to_lowercase();
        let host_lc = normalize_domain(&host_unicode);
        if !host_lc.is_empty() {
            if self.domains.contains(&host_lc) {
                return true;
            }
            if self.suffix_trie.matches(&host_lc) {
                return true;
            }
            if self.keyword_automaton.as_ref().is_some_and(|automaton| {
                automaton.is_match(&host_lc)
                    || (host_lc != host_unicode && automaton.is_match(&host_unicode))
            }) {
                return true;
            }
            if let Some(rs) = &self.regex_set {
                if rs.is_match(&host_lc) || (host_lc != host_unicode && rs.is_match(&host_unicode))
                {
                    return true;
                }
            }
            if self.fancy_regexes.iter().any(|regex| {
                regex.is_match(&host_lc).unwrap_or(false)
                    || (host_lc != host_unicode && regex.is_match(&host_unicode).unwrap_or(false))
            }) {
                return true;
            }
            if self.wildcard_set.as_ref().is_some_and(|set| {
                set.is_match(&host_lc) || (host_lc != host_unicode && set.is_match(&host_unicode))
            }) {
                return true;
            }
            // mihomo MRS domain succinct trie（含 wildcard 语义）
            if let Some(set) = &self.mrs_domain_set {
                if set.has(&host_unicode) || (host_lc != host_unicode && set.has(&host_lc)) {
                    return true;
                }
            }
            if ctx.destination_geosite.iter().any(|code| {
                self.destination_geosite
                    .contains(&code.to_ascii_lowercase())
            }) {
                return true;
            }
        }
        // IP / CIDR
        let resolved_ip = ctx.dst_ip.or_else(|| ctx.dst_host.parse::<IpAddr>().ok());
        if let Some(ip) = resolved_ip {
            if self
                .destination_ip_suffixes
                .iter()
                .any(|suffix| ip_suffix_matches(ip, *suffix))
            {
                return true;
            }
            if self.destination_prefix_table.contains(ip) {
                return true;
            }
            match ip {
                IpAddr::V4(v) => {
                    if !self.mrs_v4_ranges.is_empty()
                        && contains_range_v4(&self.mrs_v4_ranges, u32::from(v))
                    {
                        return true;
                    }
                }
                IpAddr::V6(v) => {
                    if !self.mrs_v6_ranges.is_empty()
                        && contains_range_v6(&self.mrs_v6_ranges, u128::from(v))
                    {
                        return true;
                    }
                }
            }
        }
        if let Some(ip) = ctx.src_ip {
            if self.source_prefix_table.contains(ip) {
                return true;
            }
            if self
                .source_ip_suffixes
                .iter()
                .any(|suffix| ip_suffix_matches(ip, *suffix))
            {
                return true;
            }
        }
        if ctx
            .destination_geoip
            .iter()
            .any(|code| self.destination_geoip.contains(&code.to_ascii_lowercase()))
            || ctx
                .source_geoip
                .iter()
                .any(|code| self.source_geoip.contains(&code.to_ascii_lowercase()))
            || ctx
                .destination_asn
                .is_some_and(|asn| self.destination_asn.contains(&asn))
            || ctx
                .source_asn
                .is_some_and(|asn| self.source_asn.contains(&asn))
        {
            return true;
        }
        // port
        if let Some(p) = ctx.dst_port {
            if self.ports.iter().any(|(lo, hi)| p >= *lo && p <= *hi) {
                return true;
            }
        }
        if let Some(p) = ctx.src_port {
            if self.src_ports.iter().any(|(lo, hi)| p >= *lo && p <= *hi) {
                return true;
            }
        }
        if let Some(p) = ctx.inbound_port {
            if self
                .inbound_ports
                .iter()
                .any(|(lo, hi)| p >= *lo && p <= *hi)
            {
                return true;
            }
        }
        if option_in_set(ctx.inbound_type, &self.inbound_types)
            || option_in_set(ctx.inbound_user, &self.inbound_users)
            || option_in_set(ctx.inbound_name, &self.inbound_names)
            || ctx.uid.is_some_and(|uid| self.uid_values.contains(&uid))
            || ctx
                .dscp
                .is_some_and(|dscp| self.dscp_values.contains(&dscp))
            || option_in_set(ctx.network, &self.networks)
            || ctx
                .rematch_names
                .iter()
                .any(|name| self.rematch_names.contains(&name.to_lowercase()))
        {
            return true;
        }
        // process
        if let Some(name) = ctx.process_name {
            if self.processes.contains(&name.to_ascii_lowercase()) {
                return true;
            }
            if self
                .process_regex_set
                .as_ref()
                .is_some_and(|set| set.is_match(name))
                || self
                    .process_wildcard_set
                    .as_ref()
                    .is_some_and(|set| set.is_match(name))
            {
                return true;
            }
        }
        if ctx.package_names.iter().any(|name| {
            self.processes.contains(&name.to_ascii_lowercase())
                || self
                    .process_regex_set
                    .as_ref()
                    .is_some_and(|set| set.is_match(name))
                || self
                    .process_wildcard_set
                    .as_ref()
                    .is_some_and(|set| set.is_match(name))
        }) {
            return true;
        }
        if let Some(path) = ctx.process_path {
            if self.process_paths.contains(&path.to_lowercase()) {
                return true;
            }
            if self
                .process_path_regex_set
                .as_ref()
                .is_some_and(|set| set.is_match(path))
                || self
                    .process_path_wildcard_set
                    .as_ref()
                    .is_some_and(|set| set.is_match(path))
            {
                return true;
            }
        }
        if self
            .logical_rules
            .iter()
            .filter(|rule| !rule.has_external_refs())
            .any(|rule| rule.matches(ctx))
        {
            return true;
        }
        false
    }

    /// Evaluate without eagerly resolving process metadata.
    ///
    /// Classical rules are a union, while semantic JSON/SRS rules preserve
    /// their full logical tree (including NOT), so the latter delegates to the
    /// program's tri-state evaluator.
    pub fn matches_context_lazy(
        &self,
        ctx: &RulesetMatchContext<'_>,
        process_resolved: bool,
    ) -> RulesetMatchOutcome {
        self.matches_context_deferred(ctx, process_resolved, true)
    }

    /// Evaluate while process metadata and destination DNS may still be pending.
    ///
    /// This is required for ordered routing: an IP-based MRS/RULE-SET must ask
    /// the caller to resolve a domain unless its top-level rule carries
    /// `no-resolve`; treating a missing destination IP as a hard miss silently
    /// skips every IPCIDR provider.
    pub fn matches_context_deferred(
        &self,
        ctx: &RulesetMatchContext<'_>,
        process_resolved: bool,
        destination_ip_resolved: bool,
    ) -> RulesetMatchOutcome {
        if let Some(program) = &self.semantic_program {
            return program.matches_deferred(ctx, process_resolved, destination_ip_resolved);
        }
        if self.matches_context(ctx) {
            RulesetMatchOutcome::Matched
        } else {
            let needs_process = !process_resolved
                && (!self.processes.is_empty()
                    || !self.process_paths.is_empty()
                    || self.process_regex_set.is_some()
                    || self.process_path_regex_set.is_some()
                    || self.process_wildcard_set.is_some()
                    || self.process_path_wildcard_set.is_some()
                    || self.logical_rules.iter().any(LogicalRule::needs_process));
            let needs_destination_ip = !destination_ip_resolved
                && (self.destination_ip_requires_resolution
                    || !self.mrs_v4_ranges.is_empty()
                    || !self.mrs_v6_ranges.is_empty()
                    || self
                        .logical_rules
                        .iter()
                        .any(LogicalRule::needs_destination_ip));
            match (needs_process, needs_destination_ip) {
                (false, false) => RulesetMatchOutcome::NotMatched,
                (true, false) => RulesetMatchOutcome::NeedsProcess,
                (false, true) => RulesetMatchOutcome::NeedsDestinationIp,
                (true, true) => RulesetMatchOutcome::NeedsProcessAndDestinationIp,
            }
        }
    }

    pub fn stats(&self) -> RulesetStats {
        // MRS domain set 的"domains"概念不能简单地映射到 self.domains.len()。
        // 我们把 mrs_count（header.count）记到一个独立字段，并在 cidr_* 里
        // 也累计 MRS v4/v6 ranges，便于 dashboard 总数显示。
        let domains_total = self.domains.len()
            + self
                .mrs_domain_set
                .as_ref()
                .map(|_| self.mrs_count)
                .unwrap_or(0);
        RulesetStats {
            domains: domains_total,
            suffixes: self.suffix_trie.len(),
            keywords: self.keywords.len(),
            regex: self.regex_set.as_ref().map(|r| r.len()).unwrap_or(0) + self.fancy_regexes.len(),
            cidr_v4: self.cidr_v4.len() + self.src_cidr_v4.len() + self.mrs_v4_ranges.len(),
            cidr_v6: self.cidr_v6.len() + self.src_cidr_v6.len() + self.mrs_v6_ranges.len(),
            processes: self.processes.len() + self.process_paths.len(),
            ports: self.ports.len() + self.src_ports.len(),
        }
    }
}

fn prefix_limit_error() -> RulesetPrefixError {
    RulesetPrefixError::TooManyPrefixes {
        limit: MAX_IP_PREFIX_SNAPSHOT_ITEMS,
    }
}

fn checked_prefix_total(v4: usize, v6: usize) -> Result<usize, RulesetPrefixError> {
    let total = v4.checked_add(v6).ok_or_else(prefix_limit_error)?;
    if total > MAX_IP_PREFIX_SNAPSHOT_ITEMS {
        return Err(prefix_limit_error());
    }
    Ok(total)
}

fn try_clone_prefixes(
    ipv4: &[Ipv4Net],
    ipv6: &[Ipv6Net],
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    checked_prefix_total(ipv4.len(), ipv6.len())?;
    let mut cloned_v4 = Vec::new();
    cloned_v4
        .try_reserve_exact(ipv4.len())
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    cloned_v4.extend_from_slice(ipv4);
    let mut cloned_v6 = Vec::new();
    cloned_v6
        .try_reserve_exact(ipv6.len())
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    cloned_v6.extend_from_slice(ipv6);
    Ok((cloned_v4, cloned_v6))
}

fn collect_program_prefixes(
    program: &RulesetProgram,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut error = None;
    let completed = program.visit_destination_ip_cidrs(|prefix| {
        let total = ipv4.len().saturating_add(ipv6.len());
        if total >= MAX_IP_PREFIX_SNAPSHOT_ITEMS {
            error = Some(prefix_limit_error());
            return false;
        }
        match prefix {
            IpNet::V4(prefix) => {
                if ipv4.try_reserve(1).is_err() {
                    error = Some(RulesetPrefixError::AllocationFailed);
                    return false;
                }
                ipv4.push(*prefix);
            }
            IpNet::V6(prefix) => {
                if ipv6.try_reserve(1).is_err() {
                    error = Some(RulesetPrefixError::AllocationFailed);
                    return false;
                }
                ipv6.push(*prefix);
            }
        }
        true
    });
    if !completed {
        return Err(error.unwrap_or_else(prefix_limit_error));
    }
    Ok((ipv4, ipv6))
}

fn normalize_destination_prefixes(
    mut ipv4: Vec<Ipv4Net>,
    mut ipv6: Vec<Ipv6Net>,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    checked_prefix_total(ipv4.len(), ipv6.len())?;
    for prefix in &mut ipv4 {
        *prefix = prefix.trunc();
    }
    for prefix in &mut ipv6 {
        *prefix = prefix.trunc();
    }
    aggregate_ipv4_in_place(&mut ipv4);
    aggregate_ipv6_in_place(&mut ipv6);
    Ok((ipv4, ipv6))
}

/// Aggregate sorted prefixes in their existing allocation. Besides avoiding
/// duplicate kernel-set entries, doing this in place prevents an untrusted
/// ruleset from forcing a second multi-million-item allocation.
fn aggregate_ipv4_in_place(prefixes: &mut Vec<Ipv4Net>) {
    prefixes.sort_unstable_by_key(|net| (u32::from(net.network()), net.prefix_len()));
    let original_len = prefixes.len();
    let mut write = 0usize;
    for read in 0..original_len {
        let mut candidate = prefixes[read];
        loop {
            if write == 0 {
                prefixes[write] = candidate;
                write += 1;
                break;
            }
            let previous = prefixes[write - 1];
            if previous.contains(&candidate) {
                break;
            }
            if candidate.contains(&previous) {
                write -= 1;
                continue;
            }
            let Some(parent) = previous.supernet() else {
                prefixes[write] = candidate;
                write += 1;
                break;
            };
            if previous.prefix_len() == candidate.prefix_len() && parent.contains(&candidate) {
                candidate = parent;
                write -= 1;
                continue;
            }
            prefixes[write] = candidate;
            write += 1;
            break;
        }
    }
    prefixes.truncate(write);
}

fn aggregate_ipv6_in_place(prefixes: &mut Vec<Ipv6Net>) {
    prefixes.sort_unstable_by_key(|net| (u128::from(net.network()), net.prefix_len()));
    let original_len = prefixes.len();
    let mut write = 0usize;
    for read in 0..original_len {
        let mut candidate = prefixes[read];
        loop {
            if write == 0 {
                prefixes[write] = candidate;
                write += 1;
                break;
            }
            let previous = prefixes[write - 1];
            if previous.contains(&candidate) {
                break;
            }
            if candidate.contains(&previous) {
                write -= 1;
                continue;
            }
            let Some(parent) = previous.supernet() else {
                prefixes[write] = candidate;
                write += 1;
                break;
            };
            if previous.prefix_len() == candidate.prefix_len() && parent.contains(&candidate) {
                candidate = parent;
                write -= 1;
                continue;
            }
            prefixes[write] = candidate;
            write += 1;
            break;
        }
    }
    prefixes.truncate(write);
}

fn ranges_to_prefixes(
    v4_ranges: &[(u32, u32)],
    v6_ranges: &[(u128, u128)],
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut total = 0usize;
    for &(start, end) in v4_ranges {
        append_ipv4_range(start, end, &mut ipv4, &mut total)?;
    }
    for &(start, end) in v6_ranges {
        append_ipv6_range(start, end, &mut ipv6, &mut total)?;
    }
    Ok((ipv4, ipv6))
}

fn reserve_prefix<T>(output: &mut Vec<T>, total: &mut usize) -> Result<(), RulesetPrefixError> {
    if *total >= MAX_IP_PREFIX_SNAPSHOT_ITEMS {
        return Err(prefix_limit_error());
    }
    output
        .try_reserve(1)
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    *total += 1;
    Ok(())
}

fn append_ipv4_range(
    mut start: u32,
    end: u32,
    output: &mut Vec<Ipv4Net>,
    total: &mut usize,
) -> Result<(), RulesetPrefixError> {
    if start > end {
        return Err(RulesetPrefixError::InvalidRange { family: "IPv4" });
    }
    loop {
        let alignment_bits = start.trailing_zeros();
        let difference = end - start;
        let range_bits = if difference == u32::MAX {
            u32::BITS
        } else {
            u32::BITS - (difference + 1).leading_zeros() - 1
        };
        let host_bits = alignment_bits.min(range_bits);
        let prefix_len = (u32::BITS - host_bits) as u8;
        reserve_prefix(output, total)?;
        output.push(
            Ipv4Net::new(Ipv4Addr::from(start), prefix_len)
                .expect("computed IPv4 prefix length is valid"),
        );
        if host_bits == u32::BITS {
            break;
        }
        let block_size = 1u32 << host_bits;
        let Some(next) = start.checked_add(block_size) else {
            break;
        };
        if next > end {
            break;
        }
        start = next;
    }
    Ok(())
}

fn append_ipv6_range(
    mut start: u128,
    end: u128,
    output: &mut Vec<Ipv6Net>,
    total: &mut usize,
) -> Result<(), RulesetPrefixError> {
    if start > end {
        return Err(RulesetPrefixError::InvalidRange { family: "IPv6" });
    }
    loop {
        let alignment_bits = start.trailing_zeros();
        let difference = end - start;
        let range_bits = if difference == u128::MAX {
            u128::BITS
        } else {
            u128::BITS - (difference + 1).leading_zeros() - 1
        };
        let host_bits = alignment_bits.min(range_bits);
        let prefix_len = (u128::BITS - host_bits) as u8;
        reserve_prefix(output, total)?;
        output.push(
            Ipv6Net::new(Ipv6Addr::from(start), prefix_len)
                .expect("computed IPv6 prefix length is valid"),
        );
        if host_bits == u128::BITS {
            break;
        }
        let block_size = 1u128 << host_bits;
        let Some(next) = start.checked_add(block_size) else {
            break;
        };
        if next > end {
            break;
        }
        start = next;
    }
    Ok(())
}

#[inline]
fn contains_range_v4(ranges: &[(u32, u32)], ip: u32) -> bool {
    ranges
        .binary_search_by(|(from, to)| {
            if ip < *from {
                std::cmp::Ordering::Greater
            } else if ip > *to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[inline]
fn contains_range_v6(ranges: &[(u128, u128)], ip: u128) -> bool {
    ranges
        .binary_search_by(|(from, to)| {
            if ip < *from {
                std::cmp::Ordering::Greater
            } else if ip > *to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[derive(Debug, Clone, Default)]
pub struct RulesetStats {
    pub domains: usize,
    pub suffixes: usize,
    pub keywords: usize,
    pub regex: usize,
    pub cidr_v4: usize,
    pub cidr_v6: usize,
    pub processes: usize,
    pub ports: usize,
}

/* ---------------- 索引 ---------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesetAvailability {
    Pending,
    Unavailable,
}

#[derive(Debug, Clone, Default)]
struct RulesetIndexState {
    revision: u64,
    matchers: AHashMap<String, Arc<RulesetMatcher>>,
    availability: AHashMap<String, RulesetAvailability>,
}

/// 全局规则集索引；route 引擎查 `set:<name>` 时用它。
#[derive(Debug)]
pub struct RulesetIndex {
    state: ArcSwap<RulesetIndexState>,
    update: parking_lot::Mutex<()>,
    prefix_revisions: watch::Sender<u64>,
}

impl Default for RulesetIndex {
    fn default() -> Self {
        let (prefix_revisions, _receiver) = watch::channel(0);
        Self {
            state: ArcSwap::from_pointee(RulesetIndexState::default()),
            update: parking_lot::Mutex::new(()),
            prefix_revisions,
        }
    }
}

impl RulesetIndex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Declare configured names before asynchronous loading starts.
    ///
    /// A destination-prefix consumer can therefore distinguish a pending
    /// provider from a misspelled/nonexistent set name.
    pub fn declare<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let _update = self.update.lock();
        let revision = {
            let current = self.state.load_full();
            let mut state = (*current).clone();
            let mut changed = false;
            for name in names {
                let name = name.into();
                if !state.matchers.contains_key(&name) && !state.availability.contains_key(&name) {
                    state
                        .availability
                        .insert(name, RulesetAvailability::Pending);
                    changed = true;
                }
            }
            if changed {
                let revision = bump_prefix_revision(&mut state);
                self.state.store(Arc::new(state));
                Some(revision)
            } else {
                None
            }
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    /// Mark an initial load failure without discarding a last-known-good set.
    pub fn mark_unavailable(&self, name: impl Into<String>) {
        let name = name.into();
        let _update = self.update.lock();
        let revision = {
            let current = self.state.load_full();
            let mut state = (*current).clone();
            if state.matchers.contains_key(&name)
                || state.availability.get(&name) == Some(&RulesetAvailability::Unavailable)
            {
                None
            } else {
                state
                    .availability
                    .insert(name, RulesetAvailability::Unavailable);
                let revision = bump_prefix_revision(&mut state);
                self.state.store(Arc::new(state));
                Some(revision)
            }
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    pub fn insert(&self, m: Arc<RulesetMatcher>) {
        let _update = self.update.lock();
        let revision = {
            let current = self.state.load_full();
            let mut state = (*current).clone();
            let name = m.name.clone();
            let prefix_changed = match state.matchers.get(&name) {
                Some(previous) => !previous.has_same_destination_prefixes(&m),
                None => true,
            } || state.availability.contains_key(&name);
            state.matchers.insert(name.clone(), m);
            state.availability.remove(&name);
            let revision = prefix_changed.then(|| bump_prefix_revision(&mut state));
            self.state.store(Arc::new(state));
            revision
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<RulesetMatcher>> {
        self.state.load().matchers.get(name).cloned()
    }

    /// Evaluate a named set together with any GEOSITE/GEOIP/ASN references
    /// embedded in a classical provider. The complete immutable index snapshot
    /// is held for the evaluation, so a provider refresh cannot mix versions
    /// midway through one route decision.
    pub fn matches_context_deferred(
        &self,
        name: &str,
        context: &RulesetMatchContext<'_>,
        process_resolved: bool,
        destination_ip_resolved: bool,
    ) -> RulesetMatchOutcome {
        let state = self.state.load();
        let Some(matcher) = state.matchers.get(name) else {
            return RulesetMatchOutcome::NotMatched;
        };
        let mut stack = Vec::with_capacity(4);
        evaluate_indexed_matcher(
            &state,
            name,
            matcher,
            context,
            process_resolved,
            destination_ip_resolved,
            &mut stack,
        )
    }

    pub fn names(&self) -> Vec<String> {
        self.state.load().matchers.keys().cloned().collect()
    }

    pub fn stats(&self) -> Vec<(String, RulesetStats)> {
        self.state
            .load()
            .matchers
            .iter()
            .map(|(k, v)| (k.clone(), v.stats()))
            .collect()
    }

    /// Current destination-prefix generation.
    pub fn ip_prefix_revision(&self) -> u64 {
        self.state.load().revision
    }

    /// Subscribe to desired-state changes. The receiver immediately contains
    /// the current generation; slow consumers may skip intermediate values and
    /// reconcile directly to the latest snapshot.
    pub fn subscribe_ip_prefix_updates(&self) -> watch::Receiver<u64> {
        self.prefix_revisions.subscribe()
    }

    /// Atomically read multiple named sets at one index generation.
    ///
    /// All requested names are represented, including pending, unavailable,
    /// missing and non-IP sets. Duplicate names are removed while preserving
    /// their first occurrence.
    pub fn ip_prefix_snapshot<S: AsRef<str>>(&self, names: &[S]) -> RulesetIpPrefixSnapshot {
        let state = self.state.load();
        build_ip_prefix_snapshot(&state, names)
    }

    /// Race-free initial read + update subscription.
    ///
    /// The receiver is created before the snapshot. Publication is monotonic,
    /// so an update racing either side is already visible in the snapshot or
    /// remains pending in the receiver. The two revision values may differ
    /// during that narrow window; consumers should immediately reconcile again
    /// when the receiver is newer.
    pub fn ip_prefix_snapshot_and_subscribe<S: AsRef<str>>(
        &self,
        names: &[S],
    ) -> (RulesetIpPrefixSnapshot, watch::Receiver<u64>) {
        let receiver = self.prefix_revisions.subscribe();
        let snapshot = self.ip_prefix_snapshot(names);
        (snapshot, receiver)
    }

    fn publish_prefix_revision(&self, revision: u64) {
        // Concurrent writers commit under the update mutex but publish after
        // releasing it. Only move the watch value forward so a slower writer
        // can never overwrite a newer desired state.
        self.prefix_revisions.send_if_modified(|published| {
            if revision > *published {
                *published = revision;
                true
            } else {
                false
            }
        });
    }
}

fn evaluate_indexed_matcher(
    state: &RulesetIndexState,
    name: &str,
    matcher: &RulesetMatcher,
    context: &RulesetMatchContext<'_>,
    process_resolved: bool,
    destination_ip_resolved: bool,
    stack: &mut Vec<String>,
) -> RulesetMatchOutcome {
    if stack.iter().any(|active| active == name) || stack.len() > 32 {
        return RulesetMatchOutcome::NotMatched;
    }
    stack.push(name.to_owned());

    let mut outcome =
        matcher.matches_context_deferred(context, process_resolved, destination_ip_resolved);
    if outcome == RulesetMatchOutcome::Matched {
        stack.pop();
        return outcome;
    }

    let source_context = RulesetMatchContext {
        dst_host: "",
        dst_ip: context.src_ip,
        dst_port: context.src_port,
        ..*context
    };
    for aliases in &matcher.destination_geosite_aliases {
        outcome = or_outcome(
            outcome,
            evaluate_aliases(
                state,
                aliases,
                context,
                process_resolved,
                destination_ip_resolved,
                stack,
            ),
        );
    }
    for aliases in matcher
        .destination_geoip_aliases
        .iter()
        .chain(matcher.destination_asn_aliases.iter())
    {
        outcome = or_outcome(
            outcome,
            evaluate_aliases(
                state,
                aliases,
                context,
                process_resolved,
                destination_ip_resolved,
                stack,
            ),
        );
    }
    for aliases in matcher
        .source_geoip_aliases
        .iter()
        .chain(matcher.source_asn_aliases.iter())
    {
        outcome = or_outcome(
            outcome,
            evaluate_aliases(
                state,
                aliases,
                &source_context,
                process_resolved,
                true,
                stack,
            ),
        );
    }
    for logical in &matcher.logical_rules {
        if logical.has_external_refs() {
            outcome = or_outcome(
                outcome,
                logical.matches_indexed(
                    state,
                    context,
                    process_resolved,
                    destination_ip_resolved,
                    stack,
                ),
            );
        }
    }
    stack.pop();
    outcome
}

fn evaluate_aliases(
    state: &RulesetIndexState,
    aliases: &[String],
    context: &RulesetMatchContext<'_>,
    process_resolved: bool,
    destination_ip_resolved: bool,
    stack: &mut Vec<String>,
) -> RulesetMatchOutcome {
    let mut outcome = RulesetMatchOutcome::NotMatched;
    for alias in aliases {
        let Some(matcher) = state.matchers.get(alias) else {
            continue;
        };
        outcome = or_outcome(
            outcome,
            evaluate_indexed_matcher(
                state,
                alias,
                matcher,
                context,
                process_resolved,
                destination_ip_resolved,
                stack,
            ),
        );
        if outcome == RulesetMatchOutcome::Matched {
            break;
        }
    }
    outcome
}

fn outcome_requirements(outcome: RulesetMatchOutcome) -> (bool, bool) {
    match outcome {
        RulesetMatchOutcome::NeedsProcess => (true, false),
        RulesetMatchOutcome::NeedsDestinationIp => (false, true),
        RulesetMatchOutcome::NeedsProcessAndDestinationIp => (true, true),
        RulesetMatchOutcome::Matched | RulesetMatchOutcome::NotMatched => (false, false),
    }
}

fn deferred_outcome(process: bool, destination_ip: bool) -> RulesetMatchOutcome {
    match (process, destination_ip) {
        (false, false) => RulesetMatchOutcome::NotMatched,
        (true, false) => RulesetMatchOutcome::NeedsProcess,
        (false, true) => RulesetMatchOutcome::NeedsDestinationIp,
        (true, true) => RulesetMatchOutcome::NeedsProcessAndDestinationIp,
    }
}

fn or_outcome(left: RulesetMatchOutcome, right: RulesetMatchOutcome) -> RulesetMatchOutcome {
    if left == RulesetMatchOutcome::Matched || right == RulesetMatchOutcome::Matched {
        return RulesetMatchOutcome::Matched;
    }
    let (left_process, left_destination) = outcome_requirements(left);
    let (right_process, right_destination) = outcome_requirements(right);
    deferred_outcome(
        left_process || right_process,
        left_destination || right_destination,
    )
}

fn and_outcome(left: RulesetMatchOutcome, right: RulesetMatchOutcome) -> RulesetMatchOutcome {
    if left == RulesetMatchOutcome::NotMatched || right == RulesetMatchOutcome::NotMatched {
        return RulesetMatchOutcome::NotMatched;
    }
    if left == RulesetMatchOutcome::Matched {
        return right;
    }
    if right == RulesetMatchOutcome::Matched {
        return left;
    }
    let (left_process, left_destination) = outcome_requirements(left);
    let (right_process, right_destination) = outcome_requirements(right);
    deferred_outcome(
        left_process || right_process,
        left_destination || right_destination,
    )
}

fn bump_prefix_revision(state: &mut RulesetIndexState) -> u64 {
    state.revision = state
        .revision
        .checked_add(1)
        .expect("ruleset prefix revision exhausted");
    state.revision
}

fn build_ip_prefix_snapshot<S: AsRef<str>>(
    state: &RulesetIndexState,
    names: &[S],
) -> RulesetIpPrefixSnapshot {
    let mut seen = AHashSet::new();
    let mut sets = Vec::new();
    for requested in names {
        let name = requested.as_ref();
        if !seen.insert(name) {
            continue;
        }
        let (status, ipv4, ipv6) = if let Some(matcher) = state.matchers.get(name) {
            match matcher.destination_ip_prefixes() {
                Ok((semantics, ipv4, ipv6)) => {
                    (RulesetIpPrefixStatus::Ready { semantics }, ipv4, ipv6)
                }
                Err(RulesetPrefixError::TooManyPrefixes { limit }) => (
                    RulesetIpPrefixStatus::TooManyPrefixes { limit },
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
                Err(RulesetPrefixError::AllocationFailed) => (
                    RulesetIpPrefixStatus::AllocationFailed,
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
                Err(RulesetPrefixError::InvalidRange { family }) => (
                    RulesetIpPrefixStatus::InvalidRange { family },
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
            }
        } else {
            let status = match state.availability.get(name) {
                Some(RulesetAvailability::Pending) => RulesetIpPrefixStatus::Pending,
                Some(RulesetAvailability::Unavailable) => RulesetIpPrefixStatus::Unavailable,
                None => RulesetIpPrefixStatus::Missing,
            };
            (status, Arc::new(Vec::new()), Arc::new(Vec::new()))
        };
        sets.push(RulesetIpPrefixSet {
            name: name.to_string(),
            status,
            ipv4,
            ipv6,
        });
    }
    RulesetIpPrefixSnapshot {
        revision: state.revision,
        sets: Arc::new(sets),
    }
}

/* ---------------- 后缀 trie ---------------- */

#[derive(Debug, Default)]
struct SuffixTrie {
    root: TrieNode,
    count: usize,
}

#[derive(Debug, Default)]
struct TrieNode {
    /// 段 → 子节点（注意：插入时把域名按 '.' 反向切分）
    children: AHashMap<String, TrieNode>,
    /// 此节点是终止 —— 命中代表"以此后缀结尾"。
    terminal: bool,
}

impl SuffixTrie {
    fn insert(&mut self, suffix: &str) {
        let suffix = normalize_domain(suffix.trim_matches('.'));
        if suffix.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        for seg in suffix.rsplit('.') {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.terminal = true;
        self.count += 1;
    }
    fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return false;
        }
        let mut node = &self.root;
        // 反向遍历：z.b.a 的后缀 a → b → z
        for seg in host.rsplit('.') {
            match node.children.get(seg) {
                Some(child) => {
                    if child.terminal {
                        return true;
                    }
                    node = child;
                }
                None => return false,
            }
        }
        node.terminal
    }
    fn len(&self) -> usize {
        self.count
    }
}

fn normalize_domain(s: &str) -> String {
    let trimmed = s.trim().trim_end_matches('.');
    idna::domain_to_ascii(trimmed)
        .unwrap_or_else(|_| trimmed.to_lowercase())
        .to_lowercase()
}

fn normalize_domain_pattern(pattern: &str) -> String {
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

fn compile_regex_set(patterns: &[String]) -> Option<RegexSet> {
    (!patterns.is_empty())
        .then(|| RegexSet::new(patterns).ok())
        .flatten()
}

fn compile_glob_set(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut set = GlobSetBuilder::new();
    for pattern in patterns {
        let mut builder = GlobBuilder::new(pattern);
        builder
            .case_insensitive(true)
            .literal_separator(false)
            .backslash_escape(true);
        set.add(builder.build().ok()?);
    }
    set.build().ok()
}

fn insert_slash_values(target: &mut AHashSet<String>, value: &str) {
    target.extend(
        value
            .split('/')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_lowercase),
    );
}

fn ruleset_alias_candidates(kind: &str, value: &str) -> Vec<String> {
    let value = value.trim().trim_start_matches(':').to_ascii_lowercase();
    let mut candidates = Vec::with_capacity(3);
    let mut push = |candidate: String| {
        if !candidate.is_empty() && !candidates.iter().any(|old| old == &candidate) {
            candidates.push(candidate);
        }
    };
    push(value.clone());
    push(format!("{kind}-{value}"));
    match (kind, value.as_str()) {
        ("geosite", "cn") => push("cn-domain".into()),
        ("geoip", "cn") => push("geoip-cn".into()),
        ("geoip", "private") => push("geoip-private".into()),
        _ => {}
    }
    candidates
}

fn option_in_set(value: Option<&str>, set: &AHashSet<String>) -> bool {
    value.is_some_and(|value| set.contains(&value.to_lowercase()))
}

fn parse_asn(value: &str) -> Option<u32> {
    value
        .trim()
        .trim_start_matches(|character: char| matches!(character, 'A' | 'a' | 'S' | 's'))
        .parse()
        .ok()
}

fn parse_ip_suffix(value: &str) -> Option<IpSuffix> {
    let (address, bits) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let bits = bits.parse::<u8>().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    (bits <= maximum).then_some(IpSuffix { address, bits })
}

fn ip_suffix_matches(candidate: IpAddr, suffix: IpSuffix) -> bool {
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
    let bytes = usize::from(bits / 8);
    let remaining = bits % 8;
    if bytes > 0 && candidate[candidate.len() - bytes..] != expected[expected.len() - bytes..] {
        return false;
    }
    if remaining == 0 {
        return true;
    }
    let index = candidate.len() - bytes - 1;
    let mask = (1u8 << remaining) - 1;
    candidate[index] & mask == expected[index] & mask
}

fn compile_logical_rule(kind: ClassicalKind, payload: &str) -> Option<LogicalRule> {
    let children = crate::parser::txt::parse_logical_payload(kind, payload).ok()?;
    let mut rules = children
        .into_iter()
        .filter_map(compile_classical_rule)
        .collect::<Vec<_>>();
    match kind {
        ClassicalKind::And => Some(LogicalRule::And(rules)),
        ClassicalKind::Or => Some(LogicalRule::Or(rules)),
        ClassicalKind::Not if rules.len() == 1 => Some(LogicalRule::Not(Box::new(rules.remove(0)))),
        _ => None,
    }
}

fn compile_classical_rule(entry: ClassicalEntry) -> Option<LogicalRule> {
    match entry.kind {
        ClassicalKind::And | ClassicalKind::Or | ClassicalKind::Not => {
            compile_logical_rule(entry.kind, &entry.value)
        }
        _ => Some(LogicalRule::Leaf(Box::new(RulesetMatcher::compile(
            "logical",
            vec![entry],
        )))),
    }
}

impl LogicalRule {
    fn matches(&self, context: &RulesetMatchContext<'_>) -> bool {
        match self {
            Self::Leaf(matcher) => matcher.matches_context(context),
            Self::And(children) => children.iter().all(|child| child.matches(context)),
            Self::Or(children) => children.iter().any(|child| child.matches(context)),
            Self::Not(child) => !child.matches(context),
        }
    }

    fn needs_process(&self) -> bool {
        match self {
            Self::Leaf(matcher) => matcher.has_process_predicates(),
            Self::And(children) | Self::Or(children) => children.iter().any(Self::needs_process),
            Self::Not(child) => child.needs_process(),
        }
    }

    fn needs_destination_ip(&self) -> bool {
        match self {
            Self::Leaf(matcher) => matcher.has_destination_ip_predicates(),
            Self::And(children) | Self::Or(children) => {
                children.iter().any(Self::needs_destination_ip)
            }
            Self::Not(child) => child.needs_destination_ip(),
        }
    }

    fn has_external_refs(&self) -> bool {
        match self {
            Self::Leaf(matcher) => {
                !matcher.destination_geoip_aliases.is_empty()
                    || !matcher.source_geoip_aliases.is_empty()
                    || !matcher.destination_geosite_aliases.is_empty()
                    || !matcher.destination_asn_aliases.is_empty()
                    || !matcher.source_asn_aliases.is_empty()
                    || matcher
                        .logical_rules
                        .iter()
                        .any(LogicalRule::has_external_refs)
            }
            Self::And(children) | Self::Or(children) => {
                children.iter().any(Self::has_external_refs)
            }
            Self::Not(child) => child.has_external_refs(),
        }
    }

    fn matches_indexed(
        &self,
        state: &RulesetIndexState,
        context: &RulesetMatchContext<'_>,
        process_resolved: bool,
        destination_ip_resolved: bool,
        stack: &mut Vec<String>,
    ) -> RulesetMatchOutcome {
        match self {
            Self::Leaf(matcher) => evaluate_indexed_matcher(
                state,
                &matcher.name,
                matcher,
                context,
                process_resolved,
                destination_ip_resolved,
                stack,
            ),
            Self::And(children) => {
                let mut outcome = RulesetMatchOutcome::Matched;
                for child in children {
                    outcome = and_outcome(
                        outcome,
                        child.matches_indexed(
                            state,
                            context,
                            process_resolved,
                            destination_ip_resolved,
                            stack,
                        ),
                    );
                    if outcome == RulesetMatchOutcome::NotMatched {
                        break;
                    }
                }
                outcome
            }
            Self::Or(children) => {
                let mut outcome = RulesetMatchOutcome::NotMatched;
                for child in children {
                    outcome = or_outcome(
                        outcome,
                        child.matches_indexed(
                            state,
                            context,
                            process_resolved,
                            destination_ip_resolved,
                            stack,
                        ),
                    );
                    if outcome == RulesetMatchOutcome::Matched {
                        break;
                    }
                }
                outcome
            }
            Self::Not(child) => match child.matches_indexed(
                state,
                context,
                process_resolved,
                destination_ip_resolved,
                stack,
            ) {
                RulesetMatchOutcome::Matched => RulesetMatchOutcome::NotMatched,
                RulesetMatchOutcome::NotMatched => RulesetMatchOutcome::Matched,
                deferred => deferred,
            },
        }
    }
}

impl RulesetMatcher {
    fn has_process_predicates(&self) -> bool {
        !self.processes.is_empty()
            || !self.process_paths.is_empty()
            || self.process_regex_set.is_some()
            || self.process_path_regex_set.is_some()
            || self.process_wildcard_set.is_some()
            || self.process_path_wildcard_set.is_some()
            || self.logical_rules.iter().any(LogicalRule::needs_process)
    }

    fn has_destination_ip_predicates(&self) -> bool {
        self.destination_ip_requires_resolution
            || !self.mrs_v4_ranges.is_empty()
            || !self.mrs_v6_ranges.is_empty()
            || self
                .logical_rules
                .iter()
                .any(LogicalRule::needs_destination_ip)
    }
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: ClassicalKind, v: &str) -> ClassicalEntry {
        ClassicalEntry {
            kind,
            value: v.into(),
            policy: None,
        }
    }

    #[test]
    fn suffix_and_exact_match() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DomainSuffix, "example.com"),
                entry(ClassicalKind::Domain, "exact.test"),
            ],
        );
        assert!(m.matches("a.example.com", None, None, None));
        assert!(m.matches("example.com", None, None, None));
        assert!(!m.matches("example.org", None, None, None));
        assert!(m.matches("exact.test", None, None, None));
        assert!(!m.matches("noexact.test", None, None, None));
    }

    #[test]
    fn keyword_and_regex() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DomainKeyword, "google"),
                entry(ClassicalKind::DomainRegex, r"^(?:.*\.)?facebook\.com$"),
            ],
        );
        assert!(m.matches("www.googleapis.com", None, None, None));
        assert!(m.matches("a.facebook.com", None, None, None));
        assert!(m.matches("facebook.com", None, None, None));
    }

    #[test]
    fn domain_regex_is_case_insensitive_and_supports_lookaround() {
        let m = RulesetMatcher::compile(
            "regexp2",
            vec![entry(
                ClassicalKind::DomainRegex,
                r"^(?!api0\.)(api[0-9]+)\.example\.com$",
            )],
        );
        assert!(m.matches("API42.EXAMPLE.COM", None, None, None));
        assert!(!m.matches("api0.example.com", None, None, None));
    }

    #[test]
    fn cidr_v4_v6() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::IpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::IpCidr, "fd00::/8"),
            ],
        );
        assert!(m.matches("", "10.1.2.3".parse().ok(), None, None));
        assert!(m.matches("", "fd11::1".parse().ok(), None, None));
        assert!(!m.matches("", "1.1.1.1".parse().ok(), None, None));
    }

    #[test]
    fn classical_no_resolve_ip_rule_does_not_request_dns() {
        let entries = crate::parser::txt::parse_for_type(
            b"IP-CIDR,1.1.1.0/24,no-resolve\n",
            crate::RulesetType::Classical,
        )
        .unwrap();
        let matcher = RulesetMatcher::compile("no-resolve", entries);
        let unresolved = RulesetMatchContext {
            dst_host: "resolver.example",
            ..Default::default()
        };
        assert_eq!(
            matcher.matches_context_deferred(&unresolved, true, false),
            RulesetMatchOutcome::NotMatched
        );

        let resolved = RulesetMatchContext {
            dst_host: "resolver.example",
            dst_ip: Some("1.1.1.1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            matcher.matches_context_deferred(&resolved, true, true),
            RulesetMatchOutcome::Matched
        );
    }

    #[test]
    fn port_and_process() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DstPort, "443"),
                entry(ClassicalKind::DstPort, "1000-2000"),
                entry(ClassicalKind::ProcessName, "Code"),
            ],
        );
        assert!(m.matches("", None, Some(443), None));
        assert!(m.matches("", None, Some(1500), None));
        assert!(!m.matches("", None, Some(80), None));
        assert!(m.matches("", None, None, Some("code")));
        assert!(!m.matches("", None, None, Some("notepad")));
    }

    #[test]
    fn compile_domains_with_dot_prefix() {
        let m = RulesetMatcher::compile_domains(
            "geosite-cn",
            vec!["+.qq.com".into(), "baidu.com".into(), ".cn".into()],
        );
        assert!(m.matches("im.qq.com", None, None, None));
        assert!(m.matches("baidu.com", None, None, None));
        assert!(m.matches("a.b.cn", None, None, None));
    }

    #[test]
    fn domain_behavior_preserves_clash_wildcards_and_idna() {
        let matcher = RulesetMatcher::compile_domains(
            "domain",
            [
                ".blogger.com".into(),
                "*.*.microsoft.com".into(),
                "+.例子.测试".into(),
            ],
        );
        assert!(matcher.matches("www.blogger.com", None, None, None));
        assert!(!matcher.matches("blogger.com", None, None, None));
        assert!(matcher.matches("a.b.microsoft.com", None, None, None));
        assert!(!matcher.matches("b.microsoft.com", None, None, None));
        assert!(matcher.matches("例子.测试", None, None, None));
        assert!(matcher.matches("www.xn--fsqu00a.xn--0zwm56d", None, None, None));
    }

    #[test]
    fn classical_provider_supports_extended_mihomo_context() {
        let body = br#"
IP-SUFFIX,8.8.8.8/24
SRC-IP-SUFFIX,192.168.1.9/8
IP-ASN,13335
SRC-IP-ASN,9808
IN-PORT,7890
IN-TYPE,SOCKS/HTTP
IN-USER,alice
IN-NAME,mixed-in
DSCP,4
UID,1000
PROCESS-NAME-REGEX,curl$
PROCESS-PATH-WILDCARD,/usr/*/curl
REMATCH-NAME,dns
NETWORK,udp
"#;
        let entries =
            crate::parser::txt::parse_for_type(body, crate::RulesetType::Classical).unwrap();
        assert_eq!(entries.len(), 14);
        let matcher = RulesetMatcher::compile("extended", entries);

        let rematch_names = vec!["dns".into()];
        let context = RulesetMatchContext {
            inbound_port: Some(7890),
            inbound_type: Some("http"),
            inbound_user: Some("alice"),
            inbound_name: Some("mixed-in"),
            uid: Some(1000),
            dscp: Some(4),
            destination_asn: Some(13335),
            source_asn: Some(9808),
            rematch_names: &rematch_names,
            network: Some("udp"),
            ..Default::default()
        };
        assert!(matcher.matches_context(&context));

        let suffix =
            RulesetMatcher::compile("suffix", vec![entry(ClassicalKind::IpSuffix, "8.8.8.8/24")]);
        assert!(suffix.matches_context(&RulesetMatchContext {
            dst_ip: Some("1.8.8.8".parse().unwrap()),
            ..Default::default()
        }));
        assert!(!suffix.matches_context(&RulesetMatchContext {
            dst_ip: Some("8.8.4.4".parse().unwrap()),
            ..Default::default()
        }));
    }

    #[test]
    fn classical_provider_logical_rules_keep_boolean_semantics() {
        let entries = crate::parser::txt::parse_for_type(
            b"AND,((DOMAIN,logic.example),(NETWORK,tcp))\n",
            crate::RulesetType::Classical,
        )
        .unwrap();
        let and_matcher = RulesetMatcher::compile("logical-and", entries);
        assert!(and_matcher.matches_context(&RulesetMatchContext {
            dst_host: "logic.example",
            network: Some("tcp"),
            ..Default::default()
        }));
        assert!(!and_matcher.matches_context(&RulesetMatchContext {
            dst_host: "logic.example",
            network: Some("udp"),
            ..Default::default()
        }));
        let not_entries = crate::parser::txt::parse_for_type(
            b"NOT,((DOMAIN,blocked.example))\n",
            crate::RulesetType::Classical,
        )
        .unwrap();
        let not_matcher = RulesetMatcher::compile("logical-not", not_entries);
        assert!(not_matcher.matches_context(&RulesetMatchContext {
            dst_host: "allowed.example",
            network: Some("udp"),
            ..Default::default()
        }));
        assert!(!not_matcher.matches_context(&RulesetMatchContext {
            dst_host: "blocked.example",
            ..Default::default()
        }));
    }

    #[test]
    fn classical_geoip_can_reference_an_indexed_mrs_style_ip_set() {
        let index = RulesetIndex::new();
        index.insert(Arc::new(RulesetMatcher::compile(
            "geoip-cn",
            vec![entry(ClassicalKind::IpCidr, "1.1.1.0/24")],
        )));
        index.insert(Arc::new(RulesetMatcher::compile(
            "provider",
            vec![entry(ClassicalKind::GeoIp, "CN")],
        )));
        let hit = index.matches_context_deferred(
            "provider",
            &RulesetMatchContext {
                dst_ip: Some("1.1.1.1".parse().unwrap()),
                ..Default::default()
            },
            true,
            true,
        );
        assert_eq!(hit, RulesetMatchOutcome::Matched);
    }

    #[test]
    fn classical_source_predicates_do_not_match_destination_fields() {
        let m = RulesetMatcher::compile(
            "source",
            vec![
                entry(ClassicalKind::SrcIpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::SrcPort, "1000-2000"),
            ],
        );
        let destination_only = RulesetMatchContext {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            dst_port: Some(1500),
            ..Default::default()
        };
        assert!(!m.matches_context(&destination_only));

        let source_ip = RulesetMatchContext {
            src_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        assert!(m.matches_context(&source_ip));

        let source_port = RulesetMatchContext {
            src_port: Some(1500),
            ..Default::default()
        };
        assert!(m.matches_context(&source_port));
    }

    #[test]
    fn process_path_is_exact_case_insensitive_and_lazy() {
        let m = RulesetMatcher::compile(
            "path",
            vec![entry(
                ClassicalKind::ProcessPath,
                r"C:\Program Files\Browser\browser.exe",
            )],
        );
        let unresolved = RulesetMatchContext::default();
        assert_eq!(
            m.matches_context_lazy(&unresolved, false),
            RulesetMatchOutcome::NeedsProcess
        );

        let exact = RulesetMatchContext {
            process_path: Some(r"c:\program files\browser\BROWSER.EXE"),
            ..Default::default()
        };
        assert!(m.matches_context(&exact));

        let child = RulesetMatchContext {
            process_path: Some(r"C:\Program Files\Browser\helper.exe"),
            ..Default::default()
        };
        assert!(!m.matches_context(&child));
    }

    #[test]
    fn classical_prefix_snapshot_is_canonical_and_labels_projection() {
        let exact = RulesetMatcher::compile(
            "exact",
            vec![
                entry(ClassicalKind::IpCidr, "10.128.0.0/9"),
                entry(ClassicalKind::IpCidr, "10.0.0.0/9"),
                entry(ClassicalKind::IpCidr, "10.1.0.0/16"),
                entry(ClassicalKind::IpCidr, "2001:db8::1234/32"),
            ],
        );
        let (semantics, ipv4, ipv6) = exact.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Exact);
        assert_eq!(ipv4.as_ref(), &["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(ipv6.as_ref(), &["2001:db8::/32".parse().unwrap()]);

        let projected = RulesetMatcher::compile(
            "projected",
            vec![
                entry(ClassicalKind::IpCidr, "192.0.2.123/24"),
                entry(ClassicalKind::SrcIpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::DstPort, "443"),
            ],
        );
        let (semantics, ipv4, ipv6) = projected.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Extracted);
        assert_eq!(ipv4.as_ref(), &["192.0.2.0/24".parse().unwrap()]);
        assert!(ipv6.is_empty());

        let domains = RulesetMatcher::compile_domains("domain", ["example.com".into()]);
        let (semantics, ipv4, ipv6) = domains.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::NotIpSet);
        assert!(ipv4.is_empty());
        assert!(ipv6.is_empty());
    }

    #[test]
    fn semantic_snapshot_uses_singbox_extraction_but_marks_non_exact_rules() {
        use crate::ir::{RulesetExpr, RulesetPredicate};

        let program = RulesetProgram::new(
            5,
            1,
            RulesetExpr::All(vec![
                RulesetExpr::Predicate(RulesetPredicate::DstIpCidr(vec![
                    "203.0.113.0/24".parse().unwrap(),
                ])),
                RulesetExpr::Not(Box::new(RulesetExpr::Predicate(
                    RulesetPredicate::SrcIpCidr(vec!["10.0.0.0/8".parse().unwrap()]),
                ))),
                RulesetExpr::Predicate(RulesetPredicate::DstPort(vec![crate::ir::PortRange {
                    start: 443,
                    end: 443,
                }])),
            ]),
        );
        let matcher = RulesetMatcher::compile_semantic("srs", program);
        let (semantics, ipv4, ipv6) = matcher.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Extracted);
        assert_eq!(ipv4.as_ref(), &["203.0.113.0/24".parse().unwrap()]);
        assert!(ipv6.is_empty());
    }

    #[test]
    fn mrs_closed_ranges_convert_to_minimal_exact_prefixes() {
        use crate::parser::mrs::{MrsIpCidrSet, MrsPayload};

        let payload = MrsPayload::IpCidr {
            set: Arc::new(MrsIpCidrSet {
                v4_ranges: vec![(1, 6), (u32::MAX, u32::MAX)],
                v6_ranges: vec![(0, u128::MAX)],
            }),
            count: 3,
        };
        let matcher = RulesetMatcher::compile_mrs("mrs", payload);
        let (semantics, ipv4, ipv6) = matcher.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Exact);
        assert_eq!(
            ipv4.as_ref(),
            &[
                "0.0.0.1/32".parse().unwrap(),
                "0.0.0.2/31".parse().unwrap(),
                "0.0.0.4/31".parse().unwrap(),
                "0.0.0.6/32".parse().unwrap(),
                "255.255.255.255/32".parse().unwrap(),
            ]
        );
        assert_eq!(ipv6.as_ref(), &["::/0".parse().unwrap()]);
    }

    #[test]
    fn range_conversion_covers_exactly_every_small_interval_and_boundaries() {
        for start in 0u32..=32 {
            for end in start..=32 {
                let mut prefixes = Vec::new();
                let mut total = 0;
                append_ipv4_range(start, end, &mut prefixes, &mut total).unwrap();
                for candidate in 0u32..=40 {
                    let covered = prefixes
                        .iter()
                        .any(|prefix| prefix.contains(&Ipv4Addr::from(candidate)));
                    assert_eq!(
                        covered,
                        (start..=end).contains(&candidate),
                        "range {start}..={end}, candidate={candidate}, prefixes={prefixes:?}"
                    );
                }
            }
        }

        let mut v4 = Vec::new();
        let mut total = 0;
        append_ipv4_range(0, u32::MAX, &mut v4, &mut total).unwrap();
        assert_eq!(v4, vec!["0.0.0.0/0".parse().unwrap()]);

        let mut v6 = Vec::new();
        let mut total = 0;
        append_ipv6_range(u128::MAX, u128::MAX, &mut v6, &mut total).unwrap();
        assert_eq!(
            v6,
            vec![
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
                    .parse()
                    .unwrap()
            ]
        );

        let mut rejected = Vec::<Ipv4Net>::new();
        let mut at_limit = MAX_IP_PREFIX_SNAPSHOT_ITEMS;
        assert_eq!(
            reserve_prefix(&mut rejected, &mut at_limit),
            Err(RulesetPrefixError::TooManyPrefixes {
                limit: MAX_IP_PREFIX_SNAPSHOT_ITEMS
            })
        );
        assert!(rejected.is_empty());
    }

    #[test]
    fn in_place_aggregation_matches_ipnet_reference_implementation() {
        for seed in 0u64..64 {
            let mut state = seed.wrapping_add(1);
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for _ in 0..128 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let prefix_v4 = (state % 33) as u8;
                ipv4.push(
                    Ipv4Net::new(Ipv4Addr::from(state as u32), prefix_v4)
                        .unwrap()
                        .trunc(),
                );
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let address_v6 = (u128::from(state) << 64) | u128::from(state.rotate_left(17));
                let prefix_v6 = (state % 129) as u8;
                ipv6.push(
                    Ipv6Net::new(Ipv6Addr::from(address_v6), prefix_v6)
                        .unwrap()
                        .trunc(),
                );
            }

            let expected_v4 = Ipv4Net::aggregate(&ipv4);
            let expected_v6 = Ipv6Net::aggregate(&ipv6);
            aggregate_ipv4_in_place(&mut ipv4);
            aggregate_ipv6_in_place(&mut ipv6);
            assert_eq!(ipv4, expected_v4, "IPv4 seed {seed}");
            assert_eq!(ipv6, expected_v6, "IPv6 seed {seed}");
        }
    }

    #[tokio::test]
    async fn index_snapshot_status_and_watch_converge_without_spurious_updates() {
        let index = RulesetIndex::new();
        index.declare(["pending", "gone"]);
        index.mark_unavailable("gone");
        let names = ["pending", "gone", "missing", "pending"];
        let (initial, mut updates) = index.ip_prefix_snapshot_and_subscribe(&names);
        assert_eq!(initial.revision, *updates.borrow());
        assert_eq!(initial.sets.len(), 3);
        assert_eq!(initial.sets[0].status, RulesetIpPrefixStatus::Pending);
        assert_eq!(initial.sets[1].status, RulesetIpPrefixStatus::Unavailable);
        assert_eq!(initial.sets[2].status, RulesetIpPrefixStatus::Missing);

        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["10.0.0.0/8".into()],
        )));
        updates.changed().await.unwrap();
        let ready = index.ip_prefix_snapshot(&names);
        assert_eq!(ready.revision, *updates.borrow());
        assert_eq!(
            ready.sets[0].status,
            RulesetIpPrefixStatus::Ready {
                semantics: RulesetIpPrefixSemantics::Exact,
            }
        );

        let stable_revision = ready.revision;
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["10.1.2.3/9".into(), "10.200.3.4/9".into()],
        )));
        assert_eq!(index.ip_prefix_revision(), stable_revision);
        assert!(!updates.has_changed().unwrap());

        // Monotonic watch publication retains the newest desired state even if
        // no receiver existed at publication time.
        drop(updates);
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["192.0.2.0/24".into()],
        )));
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["198.51.100.0/24".into()],
        )));
        let late = index.subscribe_ip_prefix_updates();
        assert_eq!(*late.borrow(), index.ip_prefix_revision());
        assert_eq!(
            index.ip_prefix_snapshot(&["pending"]).sets[0].ipv4.as_ref(),
            &["198.51.100.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn watch_publication_never_holds_the_index_state_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let index = RulesetIndex::new();
        let receiver = index.subscribe_ip_prefix_updates();
        let borrowed_revision = receiver.borrow();
        let completed = Arc::new(AtomicBool::new(false));
        let writer_index = index.clone();
        let writer_completed = completed.clone();
        let writer = std::thread::spawn(move || {
            writer_index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
                "geo",
                ["203.0.113.0/24".into()],
            )));
            writer_completed.store(true, Ordering::Release);
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while index.ip_prefix_revision() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "writer did not commit index state"
            );
            std::thread::yield_now();
        }
        // The writer may be waiting for the watch Ref above, but readers must
        // still be able to observe its committed full snapshot.
        assert_eq!(
            index.ip_prefix_snapshot(&["geo"]).sets[0].ipv4.as_ref(),
            &["203.0.113.0/24".parse().unwrap()]
        );
        drop(borrowed_revision);
        writer.join().unwrap();
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(*receiver.borrow(), index.ip_prefix_revision());
    }

    #[test]
    fn concurrent_writers_cannot_publish_revision_regressions() {
        let index = RulesetIndex::new();
        let receiver = index.subscribe_ip_prefix_updates();
        let mut writers = Vec::new();
        for i in 0..16u8 {
            let index = index.clone();
            writers.push(std::thread::spawn(move || {
                index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
                    format!("set-{i}"),
                    [format!("10.{i}.0.0/16")],
                )));
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(index.ip_prefix_revision(), 16);
        assert_eq!(*receiver.borrow(), 16);
        assert_eq!(index.names().len(), 16);
    }
}
