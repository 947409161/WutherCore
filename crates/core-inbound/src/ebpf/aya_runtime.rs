use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::Path,
};

use aya::{
    Ebpf, EbpfLoader, Pod,
    maps::{
        Array, HashMap, PerCpuArray, SockMap,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        CgroupAttachMode, CgroupSockAddr, LinkOrder, SchedClassifier, SkLookup, TcAttachType,
        cgroup_sock_addr::CgroupSockAddrLinkId,
        sk_lookup::SkLookupLinkId,
        tc::{NlOptions, SchedClassifierLinkId, TcAttachOptions, TcHandle, qdisc_add_clsact},
    },
};
use core_config::model::{EbpfInboundOptions, EbpfSharedNetworkOptions};
use globset::{Glob, GlobSet, GlobSetBuilder};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::if_nametoindex,
    sys::resource::{RLIM_INFINITY, Resource, setrlimit},
};
use tracing::{debug, info};

use super::{BypassPrefixSnapshot, EbpfInboundError, socket::FamilySockets};

const FLAG_INCLUDE_UID: u32 = 1 << 0;
const FLAG_IPV4: u32 = 1 << 1;
const FLAG_IPV6: u32 = 1 << 2;
const FLAG_HIJACK_DNS: u32 = 1 << 3;
const FLAG_SHARED_NETWORK: u32 = 1 << 4;
const FLAG_SHARED_SOURCE_ANY: u32 = 1 << 5;
const MAX_UID_RANGES: usize = 256;
const MAX_SHARED_INTERFACES: usize = 256;

const CGROUP_PROGRAMS: [&str; 4] = ["connect4", "connect6", "sendmsg4", "sendmsg6"];

type V4PrefixSet = BTreeSet<(u8, [u8; 4])>;
type V6PrefixSet = BTreeSet<(u8, [u8; 16])>;
type PrefixSets = (V4PrefixSet, V6PrefixSet);
type RelaySockets = (
    Vec<tokio::net::TcpListener>,
    Vec<tokio::net::UdpSocket>,
    Vec<std::net::SocketAddr>,
);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct EbpfConfig {
    mark: u32,
    self_tgid: u32,
    flags: u32,
    bypass_bank: u32,
    include_range_count: u32,
    exclude_range_count: u32,
    loopback_ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UidRange {
    start: u32,
    end: u32,
}

unsafe impl Pod for EbpfConfig {}
unsafe impl Pod for UidRange {}

#[derive(Debug, Clone, Default)]
pub struct EbpfStats {
    pub selected: u64,
    pub bypass_self: u64,
    pub bypass_uid: u64,
    pub bypass_destination: u64,
    pub mark_failed: u64,
    pub lookup_assigned: u64,
    pub lookup_failed: u64,
    pub bypass_ingress: u64,
    pub shared_selected: u64,
    pub shared_bypass_source: u64,
    pub shared_bypass_destination: u64,
    pub shared_unsupported: u64,
    pub shared_lookup_assigned: u64,
    pub shared_lookup_failed: u64,
}

struct SharedLink {
    ifindex: u32,
    link: SchedClassifierLinkId,
}

struct SharedInterfaceMatcher {
    include: GlobSet,
    exclude: GlobSet,
}

pub(super) struct AyaDataPlane {
    ebpf: Ebpf,
    sockets: FamilySockets,
    cgroup_links: Vec<(&'static str, CgroupSockAddrLinkId)>,
    lookup_link: Option<SkLookupLinkId>,
    shared_program_loaded: bool,
    shared_links: BTreeMap<String, SharedLink>,
    shared_matcher: Option<SharedInterfaceMatcher>,
    active_bypass_bank: usize,
    bank_v4: [V4PrefixSet; 2],
    bank_v6: [V6PrefixSet; 2],
}

impl AyaDataPlane {
    pub(super) fn load(
        options: &EbpfInboundOptions,
        snapshot: &BypassPrefixSnapshot,
    ) -> Result<Self, EbpfInboundError> {
        let _ = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY);
        let redirect = options
            .redirect_address
            .iter()
            .map(|value| {
                value.parse::<ipnet::IpNet>().map_err(|_| {
                    EbpfInboundError::Configuration(format!("invalid redirect_address: {value}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sockets = FamilySockets::bind(&redirect)?;
        let has_v4 = sockets.tcp4.is_some();
        let has_v6 = sockets.tcp6.is_some();
        let loopback_ifindex = if_nametoindex("lo").map_err(|error| {
            EbpfInboundError::Configuration(format!(
                "cannot resolve loopback interface index: {error}"
            ))
        })?;

        let mut loader = EbpfLoader::new();
        loader
            .map_max_entries("INCLUDE_UIDS", options.map_capacity)
            .map_max_entries("EXCLUDE_UIDS", options.map_capacity)
            .map_max_entries("BYPASS_V4", options.map_capacity)
            .map_max_entries("BYPASS_V6", options.map_capacity)
            .map_max_entries("BYPASS_V4_ALT", options.map_capacity)
            .map_max_entries("BYPASS_V6_ALT", options.map_capacity)
            .map_max_entries("SHARED_SOURCE_V4", options.map_capacity)
            .map_max_entries("SHARED_SOURCE_V6", options.map_capacity)
            .map_max_entries("SHARED_EXCLUDE_SOURCE_V4", options.map_capacity)
            .map_max_entries("SHARED_EXCLUDE_SOURCE_V6", options.map_capacity);
        let mut ebpf = loader
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/core-inbound-ebpf"
            )))
            .map_err(|error| EbpfInboundError::Aya(format!("load eBPF object: {error}")))?;

        let include_ranges = parse_ranges(&options.include_uid_range)?;
        let exclude_ranges = parse_ranges(&options.exclude_uid_range)?;
        if include_ranges.len() > MAX_UID_RANGES || exclude_ranges.len() > MAX_UID_RANGES {
            return Err(EbpfInboundError::Configuration(format!(
                "UID range lists support at most {MAX_UID_RANGES} entries each"
            )));
        }
        if options.include_uid.len() > options.map_capacity as usize
            || options.exclude_uid.len() > options.map_capacity as usize
        {
            return Err(EbpfInboundError::Configuration(
                "exact UID lists cannot exceed map_capacity".into(),
            ));
        }
        let mut flags = 0;
        if !options.include_uid.is_empty() || !include_ranges.is_empty() {
            flags |= FLAG_INCLUDE_UID;
        }
        if has_v4 {
            flags |= FLAG_IPV4;
        }
        if has_v6 {
            flags |= FLAG_IPV6;
        }
        if matches!(
            options.resolver,
            core_config::model::CaptureResolver::Hijack
        ) {
            flags |= FLAG_HIJACK_DNS;
        }
        if options.shared_network.enabled {
            flags |= FLAG_SHARED_NETWORK;
            if options.shared_network.include_source_address.is_empty() {
                flags |= FLAG_SHARED_SOURCE_ANY;
            }
        }
        {
            let map = ebpf
                .map_mut("CONFIG")
                .ok_or_else(|| missing_map("CONFIG"))?;
            let mut config: Array<_, EbpfConfig> = map.try_into().map_err(map_error)?;
            config
                .set(
                    0,
                    EbpfConfig {
                        mark: options.mark,
                        self_tgid: std::process::id(),
                        flags,
                        bypass_bank: 0,
                        include_range_count: include_ranges.len() as u32,
                        exclude_range_count: exclude_ranges.len() as u32,
                        loopback_ifindex,
                    },
                    0,
                )
                .map_err(map_error)?;
        }
        populate_uid_hash(&mut ebpf, "INCLUDE_UIDS", &options.include_uid)?;
        populate_uid_hash(&mut ebpf, "EXCLUDE_UIDS", &options.exclude_uid)?;
        populate_uid_ranges(&mut ebpf, "INCLUDE_UID_RANGES", &include_ranges)?;
        populate_uid_ranges(&mut ebpf, "EXCLUDE_UID_RANGES", &exclude_ranges)?;
        populate_shared_source_maps(&mut ebpf, &options.shared_network)?;
        populate_socket_maps(&mut ebpf, &sockets)?;
        let shared_matcher = options
            .shared_network
            .enabled
            .then(|| SharedInterfaceMatcher::compile(&options.shared_network))
            .transpose()?;

        let mut plane = Self {
            ebpf,
            sockets,
            cgroup_links: Vec::new(),
            lookup_link: None,
            shared_program_loaded: false,
            shared_links: BTreeMap::new(),
            shared_matcher,
            active_bypass_bank: 0,
            bank_v4: [BTreeSet::new(), BTreeSet::new()],
            bank_v6: [BTreeSet::new(), BTreeSet::new()],
        };
        plane.replace_bypass(options, snapshot)?;
        Ok(plane)
    }

    pub(super) fn attach_lookup(&mut self) -> Result<(), EbpfInboundError> {
        let netns = File::open("/proc/self/ns/net")
            .map_err(|error| EbpfInboundError::Aya(format!("open current netns: {error}")))?;
        let program: &mut SkLookup = self
            .ebpf
            .program_mut("assign_proxy_socket")
            .ok_or_else(|| missing_program("assign_proxy_socket"))?
            .try_into()
            .map_err(program_error)?;
        program.load().map_err(program_error)?;
        let link = program.attach(netns).map_err(program_error)?;
        self.lookup_link = Some(link);
        Ok(())
    }

    pub(super) fn attach_cgroup(&mut self, path: &Path) -> Result<(), EbpfInboundError> {
        let cgroup = File::open(path).map_err(|error| {
            EbpfInboundError::Aya(format!("open cgroup {}: {error}", path.display()))
        })?;
        for name in CGROUP_PROGRAMS {
            let program: &mut CgroupSockAddr = self
                .ebpf
                .program_mut(name)
                .ok_or_else(|| missing_program(name))?
                .try_into()
                .map_err(program_error)?;
            program.load().map_err(program_error)?;
            let link = program
                .attach(&cgroup, CgroupAttachMode::AllowMultiple)
                .map_err(program_error)?;
            self.cgroup_links.push((name, link));
        }
        Ok(())
    }

    pub(super) fn detach_cgroup(&mut self) -> Result<(), EbpfInboundError> {
        while let Some((name, link)) = self.cgroup_links.pop() {
            let program: &mut CgroupSockAddr = self
                .ebpf
                .program_mut(name)
                .ok_or_else(|| missing_program(name))?
                .try_into()
                .map_err(program_error)?;
            program.detach(link).map_err(program_error)?;
        }
        Ok(())
    }

    pub(super) fn reconcile_shared_interfaces(
        &mut self,
        shared: &EbpfSharedNetworkOptions,
    ) -> Result<Vec<String>, EbpfInboundError> {
        if !shared.enabled {
            self.detach_shared_interfaces()?;
            return Ok(Vec::new());
        }
        let matcher = self.shared_matcher.as_ref().ok_or_else(|| {
            EbpfInboundError::Configuration(
                "shared-network matcher is unavailable for an enabled configuration".into(),
            )
        })?;
        let desired = discover_shared_interfaces(matcher)?;
        if desired.len() > MAX_SHARED_INTERFACES {
            return Err(EbpfInboundError::Configuration(format!(
                "shared_network matched {} interfaces; the limit is {MAX_SHARED_INTERFACES}",
                desired.len()
            )));
        }

        let stale = self
            .shared_links
            .iter()
            .filter_map(|(name, link)| {
                (desired.get(name).copied() != Some(link.ifindex)).then_some(name.clone())
            })
            .collect::<Vec<_>>();
        for name in stale {
            self.detach_shared_interface(&name)?;
        }
        for (name, ifindex) in desired {
            if !self.shared_links.contains_key(&name) {
                self.attach_shared_interface(&name, ifindex, shared.tc_priority)?;
            }
        }
        Ok(self.shared_interfaces())
    }

    pub(super) fn detach_shared_interfaces(&mut self) -> Result<(), EbpfInboundError> {
        let names = self.shared_links.keys().cloned().collect::<Vec<_>>();
        let mut first_error = None;
        for name in names {
            if let Err(error) = self.detach_shared_interface(&name)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn shared_interfaces(&self) -> Vec<String> {
        self.shared_links.keys().cloned().collect()
    }

    fn attach_shared_interface(
        &mut self,
        name: &str,
        ifindex: u32,
        priority: u16,
    ) -> Result<(), EbpfInboundError> {
        set_shared_interface(&mut self.ebpf, ifindex, true)?;
        let result = (|| {
            let program: &mut SchedClassifier = self
                .ebpf
                .program_mut("capture_shared_ingress")
                .ok_or_else(|| missing_program("capture_shared_ingress"))?
                .try_into()
                .map_err(program_error)?;
            if !self.shared_program_loaded {
                program.load().map_err(program_error)?;
                self.shared_program_loaded = true;
            }
            match program.attach_with_options(
                name,
                TcAttachType::Ingress,
                TcAttachOptions::TcxOrder(LinkOrder::first()),
            ) {
                Ok(link) => Ok(link),
                Err(error) => {
                    debug!(
                        target: "inbound::ebpf",
                        interface = name,
                        %error,
                        "TCX attach unavailable; falling back to clsact"
                    );
                    match qdisc_add_clsact(name) {
                        Ok(()) | Err(aya::programs::tc::TcError::AlreadyAttached) => {}
                        Err(error) => return Err(program_error(error)),
                    }
                    program
                        .attach_with_options(
                            name,
                            TcAttachType::Ingress,
                            TcAttachOptions::Netlink(NlOptions {
                                priority,
                                handle: TcHandle::AUTO_ASSIGN,
                                classid: None,
                            }),
                        )
                        .map_err(program_error)
                }
            }
        })();
        match result {
            Ok(link) => {
                self.shared_links
                    .insert(name.to_owned(), SharedLink { ifindex, link });
                info!(
                    target: "inbound::ebpf",
                    interface = name,
                    ifindex,
                    tc_priority = priority,
                    "shared-network TC ingress attached"
                );
                Ok(())
            }
            Err(error) => {
                let _ = set_shared_interface(&mut self.ebpf, ifindex, false);
                Err(EbpfInboundError::Aya(format!(
                    "attach shared-network TC ingress to {name}: {error}"
                )))
            }
        }
    }

    fn detach_shared_interface(&mut self, name: &str) -> Result<(), EbpfInboundError> {
        let Some(link) = self.shared_links.remove(name) else {
            return Ok(());
        };
        let program: &mut SchedClassifier = self
            .ebpf
            .program_mut("capture_shared_ingress")
            .ok_or_else(|| missing_program("capture_shared_ingress"))?
            .try_into()
            .map_err(program_error)?;
        match program.detach(link.link) {
            Ok(()) => {
                set_shared_interface(&mut self.ebpf, link.ifindex, false)?;
                info!(
                    target: "inbound::ebpf",
                    interface = name,
                    ifindex = link.ifindex,
                    "shared-network TC ingress detached"
                );
                Ok(())
            }
            Err(error) => Err(EbpfInboundError::Aya(format!(
                "detach shared-network TC ingress from {name}: {error}"
            ))),
        }
    }

    pub(super) fn detach_lookup(&mut self) -> Result<(), EbpfInboundError> {
        let Some(link) = self.lookup_link.take() else {
            return Ok(());
        };
        let program: &mut SkLookup = self
            .ebpf
            .program_mut("assign_proxy_socket")
            .ok_or_else(|| missing_program("assign_proxy_socket"))?
            .try_into()
            .map_err(program_error)?;
        program.detach(link).map_err(program_error)
    }

    pub(super) fn take_sockets(&mut self) -> Result<RelaySockets, EbpfInboundError> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for listener in [self.sockets.tcp4.take(), self.sockets.tcp6.take()]
            .into_iter()
            .flatten()
        {
            tcp.push(
                tokio::net::TcpListener::from_std(listener).map_err(|error| {
                    EbpfInboundError::Socket(format!("register TCP listener with Tokio: {error}"))
                })?,
            );
        }
        for socket in [self.sockets.udp4.take(), self.sockets.udp6.take()]
            .into_iter()
            .flatten()
        {
            udp.push(tokio::net::UdpSocket::from_std(socket).map_err(|error| {
                EbpfInboundError::Socket(format!("register UDP socket with Tokio: {error}"))
            })?);
        }
        Ok((tcp, udp, self.sockets.anchors.clone()))
    }

    pub(super) fn replace_bypass(
        &mut self,
        options: &EbpfInboundOptions,
        snapshot: &BypassPrefixSnapshot,
    ) -> Result<(), EbpfInboundError> {
        let (next_v4, next_v6) = desired_prefixes(options, snapshot)?;
        let capacity = options.map_capacity as usize;
        if next_v4.len() > capacity || next_v6.len() > capacity {
            return Err(EbpfInboundError::RuleSet(format!(
                "merged bypass prefixes exceed eBPF map capacity {} (IPv4={}, IPv6={})",
                options.map_capacity,
                next_v4.len(),
                next_v6.len()
            )));
        }

        // Populate the inactive bank completely before the single CONFIG map
        // write makes it visible to BPF. A failed refresh therefore cannot
        // expose a partial rule-set snapshot to live traffic.
        let target = 1usize.wrapping_sub(self.active_bypass_bank);
        let v4_name = bypass_map_name(false, target);
        let v6_name = bypass_map_name(true, target);
        replace_lpm_v4(&mut self.ebpf, v4_name, &mut self.bank_v4[target], &next_v4)?;
        replace_lpm_v6(&mut self.ebpf, v6_name, &mut self.bank_v6[target], &next_v6)?;
        set_bypass_bank(&mut self.ebpf, target as u32)?;
        self.active_bypass_bank = target;
        Ok(())
    }

    pub fn stats(&self) -> Result<EbpfStats, EbpfInboundError> {
        let map = self.ebpf.map("STATS").ok_or_else(|| missing_map("STATS"))?;
        let stats: PerCpuArray<_, u64> = map.try_into().map_err(map_error)?;
        let read = |index: u32| -> Result<u64, EbpfInboundError> {
            Ok(stats
                .get(&index, 0)
                .map_err(map_error)?
                .iter()
                .copied()
                .sum())
        };
        Ok(EbpfStats {
            selected: read(0)?,
            bypass_self: read(1)?,
            bypass_uid: read(2)?,
            bypass_destination: read(3)?,
            mark_failed: read(4)?,
            lookup_assigned: read(5)?,
            lookup_failed: read(6)?,
            bypass_ingress: read(7)?,
            shared_selected: read(8)?,
            shared_bypass_source: read(9)?,
            shared_bypass_destination: read(10)?,
            shared_unsupported: read(11)?,
            shared_lookup_assigned: read(12)?,
            shared_lookup_failed: read(13)?,
        })
    }
}

impl SharedInterfaceMatcher {
    fn compile(shared: &EbpfSharedNetworkOptions) -> Result<Self, EbpfInboundError> {
        Ok(Self {
            include: compile_globs("include_interface", &shared.include_interface)?,
            exclude: compile_globs("exclude_interface", &shared.exclude_interface)?,
        })
    }

    fn matches(&self, name: &str) -> bool {
        self.include.is_match(name) && !self.exclude.is_match(name)
    }
}

fn compile_globs(field: &str, patterns: &[String]) -> Result<GlobSet, EbpfInboundError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(|error| {
            EbpfInboundError::Configuration(format!(
                "shared_network.{field} contains invalid glob {pattern}: {error}"
            ))
        })?);
    }
    builder.build().map_err(|error| {
        EbpfInboundError::Configuration(format!("compile shared_network.{field}: {error}"))
    })
}

fn discover_shared_interfaces(
    matcher: &SharedInterfaceMatcher,
) -> Result<BTreeMap<String, u32>, EbpfInboundError> {
    let entries = fs::read_dir("/sys/class/net").map_err(|error| {
        EbpfInboundError::Aya(format!(
            "enumerate network interfaces from /sys/class/net: {error}"
        ))
    })?;
    let mut interfaces = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            EbpfInboundError::Aya(format!("read network interface entry: {error}"))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !matcher.matches(name) {
            continue;
        }
        let ifindex = if_nametoindex(name).map_err(|error| {
            EbpfInboundError::Aya(format!("resolve interface index for {name}: {error}"))
        })?;
        interfaces.insert(name.to_owned(), ifindex);
    }
    Ok(interfaces)
}

fn parse_ranges(values: &[String]) -> Result<Vec<UidRange>, EbpfInboundError> {
    values
        .iter()
        .map(|value| {
            value
                .split_once(':')
                .and_then(|(start, end)| {
                    Some(UidRange {
                        start: start.parse().ok()?,
                        end: end.parse().ok()?,
                    })
                })
                .filter(|range| range.start <= range.end)
                .ok_or_else(|| {
                    EbpfInboundError::Configuration(format!("invalid UID range: {value}"))
                })
        })
        .collect()
}

fn populate_uid_hash(
    ebpf: &mut Ebpf,
    name: &'static str,
    values: &[u32],
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: HashMap<_, u32, u8> = map.try_into().map_err(map_error)?;
    for value in values {
        map.insert(*value, 1, 0).map_err(map_error)?;
    }
    Ok(())
}

fn populate_uid_ranges(
    ebpf: &mut Ebpf,
    name: &'static str,
    values: &[UidRange],
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: Array<_, UidRange> = map.try_into().map_err(map_error)?;
    for (index, value) in values.iter().enumerate() {
        map.set(index as u32, *value, 0).map_err(map_error)?;
    }
    Ok(())
}

fn populate_shared_source_maps(
    ebpf: &mut Ebpf,
    shared: &EbpfSharedNetworkOptions,
) -> Result<(), EbpfInboundError> {
    let (include_v4, include_v6) = parse_prefix_sets(&shared.include_source_address)?;
    let (exclude_v4, exclude_v6) = parse_prefix_sets(&shared.exclude_source_address)?;
    populate_lpm_v4(ebpf, "SHARED_SOURCE_V4", &include_v4)?;
    populate_lpm_v6(ebpf, "SHARED_SOURCE_V6", &include_v6)?;
    populate_lpm_v4(ebpf, "SHARED_EXCLUDE_SOURCE_V4", &exclude_v4)?;
    populate_lpm_v6(ebpf, "SHARED_EXCLUDE_SOURCE_V6", &exclude_v6)
}

fn parse_prefix_sets(values: &[String]) -> Result<PrefixSets, EbpfInboundError> {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for value in values {
        let prefix = value.parse::<ipnet::IpNet>().map_err(|_| {
            EbpfInboundError::Configuration(format!("invalid shared-network CIDR: {value}"))
        })?;
        push_prefix(prefix, &mut v4, &mut v6);
    }
    Ok((v4, v6))
}

fn populate_lpm_v4(
    ebpf: &mut Ebpf,
    name: &'static str,
    values: &V4PrefixSet,
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: LpmTrie<_, [u8; 4], u8> = map.try_into().map_err(map_error)?;
    for (prefix, address) in values.iter().copied() {
        map.insert(&Key::new(u32::from(prefix), address), 1, 0)
            .map_err(map_error)?;
    }
    Ok(())
}

fn populate_lpm_v6(
    ebpf: &mut Ebpf,
    name: &'static str,
    values: &V6PrefixSet,
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: LpmTrie<_, [u8; 16], u8> = map.try_into().map_err(map_error)?;
    for (prefix, address) in values.iter().copied() {
        map.insert(&Key::new(u32::from(prefix), address), 1, 0)
            .map_err(map_error)?;
    }
    Ok(())
}

fn set_shared_interface(
    ebpf: &mut Ebpf,
    ifindex: u32,
    enabled: bool,
) -> Result<(), EbpfInboundError> {
    let map = ebpf
        .map_mut("SHARED_INTERFACES")
        .ok_or_else(|| missing_map("SHARED_INTERFACES"))?;
    let mut map: HashMap<_, u32, u8> = map.try_into().map_err(map_error)?;
    if enabled {
        map.insert(ifindex, 1, 0).map_err(map_error)
    } else {
        match map.remove(&ifindex) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

fn populate_socket_maps(ebpf: &mut Ebpf, sockets: &FamilySockets) -> Result<(), EbpfInboundError> {
    {
        let map = ebpf
            .map_mut("TCP_SOCKETS")
            .ok_or_else(|| missing_map("TCP_SOCKETS"))?;
        let mut map: SockMap<_> = map.try_into().map_err(map_error)?;
        if let Some(socket) = &sockets.tcp4 {
            map.set(0, socket, 0).map_err(map_error)?;
        }
        if let Some(socket) = &sockets.tcp6 {
            map.set(1, socket, 0).map_err(map_error)?;
        }
    }
    {
        let map = ebpf
            .map_mut("UDP_SOCKETS")
            .ok_or_else(|| missing_map("UDP_SOCKETS"))?;
        let mut map: SockMap<_> = map.try_into().map_err(map_error)?;
        if let Some(socket) = &sockets.udp4 {
            map.set(0, socket, 0).map_err(map_error)?;
        }
        if let Some(socket) = &sockets.udp6 {
            map.set(1, socket, 0).map_err(map_error)?;
        }
    }
    Ok(())
}

fn desired_prefixes(
    options: &EbpfInboundOptions,
    snapshot: &BypassPrefixSnapshot,
) -> Result<PrefixSets, EbpfInboundError> {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for value in [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ] {
        push_prefix(value.parse().expect("static bypass CIDR"), &mut v4, &mut v6);
    }
    for value in &options.redirect_address {
        push_prefix(
            value.parse().map_err(|_| {
                EbpfInboundError::Configuration(format!("invalid redirect_address: {value}"))
            })?,
            &mut v4,
            &mut v6,
        );
    }
    for prefix in snapshot.ipv4.iter().copied() {
        push_prefix(prefix.into(), &mut v4, &mut v6);
    }
    for prefix in snapshot.ipv6.iter().copied() {
        push_prefix(prefix.into(), &mut v4, &mut v6);
    }
    if let Ok(addresses) = getifaddrs() {
        for interface in addresses {
            let Some(address) = interface.address else {
                continue;
            };
            if let Some(address) = address.as_sockaddr_in() {
                let ip = std::net::SocketAddrV4::from(*address).ip().to_owned();
                push_prefix(
                    ipnet::Ipv4Net::new(ip, 32)
                        .expect("valid host prefix")
                        .into(),
                    &mut v4,
                    &mut v6,
                );
            } else if let Some(address) = address.as_sockaddr_in6() {
                let ip = std::net::SocketAddrV6::from(*address).ip().to_owned();
                push_prefix(
                    ipnet::Ipv6Net::new(ip, 128)
                        .expect("valid host prefix")
                        .into(),
                    &mut v4,
                    &mut v6,
                );
            }
        }
    }
    Ok((v4, v6))
}

fn push_prefix(prefix: ipnet::IpNet, v4: &mut V4PrefixSet, v6: &mut V6PrefixSet) {
    match prefix {
        ipnet::IpNet::V4(prefix) => {
            v4.insert((prefix.prefix_len(), prefix.network().octets()));
        }
        ipnet::IpNet::V6(prefix) => {
            v6.insert((prefix.prefix_len(), prefix.network().octets()));
        }
    }
}

fn replace_lpm_v4(
    ebpf: &mut Ebpf,
    name: &'static str,
    current: &mut V4PrefixSet,
    next: &V4PrefixSet,
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: LpmTrie<_, [u8; 4], u8> = map.try_into().map_err(map_error)?;
    while let Some((prefix, address)) = current.first().copied() {
        map.remove(&Key::new(u32::from(prefix), address))
            .map_err(map_error)?;
        current.remove(&(prefix, address));
    }
    for (prefix, address) in next.iter().copied() {
        map.insert(&Key::new(u32::from(prefix), address), 1, 0)
            .map_err(map_error)?;
        current.insert((prefix, address));
    }
    Ok(())
}

fn replace_lpm_v6(
    ebpf: &mut Ebpf,
    name: &'static str,
    current: &mut V6PrefixSet,
    next: &V6PrefixSet,
) -> Result<(), EbpfInboundError> {
    let map = ebpf.map_mut(name).ok_or_else(|| missing_map(name))?;
    let mut map: LpmTrie<_, [u8; 16], u8> = map.try_into().map_err(map_error)?;
    while let Some((prefix, address)) = current.first().copied() {
        map.remove(&Key::new(u32::from(prefix), address))
            .map_err(map_error)?;
        current.remove(&(prefix, address));
    }
    for (prefix, address) in next.iter().copied() {
        map.insert(&Key::new(u32::from(prefix), address), 1, 0)
            .map_err(map_error)?;
        current.insert((prefix, address));
    }
    Ok(())
}

fn bypass_map_name(ipv6: bool, bank: usize) -> &'static str {
    match (ipv6, bank) {
        (false, 0) => "BYPASS_V4",
        (false, _) => "BYPASS_V4_ALT",
        (true, 0) => "BYPASS_V6",
        (true, _) => "BYPASS_V6_ALT",
    }
}

fn set_bypass_bank(ebpf: &mut Ebpf, bank: u32) -> Result<(), EbpfInboundError> {
    let map = ebpf
        .map_mut("CONFIG")
        .ok_or_else(|| missing_map("CONFIG"))?;
    let mut map: Array<_, EbpfConfig> = map.try_into().map_err(map_error)?;
    let mut config = map.get(&0, 0).map_err(map_error)?;
    config.bypass_bank = bank;
    map.set(0, config, 0).map_err(map_error)
}

fn missing_map(name: &'static str) -> EbpfInboundError {
    EbpfInboundError::Aya(format!("eBPF object is missing map {name}"))
}

fn missing_program(name: &'static str) -> EbpfInboundError {
    EbpfInboundError::Aya(format!("eBPF object is missing program {name}"))
}

fn map_error(error: impl std::fmt::Display) -> EbpfInboundError {
    EbpfInboundError::Aya(format!("eBPF map operation failed: {error}"))
}

fn program_error(error: impl std::fmt::Display) -> EbpfInboundError {
    EbpfInboundError::Aya(format!("eBPF program operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_interface_matcher_honors_exclusions() {
        let shared = EbpfSharedNetworkOptions {
            enabled: true,
            include_interface: vec!["ap*".into(), "rndis*".into(), "br*".into()],
            exclude_interface: vec!["br-docker*".into()],
            ..EbpfSharedNetworkOptions::default()
        };
        let matcher = SharedInterfaceMatcher::compile(&shared).unwrap();
        assert!(matcher.matches("ap0"));
        assert!(matcher.matches("rndis0"));
        assert!(matcher.matches("br-hotspot"));
        assert!(!matcher.matches("br-docker0"));
        assert!(!matcher.matches("rmnet_data0"));
    }

    #[test]
    fn shared_source_prefixes_preserve_both_families() {
        let (v4, v6) = parse_prefix_sets(&[
            "192.168.43.0/24".into(),
            "fd00:43::/64".into(),
            "192.168.43.0/24".into(),
        ])
        .unwrap();
        assert_eq!(v4.len(), 1);
        assert_eq!(v6.len(), 1);
    }
}
