#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_NO_PREALLOC,
    helpers::bpf_setsockopt,
    macros::{cgroup_sock_addr, map, sk_lookup},
    maps::{Array, HashMap, LpmTrie, PerCpuArray, SockMap},
    programs::{SkLookupContext, SockAddrContext},
};

const SK_PASS: u32 = 1;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;
const MAX_UID_RANGES: u32 = 256;

const FLAG_INCLUDE_UID: u32 = 1 << 0;
const FLAG_IPV4: u32 = 1 << 1;
const FLAG_IPV6: u32 = 1 << 2;
const FLAG_HIJACK_DNS: u32 = 1 << 3;

const STAT_SELECTED: u32 = 0;
const STAT_BYPASS_SELF: u32 = 1;
const STAT_BYPASS_UID: u32 = 2;
const STAT_BYPASS_DESTINATION: u32 = 3;
const STAT_MARK_FAILED: u32 = 4;
const STAT_LOOKUP_ASSIGNED: u32 = 5;
const STAT_LOOKUP_FAILED: u32 = 6;
const STAT_BYPASS_INGRESS: u32 = 7;
const STAT_COUNT: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
struct UidRange {
    start: u32,
    end: u32,
}

#[map]
static CONFIG: Array<EbpfConfig> = Array::with_max_entries(1, 0);

#[map]
static INCLUDE_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static EXCLUDE_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static INCLUDE_UID_RANGES: Array<UidRange> = Array::with_max_entries(MAX_UID_RANGES, 0);

#[map]
static EXCLUDE_UID_RANGES: Array<UidRange> = Array::with_max_entries(MAX_UID_RANGES, 0);

#[map]
static BYPASS_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V4_ALT: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V6_ALT: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static TCP_SOCKETS: SockMap = SockMap::with_max_entries(2, 0);

#[map]
static UDP_SOCKETS: SockMap = SockMap::with_max_entries(2, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_COUNT, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET6)
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET6)
}

fn select_socket(ctx: SockAddrContext, family: u32) -> i32 {
    let Some(config) = CONFIG.get(0) else {
        return 1;
    };
    if (family == AF_INET && config.flags & FLAG_IPV4 == 0)
        || (family == AF_INET6 && config.flags & FLAG_IPV6 == 0)
    {
        return 1;
    }
    if ctx.tgid() == config.self_tgid {
        increment(STAT_BYPASS_SELF);
        return 1;
    }
    let uid = ctx.uid();
    if !uid_allowed(uid, config) {
        increment(STAT_BYPASS_UID);
        return 1;
    }
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && destination_port(&ctx) == 53;
    if !hijack_dns && destination_bypassed(&ctx, family, config.bypass_bank) {
        increment(STAT_BYPASS_DESTINATION);
        return 1;
    }

    let mut mark = config.mark;
    let result = unsafe {
        bpf_setsockopt(
            ctx.as_ptr(),
            SOL_SOCKET,
            SO_MARK,
            core::ptr::from_mut(&mut mark).cast(),
            core::mem::size_of::<u32>() as i32,
        )
    };
    if result != 0 {
        increment(STAT_MARK_FAILED);
        return 1;
    }
    increment(STAT_SELECTED);
    1
}

fn uid_allowed(uid: u32, config: &EbpfConfig) -> bool {
    if exact_uid(&EXCLUDE_UIDS, uid)
        || range_contains(&EXCLUDE_UID_RANGES, config.exclude_range_count, uid)
    {
        return false;
    }
    if config.flags & FLAG_INCLUDE_UID == 0 {
        return true;
    }
    exact_uid(&INCLUDE_UIDS, uid)
        || range_contains(&INCLUDE_UID_RANGES, config.include_range_count, uid)
}

fn exact_uid(map: &HashMap<u32, u8>, uid: u32) -> bool {
    unsafe { map.get(&uid).is_some() }
}

fn range_contains(map: &Array<UidRange>, count: u32, uid: u32) -> bool {
    let mut index = 0;
    while index < count && index < MAX_UID_RANGES {
        if let Some(range) = map.get(index)
            && uid >= range.start
            && uid <= range.end
        {
            return true;
        }
        index += 1;
    }
    false
}

fn destination_bypassed(ctx: &SockAddrContext, family: u32, bank: u32) -> bool {
    if family == AF_INET {
        let address = unsafe { (*ctx.sock_addr).user_ip4.to_ne_bytes() };
        let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
        if bank == 0 {
            BYPASS_V4.get(&key).is_some()
        } else {
            BYPASS_V4_ALT.get(&key).is_some()
        }
    } else {
        let words = unsafe { (*ctx.sock_addr).user_ip6 };
        let key = aya_ebpf::maps::lpm_trie::Key::new(128, ipv6_bytes(words));
        if bank == 0 {
            BYPASS_V6.get(&key).is_some()
        } else {
            BYPASS_V6_ALT.get(&key).is_some()
        }
    }
}

#[sk_lookup]
pub fn assign_proxy_socket(ctx: SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let Some(config) = CONFIG.get(0) else {
        return SK_PASS;
    };
    if lookup.ingress_ifindex != config.loopback_ifindex {
        increment(STAT_BYPASS_INGRESS);
        return SK_PASS;
    }
    let bank = config.bypass_bank;
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && lookup.local_port == 53;
    let result = match (lookup.family, lookup.protocol) {
        (AF_INET, IPPROTO_TCP) if hijack_dns || !lookup_v4_bypassed(lookup.local_ip4, bank) => {
            TCP_SOCKETS.redirect_sk_lookup(&ctx, 0, 0)
        }
        (AF_INET6, IPPROTO_TCP) if hijack_dns || !lookup_v6_bypassed(lookup.local_ip6, bank) => {
            TCP_SOCKETS.redirect_sk_lookup(&ctx, 1, 0)
        }
        (AF_INET, IPPROTO_UDP) if hijack_dns || !lookup_v4_bypassed(lookup.local_ip4, bank) => {
            UDP_SOCKETS.redirect_sk_lookup(&ctx, 0, 0)
        }
        (AF_INET6, IPPROTO_UDP) if hijack_dns || !lookup_v6_bypassed(lookup.local_ip6, bank) => {
            UDP_SOCKETS.redirect_sk_lookup(&ctx, 1, 0)
        }
        _ => return SK_PASS,
    };
    match result {
        Ok(()) => increment(STAT_LOOKUP_ASSIGNED),
        Err(_) => increment(STAT_LOOKUP_FAILED),
    }
    SK_PASS
}

fn destination_port(ctx: &SockAddrContext) -> u16 {
    let port = unsafe { (*ctx.sock_addr).user_port } as u16;
    u16::from_be(port)
}

fn lookup_v4_bypassed(address: u32, bank: u32) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(32, address.to_ne_bytes());
    if bank == 0 {
        BYPASS_V4.get(&key).is_some()
    } else {
        BYPASS_V4_ALT.get(&key).is_some()
    }
}

fn lookup_v6_bypassed(words: [u32; 4], bank: u32) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(128, ipv6_bytes(words));
    if bank == 0 {
        BYPASS_V6.get(&key).is_some()
    } else {
        BYPASS_V6_ALT.get(&key).is_some()
    }
}

fn ipv6_bytes(words: [u32; 4]) -> [u8; 16] {
    let mut address = [0u8; 16];
    let mut index = 0;
    while index < 4 {
        let bytes = words[index].to_ne_bytes();
        let offset = index * 4;
        address[offset] = bytes[0];
        address[offset + 1] = bytes[1];
        address[offset + 2] = bytes[2];
        address[offset + 3] = bytes[3];
        index += 1;
    }
    address
}

fn increment(index: u32) {
    if let Some(value) = STATS.get_ptr_mut(index) {
        unsafe {
            *value = (*value).wrapping_add(1);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
