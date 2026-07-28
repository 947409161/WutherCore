//! Turso 持久化命名空间定义。
//!
//! 所有业务数据存放在同一个严格类型的 `kv_entries` 表中。`namespace`
//! 对应原来的逻辑表名，`key` 是业务键，`value` 保存 JSON 或原始 UTF-8。
//! 统一表让批量写只需复用两条预编译 SQL，同时保留原有模块边界。

/// 一个持久化命名空间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Table(&'static str);

impl Table {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn name(self) -> &'static str {
        self.0
    }
}

pub const SMART_NODE_STATS: Table = Table::new("smart_node_stats");
pub const SMART_DOMAIN_BEST: Table = Table::new("smart_domain_best");
pub const SMART_NEGATIVE: Table = Table::new("smart_negative");
pub const SMART_PIN: Table = Table::new("smart_pin");
/// 策略组的用户固定选择。
///
/// 与旧的 `group_manual` 不同，这里保存完整的 pin 世代、来源和策略类型，
/// 使自动策略的测速解锁可以抵御并发旧请求。旧命名空间只用于启动兼容读取。
pub const GROUP_PIN: Table = Table::new("group_pin");
pub const GROUP_MANUAL: Table = Table::new("group_manual");
pub const FEED_META: Table = Table::new("feed_meta");
pub const DNS_CACHE: Table = Table::new("dns_cache");
pub const TRAFFIC_TOTALS: Table = Table::new("traffic_totals");
pub const KV_META: Table = Table::new("kv_meta");

pub const ALL_TABLES: &[Table] = &[
    SMART_NODE_STATS,
    SMART_DOMAIN_BEST,
    SMART_NEGATIVE,
    SMART_PIN,
    GROUP_PIN,
    GROUP_MANUAL,
    FEED_META,
    DNS_CACHE,
    TRAFFIC_TOTALS,
    KV_META,
];

pub const SCHEMA_VERSION: u32 = 4;
pub const SCHEMA_KEY: &str = "schema_version";
