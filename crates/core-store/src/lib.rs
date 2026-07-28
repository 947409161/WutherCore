//! core-store —— 持久化层。
//!
//! 选型：[`turso`] 原生 Rust 嵌入式 SQL 数据库。
//! * 全异步 I/O，不在 Tokio 工作线程执行同步数据库操作；
//! * 每项操作使用独立连接，支持多线程并发读取；
//! * 多进程 WAL 允许运行中的核心和 CLI 同时访问同一数据库；
//! * 严格类型表、预编译语句、覆盖索引和批量事务；
//! * 单一主文件：`data/state/wuthercore.db`。
//!
//! 支持的 schema（见 [`schema`]）：
//!
//! | 表 | 键 | 值（JSON） | 用途 |
//! |---|---|---|---|
//! | `smart_node_stats` | `node_name` | `NodeStatsBlob` | Smart 节点评分历史 |
//! | `smart_domain_best` | `group\|etld` | `DomainBestBlob` | 域名→最佳节点缓存 |
//! | `smart_negative` | `node_name` | `NegativeBlob` | 失败节点冷却 |
//! | `smart_pin` | `group\|host` | `node_name`（字符串） | 用户固定 |
//! | `group_pin` | `group` | `GroupPinBlob` | 全策略组持久化固定选择 |
//! | `group_manual` | `group` | `node_name` | 旧版兼容读取 |
//! | `feed_meta` | `feed_name` | `FeedMetaBlob` | 订阅最近抓取元数据 |
//! | `traffic_totals` | `dimension + label` | `TrafficTotalBlob` | 任意精度持久流量汇总 |
//! | `kv_meta` | 任意 key | bytes | 通用元数据/版本号 |
//!
//! 写入策略：[`Store::write_batch`] 用异步单事务合并多个 put；
//! [`AsyncWriter`] 提供后台 mpsc + 周期 flush（默认 200ms 或 256 项触发）。

#![forbid(unsafe_code)]

pub mod async_writer;
pub mod blobs;
pub mod schema;
pub mod store;

pub use async_writer::{AsyncWriter, WriteOp};
pub use blobs::{
    DnsCacheBlob, DomainBestBlob, FeedMetaBlob, GroupPinBlob, HistoryEntry, NegativeBlob,
    NodeStatsBlob, TrafficTotalBlob,
};
pub use store::{MultiprocessWal, Store, StoreError, StoreOptions};
