//! core-feeds —— 订阅源实际拉取与解析。
//!
//! §5.3 feeds：负责把远程订阅链接转换为可用的 `ParsedNode` 列表。
//! 设计要点：
//! * 格式：WutherCore 原生 YAML/JSON、Mihomo YAML、Base64 包装的结构化
//!   文档/URI、纯文本 URI 与 SIP008；解码后会再次自动嗅探。
//! * 原生节点：复用 `core-config` 的强类型 NodeSpec，同时接受紧凑 `type`
//!   节点；Young 等自有协议不依赖 Mihomo 注册表。
//! * 抓取：`core-fetch` HTTP/HTTPS、`file://`、本地路径和 inline payload；
//!   支持请求头、大小上限与 X25519/PQ age 解密。
//! * 过滤：Mihomo 扩展正则 + keep.name_has / drop.name_has。
//! * 重命名：rename.add_prefix + rename.remove。
//! * 缓存：成功一次立刻写入磁盘，失败时回退到磁盘缓存，永远不让一次抓取
//!   失败导致无可用节点。
//! * 周期刷新：每个 feed 独立按 `every` 调度；冷启动立刻拉一次。
//! * 节点热注入：通过 [`FeedSink`] trait 把新节点列表推给 Runtime。

#![forbid(unsafe_code)]

pub mod age;
pub mod cache;
#[cfg(feature = "fetch")]
pub mod fetcher;
#[cfg(feature = "fetch")]
pub mod manager;
pub mod parser;
pub mod userinfo;

pub use cache::{FeedDiskCache, FeedMeta, url_digest};
#[cfg(feature = "fetch")]
pub use fetcher::{FetchError, FetchResult, fetch_feed, fetch_feed_for_provider};
#[cfg(feature = "fetch")]
pub use manager::{FeedManager, FeedSink, FeedStatus, FeedUpdate};
pub use parser::{
    FormatHint, ParseError, apply_filter_rename, parse_feed_payload, parse_feed_payload_checked,
};
pub use userinfo::SubscriptionUserinfo;
