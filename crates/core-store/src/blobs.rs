//! 持久化的值结构体 —— 所有 blob 都使用 serde JSON 序列化。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeStatsBlob {
    pub samples: u32,
    pub success_ewma: f64,
    pub p50_latency_ms: f64,
    #[serde(default)]
    pub p90_latency_ms: f64,
    pub jitter_ms: f64,
    pub timeout_rate: f64,
    #[serde(default)]
    pub baseline_latency_ms: f64,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub throughput_ewma_bps: f64,
    #[serde(default)]
    pub throughput_peak_bps: f64,
    #[serde(default)]
    pub throughput_updated_secs: Option<u64>,
    /// 最近一次失败相对于 UNIX_EPOCH 的秒数；None 表示无。
    pub last_failure_secs: Option<u64>,
    pub last_error: Option<String>,
    pub last_used_secs: Option<u64>,
    /// URLTest 历史 —— (epoch_ms, delay_ms)，最多 8 条；
    /// 写法保留向后兼容（旧库不存在该字段时 serde::default 给空 Vec）。
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub time_ms: u64,
    pub delay_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBestBlob {
    pub node: String,
    pub set_at_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeBlob {
    pub until_secs: u64,
    pub reason: String,
}

/// 策略组 pin 的持久化状态。
///
/// `generation` 是单调世代号。一次手动组测速开始时会记录该值，只有测速
/// 完成时世代仍相同，才允许自动策略解除 pin。这可防止慢测速覆盖用户刚做的
/// 新选择。
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GroupPinBlob {
    pub node: String,
    #[serde(default)]
    pub strategy: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedMetaBlob {
    pub last_success_secs: Option<u64>,
    pub last_attempt_secs: Option<u64>,
    pub last_node_count: u32,
    pub last_bytes: u64,
    pub last_etag: Option<String>,
    pub last_error: Option<String>,
}

/// DNS 缓存持久化条目。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsCacheBlob {
    /// IP 列表（原始字符串，便于 v4/v6 同表）
    pub ips: Vec<String>,
    /// 过期 epoch_secs；启动时若 < now 则丢弃
    pub expire_secs: u64,
    pub origin: String,
}

/// 一项持久化流量汇总。
///
/// 字节数使用十进制字符串而不是固定宽度整数，因此累计值不会受 u64 或
/// u128 上限约束。旧版本若缺少时间字段，仍可用默认值读取。
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TrafficTotalBlob {
    pub dimension: String,
    pub label: String,
    pub upload: String,
    pub download: String,
    pub connections: u64,
    #[serde(default)]
    pub first_seen_secs: u64,
    #[serde(default)]
    pub last_seen_secs: u64,
}
