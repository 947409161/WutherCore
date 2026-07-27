//! 实际拉取订阅 —— HTTP/HTTPS/file/本地路径。
//!
//! HTTP 路径除了把 body 拿回来，还会顺便把响应头里的订阅用量
//! ([`SubscriptionUserinfo`])、`ETag`、`Content-Type` 等元信息一并解析返回。
//!
//! 走 `core_fetch` 而不是 reqwest —— `core_fetch` 内置 hyper + tokio-rustls
//! + `bind_outbound_socket`，四大平台都能让 TCP 真正绕过 TUN（含 Windows，
//!   reqwest 0.12 没暴露 IP_UNICAST_IF 注入点做不到）。

use std::time::Duration;

use core_config::model::FeedDetail;
use thiserror::Error;
use tracing::{debug, warn};

use crate::userinfo::SubscriptionUserinfo;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP 请求失败: {0}")]
    Http(String),
    #[error("非 2xx 状态: {0}")]
    Status(u16),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("订阅正文超过大小上限 {limit} 字节")]
    BodyTooLarge { limit: usize },
}

impl From<core_fetch::FetchError> for FetchError {
    fn from(e: core_fetch::FetchError) -> Self {
        match e {
            core_fetch::FetchError::Status(code) => Self::Status(code),
            core_fetch::FetchError::BadUrl(s) => Self::BadUrl(s),
            core_fetch::FetchError::Io(e) => Self::Io(e),
            core_fetch::FetchError::BodyTooLarge { limit } => Self::BodyTooLarge { limit },
            other => Self::Http(other.to_string()),
        }
    }
}

/// 默认 UA —— 模拟主流客户端，避免被机场屏蔽。
pub const DEFAULT_UA: &str = concat!(
    "WutherCore/",
    env!("CARGO_PKG_VERSION"),
    " (clash-meta-compatible)"
);
const GLOBAL_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// 一次抓取的完整结果 —— body + 关键响应头。
#[derive(Debug, Clone, Default)]
pub struct FetchResult {
    /// 响应原文。
    pub bytes: Vec<u8>,
    /// 解析出的订阅用量；本地路径 / 缺头时为 None。
    pub userinfo: Option<SubscriptionUserinfo>,
    /// `ETag` 响应头（保留以便后续条件 GET 实现）。
    pub etag: Option<String>,
    /// `Content-Type` 响应头（解析器格式嗅探可参考）。
    pub content_type: Option<String>,
}

impl FetchResult {
    /// 仅含 body —— 本地路径用。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            userinfo: None,
            etag: None,
            content_type: None,
        }
    }
}

/// 兼容旧 API —— core-runtime 之前会注入 reqwest::Client；现在所有 HTTP 经
/// `core_fetch`（自身已用 net_monitor 同步的 outbound 全局态），不再需要外部
/// 注入。保留空 stub 避免老调用点编译失败，未来可删。
#[deprecated(note = "core-feeds 改走 core_fetch；此函数保留只为编译兼容，无效果")]
pub fn set_shared_http_client<T>(_client: T) {}

/// 抓取一次订阅原文 + 元信息。
pub async fn fetch_feed(url: &str, timeout: Duration) -> Result<FetchResult, FetchError> {
    fetch_feed_inner(
        url,
        timeout,
        DEFAULT_UA.to_string(),
        Vec::new(),
        GLOBAL_MAX_BODY_BYTES,
    )
    .await
}

/// Fetch using Mihomo provider-owned request headers and `size-limit`.
pub async fn fetch_feed_for_provider(
    detail: &FeedDetail,
    timeout: Duration,
) -> Result<FetchResult, FetchError> {
    let max_body_bytes = match detail.size_limit {
        None | Some(0) => GLOBAL_MAX_BODY_BYTES,
        Some(limit) => usize::try_from(limit)
            .unwrap_or(usize::MAX)
            .min(GLOBAL_MAX_BODY_BYTES),
    };
    if !detail.payload.is_empty() {
        let mut root = serde_yaml::Mapping::new();
        root.insert(
            serde_yaml::Value::String("nodes".into()),
            serde_yaml::Value::Sequence(detail.payload.clone()),
        );
        let bytes = serde_yaml::to_string(&serde_yaml::Value::Mapping(root))
            .map_err(|error| FetchError::Http(format!("inline provider 序列化失败: {error}")))?
            .into_bytes();
        ensure_size(bytes.len(), max_body_bytes)?;
        return Ok(FetchResult::from_bytes(bytes));
    }
    let mut user_agent = DEFAULT_UA.to_string();
    let mut headers = Vec::new();
    for (name, values) in &detail.headers {
        for value in values.values() {
            if name.eq_ignore_ascii_case("user-agent") {
                user_agent.clone_from(value);
            } else {
                headers.push((name.clone(), value.clone()));
            }
        }
    }
    fetch_feed_inner(&detail.url, timeout, user_agent, headers, max_body_bytes).await
}

async fn fetch_feed_inner(
    url: &str,
    timeout: Duration,
    user_agent: String,
    headers: Vec<(String, String)>,
    max_body_bytes: usize,
) -> Result<FetchResult, FetchError> {
    if url.starts_with("file://") {
        let path = url.trim_start_matches("file://");
        debug!(target: "feeds", path, "fetch from file");
        let bytes = std::fs::read(path)?;
        ensure_size(bytes.len(), max_body_bytes)?;
        return Ok(FetchResult::from_bytes(bytes));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        // 本地路径
        if std::path::Path::new(url).exists() {
            let bytes = std::fs::read(url)?;
            ensure_size(bytes.len(), max_body_bytes)?;
            return Ok(FetchResult::from_bytes(bytes));
        }
        return Err(FetchError::BadUrl(url.into()));
    }

    debug!(target: "feeds", url, "fetch http");
    let opts = core_fetch::FetchOptions {
        user_agent,
        timeout,
        connect_timeout: Duration::from_secs(10),
        headers,
        max_body_bytes,
        ..Default::default()
    };
    let resp = match core_fetch::fetch(url, &opts).await {
        Ok(r) => r,
        Err(core_fetch::FetchError::Status(code)) => {
            warn!(target: "feeds", url, code, "feed http error");
            return Err(FetchError::Status(code));
        }
        Err(e) => return Err(FetchError::from(e)),
    };

    let userinfo = SubscriptionUserinfo::from_headers(
        resp.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let etag = resp.headers.get("etag").cloned();
    let content_type = resp.headers.get("content-type").cloned();

    if let Some(ui) = &userinfo {
        debug!(
            target: "feeds",
            url,
            upload = ui.upload,
            download = ui.download,
            total = ui.total,
            expire = ui.expire,
            "subscription userinfo extracted"
        );
    }

    Ok(FetchResult {
        bytes: resp.bytes,
        userinfo,
        etag,
        content_type,
    })
}

fn ensure_size(actual: usize, limit: usize) -> Result<(), FetchError> {
    if actual > limit {
        Err(FetchError::BodyTooLarge { limit })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inline_provider_does_not_require_a_url() {
        let detail: FeedDetail = serde_yaml::from_str(
            r#"
payload:
  - {name: DIRECT, type: direct}
"#,
        )
        .unwrap();
        let result = fetch_feed_for_provider(&detail, Duration::from_secs(1))
            .await
            .unwrap();
        let text = String::from_utf8(result.bytes).unwrap();
        assert!(text.contains("nodes:"));
        assert!(text.contains("DIRECT"));
    }

    #[tokio::test]
    async fn size_limit_applies_to_inline_provider() {
        let detail: FeedDetail = serde_yaml::from_str(
            r#"
size-limit: 8
payload:
  - {name: DIRECT, type: direct}
"#,
        )
        .unwrap();
        let error = fetch_feed_for_provider(&detail, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::BodyTooLarge { limit: 8 }));
    }
}
