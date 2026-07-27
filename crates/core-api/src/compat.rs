//! Clash / Mihomo Dashboard 协议兼容层。
//!
//! 路由、字段名和传输形式兼容 Mihomo；身份、能力和值始终来自 WutherCore
//! 的真实运行时，不伪装成 Mihomo，也不为尚未实现的功能返回虚假成功。
//!
//! ```text
//!   GET    /version                         WutherCore 版本 + Clash Meta 兼容标识
//!   GET    /traffic            [WS]         实时 up/down 字节速率
//!   GET    /memory             [WS]         进程 RSS / oslimit
//!   GET    /logs               [WS]         NDJSON 日志流 (level + payload)
//!   GET    /connections        [WS]         连接列表 / 实时
//!   DEL    /connections                     关闭全部
//!   DEL    /connections/:id                 关闭单条 (uuid 或 numeric)
//!   DEL    /connections/smart/:id           关闭并把上游 smart-node 加入冷却
//!   GET    /proxies                         全量 proxy + group
//!   GET    /proxies/:name                   单个 proxy / group
//!   PUT    /proxies/:name                   选择 group 当前节点 ({name: "Tokyo-1"})
//!   PATCH  /proxies/:name                   PUT 别名（zashboard 等）
//!   DELETE /proxies/:name                   清除 group 固定 (mihomo "取消固定")
//!   GET    /proxies/:name/delay             单节点延迟测速（多采样取中位数）
//!   GET    /group                           列出所有 group
//!   GET    /group/:name                     单个 group 详情
//!   GET    /group/:name/delay               组内节点并发测速
//!   GET    /providers/proxies               proxy provider 列表
//!   GET    /providers/proxies/:name         单个 proxy provider
//!   PUT    /providers/proxies/:name         触发刷新
//!   GET    /providers/proxies/:name/healthcheck   立即测速
//!   GET    /providers/rules                 rule provider 列表
//!   GET    /providers/rules/:name           单个 rule provider
//!   PUT    /providers/rules/:name           触发 rule provider 刷新
//!   GET    /rules                           所有路由规则的 mihomo 序列化形式
//!   GET    /configs                         当前 mode / log-level / port 等
//!   PUT    /configs                         完整配置重载（运行时不支持时明确报错）
//!   PATCH  /configs                         热改可变运行时字段
//!   POST   /configs/geo                     并行热更新全部规则集
//!   GET    /dns/query?name=&type=           DoH 风格上游解析
//!   POST   /cache/fakeip/flush              清空 fake-ip 池
//!   POST   /cache/dns/flush                 清空 DNS 缓存
//!   POST   /restart                         优雅重启（占位返回 503）
//!   POST   /upgrade                         内核升级占位
//!   POST   /upgrade/ui                      Dashboard 升级占位
//! ```

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use bytes::Bytes;
use core_runtime::Runtime;
use futures::Stream;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{compat_security::WsConnectionLimiter, native::NativeState};

/// 单 dashboard 实例同时打开的 WS 数量上限 —— 5 个端点（traffic / memory /
/// logs / connections / +1 留用）× 50 个 dashboard = 250。再保守 ×2 = 500。
const WS_CONNECTION_CAP: usize = 512;

/// JSON content-type，避免每次 IntoResponse 时重复构造 HeaderValue。
const JSON_CT: &str = "application/json";

fn json_bytes(bytes: Bytes) -> axum::response::Response {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(JSON_CT),
    );
    (StatusCode::OK, h, bytes).into_response()
}

pub fn router(state: NativeState) -> Router {
    Router::new()
        .route("/version", get(version))
        // ---------- traffic / memory / logs ----------
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(logs))
        // ---------- connections ----------
        .route("/connections", get(connections).delete(connections_close_all))
        .route("/connections/{id}", delete(connections_close_one))
        .route("/connections/smart/{id}", delete(connections_smart_block))
        // ---------- proxies ----------
        .route("/proxies", get(proxies))
        .route(
            "/proxies/{name}",
            get(proxy_one)
                .put(proxy_put)
                .patch(proxy_put)
                .delete(proxy_clear),
        )
        .route("/proxies/{name}/delay", get(proxy_delay))
        // ---------- group (mihomo meta API) ----------
        .route("/group", get(groups_list))
        .route("/group/{name}", get(group_one))
        .route("/group/{name}/delay", get(group_delay))
        // ---------- providers ----------
        .route("/providers/proxies", get(providers_proxies))
        .route(
            "/providers/proxies/{name}",
            get(provider_proxy_one).put(provider_proxy_refresh),
        )
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(provider_proxy_healthcheck),
        )
        .route(
            "/providers/proxies/{provider}/{proxy}",
            get(provider_proxy_node),
        )
        .route(
            "/providers/proxies/{provider}/{proxy}/healthcheck",
            get(provider_proxy_node_healthcheck),
        )
        .route("/providers/rules", get(providers_rules))
        .route(
            "/providers/rules/{name}",
            get(provider_rule_one).put(provider_rule_refresh),
        )
        // ---------- rules ----------
        .route("/rules", get(rules))
        .route("/rules/disable", axum::routing::patch(rules_disable))
        // ---------- configs ----------
        .route("/configs", get(configs).put(configs_reload).patch(configs_put))
        .route("/configs/geo", post(configs_geo))
        // ---------- DNS / cache ----------
        .route("/dns/query", get(dns_query))
        .route("/cache/fakeip/flush", post(cache_fakeip_flush))
        .route("/cache/dns/flush", post(cache_dns_flush))
        // ---------- misc ----------
        .route("/restart", post(restart))
        .route("/upgrade", post(upgrade_kernel))
        .route("/upgrade/geo", post(configs_geo))
        .route("/upgrade/ui", post(upgrade_ui))
        .route(
            "/storage/{key}",
            get(storage_get).put(storage_put).delete(storage_delete),
        )
        .with_state(state)
}

/* ====================== version ====================== */

async fn version() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "meta": true,
    }))
}

/* ====================== traffic / memory / logs ====================== */

async fn traffic(
    State(s): State<NativeState>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> axum::response::Response {
    if let Ok(ws) = ws {
        // 取 hub receiver；连接上限保护避免 fd 耗尽。
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        let rx = s.ws_hubs.traffic.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    let hub = s.ws_hubs.traffic.clone();
    ndjson_interval(Duration::from_secs(1), move || hub.build_now())
}

async fn memory(
    State(s): State<NativeState>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> axum::response::Response {
    if let Ok(ws) = ws {
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        let rx = s.ws_hubs.memory.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    let hub = s.ws_hubs.memory.clone();
    ndjson_interval(Duration::from_secs(1), move || hub.build_now())
}

fn ndjson_interval<F>(interval: Duration, build: F) -> Response
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let build = Arc::new(build);
    let stream = futures::stream::unfold((), move |_| {
        let build = build.clone();
        async move {
            tokio::time::sleep(interval).await;
            let mut line = build();
            line.push('\n');
            Some((Ok::<Bytes, Infallible>(Bytes::from(line)), ()))
        }
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(JSON_CT),
    );
    response
}

/// 把 watch::Receiver<String> 桥接到一条 WebSocket。
/// 共享 hub 减少 N×snapshot/sec 重复成本；`permit` 持续到连接关闭。
async fn watch_to_ws(
    mut sock: WebSocket,
    mut rx: tokio::sync::watch::Receiver<String>,
    _permit: crate::compat_security::WsPermit,
) {
    // 立刻送当前值（如果非空）。
    let initial = rx.borrow_and_update().clone();
    if !initial.is_empty() {
        if sock.send(Message::Text(initial.into())).await.is_err() {
            return;
        }
    }
    // 之后监听变更；watch 永远只保留最新，慢消费者自动跳过中间帧。
    while rx.changed().await.is_ok() {
        let payload = rx.borrow_and_update().clone();
        if sock.send(Message::Text(payload.into())).await.is_err() {
            break;
        }
    }
}

/// 进程级 WS 连接上限 —— 避免 dashboard 滥连耗尽 fd 表。
fn ws_limiter() -> &'static Arc<WsConnectionLimiter> {
    use std::sync::OnceLock;
    static LIMITER: OnceLock<Arc<WsConnectionLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| WsConnectionLimiter::new("clash_ws", WS_CONNECTION_CAP))
}

#[derive(Deserialize)]
struct LogQ {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

async fn logs(
    State(s): State<NativeState>,
    Query(q): Query<LogQ>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> axum::response::Response {
    let level_filter = q.level.unwrap_or_else(|| "info".into()).to_lowercase();
    if !matches!(
        level_filter.as_str(),
        "debug" | "info" | "warning" | "warn" | "error" | "silent"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    }
    let structured = q.format.as_deref() == Some("structured");
    if let Ok(ws) = ws {
        return ws.on_upgrade(move |sock| logs_ws(sock, s, level_filter, structured));
    }
    let stream = log_event_stream(s, level_filter, structured);
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(JSON_CT),
    );
    response
}

async fn logs_ws(mut sock: WebSocket, s: NativeState, level_filter: String, structured: bool) {
    // 原子拿历史 + 订阅，避免 push 在两步之间发生导致同事件被双投递。
    let (history, mut rx) = s.runtime.logs.subscribe_with_history();
    for ev in history {
        if !level_pass(&level_filter, &ev.level) {
            continue;
        }
        let payload = format_log_event(&ev, structured);
        if sock.send(Message::Text(payload.into())).await.is_err() {
            return;
        }
    }
    while let Ok(ev) = rx.recv().await {
        if !level_pass(&level_filter, &ev.level) {
            continue;
        }
        let payload = format_log_event(&ev, structured);
        if sock.send(Message::Text(payload.into())).await.is_err() {
            break;
        }
    }
}

fn log_event_stream(
    s: NativeState,
    level_filter: String,
    structured: bool,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    use tokio_stream::{StreamExt, wrappers::BroadcastStream};

    // 与 WS 路径同因——保持 snapshot/subscribe 原子化避免事件双发。
    let (snapshot, rx) = s.runtime.logs.subscribe_with_history();
    let history_filter = level_filter.clone();
    let history = tokio_stream::iter(snapshot)
        .filter_map(move |ev| log_event_line(&history_filter, ev, structured));
    let live = BroadcastStream::new(rx).filter_map(move |r| match r {
        Ok(ev) => log_event_line(&level_filter, ev, structured),
        _ => None,
    });
    history.chain(live)
}

fn log_event_line(
    filter: &str,
    ev: core_observe::LogEvent,
    structured: bool,
) -> Option<Result<Bytes, Infallible>> {
    if !level_pass(filter, &ev.level) {
        return None;
    }
    Some(Ok(Bytes::from(format!(
        "{}\n",
        format_log_event(&ev, structured)
    ))))
}

fn format_log_event(ev: &core_observe::LogEvent, structured: bool) -> String {
    if !structured {
        return serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
    }
    let level = if ev.level == "warning" {
        "warn"
    } else {
        ev.level.as_str()
    };
    serde_json::to_string(&json!({
        "time": clock_now(),
        "level": level,
        "message": ev.payload,
        "fields": [],
    }))
    .unwrap_or_else(|_| "{}".into())
}

fn level_pass(filter: &str, msg: &str) -> bool {
    let order = |s: &str| match s {
        "debug" => 0,
        "info" => 1,
        "warning" | "warn" => 2,
        "error" => 3,
        "silent" => 99,
        _ => 1,
    };
    order(msg) >= order(filter)
}

/* ====================== connections ====================== */

#[derive(Deserialize)]
struct ConnQ {
    #[serde(default)]
    interval: Option<u64>,
}

async fn connections(
    State(s): State<NativeState>,
    Query(q): Query<ConnQ>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> axum::response::Response {
    if let Ok(ws) = ws {
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        if let Some(interval) = q.interval {
            let interval = Duration::from_millis(interval.max(100));
            return ws.on_upgrade(move |sock| connections_to_ws(sock, s, interval, permit));
        }
        let rx = s.ws_hubs.connections.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    // 非 WS：fetch 缓存（200ms TTL）。多 dashboard 同时打 GET → 一次 build。
    let runtime = s.runtime.clone();
    let bytes = s
        .caches
        .connections
        .fetch_bytes(move || build_connections_value(&runtime));
    json_bytes(bytes)
}

async fn connections_to_ws(
    mut sock: WebSocket,
    s: NativeState,
    interval: Duration,
    _permit: crate::compat_security::WsPermit,
) {
    loop {
        let payload = serde_json::to_string(&build_connections_value(&s.runtime))
            .unwrap_or_else(|_| "{}".into());
        if sock.send(Message::Text(payload.into())).await.is_err() {
            return;
        }
        tokio::time::sleep(interval).await;
    }
}

fn build_connections_value(runtime: &Arc<Runtime>) -> Value {
    let manager = runtime.connections.manager_snapshot();
    let download_total = manager.download_total;
    let upload_total = manager.upload_total;
    let memory = manager.memory;
    let conns: Vec<Value> = manager
        .connections
        .into_iter()
        .map(|conn| {
            json!({
                "id": conn.id,
                "metadata": conn.metadata,
                "upload": conn.upload,
                "download": conn.download,
                "start": iso8601(conn.start),
                "chains": conn.chains,
                "providerChains": conn.provider_chains,
                "rule": conn.rule,
                "rulePayload": conn.rule_payload,
                "maxUploadRate": conn.max_upload_rate,
                "maxDownloadRate": conn.max_download_rate,
            })
        })
        .collect();
    json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": conns,
        "memory": memory,
    })
}

async fn connections_close_all(State(s): State<NativeState>) -> impl IntoResponse {
    s.runtime.connections.close_all();
    s.caches.invalidate_connection_state();
    StatusCode::NO_CONTENT
}

async fn connections_close_one(
    State(s): State<NativeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 同时兼容 numeric id 与 uuid 字符串（mihomo dashboard 传 uuid）。
    if s.runtime.connections.close_by_uuid_or_numeric(&id) {
        s.caches.invalidate_connection_state();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn connections_smart_block(
    State(s): State<NativeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = s.runtime.connections.set_smart_block_and_close(&id);
    StatusCode::NO_CONTENT
}

/* ====================== proxies ====================== */

async fn proxies(State(s): State<NativeState>) -> axum::response::Response {
    let bytes = proxy_map_bytes(&s);
    json_bytes(bytes)
}

async fn proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    // 使用缓存的 Arc<Value> —— 避免每次单条 lookup 重新解析整张 map。
    let value = proxy_map_value(&s);
    if let Some(p) = value
        .get("proxies")
        .and_then(|m| m.as_object())
        .and_then(|m| m.get(&name))
    {
        Json(p.clone()).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "proxy not found"})),
        )
            .into_response()
    }
}

fn proxy_map_bytes(s: &NativeState) -> Bytes {
    // 闭包必须捕获 s by clone (NativeState: Clone 中只持 Arc 字段)，
    // FnOnce 调用所有权 OK。
    let s_for_build = s.clone();
    s.caches
        .proxy_map
        .fetch_bytes(move || json!({"proxies": collect_proxy_map(&s_for_build)}))
}

fn proxy_map_value(s: &NativeState) -> Arc<Value> {
    let s_for_build = s.clone();
    s.caches
        .proxy_map
        .fetch_value(move || json!({"proxies": collect_proxy_map(&s_for_build)}))
}

#[derive(Deserialize)]
struct ProxyPutBody {
    #[serde(default)]
    name: String,
}

async fn proxy_put(
    State(s): State<NativeState>,
    Path(group): Path<String>,
    Json(body): Json<ProxyPutBody>,
) -> impl IntoResponse {
    // Empty name 与 mihomo / sing-box `URLTest.SelectOutbound("")` 等价 ——
    // 清空当前固定选择。
    if body.name.is_empty() {
        let r = clear_pin_inner(&s, &group);
        s.caches.invalidate_proxy_state();
        return r;
    }
    let groups = s.runtime.groups.read();
    let Some(g) = groups.get(&group) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "group not found"})),
        )
            .into_response();
    };
    if !g.members().iter().any(|m| m == &body.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "node not in group"})),
        )
            .into_response();
    }
    drop(groups);
    s.runtime.set_group_manual(&group, &body.name);
    s.caches.invalidate_proxy_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

/// `DELETE /proxies/:name` —— mihomo 的"取消固定"语义。等价于
/// `PUT /proxies/:name {"name": ""}`。
async fn proxy_clear(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let r = clear_pin_inner(&s, &name);
    s.caches.invalidate_proxy_state();
    r
}

fn clear_pin_inner(s: &NativeState, group: &str) -> axum::response::Response {
    let groups = s.runtime.groups.read();
    let Some(g) = groups.get(group) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "group not found"})),
        )
            .into_response();
    };
    let previous = g.current_manual().unwrap_or_default();
    let now = g
        .last_pick()
        .or_else(|| g.members().first().cloned())
        .unwrap_or_default();
    drop(groups);
    s.runtime.set_group_manual(group, "");
    Json(json!({
        "group": group,
        "previous_pin": previous,
        "now": now,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DelayQ {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    expected: Option<String>,
}

async fn proxy_delay(
    State(s): State<NativeState>,
    Path(name): Path<String>,
    Query(q): Query<DelayQ>,
) -> axum::response::Response {
    let Some(url) = q.url.as_deref().filter(|url| !url.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    };
    let expected = match q.expected.as_deref().map(core_runtime::IntRanges::parse) {
        Some(Ok(expected)) => Some(expected),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response();
        }
        None => None,
    };
    let to = q.timeout.map(Duration::from_millis);
    // Mihomo `proxy.URLTest()` 对 group 名递归到当前选中成员；WutherCore 的
    // `test_node` 只查 outbounds 注册表（不含 group），group 名直接 UnknownNode，
    // dashboard 看到全是 timeout。这里仿照 mihomo：name 是 group → 转测它的
    // `now` 成员；group 没选过 → 用 members.first() 兜底；name 不是 group →
    // 走原 test_node 路径。
    let target = match s.runtime.groups.read().get(&name) {
        Some(g) => g
            .to_clash_json()
            .get("now")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .or_else(|| g.members().first().cloned())
            .unwrap_or_else(|| name.clone()),
        None => name.clone(),
    };

    // sing-box `getProxyDelay`: 多采样取中位数稳定结果。第一次 < 50ms 直接采用。
    const MAX_SAMPLES: usize = 3;
    let mut samples: Vec<u32> = Vec::with_capacity(MAX_SAMPLES);
    let mut last_err: Option<String> = None;
    for i in 0..MAX_SAMPLES {
        match s
            .urltest
            .test_node_with(
                &s.runtime,
                &target,
                core_runtime::UrlTestOpts {
                    url: Some(url.to_string()),
                    timeout: to,
                    expected_status: expected.clone(),
                    unified_delay: None,
                },
            )
            .await
        {
            Ok(ms) => {
                samples.push(ms);
                if i == 0 && ms < 50 {
                    break;
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    if samples.is_empty() {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({
                "message": if last_err.as_deref().is_some_and(|e| e.to_ascii_lowercase().contains("timeout")) {
                    "Timeout".to_string()
                } else {
                    last_err.unwrap_or_else(|| "An error occurred in the delay test".into())
                }
            })),
        )
            .into_response();
    }

    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    Json(json!({"delay": median})).into_response()
}

/* ====================== group (mihomo meta API) ====================== */

async fn groups_list(State(s): State<NativeState>) -> Json<Value> {
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    let groups: Vec<Value> = s
        .runtime
        .groups
        .read()
        .iter()
        .map(|(_, g)| group_json(g, urltest, &default_url, &s.runtime))
        .collect();
    Json(json!({"proxies": groups}))
}

async fn group_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    if let Some(g) = s.runtime.groups.read().get(&name) {
        return Json(group_json(g, urltest, &default_url, &s.runtime)).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"message": "group not found"})),
    )
        .into_response()
}

async fn group_delay(
    State(s): State<NativeState>,
    Path(name): Path<String>,
    Query(q): Query<DelayQ>,
) -> axum::response::Response {
    let Some(url) = q.url.clone().filter(|url| !url.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    };
    let expected = match q.expected.as_deref().map(core_runtime::IntRanges::parse) {
        Some(Ok(expected)) => Some(expected),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response();
        }
        None => None,
    };
    let members = match s.runtime.groups.read().get(&name) {
        Some(g) => g.members().to_vec(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"message": "group not found"})),
            )
                .into_response();
        }
    };
    let to = q.timeout.map(Duration::from_millis);
    // sing-box GroupBase.URLTest: 并发上限 4，避免 1000 节点同时拨号互相
    // 抢带宽导致测速值被网络拥塞放大。
    let body = group_delay_bounded(&s, &members, Some(url), to, expected, 4).await;
    Json(Value::Object(body)).into_response()
}

/// `test_many` + concurrency cap。对齐 sing-box `batch.WithConcurrencyNum(4)`。
async fn group_delay_bounded(
    s: &NativeState,
    members: &[String],
    url: Option<String>,
    timeout: Option<Duration>,
    expected_status: Option<core_runtime::IntRanges>,
    max_in_flight: usize,
) -> Map<String, Value> {
    use tokio::sync::Semaphore;

    if members.is_empty() {
        return Map::new();
    }
    let sem = Arc::new(Semaphore::new(max_in_flight.max(1)));
    let mut handles = Vec::with_capacity(members.len());
    for name in members {
        // acquire 在 spawn 前完成；保证全局并发 ≤ max_in_flight。
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed (program shutting down)
        };
        let urltest = s.urltest.clone();
        let runtime = s.runtime.clone();
        let url_for = url.clone();
        let expected_for = expected_status.clone();
        let n = name.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit; // hold until task ends
            let r = urltest
                .test_node_with(
                    &runtime,
                    &n,
                    core_runtime::UrlTestOpts {
                        url: url_for,
                        timeout,
                        expected_status: expected_for,
                        unified_delay: None,
                    },
                )
                .await;
            (n, r)
        }));
    }
    let mut out = Map::new();
    for h in handles {
        if let Ok((name, Ok(ms))) = h.await {
            out.insert(name, Value::from(ms));
        }
    }
    out
}

/* ====================== proxy map ====================== */

fn collect_proxy_map(s: &NativeState) -> Map<String, Value> {
    let runtime: &Arc<Runtime> = &s.runtime;
    let mut proxies = Map::new();

    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;

    let history_for = |node: &str| -> Value {
        // 1) URLTester per-(node, default_url) 历史 —— mihomo 主显示来源
        let mut entries: Vec<core_runtime::HistoryEntry> = urltest.history(node, &default_url);
        if entries.is_empty() {
            // 2) 退回 SmartSelector 历史（含其它 URL 的成功/失败）
            let stats = runtime.smart.ensure_node(node);
            entries = stats
                .history()
                .into_iter()
                .map(|e| core_runtime::HistoryEntry {
                    time_ms: e.time_ms,
                    delay_ms: e.delay_ms as u32,
                })
                .collect();
        }
        let h: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect();
        Value::Array(h)
    };

    // 把 URLTester 已知的 *所有* (node, url) per-URL 历史汇总 —— mihomo
    // `Proxy.extra` 等价；dashboard 显示"对各测速 URL 的延迟"时用。
    fn extra_for(urltest: &Arc<core_runtime::UrlTester>, node: &str) -> Value {
        // UrlTester 没有公开"拿某 node 全部 url 历史"的 API；这里只暴露 default_url
        // 一项作为最小可用集合（足够 dashboard 显示当前测速 URL）。
        let url = urltest.current_config().default_url;
        let entries = urltest.history(node, &url);
        if entries.is_empty() {
            return json!({});
        }
        let alive = urltest.alive_for_url(node, &url);
        let h: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect();
        json!({
            url: {
                "alive": alive,
                "history": h,
            }
        })
    }

    for (name, g) in runtime.groups.read().iter() {
        proxies.insert(name.clone(), group_json(g, urltest, &default_url, runtime));
        let _ = (name, g); // silence unused if future refactor
    }
    for n in &runtime.plan.nodes {
        let history = history_for(&n.name);
        let delay = delay_from_history(&history);
        let alive = urltest.alive_for_url(&n.name, &default_url);
        proxies.insert(
            n.name.clone(),
            node_proxy_json(
                s,
                &n.name,
                n.protocol.as_str(),
                Some(n),
                history,
                extra_for(urltest, &n.name),
                alive,
                delay,
                &runtime.node_provider(&n.name).unwrap_or_default(),
            ),
        );
    }
    proxies.insert(
        "DIRECT".into(),
        json!({
            "type": "Direct", "name": "DIRECT",
            "history": [], "extra": {},
            "udp": true, "xudp": false, "tfo": false, "mptcp": false, "smux": false,
            "uot": false, "interface": "", "routing-mark": 0,
            "provider-name": "", "dialer-proxy": "",
            "alive": true, "delay": 0,
        }),
    );
    proxies.insert(
        "REJECT".into(),
        json!({
            "type": "Reject", "name": "REJECT",
            "history": [], "extra": {},
            "udp": true, "xudp": false, "tfo": false, "mptcp": false, "smux": false,
            "uot": false, "interface": "", "routing-mark": 0,
            "provider-name": "", "dialer-proxy": "",
            "alive": true, "delay": 0,
        }),
    );
    let global_now = runtime.plan.route.r#final.clone();
    let global_history = history_for(&global_now);
    let global_delay = delay_from_history(&global_history);
    let global_alive = if global_now.is_empty() || global_now == "DIRECT" || global_now == "REJECT"
    {
        true
    } else {
        urltest.alive_for_url(&global_now, &default_url)
    };
    let (global_udp, global_smux) = effective_proxy_capabilities(runtime, &global_now);
    proxies.insert(
        "GLOBAL".into(),
        json!({
            "type": "Selector",
            "name": "GLOBAL",
            "now": global_now,
            "all": runtime.group_names(),
            "history": global_history,
            "extra": {},
            "alive": global_alive,
            "delay": global_delay,
            "udp": global_udp,
            "uot": false,
            "xudp": false,
            "tfo": false,
            "mptcp": false,
            "smux": global_smux,
            "hidden": false,
            "icon": "",
            "fixed": "",
            "expectedStatus": "",
            "testUrl": default_url,
            "emptyFallback": false,
        }),
    );
    proxies
}

/// Group → mihomo 兼容 JSON。在 `to_clash_json` 基础上补全：
/// * 顶层 `delay` 数值（dashboard 主要展示用）
/// * `history` / `alive` / `extra` 取自当前 `now` 成员的 urltest 状态
/// * 与 sing-box `proxyInfo` 对齐
fn group_json(
    g: &core_runtime::GroupSelector,
    urltest: &Arc<core_runtime::UrlTester>,
    default_url: &str,
    runtime: &Arc<Runtime>,
) -> Value {
    let mut json = g.to_clash_json();
    let now = json
        .get("now")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty());

    if let Some(obj) = json.as_object_mut() {
        if obj.get("type").and_then(Value::as_str) == Some("LoadBalance") {
            obj.remove("now");
            obj.remove("strategy");
            obj.remove("fixed");
        }
        // 默认填空 history / alive / delay，避免 dashboard 取不到字段
        // 时把 group 渲染为"超时"。
        if !obj.contains_key("history") {
            obj.insert("history".into(), Value::Array(vec![]));
        }
        if !obj.contains_key("delay") {
            obj.insert("delay".into(), Value::from(0u64));
        }
        obj.entry("uot").or_insert(Value::Bool(false));
        obj.entry("xudp").or_insert(Value::Bool(false));
        obj.entry("tfo").or_insert(Value::Bool(false));
        obj.entry("mptcp").or_insert(Value::Bool(false));
        obj.entry("smux").or_insert(Value::Bool(false));
        obj.entry("interface")
            .or_insert(Value::String(String::new()));
        obj.entry("routing-mark").or_insert(Value::from(0));
        obj.entry("provider-name")
            .or_insert(Value::String(String::new()));
        obj.entry("dialer-proxy")
            .or_insert(Value::String(String::new()));
        obj.entry("emptyFallback").or_insert(Value::Bool(false));
        let member_capabilities: Vec<_> = g
            .members()
            .iter()
            .map(|member| effective_proxy_capabilities(runtime, member))
            .collect();
        let group_udp_enabled = obj.get("udp").and_then(Value::as_bool).unwrap_or(false);
        obj.insert(
            "udp".into(),
            Value::Bool(group_udp_enabled && member_capabilities.iter().any(|(udp, _)| *udp)),
        );
        obj.insert(
            "smux".into(),
            Value::Bool(member_capabilities.iter().any(|(_, multiplex)| *multiplex)),
        );
        if let Some(now_node) = now.as_deref() {
            let history = node_history(urltest, runtime, now_node, default_url);
            let alive = urltest.alive_for_url(now_node, default_url);
            let delay = delay_from_history(&history);
            obj.insert("history".into(), history.clone());
            obj.insert("alive".into(), Value::Bool(alive));
            obj.insert("delay".into(), Value::from(delay));
            obj.insert(
                "extra".into(),
                node_extra(urltest, now_node, default_url, &history),
            );
        }
    }
    json
}

fn effective_proxy_capabilities(runtime: &Arc<Runtime>, name: &str) -> (bool, bool) {
    effective_proxy_capabilities_inner(runtime, name, 0)
}

fn effective_proxy_capabilities_inner(
    runtime: &Arc<Runtime>,
    name: &str,
    depth: usize,
) -> (bool, bool) {
    if depth >= 16 {
        return (false, false);
    }
    if let Some(members) = runtime
        .groups
        .read()
        .get(name)
        .map(|group| group.members().to_vec())
    {
        return members
            .iter()
            .map(|member| effective_proxy_capabilities_inner(runtime, member, depth + 1))
            .fold((false, false), |current, capabilities| {
                (current.0 || capabilities.0, current.1 || capabilities.1)
            });
    }
    runtime
        .outbounds
        .read()
        .get(name)
        .map(|outbound| {
            let capabilities = outbound.capabilities();
            (
                capabilities.udp && runtime.node_udp_enabled(name).unwrap_or(true),
                capabilities.multiplex,
            )
        })
        .unwrap_or((false, false))
}

/// 按 (node, url) 拉历史；URLTester 空时退回 SmartSelector。
fn node_history(
    urltest: &Arc<core_runtime::UrlTester>,
    runtime: &Arc<Runtime>,
    node: &str,
    url: &str,
) -> Value {
    let mut entries: Vec<core_runtime::HistoryEntry> = urltest.history(node, url);
    if entries.is_empty() {
        let stats = runtime.smart.ensure_node(node);
        entries = stats
            .history()
            .into_iter()
            .map(|e| core_runtime::HistoryEntry {
                time_ms: e.time_ms,
                delay_ms: e.delay_ms as u32,
            })
            .collect();
    }
    Value::Array(
        entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect(),
    )
}

fn node_extra(
    urltest: &Arc<core_runtime::UrlTester>,
    node: &str,
    url: &str,
    history: &Value,
) -> Value {
    if history.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        return json!({});
    }
    json!({
        url: {
            "alive": urltest.alive_for_url(node, url),
            "history": history.clone(),
        }
    })
}

/// 取 history 数组里最后一条的 `delay` 字段；空数组返回 0。
fn delay_from_history(history: &Value) -> u64 {
    history
        .as_array()
        .and_then(|arr| arr.last())
        .and_then(|entry| entry.get("delay"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn map_proto(p: &str) -> &'static str {
    match p {
        "ss" => "Shadowsocks",
        "ssr" => "ShadowsocksR",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "hysteria" => "Hysteria",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "wireguard" => "WireGuard",
        "ssh" => "Ssh",
        "http" => "Http",
        "socks5" => "Socks5",
        "anytls" => "AnyTLS",
        "snell" => "Snell",
        "mieru" => "Mieru",
        _ => "Unknown",
    }
}

/* ====================== providers ====================== */

async fn providers_proxies(State(s): State<NativeState>) -> axum::response::Response {
    let s_for_build = s.clone();
    let bytes = s.caches.providers_proxies.fetch_bytes(move || {
        let mut providers = Map::new();
        for (name, _f) in &s_for_build.runtime.plan.feeds {
            providers.insert(name.clone(), provider_json(&s_for_build, name));
        }
        json!({"providers": providers})
    });
    json_bytes(bytes)
}

async fn provider_proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if !s.runtime.plan.feeds.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "provider not found"})),
        )
            .into_response();
    }
    Json(provider_json(&s, &name)).into_response()
}

async fn provider_proxy_refresh(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let exists = s.runtime.plan.feeds.contains_key(&name);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "provider not found"})),
        )
            .into_response();
    }
    // 触发后台 FeedManager 立即刷新该 feed。
    if let Some(mgr) = s.feeds.as_ref() {
        mgr.refresh_now(&name);
    } else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "feed manager unavailable"})),
        )
            .into_response();
    }
    s.caches.invalidate_proxy_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

async fn provider_proxy_healthcheck(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let nodes: Vec<String> = nodes_in_provider(&s, &name);
    if nodes.is_empty() && !s.runtime.plan.feeds.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Resource not found"})),
        )
            .into_response();
    }
    let runtime = s.runtime.clone();
    let urltest = s.urltest.clone();
    tokio::spawn(async move {
        let _ = urltest.test_many(&runtime, &nodes, None, None).await;
    });
    StatusCode::NO_CONTENT.into_response()
}

async fn provider_proxy_node(
    State(s): State<NativeState>,
    Path((provider, proxy)): Path<(String, String)>,
) -> Response {
    if !nodes_in_provider(&s, &provider)
        .iter()
        .any(|name| name == &proxy)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Resource not found"})),
        )
            .into_response();
    }
    proxy_one(State(s), Path(proxy)).await
}

async fn provider_proxy_node_healthcheck(
    State(s): State<NativeState>,
    Path((provider, proxy)): Path<(String, String)>,
    Query(q): Query<DelayQ>,
) -> Response {
    if !nodes_in_provider(&s, &provider)
        .iter()
        .any(|name| name == &proxy)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Resource not found"})),
        )
            .into_response();
    }
    proxy_delay(State(s), Path(proxy), Query(q)).await
}

fn nodes_in_provider(s: &NativeState, name: &str) -> Vec<String> {
    if let Some(mgr) = s.feeds.as_ref() {
        if let Some(snap) = mgr.snapshot(name) {
            return snap.into_iter().map(|n| n.name).collect();
        }
    }
    s.runtime
        .plan
        .nodes
        .iter()
        .filter(|n| {
            n.name.starts_with(&format!("{}/", name)) || n.name.contains(&format!("[{}]", name))
        })
        .map(|n| n.name.clone())
        .collect()
}

fn provider_json(s: &NativeState, name: &str) -> Value {
    // 优先用 FeedManager.snapshot —— 可能比 plan.nodes 更新（订阅刷新过）。
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    let mut nodes: Vec<Value> = Vec::new();
    if let Some(mgr) = s.feeds.as_ref() {
        if let Some(snap) = mgr.snapshot(name) {
            nodes = snap
                .iter()
                .map(|n| {
                    let history = Value::Array(
                        urltest
                            .history(&n.name, &default_url)
                            .into_iter()
                            .map(|e| {
                                json!({
                                    "time": iso8601(e.time_ms / 1000),
                                    "delay": e.delay_ms,
                                })
                            })
                            .collect(),
                    );
                    let delay = delay_from_history(&history);
                    node_proxy_json(
                        s,
                        &n.name,
                        n.protocol.as_str(),
                        Some(n),
                        history,
                        json!({}),
                        urltest.alive_for_url(&n.name, &default_url),
                        delay,
                        name,
                    )
                })
                .collect();
        }
    }
    if nodes.is_empty() {
        nodes = s
            .runtime
            .plan
            .nodes
            .iter()
            .filter(|n| {
                n.name.starts_with(&format!("{}/", name)) || n.name.contains(&format!("[{}]", name))
            })
            .map(|n| {
                let history = Value::Array(
                    urltest
                        .history(&n.name, &default_url)
                        .into_iter()
                        .map(|e| {
                            json!({
                                "time": iso8601(e.time_ms / 1000),
                                "delay": e.delay_ms,
                            })
                        })
                        .collect(),
                );
                let delay = delay_from_history(&history);
                node_proxy_json(
                    s,
                    &n.name,
                    n.protocol.as_str(),
                    Some(n),
                    history,
                    json!({}),
                    urltest.alive_for_url(&n.name, &default_url),
                    delay,
                    name,
                )
            })
            .collect();
    }
    let status = s.feeds.as_ref().and_then(|m| m.status(name));
    let (last_ms, url, userinfo) = status
        .as_ref()
        .map(|st| (st.last_refreshed_ms, st.url.clone(), st.userinfo))
        .unwrap_or((0, String::new(), None));
    let configured_url = s
        .runtime
        .plan
        .feeds
        .get(name)
        .map(|feed| feed.url.as_str())
        .unwrap_or_default();
    let url = if url.is_empty() {
        configured_url.to_string()
    } else {
        url
    };
    let vehicle_type = if url.is_empty() { "File" } else { "HTTP" };
    let expected_status = s
        .urltest
        .current_config()
        .default_expected_status
        .to_string();
    let mut provider = json!({
        "name": name,
        "type": "Proxy",
        "vehicleType": vehicle_type,
        "proxies": nodes,
        "testUrl": default_url,
        "expectedStatus": expected_status,
    });
    if last_ms > 0 {
        provider
            .as_object_mut()
            .expect("provider object")
            .insert("updatedAt".into(), Value::String(iso8601(last_ms / 1000)));
    }
    if let Some(ui) = userinfo {
        provider.as_object_mut().expect("provider object").insert(
            "subscriptionInfo".into(),
            json!({
                "Upload":   ui.upload,
                "Download": ui.download,
                "Total":    ui.total,
                "Expire":   ui.expire,
            }),
        );
    }
    provider
}

async fn providers_rules(State(s): State<NativeState>) -> axum::response::Response {
    let runtime = s.runtime.clone();
    let bytes = s.caches.providers_rules.fetch_bytes(move || {
        let mut providers = Map::new();
        for (name, set) in &runtime.plan.route.sets {
            providers.insert(name.clone(), rule_provider_json(&runtime, name, set));
        }
        json!({"providers": providers})
    });
    json_bytes(bytes)
}

async fn provider_rule_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if let Some(set) = s.runtime.plan.route.sets.get(&name) {
        Json(rule_provider_json(&s.runtime, &name, set)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "ruleset not found"})),
        )
            .into_response()
    }
}

async fn provider_rule_refresh(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(manager) = s.runtime.ruleset_manager() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "ruleset manager is not running"})),
        )
            .into_response();
    };
    if !manager.contains(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "ruleset not found"})),
        )
            .into_response();
    }
    match manager.refresh(&name).await {
        Ok(_) => {
            s.caches.invalidate_rule_state();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => (StatusCode::BAD_GATEWAY, Json(json!({"message": error}))).into_response(),
    }
}

fn rule_provider_json(
    runtime: &Arc<Runtime>,
    name: &str,
    set: &core_config::model::RuleSetSpec,
) -> Value {
    let vehicle_type = if set.url.is_some() {
        "HTTP"
    } else if set.path.is_some() {
        "File"
    } else {
        "Inline"
    };
    let lowered = set.r#type.to_lowercase();
    let behavior = match lowered.as_str() {
        "domain" => "Domain".to_string(),
        "ipcidr" | "ip-cidr" | "ip_cidr" => "IPCIDR".to_string(),
        "classical" => "Classical".to_string(),
        _ => lowered.clone(),
    };
    let rule_count = runtime
        .route
        .rulesets()
        .and_then(|rulesets| rulesets.get(name))
        .map(|matcher| {
            let stats = matcher.stats();
            stats.domains
                + stats.suffixes
                + stats.keywords
                + stats.regex
                + stats.cidr_v4
                + stats.cidr_v6
                + stats.processes
                + stats.ports
        })
        .unwrap_or(set.payload.len());
    let mut provider = json!({
        "name": name,
        "type": "Rule",
        "vehicleType": vehicle_type,
        "behavior": behavior,
        "format": match set.format.as_deref().unwrap_or("yaml").to_ascii_lowercase().as_str() {
            "text" => "TextRule",
            "mrs" => "MrsRule",
            _ => "YamlRule",
        },
        "ruleCount": rule_count,
    });
    if let Some(status) = runtime
        .ruleset_manager()
        .and_then(|manager| manager.status(name))
    {
        let object = provider.as_object_mut().expect("rule provider object");
        object.insert("refreshing".into(), Value::Bool(status.refreshing));
        if let Some(updated_at) = status.updated_at_unix_ms {
            object.insert(
                "updatedAt".into(),
                Value::String(iso8601(updated_at / 1000)),
            );
        }
        if let Some(error) = status.last_error {
            object.insert("lastError".into(), Value::String(error));
        }
    }
    provider
}

/* ====================== rules ====================== */

async fn rules(State(s): State<NativeState>) -> axum::response::Response {
    let runtime = s.runtime.clone();
    let bytes = s
        .caches
        .rules
        .fetch_bytes(move || build_rules_value(&runtime));
    json_bytes(bytes)
}

fn build_rules_value(runtime: &Arc<Runtime>) -> Value {
    use core_config::runtime_plan::{RouteAction, RouteMatcher};
    let mut out = Vec::new();
    for (index, st) in runtime.plan.route.steps.iter().enumerate() {
        let (rtype, payload) = match &st.matcher {
            RouteMatcher::Any => ("MATCH", String::new()),
            RouteMatcher::Home => ("HOME", String::new()),
            RouteMatcher::Cn => ("GEOIP", "CN".into()),
            RouteMatcher::Ads => ("ADS", String::new()),
            RouteMatcher::Service(svc) => ("SERVICE", svc.clone()),
            RouteMatcher::Domain(d) => ("DOMAIN", d.clone()),
            RouteMatcher::Suffix(d) => ("DOMAIN-SUFFIX", d.clone()),
            RouteMatcher::Keyword(k) => ("DOMAIN-KEYWORD", k.clone()),
            RouteMatcher::Cidr(c) => ("IP-CIDR", c.clone()),
            RouteMatcher::Port(p) => ("DST-PORT", p.to_string()),
            RouteMatcher::PortRange(lo, hi) => ("DST-PORT", format!("{lo}-{hi}")),
            RouteMatcher::Network(n) => ("NETWORK", n.clone()),
            RouteMatcher::Process(p) => ("PROCESS-NAME", p.clone()),
            RouteMatcher::Set(s) => ("RULE-SET", s.clone()),
            RouteMatcher::Proto(p) => ("PROTOCOL", p.clone()),
            RouteMatcher::And(parts) => ("AND", format!("{} clauses", parts.len())),
            RouteMatcher::Or(parts) => ("OR", format!("{} clauses", parts.len())),
        };
        let proxy = match &st.action {
            RouteAction::Direct => "DIRECT".to_string(),
            RouteAction::Block => "REJECT".to_string(),
            RouteAction::Group(g) => g.clone(),
        };
        out.push(json!({
            "index": index,
            "type": rtype,
            "payload": payload,
            "proxy": proxy,
            "size": -1,
        }));
    }
    json!({"rules": out})
}

async fn rules_disable(
    State(s): State<NativeState>,
    Json(body): Json<HashMap<String, bool>>,
) -> Response {
    for (index, disabled) in body {
        let Ok(index) = index.parse::<usize>() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response();
        };
        if !s.runtime.route.set_rule_disabled(index, disabled) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response();
        }
    }
    s.caches.invalidate_rule_state();
    StatusCode::NO_CONTENT.into_response()
}

/* ====================== configs ====================== */

async fn configs(State(s): State<NativeState>) -> axum::response::Response {
    let s_for_build = s.clone();
    let bytes = s
        .caches
        .configs
        .fetch_bytes(move || build_configs_value(&s_for_build));
    json_bytes(bytes)
}

fn build_configs_value(s: &NativeState) -> Value {
    let mixed = s.runtime.plan.listen.mixed.as_ref();
    let port = mixed.map(|m| m.port).unwrap_or(0);
    let bind_address = mixed.map(|m| m.host.as_str()).unwrap_or("");
    let inbound_sockopt = mixed
        .and_then(|m| m.stream_settings.as_ref())
        .and_then(|settings| settings.sockopt.as_ref());
    let inbound_tfo = inbound_sockopt
        .map(|sockopt| sockopt.tfo_value() != 0)
        .unwrap_or(false);
    let inbound_mptcp = inbound_sockopt
        .map(|sockopt| sockopt.tcp_mptcp)
        .unwrap_or(false);
    let mc = s.runtime.mutable.read().clone();
    let find_process_mode = match s.runtime.plan.find_process_mode {
        core_config::model::FindProcessMode::Off => "off",
        core_config::model::FindProcessMode::Strict => "strict",
        core_config::model::FindProcessMode::Always => "always",
    };
    // 只回用户名，永不回明文密码。空数组表示未启用入站认证。
    let authentication: Vec<String> = s
        .runtime
        .plan
        .listen
        .auth
        .iter()
        .map(|up| up.user.clone())
        .collect();
    json!({
        "port": 0,
        "socks-port": 0,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": port,
        "authentication": authentication,
        "allow-lan": mc.allow_lan,
        "bind-address": bind_address,
        "inbound-tfo": inbound_tfo,
        "inbound-mptcp": inbound_mptcp,
        "mode": mc.mode,
        "log-level": mc.log_level,
        "ipv6": mc.ipv6,
        "tun": {
            "enable": mc.tun_enable,
            "stack": format!("{:?}", s.runtime.plan.capture.stack).to_lowercase(),
            "device": s.runtime.plan.capture.tun.interface_name.clone().unwrap_or_default(),
        },
        "find-process-mode": find_process_mode,
        "unified-delay": s.urltest.current_config().default_unified_delay,
    })
}

#[allow(clippy::too_many_arguments)]
fn node_proxy_json(
    s: &NativeState,
    name: &str,
    protocol: &str,
    node: Option<&core_config::node_uri::ParsedNode>,
    history: Value,
    extra: Value,
    alive: bool,
    delay: u64,
    provider: &str,
) -> Value {
    let capabilities = s
        .runtime
        .outbounds
        .read()
        .get(name)
        .map(|outbound| outbound.capabilities());
    let sockopt = node
        .and_then(|node| node.stream_settings.as_ref())
        .and_then(|settings| settings.sockopt.as_ref());
    let param_bool = |key: &str| {
        node.and_then(|node| node.params.get(key))
            .is_some_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
    };
    let udp = capabilities
        .map(|capabilities| capabilities.udp)
        .unwrap_or(false)
        && s.runtime.node_udp_enabled(name).unwrap_or(true);
    let smux = capabilities
        .map(|capabilities| capabilities.multiplex)
        .unwrap_or(false);
    let uot = param_bool("udp-over-tcp") || param_bool("udp_over_tcp");
    let tfo = sockopt
        .map(|sockopt| sockopt.tfo_value() != 0)
        .unwrap_or_else(|| param_bool("tfo"));
    let mptcp = sockopt
        .map(|sockopt| sockopt.tcp_mptcp)
        .unwrap_or_else(|| param_bool("mptcp"));
    let interface = sockopt
        .map(|sockopt| sockopt.interface.clone())
        .unwrap_or_default();
    let routing_mark = sockopt
        .map(|sockopt| sockopt.mark)
        .or_else(|| {
            node.and_then(|node| node.params.get("mark"))
                .and_then(|mark| mark.parse::<i32>().ok())
        })
        .unwrap_or_default();
    let dialer_proxy = sockopt
        .map(|sockopt| sockopt.dialer_proxy.clone())
        .unwrap_or_default();

    json!({
        "type": map_proto(protocol),
        "name": name,
        "history": history,
        "extra": extra,
        "alive": alive,
        "delay": delay,
        "udp": udp,
        "uot": uot,
        "xudp": false,
        "tfo": tfo,
        "mptcp": mptcp,
        "smux": smux,
        "interface": interface,
        "routing-mark": routing_mark,
        "provider-name": provider,
        "dialer-proxy": dialer_proxy,
    })
}

#[derive(Deserialize, Default)]
struct ConfigsPut {
    #[serde(default)]
    mode: Option<String>,
    #[serde(rename = "log-level", default)]
    log_level: Option<String>,
    #[serde(rename = "allow-lan", default)]
    allow_lan: Option<bool>,
    #[serde(default)]
    ipv6: Option<bool>,
    #[serde(default)]
    tun: Option<TunPut>,
}

#[derive(Deserialize, Default)]
struct TunPut {
    #[serde(default)]
    enable: Option<bool>,
}

#[derive(Deserialize, Default)]
struct ConfigReload {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    payload: Option<String>,
}

async fn configs_reload(
    State(_s): State<NativeState>,
    Query(_query): Query<HashMap<String, String>>,
    Json(body): Json<ConfigReload>,
) -> Response {
    if body.path.as_deref().unwrap_or_default().is_empty()
        && body.payload.as_deref().unwrap_or_default().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"message": "runtime config reload is not supported"})),
    )
        .into_response()
}

async fn configs_put(
    State(s): State<NativeState>,
    Json(body): Json<ConfigsPut>,
) -> impl IntoResponse {
    // mode 已接入选路；其余字段仍只更新 MutableConfig 视图。
    // allow-lan / tun_enable / ipv6 / log-level 的真实副作用尚未热切换绑定/capture，
    // 但至少 mode 不再是“写成功假象”。
    let mut mc = s.runtime.mutable.write();
    if let Some(v) = body.mode {
        let normalized = v.to_lowercase();
        match normalized.as_str() {
            "rule" | "global" | "direct" => mc.mode = normalized,
            other => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "message": format!(
                            "unsupported mode \"{other}\"; expected rule|global|direct"
                        )
                    })),
                )
                    .into_response();
            }
        }
    }
    if let Some(v) = body.log_level {
        mc.log_level = v.to_lowercase();
    }
    if let Some(v) = body.allow_lan {
        // 入站 bind 在启动时由 listen.share / host 决定，运行时无法安全热切换。
        // 拒绝静默写入，避免 dashboard 显示 allow-lan=false 但端口仍对外监听。
        let current = mc.allow_lan;
        if v != current {
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(json!({
                    "message": format!(
                        "allow-lan cannot be changed at runtime (current={current}, requested={v}); \
                         restart with listen.share false|home|all"
                    )
                })),
            )
                .into_response();
        }
    }
    if let Some(v) = body.ipv6 {
        mc.ipv6 = v;
    }
    if let Some(t) = body.tun {
        if let Some(e) = t.enable {
            let current = mc.tun_enable;
            if e != current {
                return (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "message": format!(
                            "tun.enable cannot be changed at runtime (current={current}, requested={e}); \
                             restart with capture.on"
                        )
                    })),
                )
                    .into_response();
            }
        }
    }
    drop(mc);
    s.caches.invalidate_config_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

async fn configs_geo(State(s): State<NativeState>) -> impl IntoResponse {
    let Some(manager) = s.runtime.ruleset_manager() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "ruleset manager is not running"})),
        )
            .into_response();
    };
    let report = manager.refresh_all().await;
    s.caches.invalidate_rule_state();
    if report.failed.is_empty() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "message": "one or more rulesets failed to refresh; last-known-good copies remain active",
                "updated": report.updated.iter().map(|update| &update.name).collect::<Vec<_>>(),
                "failed": report.failed.into_iter().map(|(name, error)| {
                    json!({"name": name, "error": error})
                }).collect::<Vec<_>>(),
            })),
        )
            .into_response()
    }
}

/* ====================== DNS / cache ====================== */

#[derive(Deserialize)]
struct DnsQ {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    qtype: Option<String>,
}

async fn dns_query(
    State(s): State<NativeState>,
    Query(q): Query<DnsQ>,
) -> axum::response::Response {
    let Some(name) = q.name else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "name required"})),
        )
            .into_response();
    };
    let qtype_label = q.qtype.as_deref().unwrap_or("A").to_uppercase();
    let qtype_num: u16 = match qtype_label.as_str() {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" | "TXT" | "MX" | "NS" | "PTR" | "SRV" | "HTTPS" | "SVCB" => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(json!({
                    "message": format!("DNS query type {qtype_label} is not supported")
                })),
            )
                .into_response();
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "invalid query type"})),
            )
                .into_response();
        }
    };
    let answers = s
        .runtime
        .resolver
        .resolve_compat(&name, qtype_label.as_str())
        .await;
    // sing-box `dnsRouter`: 用 mihomo `Question` 字段大写形式（Name/Qtype/Qclass）。
    let mut response = json!({
        "Status": 0,
        "TC": false,
        "RD": true,
        "RA": true,
        "AD": false,
        "CD": false,
        "Question": [{
            "Name": format!("{}.", name.trim_end_matches('.')),
            "Qtype": qtype_num,
            "Qclass": 1,
        }],
    });
    if let Value::Array(answers) = answers {
        if !answers.is_empty() {
            response
                .as_object_mut()
                .expect("dns response object")
                .insert("Answer".into(), Value::Array(answers));
        }
    }
    Json(response).into_response()
}

async fn cache_fakeip_flush(State(s): State<NativeState>) -> impl IntoResponse {
    s.runtime.resolver.flush_fakeip();
    StatusCode::NO_CONTENT
}

/// `POST /cache/dns/flush` —— 与 sing-box 的 `flushDNS` 等价，清掉 DNS 解析
/// 缓存。这里同时清 fake-ip 池和 DNS cache（mihomo 的 `dnsRouter.ClearCache`）。
async fn cache_dns_flush(State(s): State<NativeState>) -> impl IntoResponse {
    s.runtime.resolver.cache().clear();
    s.runtime.resolver.flush_fakeip();
    StatusCode::NO_CONTENT
}

/* ====================== storage ====================== */

fn dashboard_storage() -> &'static dashmap::DashMap<String, Bytes> {
    static STORAGE: OnceLock<dashmap::DashMap<String, Bytes>> = OnceLock::new();
    STORAGE.get_or_init(dashmap::DashMap::new)
}

fn storage_key(key: &str) -> String {
    format!("clash_storage:{key}")
}

async fn storage_get(State(s): State<NativeState>, Path(key): Path<String>) -> Response {
    if let Some(store) = s.runtime.store.as_ref() {
        return match store.get_json::<Value>(core_store::schema::KV_META, &storage_key(&key)) {
            Ok(Some(value)) => Json(value).into_response(),
            Ok(None) => json_bytes(Bytes::from_static(b"null")),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": error.to_string()})),
            )
                .into_response(),
        };
    }
    let value = dashboard_storage()
        .get(&key)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);
    Json(value).into_response()
}

async fn storage_put(
    State(s): State<NativeState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    };
    if let Some(store) = s.runtime.store.as_ref() {
        return match store.put_json(core_store::schema::KV_META, &storage_key(&key), &value) {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": error.to_string()})),
            )
                .into_response(),
        };
    }
    dashboard_storage().insert(key, body);
    StatusCode::NO_CONTENT.into_response()
}

async fn storage_delete(State(s): State<NativeState>, Path(key): Path<String>) -> Response {
    if let Some(store) = s.runtime.store.as_ref() {
        return match store.delete(core_store::schema::KV_META, &storage_key(&key)) {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"message": error.to_string()})),
            )
                .into_response(),
        };
    }
    dashboard_storage().remove(&key);
    StatusCode::NO_CONTENT.into_response()
}

/* ====================== misc ====================== */

async fn restart() -> impl IntoResponse {
    // 优雅重启需要外部 supervisor 协助；本进程内仅返回 503 让 dashboard 提示。
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"message": "in-process restart not supported; use systemd/runit"})),
    )
}

async fn upgrade_kernel() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"message": "kernel upgrade is out-of-band"})),
    )
}

async fn upgrade_ui() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"message": "ui upgrade is out-of-band"})),
    )
}

/* ====================== utils ====================== */

/// 把 Unix 秒时间戳格式化为 RFC3339 / ISO 8601（UTC zulu 风格），
/// 与 mihomo `time.Time.MarshalJSON` 输出兼容，让 yacd / metacubexd /
/// Razord-meta 等 dashboard 能正确 `new Date(...)` 解析展示。
///
/// 例：1714512345 → "2024-04-30T22:45:45Z"
///
/// 不引入 chrono：用 civil_from_days 算法把秒拆成 (y,m,d,h,m,s)。
fn iso8601(ts_secs: u64) -> String {
    let days = (ts_secs / 86_400) as i64;
    let secs_of_day = (ts_secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

/// Howard Hinnant 公元日历算法：从 1970-01-01 起的天数 → (year, month, day)。
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

fn clock_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

#[cfg(test)]
mod time_tests {
    use super::*;
    #[test]
    fn rfc3339_known_dates() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        // 2024-04-30 22:45:45 UTC
        assert_eq!(iso8601(1_714_517_145), "2024-04-30T22:45:45Z");
        // 2025-01-01 00:00:00 UTC
        assert_eq!(iso8601(1_735_689_600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn delay_from_history_takes_last() {
        let h = json!([
            {"time": "2024-04-30T22:45:45Z", "delay": 80},
            {"time": "2024-04-30T22:46:45Z", "delay": 123},
        ]);
        assert_eq!(super::delay_from_history(&h), 123);
    }

    #[test]
    fn delay_from_empty_history_is_zero() {
        let h = json!([]);
        assert_eq!(super::delay_from_history(&h), 0);
    }
}
