//! 订阅格式解析 + 过滤/重命名。

use base64::Engine;
use core_config::{
    compile_node_spec,
    model::{FeedDetail, NodeSpec},
    node_uri::{NodeProtocol, ParsedNode, parse_uri, validate_young_node},
};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatHint {
    Auto,
    Base64,
    /// WutherCore's native subscription document (`nodes` / `outbounds`).
    WutherYaml,
    /// Mihomo-compatible subscription document (`proxies` / `payload`).
    ClashYaml,
    PlainUri,
    Sip008,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("订阅正文为空")]
    Empty,
    #[error("订阅格式探测为 {format:?}，但没有解析出任何有效节点")]
    NoValidNode { format: FormatHint },
}

/// 主入口：尝试自动嗅探格式并解析为节点列表。
pub fn parse_feed_payload(raw: &[u8], hint: FormatHint) -> Vec<ParsedNode> {
    parse_feed_payload_inner(raw, hint, 0)
}

/// Strict entry point used by live updates. Invalid bodies are errors instead
/// of successful empty updates, while an explicit `nodes: []` remains a valid
/// way for a provider to publish an empty subscription.
pub fn parse_feed_payload_checked(
    raw: &[u8],
    hint: FormatHint,
) -> Result<Vec<ParsedNode>, ParseError> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }
    let format = match hint {
        FormatHint::Auto => sniff(trimmed),
        format => format,
    };
    let nodes = parse_feed_payload_inner(raw, hint, 0);
    if !nodes.is_empty() || declares_empty_subscription(trimmed) {
        Ok(nodes)
    } else {
        Err(ParseError::NoValidNode { format })
    }
}

fn declares_empty_subscription(text: &str) -> bool {
    declares_empty_subscription_inner(text, 0)
}

fn declares_empty_subscription_inner(text: &str, depth: u8) -> bool {
    if depth > 2 {
        return false;
    }
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return declares_base64_empty_subscription(text, depth);
    };
    let direct = match value {
        serde_yaml::Value::Sequence(nodes) => nodes.is_empty(),
        serde_yaml::Value::Mapping(map) => ["nodes", "outbounds", "proxies", "payload", "servers"]
            .into_iter()
            .filter_map(|key| map.get(serde_yaml::Value::String(key.into())))
            .any(|value| match value {
                serde_yaml::Value::Sequence(nodes) => nodes.is_empty(),
                serde_yaml::Value::Mapping(nodes) => nodes.is_empty(),
                _ => false,
            }),
        _ => false,
    };
    direct || declares_base64_empty_subscription(text, depth)
}

fn declares_base64_empty_subscription(text: &str, depth: u8) -> bool {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    let cleaned = text.replace(['\n', '\r', ' '], "");
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .into_iter()
        .filter_map(|engine| engine.decode(&cleaned).ok())
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .any(|decoded| declares_empty_subscription_inner(decoded.trim(), depth + 1))
}

fn parse_feed_payload_inner(raw: &[u8], hint: FormatHint, depth: u8) -> Vec<ParsedNode> {
    if depth > 2 {
        return Vec::new();
    }
    // 先尝试 UTF-8。订阅几乎都是文本。
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim_start_matches('\u{feff}').trim();

    let actual = match hint {
        FormatHint::Auto => sniff(trimmed),
        other => other,
    };
    debug!(target: "feeds::parser", ?actual, len = trimmed.len(), "parse feed");

    let mut nodes = match actual {
        FormatHint::Base64 => parse_base64(trimmed, depth),
        FormatHint::WutherYaml => parse_wuther_yaml(trimmed),
        FormatHint::ClashYaml => parse_clash_yaml(trimmed),
        FormatHint::PlainUri => parse_plain(trimmed),
        FormatHint::Sip008 => parse_sip008(trimmed),
        FormatHint::Auto => Vec::new(),
    };

    // 失败回退：base64 失败试 plain，反之亦然。
    if nodes.is_empty() && actual != FormatHint::PlainUri {
        let alt = parse_plain(trimmed);
        if !alt.is_empty() {
            nodes = alt;
        }
    }
    if nodes.is_empty() && actual != FormatHint::WutherYaml {
        nodes = parse_wuther_yaml(trimmed);
    }
    if nodes.is_empty() && actual != FormatHint::ClashYaml {
        nodes = parse_clash_yaml(trimmed);
    }
    nodes
}

fn sniff(s: &str) -> FormatHint {
    if s.contains("://") {
        return FormatHint::PlainUri;
    }
    if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(s) {
        match &value {
            serde_yaml::Value::Mapping(map) => {
                if has_mapping_key(map, "nodes") || has_mapping_key(map, "outbounds") {
                    return FormatHint::WutherYaml;
                }
                if has_mapping_key(map, "proxies") || has_mapping_key(map, "payload") {
                    return FormatHint::ClashYaml;
                }
                if has_mapping_key(map, "servers") {
                    return FormatHint::Sip008;
                }
                if looks_like_node_mapping(map) {
                    return FormatHint::WutherYaml;
                }
            }
            serde_yaml::Value::Sequence(_) => return FormatHint::WutherYaml,
            _ => {}
        }
    }
    // 默认按 base64 尝试
    FormatHint::Base64
}

fn has_mapping_key(map: &serde_yaml::Mapping, key: &str) -> bool {
    map.contains_key(serde_yaml::Value::String(key.into()))
}

fn looks_like_node_mapping(map: &serde_yaml::Mapping) -> bool {
    [
        "type", "protocol", "kind", "link", "uri", "url", "server", "address", "endpoint",
    ]
    .iter()
    .any(|key| has_mapping_key(map, key))
}

fn parse_plain(s: &str) -> Vec<ParsedNode> {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| match parse_uri(l) {
            Ok(n) => Some(n),
            Err(e) => {
                debug!(target: "feeds::parser", line = l, error = %e, "skip bad uri");
                None
            }
        })
        .collect()
}

fn parse_base64(s: &str, depth: u8) -> Vec<ParsedNode> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let cleaned = s.replace(['\n', '\r', ' '], "");
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&cleaned) {
            let nodes = parse_feed_payload_inner(&bytes, FormatHint::Auto, depth + 1);
            if !nodes.is_empty() {
                return nodes;
            }
        }
    }
    Vec::new()
}

fn parse_wuther_yaml(s: &str) -> Vec<ParsedNode> {
    let root: serde_yaml::Value = match serde_yaml::from_str(s) {
        Ok(value) => value,
        Err(error) => {
            debug!(target: "feeds::parser", %error, "native subscription yaml parse failed");
            return Vec::new();
        }
    };
    match root {
        serde_yaml::Value::Mapping(map) => {
            let is_document = has_mapping_key(&map, "nodes") || has_mapping_key(&map, "outbounds");
            if is_document && !native_version_supported(&map) {
                warn!(target: "feeds::parser", "unsupported native subscription version");
                return Vec::new();
            }
            for key in ["nodes", "outbounds"] {
                if let Some(nodes) = map.get(serde_yaml::Value::String(key.into())) {
                    return parse_native_collection(nodes);
                }
            }
            if looks_like_node_mapping(&map) {
                parse_native_entry(serde_yaml::Value::Mapping(map), None)
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            }
        }
        serde_yaml::Value::Sequence(nodes) => nodes
            .into_iter()
            .filter_map(|node| parse_native_entry(node, None))
            .collect(),
        serde_yaml::Value::String(uri) => parse_uri(&uri).ok().into_iter().collect(),
        _ => Vec::new(),
    }
}

fn native_version_supported(map: &serde_yaml::Mapping) -> bool {
    let Some(version) = map.get(serde_yaml::Value::String("version".into())) else {
        return true;
    };
    version.as_u64() == Some(1)
        || version
            .as_str()
            .is_some_and(|version| version.trim() == "1")
}

fn parse_native_collection(value: &serde_yaml::Value) -> Vec<ParsedNode> {
    match value {
        serde_yaml::Value::Sequence(nodes) => nodes
            .iter()
            .cloned()
            .filter_map(|node| parse_native_entry(node, None))
            .collect(),
        serde_yaml::Value::Mapping(nodes) => nodes
            .iter()
            .filter_map(|(name, node)| {
                let name = name.as_str()?;
                parse_native_entry(node.clone(), Some(name))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_native_entry(mut value: serde_yaml::Value, name_hint: Option<&str>) -> Option<ParsedNode> {
    if let serde_yaml::Value::String(uri) = &value {
        return match parse_uri(uri) {
            Ok(mut node) => {
                if let Some(name) = name_hint {
                    node.name = name.to_string();
                }
                Some(node)
            }
            Err(error) => {
                debug!(target: "feeds::parser", %error, "skip invalid native subscription URI");
                None
            }
        };
    }

    let map = value.as_mapping_mut()?;
    if let Some(name) = name_hint
        && !has_mapping_key(map, "name")
    {
        map.insert(
            serde_yaml::Value::String("name".into()),
            serde_yaml::Value::String(name.into()),
        );
    }

    let native_shape = [
        "address",
        "login",
        "secure",
        "transport",
        "network",
        "params",
        "streamSettings",
        "stream_settings",
    ]
    .iter()
    .any(|key| has_mapping_key(map, key));
    let mut native_type_detected = false;
    if native_shape
        && explicit_node_type(map).is_none()
        && let Some(kind) = detect_native_node_type(map)
    {
        map.insert(
            serde_yaml::Value::String("protocol".into()),
            serde_yaml::Value::String(kind),
        );
        native_type_detected = true;
    }

    // The native schema is exactly the same strongly typed NodeSpec accepted
    // by local configuration. Compact provider-style maps fall through to the
    // generic structured parser below.
    if let Ok(spec) = serde_yaml::from_value::<NodeSpec>(value.clone()) {
        match compile_node_spec(&spec) {
            Ok(mut node) => {
                node.params
                    .insert("subscription-format".into(), "wuther".into());
                node.params
                    .insert("subscription-type".into(), node.protocol.as_str().into());
                if native_type_detected {
                    node.params
                        .insert("subscription-type-detected".into(), "1".into());
                }
                if let Err(error) = validate_young_node(&node) {
                    debug!(
                        target: "feeds::parser",
                        %error,
                        "skip invalid native Young node"
                    );
                    return None;
                }
                return Some(node);
            }
            Err(error) => {
                debug!(
                    target: "feeds::parser",
                    %error,
                    "native NodeSpec validation failed; trying compact node form"
                );
            }
        }
    }

    structured_proxy_to_node(value.as_mapping()?, StructuredFlavor::Native)
}

fn detect_native_node_type(map: &serde_yaml::Mapping) -> Option<String> {
    if let Some(kind) = detect_node_type(map) {
        return Some(kind);
    }
    let login = map
        .get(serde_yaml::Value::String("login".into()))
        .and_then(serde_yaml::Value::as_mapping);
    let params = map
        .get(serde_yaml::Value::String("params".into()))
        .and_then(serde_yaml::Value::as_mapping);
    let has_login_key = login.is_some_and(|login| {
        ["user", "password"]
            .iter()
            .any(|key| has_mapping_key(login, key))
    });
    let has_certificate_pin = params.is_some_and(|params| {
        ["pin-sha256", "pin_sha256", "pin", "certificate-sha256"]
            .iter()
            .any(|key| has_mapping_key(params, key))
    });
    (has_login_key && has_certificate_pin).then(|| "young".into())
}

fn parse_clash_yaml(s: &str) -> Vec<ParsedNode> {
    let root: serde_yaml::Value = match serde_yaml::from_str(s) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "feeds::parser", error = %e, "clash yaml parse failed");
            return Vec::new();
        }
    };
    let proxies = match root {
        serde_yaml::Value::Mapping(map) => map
            .get(serde_yaml::Value::String("proxies".into()))
            .or_else(|| map.get(serde_yaml::Value::String("payload".into())))
            .and_then(serde_yaml::Value::as_sequence)
            .cloned()
            .unwrap_or_default(),
        serde_yaml::Value::Sequence(values) => values,
        _ => Vec::new(),
    };
    let mut out = Vec::with_capacity(proxies.len());
    for v in proxies {
        let map = match v.as_mapping() {
            Some(m) => m,
            None => continue,
        };
        if let Some(node) = structured_proxy_to_node(map, StructuredFlavor::Mihomo) {
            out.push(node);
        }
    }
    out
}

#[derive(Clone, Copy)]
enum StructuredFlavor {
    Native,
    Mihomo,
}

fn mapping_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.into()))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn explicit_node_type(map: &serde_yaml::Mapping) -> Option<String> {
    for key in ["type", "kind"] {
        if let Some(kind) = mapping_string(map, key) {
            return Some(kind.to_ascii_lowercase());
        }
    }
    let protocol = mapping_string(map, "protocol")?.to_ascii_lowercase();
    is_known_node_type(&protocol).then_some(protocol)
}

fn is_known_node_type(value: &str) -> bool {
    matches!(
        value,
        "direct"
            | "block"
            | "reject"
            | "dns"
            | "http"
            | "https"
            | "socks"
            | "socks5"
            | "ss"
            | "ssr"
            | "vmess"
            | "vless"
            | "trojan"
            | "naive"
            | "naive+https"
            | "naive+quic"
            | "hysteria"
            | "hysteria2"
            | "hy2"
            | "tuic"
            | "wireguard"
            | "wg"
            | "ssh"
            | "snell"
            | "anytls"
            | "mieru"
            | "sudoku"
            | "trusttunnel"
            | "young"
            | "shadowquic"
            | "gost-relay"
            | "rematch"
            | "masque"
            | "openvpn"
            | "tailscale"
    )
}

/// Detect only signatures that have a useful protocol-specific fingerprint.
/// Ambiguous username/password nodes are deliberately rejected instead of
/// silently being turned into the wrong protocol.
fn detect_node_type(map: &serde_yaml::Mapping) -> Option<String> {
    let has = |key: &str| has_mapping_key(map, key);
    let string = |key: &str| mapping_string(map, key);

    if (has("pin-sha256") || has("pin_sha256") || has("certificate-sha256") || has("pin"))
        && (has("key") || has("secret") || has("user") || has("username") || has("password"))
    {
        return Some("young".into());
    }
    if has("peers") || (has("private-key") && has("public-key")) {
        return Some("wireguard".into());
    }
    if has("private-key") && (has("username") || has("user")) {
        return Some("ssh".into());
    }
    if has("clientId")
        || has("client-id")
        || has("idle-session-check-interval")
        || has("min-idle-session")
    {
        return Some("anytls".into());
    }
    if has("alterId") || has("alter-id") {
        return Some("vmess".into());
    }
    if has("flow") || has("reality-opts") {
        return Some("vless".into());
    }
    if has("obfs")
        && has("password")
        && string("protocol").is_some_and(|protocol| !is_known_node_type(&protocol))
    {
        return Some("ssr".into());
    }
    if has("congestion-controller") && (has("uuid") || has("token")) {
        return Some("tuic".into());
    }
    if has("hop-interval") || has("hopInterval") {
        return Some("hysteria2".into());
    }
    if has("ports") && (has("auth") || has("auth-str")) {
        return Some("hysteria".into());
    }
    if has("psk") && has("version") {
        return Some("snell".into());
    }
    if has("cipher") && has("password") {
        return Some("ss".into());
    }
    if has("uuid") || has("id") {
        return Some("vless".into());
    }
    if has("password")
        && (has("tls") || has("sni") || has("servername") || has("server-name") || has("alpn"))
    {
        return Some("trojan".into());
    }
    None
}

fn split_node_address(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return (address.port() != 0).then(|| (address.ip().to_string(), address.port()));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
        return Some((host.into(), port));
    }
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    (!host.trim().is_empty()).then(|| (host.trim().into(), port))
}

fn structured_proxy_to_node(
    m: &serde_yaml::Mapping,
    flavor: StructuredFlavor,
) -> Option<ParsedNode> {
    let g = |k: &str| m.get(serde_yaml::Value::String(k.into())).cloned();
    let str_g = |k: &str| g(k).and_then(|v| v.as_str().map(String::from));
    let u16_g = |k: &str| {
        g(k).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
        })
    };

    let name = str_g("name")
        .or_else(|| str_g("tag"))
        .or_else(|| str_g("label"))?;
    let (kind, type_detected) = explicit_node_type(m)
        .map(|kind| (kind, false))
        .or_else(|| detect_node_type(m).map(|kind| (kind, true)))?;
    let proto = match kind.as_str() {
        "reject" => NodeProtocol::Block,
        other => NodeProtocol::from_scheme(other),
    };
    let endpoint_optional = matches!(
        kind.as_str(),
        "direct" | "dns" | "reject" | "rematch" | "tailscale"
    );
    let mut host = str_g("server")
        .or_else(|| str_g("host"))
        .unwrap_or_default();
    let mut port = u16_g("port");
    if let Some(address) = str_g("address").or_else(|| str_g("endpoint"))
        && let Some((address_host, address_port)) = split_node_address(&address)
    {
        if host.is_empty() {
            host = address_host;
        }
        if port.is_none() {
            port = Some(address_port);
        }
    }

    // Mihomo lets Hysteria use a hopping range, and Mieru use `port-range`.
    // ParsedNode still needs one primary endpoint, so select the first port
    // while preserving the complete range below in `params`.
    if port.is_none() {
        port = ["ports", "port-range"]
            .into_iter()
            .find_map(|key| str_g(key).as_deref().and_then(first_port));
    }

    // Modern WireGuard providers may define only `peers`. Use the first peer
    // as the legacy primary endpoint without dropping the full peer list.
    if matches!(&proto, NodeProtocol::Wireguard)
        && (host.is_empty() || port.is_none())
        && let Some(peer) = g("peers")
            .and_then(|value| value.as_sequence().cloned())
            .and_then(|peers| peers.into_iter().next())
            .and_then(|peer| peer.as_mapping().cloned())
    {
        if host.is_empty() {
            host = peer
                .get(serde_yaml::Value::String("server".into()))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default()
                .to_string();
        }
        if port.is_none() {
            port = peer
                .get(serde_yaml::Value::String("port".into()))
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                })
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value != 0);
        }
    }

    if !endpoint_optional && (host.is_empty() || port.is_none()) {
        debug!(
            target: "feeds::parser",
            %name,
            %kind,
            "skip structured subscription node without a valid endpoint"
        );
        return None;
    }
    if host.is_empty() {
        host = "0.0.0.0".into();
    }
    let port = port.unwrap_or(0);

    let mut node = ParsedNode::new(name, proto.clone(), host, port);
    node.raw = serde_yaml::to_string(&serde_yaml::Value::Mapping(m.clone())).unwrap_or_default();
    node.params.insert("subscription-type".into(), kind.clone());
    node.params.insert(
        "subscription-format".into(),
        match flavor {
            StructuredFlavor::Native => "wuther",
            StructuredFlavor::Mihomo => "mihomo",
        }
        .into(),
    );
    if type_detected {
        node.params
            .insert("subscription-type-detected".into(), "1".into());
    }
    if let Ok(json) = serde_json::to_string(&serde_yaml::Value::Mapping(m.clone())) {
        node.params.insert("subscription-raw".into(), json.clone());
        if matches!(flavor, StructuredFlavor::Mihomo) {
            node.params.insert("mihomo-raw".into(), json);
        }
    }
    if matches!(flavor, StructuredFlavor::Mihomo) {
        node.params.insert("mihomo-type".into(), kind.clone());
    }
    node.user = str_g("username").or_else(|| str_g("user"));
    if matches!(proto, NodeProtocol::Young) {
        node.user = str_g("key")
            .or_else(|| str_g("secret"))
            .or(node.user.take());
    }
    node.password = str_g("password");
    node.uuid = str_g("uuid").or_else(|| str_g("id"));
    node.method = str_g("cipher").or_else(|| str_g("method"));
    node.tls = g("tls").and_then(|v| v.as_bool()).unwrap_or(false)
        || matches!(
            &proto,
            NodeProtocol::Trojan
                | NodeProtocol::Naive
                | NodeProtocol::Hysteria2
                | NodeProtocol::Tuic
                | NodeProtocol::AnyTls
                | NodeProtocol::Young
                | NodeProtocol::TrustTunnel
        );
    node.sni = str_g("sni")
        .or_else(|| str_g("servername"))
        .or_else(|| str_g("server-name"));
    if let Some(net) = str_g("network") {
        node.transport = net;
    } else if matches!(proto, NodeProtocol::Young) {
        node.transport = "webtransport".into();
    }
    if let Some(udp) = g("udp").and_then(|v| v.as_bool()) {
        node.udp = udp;
    }

    /* ============================================================
    关键：把全部顶层标量字段 + 嵌套 transport-opts 平铺到 node.params。
    下游 registry::build_outbound 通过 params.get() 读 skip-cert-verify /
    alpn / ws-path / grpc-service-name / reality public-key 等。
    否则 Clash YAML 订阅的"假 SNI + skip-cert-verify"无法生效，
    证书校验会用真实服务端 cert 失败（用户实际遭遇）。
    ============================================================ */

    // 1. 全部顶层字段。标量保持原形；映射与数组编码为 JSON，使任何
    // Mihomo 新增字段都不会在 ParsedNode 兼容层里静默丢失。
    for (k, v) in m.iter() {
        let Some(key) = k.as_str() else { continue };
        if matches!(
            key,
            // 已经映射到 ParsedNode 字段的，避免重复
            "name"
                | "type"
                | "protocol"
                | "kind"
                | "tag"
                | "label"
                | "server"
                | "host"
                | "address"
                | "endpoint"
                | "port"
                | "username"
                | "user"
                | "password"
                | "uuid"
                | "id"
                | "cipher"
                | "method"
                | "tls"
                | "sni"
                | "servername"
                | "server-name"
                | "network"
                | "udp"
        ) {
            continue;
        }
        if let Some(s) = scalar_to_string(v) {
            node.params.insert(key.to_string(), s);
        } else if let Ok(json) = serde_json::to_string(v) {
            node.params.insert(key.to_string(), json);
        }
    }

    if matches!(proto, NodeProtocol::Young) {
        for (canonical, aliases) in [
            (
                "pin-sha256",
                &["pin_sha256", "pin", "certificate-sha256"][..],
            ),
            ("padding-min", &["padding_min"][..]),
            ("padding-max", &["padding_max"][..]),
            ("idle-secs", &["idle_secs"][..]),
            ("max-streams", &["max_streams"][..]),
        ] {
            if node.params.contains_key(canonical) {
                continue;
            }
            if let Some(value) = aliases
                .iter()
                .find_map(|alias| g(alias).and_then(|value| scalar_to_string(&value)))
            {
                node.params.insert(canonical.into(), value);
            }
        }
    }

    // WireGuard 的标准多 peer / 列表字段不能按普通“仅标量”路径丢弃。
    // 统一保存为 JSON，registry 再做严格别名、类型和冲突校验。
    if matches!(&proto, NodeProtocol::Wireguard) {
        if let Some(network) = str_g("network") {
            node.params.insert("network".into(), network);
        }
        for key in ["allowed-ips", "dns", "reserved", "peers"] {
            if let Some(value) = g(key)
                && let Ok(json) = serde_json::to_string(&value)
            {
                node.params.insert(key.into(), json);
            }
        }
    }

    // 2. allowInsecure 别名归一 —— 让下游 registry 只看一个键。
    for alias in [
        "skip-cert-verify",
        "skipCertVerify",
        "allow-insecure",
        "insecure",
    ] {
        if let Some(v) = g(alias).and_then(|v| scalar_to_string(&v)) {
            // 任一变种命中 → 同时设 allowInsecure（registry 当前主键）
            if v == "1" || v.eq_ignore_ascii_case("true") {
                node.params.insert("allowInsecure".into(), "1".into());
            }
        }
    }

    // 3. alpn：YAML list → 逗号字符串
    if let Some(seq) = g("alpn").and_then(|v| v.as_sequence().cloned()) {
        let joined = seq
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
            .join(",");
        if !joined.is_empty() {
            node.params.insert("alpn".into(), joined);
        }
    }

    // SSH 的主机公钥和算法字段在 mihomo 中是字符串数组。ParsedNode 的
    // 兼容参数表只存字符串，因此分别用换行和逗号保存，避免通用标量路径
    // 静默丢弃这些安全关键字段。
    if matches!(proto, NodeProtocol::Ssh) {
        for (field, separator) in [("host-key", "\n"), ("host-key-algorithms", ",")] {
            if let Some(sequence) = g(field).and_then(|value| value.as_sequence().cloned()) {
                let joined = sequence
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(separator);
                if !joined.is_empty() {
                    node.params.insert(field.into(), joined);
                }
            }
        }
    }

    // 4. transport-opts 平铺
    flatten_transport_opts(m, "ws-opts", &["path", "headers"], &mut node.params, "ws-");
    flatten_transport_opts(m, "grpc-opts", &["grpc-service-name"], &mut node.params, "");
    flatten_transport_opts(m, "h2-opts", &["host", "path"], &mut node.params, "h2-");
    flatten_transport_opts(
        m,
        "reality-opts",
        &["public-key", "short-id"],
        &mut node.params,
        "reality-",
    );
    flatten_transport_opts(
        m,
        "ech-opts",
        &["enable", "config"],
        &mut node.params,
        "ech-",
    );

    // 5. ws-opts 嵌套 path / headers（headers 是 map）
    if let Some(ws_opts) = g("ws-opts").and_then(|v| v.as_mapping().cloned()) {
        if let Some(path) = ws_opts
            .get(serde_yaml::Value::String("path".into()))
            .and_then(|v| v.as_str())
        {
            node.params.insert("path".into(), path.to_string());
        }
        if let Some(headers) = ws_opts
            .get(serde_yaml::Value::String("headers".into()))
            .and_then(|v| v.as_mapping().cloned())
            && let Some(host) = headers
                .get(serde_yaml::Value::String("Host".into()))
                .or_else(|| headers.get(serde_yaml::Value::String("host".into())))
            && let Some(host) = host.as_str()
        {
            node.params.insert("host".into(), host.to_string());
        }
    }
    if let Some(grpc) = g("grpc-opts").and_then(|v| v.as_mapping().cloned())
        && let Some(svc) = grpc
            .get(serde_yaml::Value::String("grpc-service-name".into()))
            .and_then(|v| v.as_str())
    {
        node.params.insert("serviceName".into(), svc.to_string());
    }

    // Naive's extra headers are a map rather than scalars. Preserve them with
    // an unambiguous prefix for core-outbound.
    for key in ["extra-headers", "extra_headers"] {
        if let Some(headers) = g(key).and_then(|v| v.as_mapping().cloned()) {
            for (name, value) in headers {
                if let (Some(name), Some(value)) = (name.as_str(), scalar_to_string(&value)) {
                    node.params.insert(format!("extra-header.{name}"), value);
                }
            }
        }
    }

    if let Err(error) = validate_young_node(&node) {
        debug!(
            target: "feeds::parser",
            %error,
            "skip invalid structured Young node"
        );
        return None;
    }
    Some(node)
}

/// YAML scalar → string；bool / number / string 都接收，其它跳过。
fn scalar_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(if *b { "1".into() } else { "0".into() }),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn first_port(value: &str) -> Option<u16> {
    value
        .split([',', '-'])
        .map(str::trim)
        .find(|part| !part.is_empty())
        .and_then(|part| part.parse::<u16>().ok())
        .filter(|port| *port != 0)
}

/// 把 `parent.{key1, key2, ...}` 子映射展开到 params；可选加前缀。
fn flatten_transport_opts(
    m: &serde_yaml::Mapping,
    parent: &str,
    keys: &[&str],
    params: &mut std::collections::BTreeMap<String, String>,
    prefix: &str,
) {
    let Some(child) = m
        .get(serde_yaml::Value::String(parent.into()))
        .and_then(|v| v.as_mapping().cloned())
    else {
        return;
    };
    for k in keys {
        if let Some(v) = child.get(serde_yaml::Value::String((*k).into()))
            && let Some(s) = scalar_to_string(v)
        {
            params.insert(format!("{prefix}{k}"), s);
        }
    }
}

#[derive(Deserialize)]
struct Sip008 {
    servers: Vec<Sip008Server>,
}
#[derive(Deserialize)]
struct Sip008Server {
    remarks: Option<String>,
    server: String,
    server_port: u16,
    method: String,
    password: String,
}

fn parse_sip008(s: &str) -> Vec<ParsedNode> {
    let r: Sip008 = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "feeds::parser", error = %e, "sip008 parse failed");
            return Vec::new();
        }
    };
    r.servers
        .into_iter()
        .map(|s| {
            let mut n = ParsedNode::new(
                s.remarks.unwrap_or_else(|| format!("ss-{}", s.server)),
                NodeProtocol::Shadowsocks,
                s.server,
                s.server_port,
            );
            n.method = Some(s.method);
            n.password = Some(s.password);
            n
        })
        .collect()
}

/* ---------------- 过滤 / 重命名 ---------------- */

pub fn apply_filter_rename(detail: &FeedDetail, mut nodes: Vec<ParsedNode>) -> Vec<ParsedNode> {
    // Mihomo provider regex syntax allows look-around and splits multiple
    // expressions with a backtick. `fancy_regex` covers those constructs.
    let include = compile_provider_regexes(detail.filter.as_deref(), "filter");
    let exclude = compile_provider_regexes(detail.exclude_filter.as_deref(), "exclude-filter");
    let excluded_types = detail
        .exclude_type
        .as_deref()
        .unwrap_or_default()
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<std::collections::HashSet<_>>();
    nodes.retain(|node| {
        let protocol = node
            .params
            .get("subscription-type")
            .or_else(|| node.params.get("mihomo-type"))
            .map(String::as_str)
            .unwrap_or_else(|| node.protocol.as_str());
        if excluded_types.contains(&protocol.to_ascii_lowercase()) {
            return false;
        }
        if exclude
            .iter()
            .any(|regex| regex.is_match(&node.name).unwrap_or(false))
        {
            return false;
        }
        include.is_empty()
            || include
                .iter()
                .any(|regex| regex.is_match(&node.name).unwrap_or(false))
    });

    // drop 优先级 > keep
    if !detail.drop.name_has.is_empty() {
        let drops = detail.drop.name_has.clone();
        nodes.retain(|n| !drops.iter().any(|d| n.name.contains(d)));
    }
    if !detail.keep.name_has.is_empty() {
        let keeps = detail.keep.name_has.clone();
        nodes.retain(|n| keeps.iter().any(|k| n.name.contains(k)));
    }
    if let Some(prefix) = detail.rename.add_prefix.as_ref() {
        for n in &mut nodes {
            if !n.name.starts_with(prefix) {
                n.name = format!("{prefix}{}", n.name);
            }
        }
    }
    if !detail.rename.remove.is_empty() {
        for n in &mut nodes {
            for r in &detail.rename.remove {
                if !r.is_empty() {
                    n.name = n.name.replace(r, "");
                }
            }
            n.name = n.name.trim().to_string();
        }
    }
    detail.apply_overrides(&mut nodes);
    // 名称去重（保留先到的）
    let mut seen = std::collections::HashSet::new();
    nodes.retain(|n| seen.insert(n.name.clone()));
    nodes
}

fn compile_provider_regexes(value: Option<&str>, field: &str) -> Vec<fancy_regex::Regex> {
    value
        .unwrap_or_default()
        .split('`')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .filter_map(|pattern| match fancy_regex::Regex::new(pattern) {
            Ok(regex) => Some(regex),
            Err(error) => {
                warn!(
                    target: "feeds::parser",
                    field,
                    pattern,
                    %error,
                    "ignore invalid provider regex"
                );
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use core_config::model::{FeedDetail, FeedFilter, FeedRename};

    use super::*;

    fn detail() -> FeedDetail {
        FeedDetail {
            url: String::new(),
            payload: Vec::new(),
            every: Duration::from_secs(3600),
            via: "direct".into(),
            keep: FeedFilter::default(),
            drop: FeedFilter::default(),
            rename: FeedRename::default(),
            age_secret_key: None,
            size_limit: None,
            headers: Default::default(),
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            overrides: Default::default(),
        }
    }

    #[test]
    fn parse_plain_uri() {
        let s = "trojan://pwd@example.com:443?sni=example.com#HK-1\nss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#JP-1\n";
        let nodes = parse_feed_payload(s.as_bytes(), FormatHint::PlainUri);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "HK-1");
        assert_eq!(nodes[1].name, "JP-1");
    }

    #[test]
    fn parse_base64_subscription() {
        let inner = "trojan://pwd@example.com:443?sni=example.com#HK-1\nss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#JP-1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let nodes = parse_feed_payload(b64.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn parse_base64_wrapped_mihomo_yaml() {
        let yaml = "proxies:\n  - {name: DIRECT, type: direct}\n  - {name: BLOCK, type: reject}\n";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(yaml);
        let nodes = parse_feed_payload(encoded.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, NodeProtocol::Direct);
        assert_eq!(nodes[1].protocol, NodeProtocol::Block);
    }

    #[test]
    fn parses_native_compact_young_node_with_explicit_type() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a; 32]);
        let pin = "ab".repeat(32);
        let yaml = format!(
            r#"
version: 1
nodes:
  - name: Young Native
    type: young
    server: young.example.com
    port: 443
    key: {key}
    sni: young.example.com
    pin-sha256: {pin}
    authority: edge.example.com
    path: /assets
"#
        );
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.protocol, NodeProtocol::Young);
        assert_eq!(node.host, "young.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.user.as_deref(), Some(key.as_str()));
        assert_eq!(node.params["pin-sha256"], pin);
        assert_eq!(node.params["authority"], "edge.example.com");
        assert_eq!(node.transport, "webtransport");
        assert_eq!(node.params["subscription-format"], "wuther");
        assert!(!node.params.contains_key("subscription-type-detected"));
    }

    #[test]
    fn auto_detects_young_in_named_native_node_map() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33; 32]);
        let pin = "cd".repeat(32);
        let yaml = format!(
            r#"
nodes:
  Young Auto:
    server: 203.0.113.9
    port: 8443
    key: {key}
    sni: young.example.com
    pin_sha256: {pin}
"#
        );
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.name, "Young Auto");
        assert_eq!(node.protocol, NodeProtocol::Young);
        assert_eq!(node.params["pin-sha256"], pin);
        assert_eq!(node.params["subscription-type"], "young");
        assert_eq!(node.params["subscription-type-detected"], "1");
    }

    #[test]
    fn native_subscription_auto_detects_strongly_typed_young_node_spec() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x44; 32]);
        let pin = "ef".repeat(32);
        let yaml = format!(
            r#"
nodes:
  - name: Young Typed
    address: "[2001:db8::1]:443"
    login:
      user: {key}
    secure:
      tls: true
      sni: young.example.com
    params:
      pin-sha256: {pin}
      authority: young.example.com
      path: /native
"#
        );
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::WutherYaml);
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.protocol, NodeProtocol::Young);
        assert_eq!(node.host, "2001:db8::1");
        assert_eq!(node.port, 443);
        assert_eq!(node.user.as_deref(), Some(key.as_str()));
        assert_eq!(node.params["path"], "/native");
        assert_eq!(node.params["subscription-format"], "wuther");
        assert_eq!(node.params["subscription-type-detected"], "1");
    }

    #[test]
    fn base64_native_document_is_recursively_detected() {
        let yaml = r#"
nodes:
  Direct: {type: direct}
  Block: {type: reject}
"#;
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(yaml);
        let nodes = parse_feed_payload(encoded.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, NodeProtocol::Direct);
        assert_eq!(nodes[1].protocol, NodeProtocol::Block);
    }

    #[test]
    fn native_document_accepts_uri_and_structured_nodes_together() {
        let yaml = r#"
nodes:
  - "socks5://127.0.0.1:1080#Local URI"
  - name: Auto SS
    server: 192.0.2.10
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, NodeProtocol::Socks5);
        assert_eq!(nodes[1].protocol, NodeProtocol::Shadowsocks);
        assert_eq!(nodes[1].params["subscription-type-detected"], "1");
    }

    #[test]
    fn checked_parser_rejects_garbage_but_accepts_explicit_empty_manifest() {
        assert!(matches!(
            parse_feed_payload_checked(b"not a subscription", FormatHint::Auto),
            Err(ParseError::NoValidNode { .. })
        ));
        assert_eq!(
            parse_feed_payload_checked(b"version: 1\nnodes: []\n", FormatHint::Auto)
                .unwrap()
                .len(),
            0
        );
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("version: 1\nnodes: []\n");
        assert!(
            parse_feed_payload_checked(encoded.as_bytes(), FormatHint::Auto)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            parse_feed_payload_checked(
                b"version: 2\nnodes:\n  - {name: DIRECT, type: direct}\n",
                FormatHint::Auto
            ),
            Err(ParseError::NoValidNode { .. })
        ));
    }

    #[test]
    fn repository_native_subscription_example_stays_executable() {
        let nodes = parse_feed_payload(
            include_str!("../../../examples/subscription-native.yaml").as_bytes(),
            FormatHint::Auto,
        );
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].protocol, NodeProtocol::Young);
        assert_eq!(nodes[1].protocol, NodeProtocol::Young);
        assert_eq!(nodes[2].protocol, NodeProtocol::Socks5);
        assert_eq!(nodes[1].params["subscription-type-detected"], "1");
    }

    #[test]
    fn parse_clash_yaml_proxies() {
        let yaml = r#"
proxies:
  - name: HK-1
    type: trojan
    server: example.com
    port: 443
    password: pwd
    sni: example.com
  - name: JP-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pwd
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, NodeProtocol::Trojan);
        assert_eq!(nodes[1].method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn parse_naive_clash_headers_and_transport_options() {
        let yaml = r#"
proxies:
  - name: Naive-H3
    type: naive
    server: proxy.example.com
    port: 443
    username: alice
    password: secret
    udp: true
    udp-over-tcp: true
    quic: true
    extra-headers:
      X-Client: WutherCore
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].protocol, NodeProtocol::Naive);
        assert_eq!(nodes[0].user.as_deref(), Some("alice"));
        assert_eq!(
            nodes[0]
                .params
                .get("extra-header.X-Client")
                .map(String::as_str),
            Some("WutherCore")
        );
        assert_eq!(
            nodes[0].params.get("udp-over-tcp").map(String::as_str),
            Some("1")
        );
        assert_eq!(nodes[0].params.get("quic").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_anytls_clash_session_options() {
        let yaml = r#"
proxies:
  - name: AnyTLS-v2
    type: anytls
    server: proxy.example.com
    port: 443
    password: secret
    sni: edge.example.com
    udp: true
    idle-session-check-interval: 31s
    idle-session-timeout: 45s
    min-idle-session: 2
    disable-reuse: false
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].protocol, NodeProtocol::AnyTls);
        assert_eq!(nodes[0].password.as_deref(), Some("secret"));
        assert!(nodes[0].tls);
        assert_eq!(
            nodes[0]
                .params
                .get("idle-session-check-interval")
                .map(String::as_str),
            Some("31s")
        );
        assert_eq!(
            nodes[0].params.get("min-idle-session").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            nodes[0].params.get("disable-reuse").map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn parses_every_mihomo_v1_19_29_proxy_type_without_field_loss() {
        let yaml = r#"
proxies:
  - {name: ss, type: ss, server: proxy.example, port: 443}
  - {name: ssr, type: ssr, server: proxy.example, port: 443}
  - {name: socks5, type: socks5, server: proxy.example, port: 443}
  - {name: http, type: http, server: proxy.example, port: 443}
  - {name: vmess, type: vmess, server: proxy.example, port: 443}
  - {name: vless, type: vless, server: proxy.example, port: 443}
  - {name: snell, type: snell, server: proxy.example, port: 443}
  - {name: trojan, type: trojan, server: proxy.example, port: 443}
  - {name: hysteria, type: hysteria, server: proxy.example, ports: "20000-20010"}
  - {name: hysteria2, type: hysteria2, server: proxy.example, ports: "30000,30001"}
  - name: wireguard
    type: wireguard
    peers:
      - {server: wg.example, port: 51820, public-key: abc}
  - {name: tuic, type: tuic, server: proxy.example, port: 443}
  - {name: shadowquic, type: shadowquic, server: proxy.example, port: 443}
  - {name: gost-relay, type: gost-relay, server: proxy.example, port: 443}
  - {name: direct, type: direct}
  - {name: dns, type: dns}
  - {name: reject, type: reject}
  - {name: rematch, type: rematch}
  - {name: ssh, type: ssh, server: proxy.example, port: 22}
  - {name: mieru, type: mieru, server: proxy.example, port-range: "40000-40010"}
  - {name: anytls, type: anytls, server: proxy.example, port: 443}
  - {name: sudoku, type: sudoku, server: proxy.example, port: 443}
  - {name: masque, type: masque, server: proxy.example, port: 443}
  - {name: trusttunnel, type: trusttunnel, server: proxy.example, port: 443}
  - {name: openvpn, type: openvpn, server: proxy.example, port: 1194}
  - {name: tailscale, type: tailscale, auth-key: tskey-auth-example}
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::ClashYaml);
        assert_eq!(nodes.len(), 26);
        assert_eq!(nodes[8].port, 20_000);
        assert_eq!(nodes[9].port, 30_000);
        assert_eq!(nodes[10].host, "wg.example");
        assert_eq!(nodes[19].port, 40_000);

        let unsupported = nodes
            .iter()
            .filter_map(|node| match &node.protocol {
                NodeProtocol::Other(protocol) => Some(protocol.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            unsupported,
            [
                "shadowquic",
                "gost-relay",
                "rematch",
                "masque",
                "openvpn",
                "tailscale"
            ]
        );
        let wireguard = &nodes[10];
        assert!(wireguard.params["peers"].contains("public-key"));
        assert!(wireguard.params["mihomo-raw"].contains("\"peers\""));
        assert!(!wireguard.raw.is_empty());
    }

    #[test]
    fn rejects_zero_and_out_of_range_ports_instead_of_wrapping() {
        let yaml = "proxies:\n  - {name: zero, type: trojan, server: example.com, port: 0}\n  - {name: overflow, type: trojan, server: example.com, port: 65537}\n";
        assert!(parse_feed_payload(yaml.as_bytes(), FormatHint::ClashYaml).is_empty());
    }

    #[test]
    fn provider_client_id_override_only_changes_anytls_nodes() {
        let yaml = r#"
proxies:
  - name: AnyTLS
    type: anytls
    server: proxy.example.com
    port: 443
    password: secret
    clientId: upstream-client/1.0
  - name: Trojan
    type: trojan
    server: proxy.example.com
    port: 443
    password: secret
"#;
        let mut detail = detail();
        detail.overrides.client_id = Some("sing-anytls/0.0.11".into());
        let nodes = apply_filter_rename(
            &detail,
            parse_feed_payload(yaml.as_bytes(), FormatHint::Auto),
        );

        assert_eq!(
            nodes[0].params.get("clientId").map(String::as_str),
            Some("sing-anytls/0.0.11")
        );
        assert!(!nodes[1].params.contains_key("clientId"));
    }

    #[test]
    fn parse_clash_wireguard_preserves_lists_and_multi_peer_objects() {
        let yaml = r#"
proxies:
  - name: WG-full
    type: wireguard
    server: 127.0.0.1
    port: 51820
    private-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    ip: 10.0.0.2/32
    ipv6: fd00::2/128
    mtu: 1380
    udp: true
    network: tcp,udp
    dns: [10.0.0.53, "fd00::53"]
    remote-dns-resolve: true
    peers:
      - server: 192.0.2.1
        port: 51820
        public-key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
        allowed-ips: [10.0.0.0/8]
        reserved: [1, 2, 3]
      - server: "2001:db8::1"
        port: 51821
        public-key: AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
        allowed-ips: ["fd00::/8"]
        persistent-keepalive: 0
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::ClashYaml);
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.protocol, NodeProtocol::Wireguard);
        assert_eq!(
            node.params.get("network").map(String::as_str),
            Some("tcp,udp")
        );
        assert_eq!(
            node.params.get("remote-dns-resolve").map(String::as_str),
            Some("1")
        );
        let dns: serde_json::Value = serde_json::from_str(node.params.get("dns").unwrap()).unwrap();
        assert_eq!(dns.as_array().unwrap().len(), 2);
        let peers: serde_json::Value =
            serde_json::from_str(node.params.get("peers").unwrap()).unwrap();
        assert_eq!(peers.as_array().unwrap().len(), 2);
        assert_eq!(peers[0]["reserved"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn parse_clash_ssh_preserves_username_host_keys_and_algorithms() {
        let yaml = r#"
proxies:
  - name: SSH
    type: ssh
    server: ssh.example.com
    port: 22
    username: alice
    password: secret
    host-key:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2U"
      - "rsa-sha2-256 AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
    host-key-algorithms: [ed25519, rsa]
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].user.as_deref(), Some("alice"));
        assert_eq!(
            nodes[0].params.get("host-key").map(String::as_str),
            Some(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2U\n\
                 rsa-sha2-256 AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
            )
        );
        assert_eq!(
            nodes[0]
                .params
                .get("host-key-algorithms")
                .map(String::as_str),
            Some("ed25519,rsa")
        );
    }

    #[test]
    fn keep_drop_rename_dedup() {
        let nodes = parse_feed_payload(
            (b"trojan://pwd@a:443#HK-1x\n\
              trojan://pwd@b:443#JP-2x\n\
              trojan://pwd@c:443#US-3x\n\
              trojan://pwd@d:443#Expire-2026")
                .as_ref(),
            FormatHint::PlainUri,
        );
        assert_eq!(nodes.len(), 4);
        let mut d = detail();
        d.keep.name_has = vec!["HK".into(), "JP".into(), "US".into()];
        d.drop.name_has = vec!["Expire".into()];
        d.rename.remove = vec!["x".into()];
        d.rename.add_prefix = Some("B-".into());
        let out = apply_filter_rename(&d, nodes);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].name, "B-HK-1");
        assert_eq!(out[2].name, "B-US-3");
    }

    #[test]
    fn mihomo_provider_filters_support_lookaround_and_excluded_types() {
        let yaml = r#"
proxies:
  - {name: "HK premium", type: trojan, server: a.example, port: 443}
  - {name: "HK expired", type: trojan, server: b.example, port: 443}
  - {name: "HK direct", type: direct}
"#;
        let mut detail = detail();
        detail.filter = Some(r"^HK(?= )".into());
        detail.exclude_filter = Some("expired".into());
        detail.exclude_type = Some("direct|reject".into());
        let nodes = apply_filter_rename(
            &detail,
            parse_feed_payload(yaml.as_bytes(), FormatHint::ClashYaml),
        );
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "HK premium");
    }
}
