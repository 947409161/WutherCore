//! 订阅格式解析 + 过滤/重命名。

use base64::Engine;
use core_config::{
    model::FeedDetail,
    node_uri::{NodeProtocol, ParsedNode, parse_uri},
};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatHint {
    Auto,
    Base64,
    ClashYaml,
    PlainUri,
    Sip008,
}

/// 主入口：尝试自动嗅探格式并解析为节点列表。
pub fn parse_feed_payload(raw: &[u8], hint: FormatHint) -> Vec<ParsedNode> {
    parse_feed_payload_inner(raw, hint, 0)
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
    if nodes.is_empty() && actual != FormatHint::ClashYaml && trimmed.contains("proxies:") {
        nodes = parse_clash_yaml(trimmed);
    }
    nodes
}

fn sniff(s: &str) -> FormatHint {
    if s.starts_with('{') && s.contains("\"servers\"") {
        return FormatHint::Sip008;
    }
    if s.contains("proxies:") || s.starts_with("proxies:") {
        return FormatHint::ClashYaml;
    }
    if s.contains("://") {
        return FormatHint::PlainUri;
    }
    // 默认按 base64 尝试
    FormatHint::Base64
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
        if let Some(node) = clash_proxy_to_node(map) {
            out.push(node);
        }
    }
    out
}

fn clash_proxy_to_node(m: &serde_yaml::Mapping) -> Option<ParsedNode> {
    let g = |k: &str| m.get(&serde_yaml::Value::String(k.into())).cloned();
    let str_g = |k: &str| g(k).and_then(|v| v.as_str().map(String::from));
    let u16_g = |k: &str| {
        g(k).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
        })
    };

    let name = str_g("name")?;
    let kind = str_g("type")?.to_ascii_lowercase();
    let proto = match kind.as_str() {
        "reject" => NodeProtocol::Block,
        other => NodeProtocol::from_scheme(other),
    };
    let endpoint_optional = matches!(
        kind.as_str(),
        "direct" | "dns" | "reject" | "rematch" | "tailscale"
    );
    let mut host = str_g("server").unwrap_or_default();
    let mut port = u16_g("port");

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
            "skip mihomo node without a valid endpoint"
        );
        return None;
    }
    if host.is_empty() {
        host = "0.0.0.0".into();
    }
    let port = port.unwrap_or(0);

    let mut node = ParsedNode::new(name, proto.clone(), host, port);
    node.raw = serde_yaml::to_string(&serde_yaml::Value::Mapping(m.clone())).unwrap_or_default();
    node.params.insert("mihomo-type".into(), kind.clone());
    if let Ok(json) = serde_json::to_string(&serde_yaml::Value::Mapping(m.clone())) {
        node.params.insert("mihomo-raw".into(), json);
    }
    node.user = str_g("username").or_else(|| str_g("user"));
    node.password = str_g("password");
    node.uuid = str_g("uuid");
    node.method = str_g("cipher").or_else(|| str_g("method"));
    node.tls = g("tls").and_then(|v| v.as_bool()).unwrap_or(false)
        || matches!(
            &proto,
            NodeProtocol::Trojan
                | NodeProtocol::Naive
                | NodeProtocol::Hysteria2
                | NodeProtocol::Tuic
                | NodeProtocol::AnyTls
        );
    node.sni = str_g("sni").or_else(|| str_g("servername"));
    if let Some(net) = str_g("network") {
        node.transport = net;
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
                | "server"
                | "port"
                | "username"
                | "user"
                | "password"
                | "uuid"
                | "cipher"
                | "method"
                | "tls"
                | "sni"
                | "servername"
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
            .get(&serde_yaml::Value::String("path".into()))
            .and_then(|v| v.as_str())
        {
            node.params.insert("path".into(), path.to_string());
        }
        if let Some(headers) = ws_opts
            .get(&serde_yaml::Value::String("headers".into()))
            .and_then(|v| v.as_mapping().cloned())
        {
            if let Some(host) = headers
                .get(&serde_yaml::Value::String("Host".into()))
                .or_else(|| headers.get(&serde_yaml::Value::String("host".into())))
            {
                if let Some(s) = host.as_str() {
                    node.params.insert("host".into(), s.to_string());
                }
            }
        }
    }
    if let Some(grpc) = g("grpc-opts").and_then(|v| v.as_mapping().cloned()) {
        if let Some(svc) = grpc
            .get(&serde_yaml::Value::String("grpc-service-name".into()))
            .and_then(|v| v.as_str())
        {
            node.params.insert("serviceName".into(), svc.to_string());
        }
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
        .get(&serde_yaml::Value::String(parent.into()))
        .and_then(|v| v.as_mapping().cloned())
    else {
        return;
    };
    for k in keys {
        if let Some(v) = child.get(&serde_yaml::Value::String((*k).into())) {
            if let Some(s) = scalar_to_string(v) {
                params.insert(format!("{prefix}{k}"), s);
            }
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
            .get("mihomo-type")
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
