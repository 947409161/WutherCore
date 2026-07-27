//! Mihomo 配置迁移工具 —— §13.3。
//!
//! MVP：把 mihomo 的 `port`/`socks-port`/`mixed-port`/`proxy-providers`/
//! `proxies` 等字段映射为 Friendly YAML。完整字段映射会在 M6 完善。

use std::collections::BTreeMap;

use serde_yaml::Value;

use crate::{
    error::{ConfigError, ConfigResult},
    model::MihomoRuleProviderSpec,
};

/// 把 Mihomo YAML 文本转换为 Friendly YAML 文本。
pub fn migrate_mihomo(text: &str) -> ConfigResult<String> {
    let m: Value = serde_yaml::from_str(text)?;
    let m = m.as_mapping().ok_or_else(|| {
        ConfigError::invalid("Mihomo YAML 顶层必须是 mapping").hint("请检查文件是否为 YAML object")
    })?;

    let mut friendly = serde_yaml::Mapping::new();
    friendly.insert("version".into(), 1.into());
    friendly.insert("profile".into(), "desktop".into());

    // listen
    let mut listen = serde_yaml::Mapping::new();
    if let Some(p) = m
        .get(&Value::String("mixed-port".into()))
        .and_then(Value::as_u64)
    {
        listen.insert("local".into(), (p as u64).into());
    } else if let Some(p) = m.get(&Value::String("port".into())).and_then(Value::as_u64) {
        listen.insert("local".into(), (p as u64).into());
    }
    if let Some(controller) = m
        .get(&Value::String("external-controller".into()))
        .and_then(Value::as_str)
    {
        listen.insert("panel".into(), Value::String(controller.into()));
    }
    if !listen.is_empty() {
        friendly.insert("listen".into(), Value::Mapping(listen));
    }

    // feeds 来自 proxy-providers
    let mut feeds: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(providers) = m
        .get(&Value::String("proxy-providers".into()))
        .and_then(Value::as_mapping)
    {
        for (k, v) in providers {
            let Some(name) = k.as_str() else { continue };
            let Some(provider) = v.as_mapping() else {
                continue;
            };
            let source = provider
                .get(Value::String("url".into()))
                .or_else(|| provider.get(Value::String("path".into())))
                .and_then(Value::as_str);
            let payload = provider
                .get(Value::String("payload".into()))
                .and_then(Value::as_sequence);
            if source.is_none() && payload.is_none() {
                continue;
            }
            let mut detail = serde_yaml::Mapping::new();
            if let Some(source) = source {
                detail.insert("url".into(), source.into());
            }
            if let Some(payload) = payload {
                detail.insert("payload".into(), Value::Sequence(payload.clone()));
            }
            for key in [
                "age-secret-key",
                "size-limit",
                "header",
                "filter",
                "exclude-filter",
                "exclude-type",
            ] {
                if let Some(value) = provider.get(Value::String(key.into())) {
                    detail.insert(key.into(), value.clone());
                }
            }
            if let Some(interval) = provider
                .get(Value::String("interval".into()))
                .and_then(Value::as_u64)
            {
                detail.insert("every".into(), format!("{interval}s").into());
            }
            let mut overrides = serde_yaml::Mapping::new();
            if let Some(source) = provider
                .get(Value::String("override".into()))
                .and_then(Value::as_mapping)
            {
                for key in [
                    "clientId",
                    "client-id",
                    "client_id",
                    "tfo",
                    "mptcp",
                    "udp",
                    "udp-over-tcp",
                    "up",
                    "down",
                    "dialer-proxy",
                    "skip-cert-verify",
                    "name-cert-verify",
                    "interface-name",
                    "routing-mark",
                    "ip-version",
                    "additional-prefix",
                    "additional-suffix",
                    "proxy-name",
                ] {
                    if let Some(value) = source.get(Value::String(key.into())) {
                        overrides.insert(key.into(), value.clone());
                    }
                }
            }
            if let Some(dialer_proxy) = provider.get(Value::String("dialer-proxy".into())) {
                overrides.insert("dialer-proxy".into(), dialer_proxy.clone());
            }
            if !overrides.is_empty() {
                detail.insert("override".into(), Value::Mapping(overrides));
            }
            if detail.len() == 1
                && let Some(source) = source
            {
                feeds.insert(name.to_string(), Value::String(source.to_string()));
            } else {
                feeds.insert(name.to_string(), Value::Mapping(detail));
            }
        }
    }
    if !feeds.is_empty() {
        let mut map = serde_yaml::Mapping::new();
        for (k, v) in feeds {
            map.insert(Value::String(k), v);
        }
        friendly.insert("feeds".into(), Value::Mapping(map));
    }

    // proxies -> nodes
    let mut nodes = Vec::new();
    if let Some(proxies) = m
        .get(&Value::String("proxies".into()))
        .and_then(Value::as_sequence)
    {
        for p in proxies {
            if let Some(map) = p.as_mapping() {
                if let Some(name) = map
                    .get(&Value::String("name".into()))
                    .and_then(Value::as_str)
                {
                    if let Some(uri) = mihomo_proxy_to_uri(map) {
                        nodes.push(Value::String(format!("{}#{}", uri, name)));
                    }
                }
            }
        }
    }
    if !nodes.is_empty() {
        friendly.insert("nodes".into(), Value::Sequence(nodes));
    }

    // route preset + rule-providers -> 原生 route.sets。使用与 loader 相同的
    // 严格归一化逻辑，避免 migrate 接受、运行时却忽略某个 provider 字段。
    let mut route = serde_yaml::Mapping::new();
    route.insert("preset".into(), Value::String("cn_smart".into()));
    if let Some(providers) = m
        .get(Value::String("rule-providers".into()))
        .and_then(Value::as_mapping)
    {
        let providers: BTreeMap<String, MihomoRuleProviderSpec> =
            serde_yaml::from_value(Value::Mapping(providers.clone()))?;
        let sets = crate::ruleset_compat::normalize_mihomo_rule_providers(providers)?;
        if !sets.is_empty() {
            let value = serde_yaml::to_value(sets).map_err(ConfigError::from)?;
            route.insert("sets".into(), value);
        }
    }
    friendly.insert("route".into(), Value::Mapping(route));

    serde_yaml::to_string(&Value::Mapping(friendly)).map_err(Into::into)
}

fn mihomo_proxy_to_uri(p: &serde_yaml::Mapping) -> Option<String> {
    let kind = p
        .get(&Value::String("type".into()))
        .and_then(Value::as_str)?;
    // type: dns 不需要 server/port —— 是本机 DNS hijack 出站。
    if kind.eq_ignore_ascii_case("dns") {
        return Some("dns://".to_string());
    }
    let host = p
        .get(&Value::String("server".into()))
        .and_then(Value::as_str)?;
    let port = p.get(&Value::String("port".into())).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })?;
    let pwd = p
        .get(&Value::String("password".into()))
        .and_then(Value::as_str);
    let uuid = p.get(&Value::String("uuid".into())).and_then(Value::as_str);
    Some(match kind {
        "ss" => {
            let cipher = p
                .get(&Value::String("cipher".into()))
                .and_then(Value::as_str)
                .unwrap_or("aes-256-gcm");
            let pwd = pwd.unwrap_or("");
            let userinfo =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{cipher}:{pwd}"));
            format!("ss://{userinfo}@{host}:{port}")
        }
        "trojan" => format!("trojan://{}@{host}:{port}?security=tls", pwd.unwrap_or("")),
        "vless" => format!("vless://{}@{host}:{port}?security=tls", uuid.unwrap_or("")),
        "vmess" => format!("vless://{}@{host}:{port}?security=tls", uuid.unwrap_or("")),
        "hysteria2" | "hy2" => format!("hysteria2://{}@{host}:{port}", pwd.unwrap_or("")),
        _ => return None,
    })
}

use base64::Engine;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn migration_preserves_anytls_provider_client_id_override() {
        let input = r#"
proxy-providers:
  airport:
    type: http
    url: "https://example.com/sub"
    override:
      clientId: "sing-anytls/0.0.11"
"#;
        let migrated = migrate_mihomo(input).unwrap();
        let plan = crate::loader::load_from_str(&migrated).unwrap();
        assert_eq!(
            plan.feeds["airport"].overrides.client_id.as_deref(),
            Some("sing-anytls/0.0.11")
        );
    }

    #[test]
    fn migration_preserves_mihomo_provider_fetch_and_filter_fields() {
        let input = r#"
proxy-providers:
  airport:
    type: http
    url: "https://example.com/sub"
    interval: 1800
    size-limit: 1048576
    age-secret-key: "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33"
    header:
      User-Agent: ["Mihomo/1.19"]
      X-Age-Public-Key: "age1example"
    filter: "^(HK|JP)"
    exclude-filter: "expired"
    exclude-type: "direct|reject"
    override:
      udp: false
      additional-prefix: "Airport "
"#;
        let migrated = migrate_mihomo(input).unwrap();
        let plan = crate::loader::load_from_str(&migrated).unwrap();
        let detail = &plan.feeds["airport"];
        assert_eq!(detail.every, Duration::from_secs(1800));
        assert_eq!(detail.size_limit, Some(1_048_576));
        assert_eq!(
            detail.age_secret_key.as_deref(),
            Some("AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33")
        );
        assert_eq!(
            detail.headers["User-Agent"].values(),
            &["Mihomo/1.19".to_string()]
        );
        assert_eq!(detail.filter.as_deref(), Some("^(HK|JP)"));
        assert_eq!(detail.exclude_type.as_deref(), Some("direct|reject"));
        assert_eq!(detail.overrides.udp, Some(false));
        assert_eq!(
            detail.overrides.additional_prefix.as_deref(),
            Some("Airport ")
        );
    }

    #[test]
    fn migration_preserves_file_and_inline_proxy_providers() {
        let input = r#"
proxy-providers:
  local:
    type: file
    path: "./providers/local.yaml"
  built-in:
    type: inline
    payload:
      - {name: DIRECT, type: direct}
"#;
        let migrated = migrate_mihomo(input).unwrap();
        let plan = crate::loader::load_from_str(&migrated).unwrap();
        assert_eq!(plan.feeds["local"].url, "./providers/local.yaml");
        assert_eq!(plan.feeds["built-in"].payload.len(), 1);
    }

    #[test]
    fn migrates_mihomo_rule_providers_into_native_route_sets() {
        let input = r#"
rule-providers:
  domain-set:
    type: http
    behavior: domain
    format: mrs
    url: "https://rules.example/domain.mrs"
    path: "./cache/domain.mrs"
    interval: 3600
    proxy: DIRECT
  inline-set:
    type: inline
    behavior: classical
    format: text
    payload:
      - "DOMAIN-SUFFIX,example.com"
"#;
        let migrated = migrate_mihomo(input).unwrap();
        assert!(migrated.contains("sets:"), "{migrated}");
        assert!(!migrated.contains("rule-providers:"), "{migrated}");

        let plan = crate::loader::load_from_str(&migrated).unwrap();
        let remote = &plan.route.sets["domain-set"];
        assert_eq!(remote.path.as_deref(), Some("./cache/domain.mrs"));
        assert_eq!(remote.every, Duration::from_secs(3600));
        assert_eq!(
            plan.route.sets["inline-set"].payload,
            vec!["DOMAIN-SUFFIX,example.com"]
        );
    }

    #[test]
    fn migration_rejects_provider_fields_the_runtime_cannot_honor() {
        let input = r#"
rule-providers:
  proxied:
    type: http
    behavior: domain
    url: "https://rules.example/domain.yaml"
    proxy: Proxy
"#;
        let error = migrate_mihomo(input).unwrap_err().to_string();
        assert!(error.contains("core-fetch"), "{error}");
        assert!(error.contains("proxy"), "{error}");
    }
}
