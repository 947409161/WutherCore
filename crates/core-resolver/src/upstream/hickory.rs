//! hickory-resolver 包装：DoH / DoT / UDP / TCP 上游。

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::{RData, Record, RecordType},
};

use super::{DnsError, DnsUpstream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HickoryKind {
    DoH,
    DoT,
    Udp,
    Tcp,
}

impl HickoryKind {
    fn label(&self) -> &'static str {
        match self {
            Self::DoH => "doh",
            Self::DoT => "dot",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
    fn connection(&self, server_name: Arc<str>) -> ConnectionConfig {
        match self {
            Self::DoH => ConnectionConfig::https(server_name, None),
            Self::DoT => ConnectionConfig::tls(server_name),
            Self::Udp => ConnectionConfig::udp(),
            Self::Tcp => ConnectionConfig::tcp(),
        }
    }
}

#[derive(Clone)]
pub struct HickoryUpstream {
    name: String,
    kind: HickoryKind,
    inner: Arc<TokioResolver>,
    client_subnet: Option<ipnet::IpNet>,
}

impl std::fmt::Debug for HickoryUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryUpstream")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish()
    }
}

impl HickoryUpstream {
    pub fn build(
        name: impl Into<String>,
        kind: HickoryKind,
        addr: SocketAddr,
        sni: Option<String>,
    ) -> Result<Self, DnsError> {
        let server_name: Arc<str> = sni
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| addr.ip().to_string())
            .into();
        let mut connection = kind.connection(server_name);
        connection.port = addr.port();
        let ns = NameServerConfig::new(addr.ip(), true, vec![connection]);
        let cfg = ResolverConfig::from_parts(None, vec![], vec![ns]);
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0; // 我们自己管缓存
        opts.attempts = 2;
        opts.timeout = std::time::Duration::from_secs(3);
        opts.use_hosts_file = ResolveHosts::Never;
        let mut builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
        *builder.options_mut() = opts;
        let resolver = builder
            .build()
            .map_err(|error| DnsError::Failed(format!("构造 DNS resolver 失败: {error}")))?;
        Ok(Self {
            name: name.into(),
            kind,
            inner: Arc::new(resolver),
            client_subnet: None,
        })
    }

    /// 设置 server 默认 ECS（与 sing-box `dns.servers[].client_subnet` 一致）。
    /// 字段已写入 upstream；下层 EDNS0 OPT 实际发送暂走 hickory 默认（待 hickory 0.25 升级）。
    pub fn with_client_subnet(mut self, net: ipnet::IpNet) -> Self {
        self.client_subnet = Some(net);
        self
    }

    /// 便捷构造：DoH URL。
    ///
    /// - `host` 可为 IP literal 或域名。
    /// - 域名会通过系统 DNS 同步解析一次（mihomo `default-nameserver` bootstrap
    ///   行为等价；用户应保证 default-nameserver 是 IP literal 以保证启动可达）。
    /// - SNI 默认就是 `host`（IP 时 rustls 走 IP-SAN 验证）。
    pub fn doh(
        name: impl Into<String>,
        host: &str,
        port: u16,
        sni: Option<String>,
    ) -> Result<Self, DnsError> {
        let addr = resolve_host_for_upstream(host, port, "DoH")?;
        Self::build(name, HickoryKind::DoH, addr, sni)
    }

    pub fn dot(
        name: impl Into<String>,
        host: &str,
        port: u16,
        sni: Option<String>,
    ) -> Result<Self, DnsError> {
        let addr = resolve_host_for_upstream(host, port, "DoT")?;
        Self::build(name, HickoryKind::DoT, addr, sni)
    }

    pub fn udp(name: impl Into<String>, addr: SocketAddr) -> Result<Self, DnsError> {
        Self::build(name, HickoryKind::Udp, addr, None)
    }
}

/// 把 `host:port` 解析为 SocketAddr。host 是 IP literal 直接组装；
/// host 是域名时走 std `to_socket_addrs`（getaddrinfo / Windows DNS API），
/// 等价于 mihomo bootstrap 用 system resolver 解析 default-nameserver 域名。
///
/// `kind_label` 仅用于错误信息（"DoH" / "DoT"）。
fn resolve_host_for_upstream(
    host: &str,
    port: u16,
    kind_label: &'static str,
) -> Result<SocketAddr, DnsError> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let target = format!("{host}:{port}");
    target
        .to_socket_addrs()
        .map_err(|e| DnsError::Failed(format!("{kind_label} host {host} 解析失败: {e}")))?
        .next()
        .ok_or_else(|| DnsError::Failed(format!("{kind_label} host {host} 解析为空")))
}

#[async_trait]
impl DnsUpstream for HickoryUpstream {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        self.kind.label()
    }
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.client_subnet
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let r = self
            .inner
            .ipv4_lookup(host)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let v: Vec<IpAddr> = r
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                _ => None,
            })
            .collect();
        if v.is_empty() {
            Err(DnsError::Empty)
        } else {
            Ok(v)
        }
    }
    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let r = self
            .inner
            .ipv6_lookup(host)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let v: Vec<IpAddr> = r
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect();
        if v.is_empty() {
            Err(DnsError::Empty)
        } else {
            Ok(v)
        }
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let r = self
            .inner
            .lookup(host.trim_end_matches('.'), record_type)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let records = r.answers().to_vec();
        if records.is_empty() {
            Err(DnsError::Empty)
        } else {
            Ok(records)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_accepts_ip_literal_host() {
        let up = HickoryUpstream::doh("ali", "223.5.5.5", 443, None);
        assert!(up.is_ok(), "DoH IP host should construct: {:?}", up.err());
    }

    #[test]
    fn doh_accepts_ipv6_literal_host() {
        let up = HickoryUpstream::doh("v6", "2606:4700:4700::1111", 443, None);
        assert!(up.is_ok(), "DoH IPv6 host should construct: {:?}", up.err());
    }

    #[test]
    fn dot_accepts_ip_literal_host() {
        let up = HickoryUpstream::dot("ali-dot", "223.5.5.5", 853, None);
        assert!(up.is_ok());
    }
}
