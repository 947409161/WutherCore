//! TUN 设备配置 —— 平台无关字段。具体打开/读写 IP 包由 platform/* 完成。

use std::num::NonZeroU16;

use ipnet::{Ipv4Net, Ipv6Net};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: NonZeroU16,
    pub ipv4: Ipv4Net,
    pub ipv6: Ipv6Net,
    pub auto_route: bool,
}

/// TUN 设备句柄抽象 —— 平台后端实现 read/write IP 包。
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mtu(&self) -> NonZeroU16;
    fn ipv4(&self) -> Ipv4Net;
    fn ipv6(&self) -> Ipv6Net;
}
