//! Windows process lookup backed by `netstat2`'s IP Helper API integration and
//! `sysinfo`'s native process metadata implementation.

use std::net::IpAddr;

use crate::{NetworkProto, ProcessFinder, ProcessInfo, system};

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFinder;

impl WindowsFinder {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessFinder for WindowsFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        system::find_process(proto, src_ip, src_port, None)
    }

    fn find_with_dst(
        &self,
        proto: NetworkProto,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<ProcessInfo> {
        system::find_process(proto, src_ip, src_port, Some((dst_ip, dst_port)))
    }
}
