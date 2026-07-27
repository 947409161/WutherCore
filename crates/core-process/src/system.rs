//! Shared socket-to-process lookup using maintained platform crates.

use std::net::IpAddr;

use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
};
use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::{NetworkProto, ProcessInfo};

pub(crate) fn find_process(
    proto: NetworkProto,
    src_ip: IpAddr,
    src_port: u16,
    dst: Option<(IpAddr, u16)>,
) -> Option<ProcessInfo> {
    let family = match src_ip {
        IpAddr::V4(_) => AddressFamilyFlags::IPV4,
        IpAddr::V6(_) => AddressFamilyFlags::IPV6,
    };
    let protocol = match proto {
        NetworkProto::Tcp => ProtocolFlags::TCP,
        NetworkProto::Udp => ProtocolFlags::UDP,
    };
    let sockets = get_sockets_info(family, protocol)
        .map_err(|error| {
            tracing::debug!(target: "core-process", %error, "socket table lookup failed");
            error
        })
        .ok()?;

    let socket = best_socket(&sockets, proto, src_ip, src_port, dst)?;
    let pid = *socket.associated_pids.first()?;
    process_info(pid, socket_uid(socket))
}

fn best_socket<'a>(
    sockets: &'a [SocketInfo],
    proto: NetworkProto,
    src_ip: IpAddr,
    src_port: u16,
    dst: Option<(IpAddr, u16)>,
) -> Option<&'a SocketInfo> {
    sockets
        .iter()
        .filter_map(|socket| {
            let local_matches = socket.local_port() == src_port
                && (socket.local_addr() == src_ip || socket.local_addr().is_unspecified());
            if !local_matches {
                return None;
            }
            let score = match (&socket.protocol_socket_info, proto) {
                (ProtocolSocketInfo::Tcp(tcp), NetworkProto::Tcp) => {
                    if let Some((dst_ip, dst_port)) = dst
                        && (tcp.remote_addr != dst_ip || tcp.remote_port != dst_port)
                    {
                        return None;
                    }
                    2 + usize::from(tcp.local_addr == src_ip)
                }
                (ProtocolSocketInfo::Udp(_), NetworkProto::Udp) => {
                    1 + usize::from(socket.local_addr() == src_ip)
                }
                _ => return None,
            };
            Some((score, socket))
        })
        .max_by_key(|(score, _)| *score)
        .map(|(_, socket)| socket)
}

fn process_info(pid: u32, uid: u32) -> Option<ProcessInfo> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let process = system.process(pid)?;
    let path = process
        .exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = process.name().to_string_lossy().into_owned();
    Some(ProcessInfo {
        name,
        path,
        uid: process_uid(process).unwrap_or(uid),
        package_names: Vec::new(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_uid(socket: &SocketInfo) -> u32 {
    socket.uid
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn socket_uid(_socket: &SocketInfo) -> u32 {
    0
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn process_uid(process: &sysinfo::Process) -> Option<u32> {
    process.user_id().map(|uid| **uid)
}

#[cfg(target_os = "windows")]
fn process_uid(_process: &sysinfo::Process) -> Option<u32> {
    None
}
