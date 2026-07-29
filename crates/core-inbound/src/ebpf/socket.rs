use std::{
    io::{IoSliceMut, Result as IoResult},
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, OwnedFd},
};

use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol, SockType,
    SockaddrIn, SockaddrIn6, SockaddrStorage, bind, listen, recvmsg, setsockopt, socket, sockopt,
};

use super::EbpfInboundError;

pub(super) struct FamilySockets {
    pub(super) tcp4: Option<std::net::TcpListener>,
    pub(super) tcp6: Option<std::net::TcpListener>,
    pub(super) udp4: Option<std::net::UdpSocket>,
    pub(super) udp6: Option<std::net::UdpSocket>,
    pub(super) anchors: Vec<SocketAddr>,
}

impl FamilySockets {
    pub(super) fn bind(redirect: &[ipnet::IpNet]) -> Result<Self, EbpfInboundError> {
        let ipv4 = redirect.iter().find_map(|net| match net {
            ipnet::IpNet::V4(net) => Some(IpAddr::V4(net.addr())),
            ipnet::IpNet::V6(_) => None,
        });
        let ipv6 = redirect.iter().find_map(|net| match net {
            ipnet::IpNet::V4(_) => None,
            ipnet::IpNet::V6(net) => Some(IpAddr::V6(net.addr())),
        });
        let mut result = Self {
            tcp4: None,
            tcp6: None,
            udp4: None,
            udp6: None,
            anchors: Vec::new(),
        };
        if let Some(ip) = ipv4 {
            let (tcp, tcp_addr) = bind_tcp(ip)?;
            let (udp, udp_addr) = bind_udp(ip)?;
            result.tcp4 = Some(tcp);
            result.udp4 = Some(udp);
            result.anchors.extend([tcp_addr, udp_addr]);
        }
        if let Some(ip) = ipv6 {
            let (tcp, tcp_addr) = bind_tcp(ip)?;
            let (udp, udp_addr) = bind_udp(ip)?;
            result.tcp6 = Some(tcp);
            result.udp6 = Some(udp);
            result.anchors.extend([tcp_addr, udp_addr]);
        }
        Ok(result)
    }
}

fn bind_tcp(ip: IpAddr) -> Result<(std::net::TcpListener, SocketAddr), EbpfInboundError> {
    let fd = create_socket(ip, SockType::Stream, SockProtocol::Tcp)?;
    bind_fd(&fd, SocketAddr::new(ip, 0))?;
    listen(&fd, Backlog::MAXCONN)
        .map_err(|error| EbpfInboundError::Socket(format!("listen on {ip}: {error}")))?;
    let listener = std::net::TcpListener::from(fd);
    listener
        .set_nonblocking(true)
        .map_err(|error| EbpfInboundError::Socket(format!("set TCP nonblocking: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| EbpfInboundError::Socket(format!("read TCP anchor: {error}")))?;
    Ok((listener, address))
}

fn bind_udp(ip: IpAddr) -> Result<(std::net::UdpSocket, SocketAddr), EbpfInboundError> {
    let fd = create_socket(ip, SockType::Datagram, SockProtocol::Udp)?;
    if ip.is_ipv4() {
        setsockopt(&fd, sockopt::Ipv4OrigDstAddr, &true)
            .map_err(|error| EbpfInboundError::Socket(format!("IP_RECVORIGDSTADDR: {error}")))?;
    } else {
        setsockopt(&fd, sockopt::Ipv6OrigDstAddr, &true)
            .map_err(|error| EbpfInboundError::Socket(format!("IPV6_RECVORIGDSTADDR: {error}")))?;
    }
    bind_fd(&fd, SocketAddr::new(ip, 0))?;
    let socket = std::net::UdpSocket::from(fd);
    socket
        .set_nonblocking(true)
        .map_err(|error| EbpfInboundError::Socket(format!("set UDP nonblocking: {error}")))?;
    let address = socket
        .local_addr()
        .map_err(|error| EbpfInboundError::Socket(format!("read UDP anchor: {error}")))?;
    Ok((socket, address))
}

fn create_socket(
    ip: IpAddr,
    kind: SockType,
    protocol: SockProtocol,
) -> Result<OwnedFd, EbpfInboundError> {
    let family = if ip.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let fd = socket(
        family,
        kind,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        protocol,
    )
    .map_err(|error| EbpfInboundError::Socket(format!("create {family:?} socket: {error}")))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)
        .map_err(|error| EbpfInboundError::Socket(format!("SO_REUSEADDR: {error}")))?;
    setsockopt(&fd, sockopt::IpTransparent, &true)
        .map_err(|error| EbpfInboundError::Socket(format!("IP_TRANSPARENT: {error}")))?;
    setsockopt(&fd, sockopt::IpFreebind, &true)
        .map_err(|error| EbpfInboundError::Socket(format!("IP_FREEBIND: {error}")))?;
    if ip.is_ipv6() {
        setsockopt(&fd, sockopt::Ipv6V6Only, &true)
            .map_err(|error| EbpfInboundError::Socket(format!("IPV6_V6ONLY: {error}")))?;
    }
    Ok(fd)
}

fn bind_fd(fd: &OwnedFd, address: SocketAddr) -> Result<(), EbpfInboundError> {
    match address {
        SocketAddr::V4(address) => bind(fd.as_raw_fd(), &SockaddrIn::from(address)),
        SocketAddr::V6(address) => bind(fd.as_raw_fd(), &SockaddrIn6::from(address)),
    }
    .map_err(|error| EbpfInboundError::Socket(format!("bind {address}: {error}")))
}

pub(super) fn bind_transparent_udp_source(
    source: SocketAddr,
) -> Result<tokio::net::UdpSocket, EbpfInboundError> {
    let fd = create_socket(source.ip(), SockType::Datagram, SockProtocol::Udp)?;
    bind_fd(&fd, source)?;
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true).map_err(|error| {
        EbpfInboundError::Socket(format!("set UDP return nonblocking: {error}"))
    })?;
    tokio::net::UdpSocket::from_std(socket)
        .map_err(|error| EbpfInboundError::Socket(format!("register UDP return socket: {error}")))
}

pub(super) fn recv_udp(
    fd: std::os::fd::RawFd,
    buffer: &mut [u8],
) -> IoResult<(usize, SocketAddr, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buffer)];
    let mut control = nix::cmsg_space!(
        libc::sockaddr_in,
        libc::sockaddr_in6,
        libc::in_pktinfo,
        libc::in6_pktinfo
    );
    let message =
        recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut control), MsgFlags::MSG_DONTWAIT)
            .map_err(std::io::Error::from)?;
    let peer = message
        .address
        .as_ref()
        .and_then(storage_address)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing UDP peer"))?;
    let mut destination = None;
    for cmsg in message.cmsgs().map_err(std::io::Error::from)? {
        match cmsg {
            ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                destination = Some(SocketAddr::new(
                    std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)).into(),
                    u16::from_be(address.sin_port),
                ));
            }
            ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                destination = Some(SocketAddr::new(
                    std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                    u16::from_be(address.sin6_port),
                ));
            }
            _ => {}
        }
    }
    let destination = destination.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing eBPF UDP original destination",
        )
    })?;
    Ok((message.bytes, peer, destination))
}

fn storage_address(address: &SockaddrStorage) -> Option<SocketAddr> {
    address
        .as_sockaddr_in()
        .copied()
        .map(SocketAddr::from)
        .or_else(|| address.as_sockaddr_in6().copied().map(SocketAddr::from))
}
