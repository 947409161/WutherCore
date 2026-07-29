use std::{
    collections::HashMap,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

use core_observe::ConnectionGuard;
use core_runtime::{
    Runtime,
    listener_handler::{InboundMetadata, ListenerHandler},
};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinSet,
};
use tracing::{debug, info, warn};

use super::socket::{bind_transparent_udp_source, recv_udp};

pub(super) async fn run_tcp(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    tag: Arc<str>,
    hijack_dns: bool,
    mut stop: watch::Receiver<bool>,
) {
    let anchor = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            warn!(target: "inbound::ebpf", %error, "cannot read TCP anchor");
            return;
        }
    };
    let mut relays = JoinSet::new();
    info!(target: "inbound::ebpf", %anchor, "eBPF TCP socket active");
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            joined = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(target: "inbound::ebpf", %error, "TCP relay task ended");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(target: "inbound::ebpf", %error, "eBPF TCP accept failed");
                        continue;
                    }
                };
                let original = match stream.local_addr() {
                    Ok(address) if address != anchor => address,
                    Ok(_) => {
                        debug!(target: "inbound::ebpf", %peer, %anchor, "reject direct access to internal eBPF anchor");
                        continue;
                    }
                    Err(error) => {
                        warn!(target: "inbound::ebpf", %peer, %error, "cannot recover TCP original destination");
                        continue;
                    }
                };
                let runtime = runtime.clone();
                let tag = tag.clone();
                relays.spawn(async move {
                    if hijack_dns && original.port() == 53 {
                        if let Err(error) =
                            serve_dns_tcp(stream, runtime.dns_service.clone()).await
                        {
                            debug!(
                                target: "inbound::ebpf",
                                %peer,
                                %error,
                                "eBPF TCP DNS session ended"
                            );
                        }
                        return;
                    }
                    let handler = ListenerHandler::new(runtime);
                    let metadata = InboundMetadata::tcp(
                        tag.as_ref(),
                        "EBPF",
                        peer,
                        anchor,
                        original.ip().to_string(),
                        original.port(),
                    )
                    .with_destination_ip(Some(original.ip()))
                    .with_route_ip(Some(original.ip()));
                    match handler.prepare_tcp(metadata).await {
                        Ok(prepared) => {
                            if let Err(error) = handler.relay_prepared_tcp(stream, prepared).await {
                                debug!(
                                    target: "inbound::ebpf",
                                    %peer,
                                    destination = %original,
                                    %error,
                                    "eBPF TCP relay ended"
                                );
                            }
                        }
                        Err(error) => {
                            warn!(
                                target: "inbound::ebpf",
                                %peer,
                                destination = %original,
                                %error,
                                "eBPF TCP outbound preparation failed"
                            );
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    relays.shutdown().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    peer: SocketAddr,
    destination: SocketAddr,
}

struct UdpSession {
    outbound: core_outbound::adapter::BoxedUdp,
    guard: ConnectionGuard,
    return_socket: Arc<UdpSocket>,
    target_host: String,
    target_port: u16,
    peer: SocketAddr,
    last_seen: Mutex<Instant>,
}

impl UdpSession {
    fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }
}

type UdpSessions = Arc<DashMap<UdpKey, Arc<UdpSession>>>;
const MAX_DNS_RETURN_SOCKETS: usize = 128;

pub(super) async fn run_udp(
    socket: UdpSocket,
    runtime: Arc<Runtime>,
    tag: Arc<str>,
    hijack_dns: bool,
    mut stop: watch::Receiver<bool>,
) {
    let anchor = match socket.local_addr() {
        Ok(address) => address,
        Err(error) => {
            warn!(target: "inbound::ebpf", %error, "cannot read UDP anchor");
            return;
        }
    };
    let socket = Arc::new(socket);
    let handler = ListenerHandler::new(runtime);
    let sessions: UdpSessions = Arc::new(DashMap::new());
    let mut returns = JoinSet::new();
    let mut gc = tokio::time::interval(Duration::from_secs(30));
    gc.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buffer = vec![0u8; u16::MAX as usize];
    let mut dns_returns = HashMap::<SocketAddr, Arc<UdpSocket>>::new();
    info!(target: "inbound::ebpf", %anchor, "eBPF UDP socket active");

    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            joined = returns.join_next(), if !returns.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(target: "inbound::ebpf", %error, "UDP return task ended");
                }
            }
            _ = gc.tick() => purge_udp(&sessions, Duration::from_secs(90)),
            ready = socket.readable() => {
                if let Err(error) = ready {
                    warn!(target: "inbound::ebpf", %error, "UDP readiness failed");
                    continue;
                }
                let received = socket.try_io(tokio::io::Interest::READABLE, || {
                    recv_udp(socket.as_raw_fd(), &mut buffer)
                });
                let (size, peer, destination) = match received {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        warn!(target: "inbound::ebpf", %error, "eBPF UDP recvmsg failed");
                        continue;
                    }
                };
                if size == 0 || destination == anchor {
                    continue;
                }
                let payload = &buffer[..size];
                if hijack_dns && destination.port() == 53 {
                    let return_socket = match dns_returns.get(&destination).cloned() {
                        Some(socket) => socket,
                        None => match bind_transparent_udp_source(destination) {
                            Ok(socket) => {
                                let socket = Arc::new(socket);
                                if dns_returns.len() >= MAX_DNS_RETURN_SOCKETS {
                                    dns_returns.clear();
                                }
                                dns_returns.insert(destination, socket.clone());
                                socket
                            }
                            Err(error) => {
                                warn!(
                                    target: "inbound::ebpf",
                                    %destination,
                                    %error,
                                    "cannot bind UDP DNS return source"
                                );
                                continue;
                            }
                        },
                    };
                    let request = payload.to_vec();
                    let service = handler.runtime().dns_service.clone();
                    returns.spawn(async move {
                        let response = service.serve_packet(&request).await;
                        if !response.is_empty()
                            && let Err(error) = return_socket.send_to(&response, peer).await
                        {
                            debug!(
                                target: "inbound::ebpf",
                                %peer,
                                %destination,
                                %error,
                                "eBPF UDP DNS response failed"
                            );
                        }
                    });
                    continue;
                }
                let key = UdpKey { peer, destination };
                if let Some(session) = sessions.get(&key).map(|entry| entry.value().clone()) {
                    match session
                        .outbound
                        .send_to(payload, &session.target_host, session.target_port)
                        .await
                    {
                        Ok(_) => {
                            handler.record_upload(&session.guard, size as u64);
                            session.touch();
                        }
                        Err(error) => {
                            debug!(target: "inbound::ebpf", %error, "UDP session send failed");
                            remove_udp(&sessions, key);
                        }
                    }
                    continue;
                }

                let metadata = InboundMetadata::udp(
                    tag.as_ref(),
                    "EBPF",
                    peer,
                    Some(anchor),
                    destination.ip().to_string(),
                    destination.port(),
                )
                .with_destination_ip(Some(destination.ip()))
                .with_route_ip(Some(destination.ip()));
                let prepared = match handler.new_packet(metadata).await {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        debug!(
                            target: "inbound::ebpf",
                            %peer,
                            %destination,
                            %error,
                            "eBPF UDP outbound preparation failed"
                        );
                        continue;
                    }
                };
                let return_socket = match bind_transparent_udp_source(destination) {
                    Ok(socket) => Arc::new(socket),
                    Err(error) => {
                        warn!(target: "inbound::ebpf", %destination, %error, "cannot bind UDP return source");
                        continue;
                    }
                };
                let session = Arc::new(UdpSession {
                    outbound: prepared.socket,
                    guard: prepared.guard,
                    return_socket,
                    target_host: prepared.target_host,
                    target_port: prepared.target_port,
                    peer,
                    last_seen: Mutex::new(Instant::now()),
                });
                sessions.insert(key, session.clone());
                spawn_udp_return(
                    &mut returns,
                    key,
                    sessions.clone(),
                    session.clone(),
                    handler.runtime().metrics.clone(),
                    stop.clone(),
                );
                match session
                    .outbound
                    .send_to(payload, &session.target_host, session.target_port)
                    .await
                {
                    Ok(_) => {
                        handler.record_upload(&session.guard, size as u64);
                        session.touch();
                    }
                    Err(error) => {
                        debug!(target: "inbound::ebpf", %error, "first UDP send failed");
                        remove_udp(&sessions, key);
                    }
                }
            }
        }
    }

    for entry in sessions.iter() {
        entry.value().guard.cancel.cancel();
    }
    sessions.clear();
    returns.shutdown().await;
}

async fn serve_dns_tcp(
    mut stream: tokio::net::TcpStream,
    service: Arc<core_resolver::DnsService>,
) -> std::io::Result<()> {
    loop {
        let size = match stream.read_u16().await {
            Ok(size) => usize::from(size),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        if size == 0 {
            continue;
        }
        let mut request = vec![0u8; size];
        stream.read_exact(&mut request).await?;
        let response = service.serve_packet(&request).await;
        if response.is_empty() || response.len() > usize::from(u16::MAX) {
            continue;
        }
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

fn spawn_udp_return(
    tasks: &mut JoinSet<()>,
    key: UdpKey,
    sessions: UdpSessions,
    session: Arc<UdpSession>,
    metrics: Arc<core_observe::Metrics>,
    mut stop: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        metrics.inc_connection();
        let cancel = session.guard.cancel.clone();
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                _ = cancel.cancelled() => break,
                received = session.outbound.recv_from(&mut buffer) => {
                    let size = match received {
                        Ok(size) if size > 0 => size,
                        Ok(_) => break,
                        Err(error) => {
                            debug!(target: "inbound::ebpf", %error, "UDP outbound receive ended");
                            break;
                        }
                    };
                    if let Err(error) = session.return_socket.send_to(&buffer[..size], session.peer).await {
                        debug!(target: "inbound::ebpf", %error, "UDP return send failed");
                        break;
                    }
                    session.guard.record_download(size as u64);
                    metrics.add_down(size as u64);
                    session.touch();
                }
            }
        }
        remove_udp(&sessions, key);
        metrics.dec_connection();
    });
}

fn remove_udp(sessions: &UdpSessions, key: UdpKey) {
    if let Some((_, session)) = sessions.remove(&key) {
        session.guard.cancel.cancel();
    }
}

fn purge_udp(sessions: &UdpSessions, idle: Duration) {
    let cutoff = Instant::now() - idle;
    let keys = sessions
        .iter()
        .filter_map(|entry| (*entry.value().last_seen.lock() < cutoff).then_some(*entry.key()))
        .collect::<Vec<_>>();
    for key in keys {
        remove_udp(sessions, key);
    }
}
