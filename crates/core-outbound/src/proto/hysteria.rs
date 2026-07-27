//! Hysteria 1 client data plane.
//!
//! This module follows `apernet/hysteria`'s `hy1` branch byte-for-byte:
//! protocol version 3, fixed-width big-endian control/request frames, QUIC
//! datagrams with server-assigned UDP sessions and fragmentation, XPlus packet
//! obfuscation, and Hysteria 1's 1.5× Brutal congestion window.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use core_config::{BandwidthValue, QuicParamsConfig, UdpMaskConfig};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex as AsyncMutex, mpsc},
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    transport::{
        TlsOptions,
        ech::resolve_ech_config,
        finalmask::{
            QuinnUdpSocket, UdpHopCarrier, open_direct_carrier,
            quic::{HysteriaPeerRx, apply_hysteria1_client_config},
            wrap_udp_client,
        },
        tls::build_tls_client_config,
    },
};

const PROTOCOL_VERSION: u8 = 3;
const MAX_AUTH_LENGTH: usize = u16::MAX as usize;
const MAX_HOST_LENGTH: usize = u16::MAX as usize;
const MAX_MESSAGE_LENGTH: usize = u16::MAX as usize;
const MAX_UDP_SIZE: usize = u16::MAX as usize;
const DEFAULT_DATAGRAM_SIZE: usize = 1200;
const UDP_QUEUE_PACKETS: usize = 1024;
const XPLUS_SALT_SIZE: usize = 16;
const MIN_BANDWIDTH: u64 = 16_384;

#[derive(Debug, Clone)]
pub struct HysteriaOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Vec<u8>,
    pub obfs: Option<Vec<u8>>,
    /// Required client upload limit, in bytes per second.
    pub tx_bps: u64,
    /// Required client download limit, in bytes per second.
    pub rx_bps: u64,
    pub tls: TlsOptions,
    /// Optional Hysteria 1 QUIC handshake deadline. The official client leaves
    /// zero to quic-go's default and only installs an override when configured.
    pub handshake_timeout: Option<Duration>,
    pub fast_open: bool,
    pub udp: bool,
    pub quic_params: QuicParamsConfig,
    state: Arc<AsyncMutex<Option<Arc<HysteriaSession>>>>,
}

impl HysteriaOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        auth: Vec<u8>,
        tx_bps: u64,
        rx_bps: u64,
    ) -> io::Result<Self> {
        if auth.len() > MAX_AUTH_LENGTH {
            return Err(invalid("Hysteria 1 auth exceeds 65535 bytes"));
        }
        if tx_bps < MIN_BANDWIDTH || rx_bps < MIN_BANDWIDTH {
            return Err(invalid(
                "Hysteria 1 upload and download bandwidth must be at least 16384 bytes/s",
            ));
        }
        Ok(Self {
            name: name.into(),
            host: host.into(),
            port,
            auth,
            obfs: None,
            tx_bps,
            rx_bps,
            tls: TlsOptions {
                enabled: true,
                alpn: vec!["hysteria".into()],
                ..TlsOptions::default()
            },
            handshake_timeout: None,
            fast_open: false,
            udp: true,
            quic_params: QuicParamsConfig::default(),
            state: Arc::new(AsyncMutex::new(None)),
        })
    }

    pub fn with_obfs(mut self, password: Vec<u8>) -> io::Result<Self> {
        if password.is_empty() {
            return Err(invalid("Hysteria 1 XPlus password cannot be empty"));
        }
        self.obfs = Some(password);
        Ok(self)
    }

    async fn ensure_session(&self) -> io::Result<Arc<HysteriaSession>> {
        let mut state = self.state.lock().await;
        if let Some(session) = state.as_ref()
            && !session.is_closed()
        {
            return Ok(session.clone());
        }
        let session = Arc::new(self.connect_and_auth().await?);
        *state = Some(session.clone());
        Ok(session)
    }

    async fn connect_and_auth(&self) -> io::Result<HysteriaSession> {
        let target_addr = resolve_first(&self.host, self.port).await?;
        let mut tls = self.tls.clone();
        tls.enabled = true;
        if tls.alpn.is_empty() {
            tls.alpn = vec!["hysteria".into()];
        }
        if tls
            .xray_settings
            .as_ref()
            .and_then(|settings| settings.ech_config_list.as_deref())
            .is_some_and(|source| source.contains("://"))
        {
            tls.resolved_ech_config_list = resolve_ech_config(&tls, &self.host).await?;
        }
        let rustls = build_tls_client_config(&tls)?;
        let crypto =
            QuicClientConfig::try_from(rustls).map_err(|error| invalid(error.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(crypto));

        let mut quic_params = self.quic_params.clone();
        quic_params.brutal_up = bandwidth_value(self.tx_bps)?;
        quic_params.brutal_down = bandwidth_value(self.rx_bps)?;
        quic_params.congestion = "brutal".into();
        let applied_quic = apply_hysteria1_client_config(&mut client_config, &quic_params)?;

        let active_policy = crate::socket_policy::current();
        let nominal_local: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().expect("IPv6 wildcard")
        } else {
            "0.0.0.0:0".parse().expect("IPv4 wildcard")
        };
        let masks = active_policy
            .as_ref()
            .and_then(|policy| policy.settings.finalmask.as_ref())
            .map(|finalmask| finalmask.udp.clone())
            .unwrap_or_default();
        if applied_quic.udp_hop().is_some()
            && masks
                .iter()
                .any(|mask| matches!(mask, UdpMaskConfig::Realm(_) | UdpMaskConfig::Xicmp(_)))
        {
            return Err(invalid(
                "Hysteria port hopping cannot be combined with realm/xicmp carriers",
            ));
        }
        let proxy = active_policy.as_ref().and_then(|policy| policy.proxy());
        let (raw, carrier_local) = if let Some(hop) = applied_quic.udp_hop().cloned() {
            UdpHopCarrier::open(hop, proxy, self.host.clone(), target_addr).await?
        } else if let Some(proxy) = proxy {
            (
                crate::socket_policy::dial_udp_through_proxy(
                    proxy,
                    self.host.clone(),
                    target_addr.port(),
                )
                .await?,
                nominal_local,
            )
        } else {
            open_direct_carrier(self.host.clone(), target_addr)?
        };
        let masked = if masks.is_empty() {
            raw
        } else {
            wrap_udp_client(
                raw,
                &masks,
                self.host.clone(),
                target_addr.port(),
                None,
                Some(target_addr),
            )
            .await?
        };
        let carrier: BoxedUdp = match self.obfs.as_ref() {
            Some(password) => Box::new(XPlusUdp::new(masked, password.clone())),
            None => masked,
        };
        let socket = QuinnUdpSocket::new_with_pacing(
            carrier,
            carrier_local,
            target_addr,
            self.host.clone(),
            target_addr.port(),
            applied_quic.packet_pacing(),
        );
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| invalid(format!("Hysteria 1 endpoint: {error}")))?;
        endpoint.set_default_client_config(client_config);

        let server_name = tls.sni.clone().unwrap_or_else(|| self.host.clone());
        let connecting = endpoint
            .connect(target_addr, &server_name)
            .map_err(|error| invalid(format!("Hysteria 1 connect: {error}")))?;
        let connection = match self.handshake_timeout {
            Some(timeout) => tokio::time::timeout(timeout, connecting)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("Hysteria 1 handshake timed out after {timeout:?}"),
                    )
                })?,
            None => connecting.await,
        }
        .map_err(|error| invalid(format!("Hysteria 1 handshake: {error}")))?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| invalid(format!("Hysteria 1 control stream: {error}")))?;
        send.write_all(&encode_client_hello(self.tx_bps, self.rx_bps, &self.auth)?)
            .await
            .map_err(|error| invalid(format!("Hysteria 1 client hello: {error}")))?;
        send.flush().await?;
        let server_hello = read_server_hello(&mut recv).await?;
        if !server_hello.ok {
            connection.close(2u32.into(), b"auth error");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Hysteria 1 authentication rejected: {}",
                    server_hello.message
                ),
            ));
        }
        if server_hello.recv_bps == 0 || server_hello.send_bps == 0 {
            connection.close(1u32.into(), b"invalid bandwidth");
            return Err(invalid(
                "Hysteria 1 server returned a zero negotiated bandwidth",
            ));
        }
        applied_quic.finish_hysteria_negotiation(HysteriaPeerRx::Rate(server_hello.recv_bps));
        applied_quic.apply_max_receive_window(&connection);
        let router = self.udp.then(|| HysteriaUdpRouter::new(connection.clone()));
        Ok(HysteriaSession {
            connection,
            endpoint,
            control: AsyncMutex::new(Some(super::hysteria2::QuinnBiStream::new(send, recv))),
            router,
        })
    }
}

#[async_trait]
impl OutboundAdapter for HysteriaOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "hysteria"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> io::Result<BoxedStream> {
        let session = self.ensure_session().await?;
        let (mut send, recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|error| invalid(format!("Hysteria 1 open TCP stream: {error}")))?;
        send.write_all(&encode_client_request(false, &ctx.host, ctx.port)?)
            .await
            .map_err(|error| invalid(format!("Hysteria 1 write TCP request: {error}")))?;
        send.flush().await?;
        let mut stream = HysteriaTcpStream::new(send, recv);
        if !self.fast_open {
            stream.establish().await?;
        }
        Ok(Box::pin(stream))
    }

    async fn dial_udp(&self, _ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria 1 UDP is disabled by configuration",
            ));
        }
        let session = self.ensure_session().await?;
        let router = session
            .router
            .as_ref()
            .ok_or_else(|| invalid("Hysteria 1 UDP router is unavailable"))?
            .clone();
        let (mut send, mut recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|error| invalid(format!("Hysteria 1 open UDP stream: {error}")))?;
        send.write_all(&encode_client_request(true, "", 0)?)
            .await
            .map_err(|error| invalid(format!("Hysteria 1 write UDP request: {error}")))?;
        send.flush().await?;
        let response = read_server_response(&mut recv).await?;
        if !response.ok {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "Hysteria 1 server rejected UDP session: {}",
                    response.message
                ),
            ));
        }
        Ok(Box::new(router.open(
            response.udp_session_id,
            super::hysteria2::QuinnBiStream::new(send, recv),
        )?))
    }
}

#[derive(Debug)]
struct HysteriaSession {
    connection: quinn::Connection,
    endpoint: Endpoint,
    control: AsyncMutex<Option<super::hysteria2::QuinnBiStream>>,
    router: Option<Arc<HysteriaUdpRouter>>,
}

impl HysteriaSession {
    fn is_closed(&self) -> bool {
        let _keep_endpoint_alive = &self.endpoint;
        let _keep_control_stream_alive = &self.control;
        self.connection.close_reason().is_some()
    }
}

/* ---------------- fixed-width wire protocol ---------------- */

fn encode_client_hello(send_bps: u64, recv_bps: u64, auth: &[u8]) -> io::Result<Vec<u8>> {
    let auth_len =
        u16::try_from(auth.len()).map_err(|_| invalid("Hysteria 1 auth exceeds 65535 bytes"))?;
    let mut output = Vec::with_capacity(19 + auth.len());
    output.push(PROTOCOL_VERSION);
    output.extend_from_slice(&send_bps.to_be_bytes());
    output.extend_from_slice(&recv_bps.to_be_bytes());
    output.extend_from_slice(&auth_len.to_be_bytes());
    output.extend_from_slice(auth);
    Ok(output)
}

#[derive(Debug, PartialEq, Eq)]
struct ServerHello {
    ok: bool,
    send_bps: u64,
    recv_bps: u64,
    message: String,
}

async fn read_server_hello(recv: &mut RecvStream) -> io::Result<ServerHello> {
    let fixed = read_exact::<19>(recv, "server hello").await?;
    let message_len = u16::from_be_bytes([fixed[17], fixed[18]]) as usize;
    Ok(ServerHello {
        ok: parse_bool(fixed[0])?,
        send_bps: u64::from_be_bytes(fixed[1..9].try_into().expect("eight bytes")),
        recv_bps: u64::from_be_bytes(fixed[9..17].try_into().expect("eight bytes")),
        message: read_utf8(recv, message_len, "server hello message").await?,
    })
}

fn encode_client_request(udp: bool, host: &str, port: u16) -> io::Result<Vec<u8>> {
    let host_len =
        u16::try_from(host.len()).map_err(|_| invalid("Hysteria 1 host exceeds 65535 bytes"))?;
    let mut output = Vec::with_capacity(5 + host.len());
    output.push(u8::from(udp));
    output.extend_from_slice(&host_len.to_be_bytes());
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&port.to_be_bytes());
    Ok(output)
}

#[derive(Debug, PartialEq, Eq)]
struct ServerResponse {
    ok: bool,
    udp_session_id: u32,
    message: String,
}

async fn read_server_response(recv: &mut RecvStream) -> io::Result<ServerResponse> {
    let fixed = read_exact::<7>(recv, "server response").await?;
    let message_len = u16::from_be_bytes([fixed[5], fixed[6]]) as usize;
    Ok(ServerResponse {
        ok: parse_bool(fixed[0])?,
        udp_session_id: u32::from_be_bytes(fixed[1..5].try_into().expect("four bytes")),
        message: read_utf8(recv, message_len, "server response message").await?,
    })
}

async fn read_exact<const N: usize>(
    recv: &mut RecvStream,
    context: &'static str,
) -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    let mut offset = 0;
    while offset < N {
        let read = recv
            .read(&mut output[offset..])
            .await
            .map_err(|error| invalid(format!("Hysteria 1 read {context}: {error}")))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Hysteria 1 stream closed during {context}"),
                )
            })?;
        offset += read;
    }
    Ok(output)
}

async fn read_utf8(
    recv: &mut RecvStream,
    length: usize,
    context: &'static str,
) -> io::Result<String> {
    if length > MAX_MESSAGE_LENGTH {
        return Err(invalid("Hysteria 1 message exceeds protocol limit"));
    }
    let mut output = vec![0u8; length];
    let mut offset = 0;
    while offset < length {
        let read = recv
            .read(&mut output[offset..])
            .await
            .map_err(|error| invalid(format!("Hysteria 1 read {context}: {error}")))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, context))?;
        offset += read;
    }
    String::from_utf8(output).map_err(|_| invalid(format!("Hysteria 1 {context} is not UTF-8")))
}

fn parse_bool(value: u8) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("Hysteria 1 boolean is neither 0 nor 1")),
    }
}

enum ResponseParse {
    NeedMore,
    Invalid(&'static str),
    Done {
        ok: bool,
        message: String,
        consumed: usize,
    },
}

fn parse_server_response(input: &[u8]) -> ResponseParse {
    if input.len() < 7 {
        return ResponseParse::NeedMore;
    }
    let Ok(ok) = parse_bool(input[0]) else {
        return ResponseParse::Invalid("invalid response boolean");
    };
    let message_len = u16::from_be_bytes([input[5], input[6]]) as usize;
    let consumed = 7 + message_len;
    if input.len() < consumed {
        return ResponseParse::NeedMore;
    }
    let Ok(message) = std::str::from_utf8(&input[7..consumed]) else {
        return ResponseParse::Invalid("response message is not UTF-8");
    };
    ResponseParse::Done {
        ok,
        message: message.to_owned(),
        consumed,
    }
}

struct HysteriaTcpStream {
    send: SendStream,
    recv: RecvStream,
    response_done: bool,
    scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_offset: usize,
}

impl HysteriaTcpStream {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            response_done: false,
            scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_offset: 0,
        }
    }

    async fn establish(&mut self) -> io::Result<()> {
        std::future::poll_fn(|context| Pin::new(&mut *self).poll_establish(context)).await
    }

    fn poll_establish(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.response_done {
            match parse_server_response(&self.scratch) {
                ResponseParse::Done {
                    ok,
                    message,
                    consumed,
                } => {
                    if !ok {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Hysteria 1 server rejected TCP request: {message}"),
                        )));
                    }
                    self.leftover = self.scratch.split_off(consumed);
                    self.scratch.clear();
                    self.response_done = true;
                }
                ResponseParse::Invalid(reason) => {
                    return Poll::Ready(Err(invalid(format!(
                        "malformed Hysteria 1 TCP response: {reason}"
                    ))));
                }
                ResponseParse::NeedMore => {
                    let mut buffer = [0u8; 512];
                    let mut read = ReadBuf::new(&mut buffer);
                    match Pin::new(&mut self.recv).poll_read(context, &mut read) {
                        Poll::Ready(Ok(())) if read.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Hysteria 1 stream closed before TCP response",
                            )));
                        }
                        Poll::Ready(Ok(())) => self.scratch.extend_from_slice(read.filled()),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HysteriaTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.response_done {
            match self.as_mut().poll_establish(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.leftover_offset < self.leftover.len() {
            let available = &self.leftover[self.leftover_offset..];
            let length = available.len().min(output.remaining());
            output.put_slice(&available[..length]);
            self.leftover_offset += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(context, output)
    }
}

impl AsyncWrite for HysteriaTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(context, input)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.recv.stop(0u32.into()).ok();
        Pin::new(&mut self.send).poll_shutdown(context)
    }
}

/* ---------------- Hysteria 1 UDP datagrams ---------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
struct HysteriaUdpMessage {
    session_id: u32,
    host: String,
    port: u16,
    message_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    data: Vec<u8>,
}

impl HysteriaUdpMessage {
    fn header_size(&self) -> io::Result<usize> {
        if self.host.len() > MAX_HOST_LENGTH {
            return Err(invalid("Hysteria 1 UDP host exceeds 65535 bytes"));
        }
        Ok(14 + self.host.len())
    }

    fn serialize(&self) -> io::Result<Vec<u8>> {
        if self.fragment_count == 0 || self.fragment_id >= self.fragment_count {
            return Err(invalid("Hysteria 1 UDP fragment metadata is invalid"));
        }
        if self.fragment_count > 1 && self.message_id == 0 {
            return Err(invalid(
                "Hysteria 1 fragmented UDP message ID must be non-zero",
            ));
        }
        let host_len = u16::try_from(self.host.len())
            .map_err(|_| invalid("Hysteria 1 UDP host is too long"))?;
        let data_len = u16::try_from(self.data.len())
            .map_err(|_| invalid("Hysteria 1 UDP payload exceeds 65535 bytes"))?;
        let mut output = Vec::with_capacity(self.header_size()? + self.data.len());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&host_len.to_be_bytes());
        output.extend_from_slice(self.host.as_bytes());
        output.extend_from_slice(&self.port.to_be_bytes());
        output.extend_from_slice(&self.message_id.to_be_bytes());
        output.push(self.fragment_id);
        output.push(self.fragment_count);
        output.extend_from_slice(&data_len.to_be_bytes());
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    fn parse(input: &[u8]) -> io::Result<Self> {
        if input.len() < 14 {
            return Err(invalid("Hysteria 1 UDP datagram is truncated"));
        }
        let session_id = u32::from_be_bytes(input[0..4].try_into().expect("four bytes"));
        let host_len = u16::from_be_bytes(input[4..6].try_into().expect("two bytes")) as usize;
        let fixed_end = 6usize
            .checked_add(host_len)
            .and_then(|value| value.checked_add(8))
            .ok_or_else(|| invalid("Hysteria 1 UDP length overflow"))?;
        if input.len() < fixed_end {
            return Err(invalid("Hysteria 1 UDP host is truncated"));
        }
        let host = std::str::from_utf8(&input[6..6 + host_len])
            .map_err(|_| invalid("Hysteria 1 UDP host is not UTF-8"))?
            .to_owned();
        let offset = 6 + host_len;
        let port = u16::from_be_bytes(input[offset..offset + 2].try_into().expect("two bytes"));
        let message_id =
            u16::from_be_bytes(input[offset + 2..offset + 4].try_into().expect("two bytes"));
        let fragment_id = input[offset + 4];
        let fragment_count = input[offset + 5];
        let data_len =
            u16::from_be_bytes(input[offset + 6..offset + 8].try_into().expect("two bytes"))
                as usize;
        if fragment_count == 0
            || fragment_id >= fragment_count
            || (fragment_count > 1 && message_id == 0)
        {
            return Err(invalid("Hysteria 1 UDP fragment metadata is invalid"));
        }
        if input.len() != fixed_end + data_len {
            return Err(invalid("Hysteria 1 UDP data length does not match frame"));
        }
        Ok(Self {
            session_id,
            host,
            port,
            message_id,
            fragment_id,
            fragment_count,
            data: input[fixed_end..].to_vec(),
        })
    }
}

#[derive(Default)]
struct HysteriaDefragger {
    message_id: u16,
    fragments: Vec<Option<HysteriaUdpMessage>>,
    received: usize,
    size: usize,
}

impl HysteriaDefragger {
    fn feed(&mut self, message: HysteriaUdpMessage) -> Option<HysteriaUdpMessage> {
        if message.fragment_count <= 1 {
            return Some(message);
        }
        if message.message_id != self.message_id
            || self.fragments.len() != usize::from(message.fragment_count)
        {
            self.message_id = message.message_id;
            self.fragments = vec![None; usize::from(message.fragment_count)];
            self.received = 0;
            self.size = 0;
        }
        let index = usize::from(message.fragment_id);
        if self.fragments[index].is_some() {
            return None;
        }
        self.size = self.size.saturating_add(message.data.len());
        if self.size > MAX_UDP_SIZE {
            self.fragments.clear();
            return None;
        }
        self.fragments[index] = Some(message);
        self.received += 1;
        if self.received != self.fragments.len() {
            return None;
        }
        let mut first = self.fragments[0].take()?;
        let mut data = Vec::with_capacity(self.size);
        data.extend_from_slice(&first.data);
        for fragment in self.fragments.iter_mut().skip(1) {
            data.extend_from_slice(&fragment.take()?.data);
        }
        first.fragment_id = 0;
        first.fragment_count = 1;
        first.data = data;
        self.fragments.clear();
        self.received = 0;
        self.size = 0;
        Some(first)
    }
}

#[derive(Debug)]
struct HysteriaUdpRouter {
    connection: quinn::Connection,
    sessions: Mutex<HashMap<u32, mpsc::Sender<HysteriaUdpMessage>>>,
}

impl HysteriaUdpRouter {
    fn new(connection: quinn::Connection) -> Arc<Self> {
        let router = Arc::new(Self {
            connection: connection.clone(),
            sessions: Mutex::new(HashMap::new()),
        });
        let weak = Arc::downgrade(&router);
        tokio::spawn(async move {
            receive_hysteria_datagrams(connection, weak).await;
        });
        router
    }

    fn open(
        self: &Arc<Self>,
        id: u32,
        control: super::hysteria2::QuinnBiStream,
    ) -> io::Result<HysteriaUdp> {
        let (sender, receiver) = mpsc::channel(UDP_QUEUE_PACKETS);
        let previous = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, sender);
        if previous.is_some() {
            return Err(invalid("Hysteria 1 server reused an active UDP session ID"));
        }
        Ok(HysteriaUdp {
            router: self.clone(),
            id,
            control: AsyncMutex::new(Some(control)),
            receive: AsyncMutex::new(HysteriaUdpReceive {
                receiver,
                defragger: HysteriaDefragger::default(),
            }),
            closed: AtomicBool::new(false),
        })
    }

    fn remove(&self, id: u32) {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&id);
    }

    fn dispatch(&self, message: HysteriaUdpMessage) {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = sessions.get(&message.session_id) {
            let _ = sender.try_send(message);
        }
    }

    fn close_all(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

async fn receive_hysteria_datagrams(
    connection: quinn::Connection,
    router: Weak<HysteriaUdpRouter>,
) {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                if let Ok(message) = HysteriaUdpMessage::parse(&datagram) {
                    let Some(router) = router.upgrade() else {
                        return;
                    };
                    router.dispatch(message);
                }
            }
            Err(_) => {
                if let Some(router) = router.upgrade() {
                    router.close_all();
                }
                return;
            }
        }
    }
}

struct HysteriaUdpReceive {
    receiver: mpsc::Receiver<HysteriaUdpMessage>,
    defragger: HysteriaDefragger,
}

struct HysteriaUdp {
    router: Arc<HysteriaUdpRouter>,
    id: u32,
    control: AsyncMutex<Option<super::hysteria2::QuinnBiStream>>,
    receive: AsyncMutex<HysteriaUdpReceive>,
    closed: AtomicBool,
}

impl HysteriaUdp {
    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::ErrorKind::NotConnected.into())
        } else {
            Ok(())
        }
    }

    fn send_message(&self, message: HysteriaUdpMessage) -> io::Result<()> {
        match self
            .router
            .connection
            .send_datagram(Bytes::from(message.serialize()?))
        {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                let maximum = self
                    .router
                    .connection
                    .max_datagram_size()
                    .unwrap_or(DEFAULT_DATAGRAM_SIZE);
                self.send_fragmented(message, maximum)
            }
            Err(error) => Err(invalid(format!("Hysteria 1 UDP send: {error}"))),
        }
    }

    fn send_fragmented(&self, mut message: HysteriaUdpMessage, maximum: usize) -> io::Result<()> {
        let header = message.header_size()?;
        let payload_max = maximum
            .checked_sub(header)
            .filter(|size| *size > 0)
            .ok_or_else(|| invalid("Hysteria 1 UDP datagram limit is smaller than its header"))?;
        let count = message.data.len().div_ceil(payload_max);
        if count == 0 || count > u8::MAX as usize {
            return Err(invalid("Hysteria 1 UDP packet requires too many fragments"));
        }
        message.message_id = rand::rng().random_range(1..=u16::MAX);
        message.fragment_count = count as u8;
        let payload = std::mem::take(&mut message.data);
        for (index, chunk) in payload.chunks(payload_max).enumerate() {
            let mut fragment = message.clone();
            fragment.fragment_id = index as u8;
            fragment.data = chunk.to_vec();
            self.router
                .connection
                .send_datagram(Bytes::from(fragment.serialize()?))
                .map_err(|error| invalid(format!("Hysteria 1 UDP fragment send: {error}")))?;
        }
        Ok(())
    }
}

impl Drop for HysteriaUdp {
    fn drop(&mut self) {
        self.router.remove(self.id);
    }
}

#[async_trait]
impl UdpSocketLike for HysteriaUdp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        self.check_open()?;
        if payload.is_empty() || payload.len() > MAX_UDP_SIZE {
            return Err(invalid(format!(
                "Hysteria 1 UDP payload must be 1..={MAX_UDP_SIZE} bytes"
            )));
        }
        self.send_message(HysteriaUdpMessage {
            session_id: self.id,
            host: target.to_owned(),
            port,
            message_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            data: payload.to_vec(),
        })?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        self.check_open()?;
        let mut receive = self.receive.lock().await;
        loop {
            let message = receive
                .receiver
                .recv()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            let Some(message) = receive.defragger.feed(message) else {
                continue;
            };
            if message.data.len() > output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Hysteria 1 UDP received {} bytes into {} byte buffer",
                        message.data.len(),
                        output.len()
                    ),
                ));
            }
            output[..message.data.len()].copy_from_slice(&message.data);
            let source = format_host_port(&message.host, message.port)
                .parse::<SocketAddr>()
                .ok();
            return Ok((message.data.len(), source));
        }
    }

    fn supports_multi_target(&self) -> bool {
        true
    }

    async fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.router.remove(self.id);
            if let Some(mut control) = self.control.lock().await.take() {
                control.shutdown().await?;
            }
        }
        Ok(())
    }
}

/* ---------------- official XPlus packet obfuscation ---------------- */

struct XPlusUdp {
    inner: BoxedUdp,
    key: Vec<u8>,
}

impl XPlusUdp {
    fn new(inner: BoxedUdp, key: Vec<u8>) -> Self {
        Self { inner, key }
    }

    fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; XPLUS_SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);
        xplus_encode_with_salt(&self.key, payload, salt)
    }

    fn decode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.len() <= XPLUS_SALT_SIZE {
            return Err(invalid("Hysteria 1 XPlus packet is truncated"));
        }
        let mut salt = [0u8; XPLUS_SALT_SIZE];
        salt.copy_from_slice(&packet[..XPLUS_SALT_SIZE]);
        Ok(xplus_xor(&self.key, salt, &packet[XPLUS_SALT_SIZE..]))
    }
}

#[async_trait]
impl UdpSocketLike for XPlusUdp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        let encoded = self.encode(payload);
        self.inner.send_to(&encoded, target, port).await?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        let mut packet = vec![0u8; 65_535 + XPLUS_SALT_SIZE];
        loop {
            let (length, source) = self.inner.recv_from_endpoint(&mut packet).await?;
            let Ok(decoded) = self.decode(&packet[..length]) else {
                continue;
            };
            if decoded.len() > output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Hysteria 1 decoded XPlus packet exceeds receive buffer",
                ));
            }
            output[..decoded.len()].copy_from_slice(&decoded);
            return Ok((decoded.len(), source));
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    fn supports_multi_target(&self) -> bool {
        self.inner.supports_multi_target()
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

fn xplus_encode_with_salt(key: &[u8], payload: &[u8], salt: [u8; XPLUS_SALT_SIZE]) -> Vec<u8> {
    let mut output = Vec::with_capacity(XPLUS_SALT_SIZE + payload.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&xplus_xor(key, salt, payload));
    output
}

fn xplus_xor(key: &[u8], salt: [u8; XPLUS_SALT_SIZE], payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(salt);
    let stream = hasher.finalize();
    payload
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index % stream.len()])
        .collect()
}

fn bandwidth_value(bytes_per_second: u64) -> io::Result<BandwidthValue> {
    bytes_per_second
        .checked_mul(8)
        .map(BandwidthValue::Number)
        .ok_or_else(|| invalid("Hysteria 1 bandwidth overflows bits per second"))
}

fn format_host_port(host: &str, port: u16) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn resolve_first(host: &str, port: u16) -> io::Result<SocketAddr> {
    crate::adapter::resolve_host(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("Hysteria 1 server resolved to no address"))
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_client_hello_layout() {
        let encoded = encode_client_hello(0x0102, 0x0304, b"auth").unwrap();
        assert_eq!(encoded[0], 3);
        assert_eq!(&encoded[1..9], &0x0102u64.to_be_bytes());
        assert_eq!(&encoded[9..17], &0x0304u64.to_be_bytes());
        assert_eq!(&encoded[17..19], &[0, 4]);
        assert_eq!(&encoded[19..], b"auth");
    }

    #[test]
    fn official_tcp_and_udp_request_layouts() {
        assert_eq!(
            encode_client_request(false, "example.com", 443).unwrap(),
            [
                0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
                0xbb
            ]
        );
        assert_eq!(encode_client_request(true, "", 0).unwrap(), [1, 0, 0, 0, 0]);
    }

    #[test]
    fn official_udp_golden_vector_round_trips() {
        let message = HysteriaUdpMessage {
            // The official server assigns its first UDP association ID as
            // zero; this is a real wire value rather than a placeholder.
            session_id: 0,
            host: "example.com".into(),
            port: 53,
            message_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            data: b"abc".to_vec(),
        };
        let expected = [
            0, 0, 0, 0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0,
            53, 0, 0, 0, 1, 0, 3, b'a', b'b', b'c',
        ];
        assert_eq!(message.serialize().unwrap(), expected);
        assert_eq!(HysteriaUdpMessage::parse(&expected).unwrap(), message);
    }

    #[test]
    fn xplus_matches_official_sha256_xor_layout() {
        let salt = [7u8; XPLUS_SALT_SIZE];
        let encoded = xplus_encode_with_salt(b"password", b"payload", salt);
        assert_eq!(&encoded[..XPLUS_SALT_SIZE], &salt);
        assert_eq!(
            xplus_xor(b"password", salt, &encoded[XPLUS_SALT_SIZE..]),
            b"payload"
        );
    }

    #[test]
    fn fragmented_udp_requires_nonzero_message_id() {
        let message = HysteriaUdpMessage {
            session_id: 1,
            host: "1.1.1.1".into(),
            port: 53,
            message_id: 0,
            fragment_id: 0,
            fragment_count: 2,
            data: vec![1],
        };
        assert!(message.serialize().is_err());
    }
}
