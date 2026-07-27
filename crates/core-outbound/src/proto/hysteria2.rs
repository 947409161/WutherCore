//! Hysteria 2 client data plane.
//!
//! The wire format follows `apernet/hysteria`'s `core/v2` implementation:
//! HTTP/3 status 233 authentication, padded TCP request/response frames,
//! QUIC unreliable datagrams with session routing and fragmentation, and the
//! post-auth Brutal/BBR negotiation.  QUIC, HTTP/3, TLS/ECH and packet masks
//! are delegated to Quinn, h3, rustls and the shared finalmask executors.

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use core_config::{
    BandwidthValue, I32Range, QuicParamsConfig, SalamanderMaskConfig, UdpMaskConfig,
};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rand::RngExt;
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
            quic::{HysteriaPeerRx, apply_client_config},
            wrap_udp_client,
        },
        tls::build_tls_client_config,
    },
};

const AUTH_STATUS_OK: u16 = 233;
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
const MAX_ADDRESS_LENGTH: usize = 2048;
const MAX_MESSAGE_LENGTH: usize = 2048;
const MAX_PADDING_LENGTH: usize = 4096;
const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
const MAX_UDP_SIZE: usize = 4096;
const UDP_QUEUE_PACKETS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Obfs {
    None,
    Salamander {
        password: String,
    },
    Gecko {
        password: String,
        min_packet_size: i32,
        max_packet_size: i32,
    },
}

impl Default for Hysteria2Obfs {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone)]
pub struct Hysteria2Outbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsOptions,
    /// Client upload cap in bytes per second. Zero selects adaptive CC.
    pub tx_bps: u64,
    /// Client download cap in bytes per second. Zero means unknown.
    pub rx_bps: u64,
    pub disable_loss_compensation: bool,
    pub fast_open: bool,
    pub udp: bool,
    pub obfs: Hysteria2Obfs,
    pub quic_params: QuicParamsConfig,
    state: Arc<AsyncMutex<Option<Arc<Hysteria2Session>>>>,
}

impl Hysteria2Outbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: password.into(),
            tls: TlsOptions {
                enabled: true,
                alpn: vec!["h3".into()],
                ..TlsOptions::default()
            },
            tx_bps: 0,
            rx_bps: 0,
            disable_loss_compensation: false,
            fast_open: false,
            udp: true,
            obfs: Hysteria2Obfs::None,
            quic_params: QuicParamsConfig::default(),
            state: Arc::new(AsyncMutex::new(None)),
        }
    }

    /// Compatibility builder for the official Salamander mask.
    pub fn with_obfs(mut self, password: impl Into<String>) -> Self {
        self.obfs = Hysteria2Obfs::Salamander {
            password: password.into(),
        };
        self
    }

    async fn ensure_session(&self) -> io::Result<Arc<Hysteria2Session>> {
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

    async fn connect_and_auth(&self) -> io::Result<Hysteria2Session> {
        let target_addr = resolve_first(&self.host, self.port).await?;

        let mut tls = self.tls.clone();
        tls.enabled = true;
        tls.alpn = vec!["h3".into()];
        if tls
            .xray_settings
            .as_ref()
            .and_then(|settings| settings.ech_config_list.as_deref())
            .is_some_and(|source| source.contains("://"))
        {
            tls.resolved_ech_config_list = resolve_ech_config(&tls, &self.host).await?;
        }
        let rustls = build_tls_client_config(&tls)?;
        let quic_crypto =
            QuicClientConfig::try_from(rustls).map_err(|error| invalid(error.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));

        let mut quic_params = self.quic_params.clone();
        quic_params.brutal_up = bandwidth_value(self.tx_bps)?;
        quic_params.brutal_down = bandwidth_value(self.rx_bps)?;
        quic_params.brutal_disable_loss_compensation = self.disable_loss_compensation;
        // A configured upload bandwidth always selects Brutal. `congestion`
        // only applies to directions for which bandwidth is unknown.
        if self.tx_bps > 0 {
            quic_params.congestion = "brutal".into();
        }
        let applied_quic = apply_client_config(&mut client_config, Some(&quic_params))?;

        let active_policy = crate::socket_policy::current();
        let nominal_local: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().expect("IPv6 wildcard")
        } else {
            "0.0.0.0:0".parse().expect("IPv4 wildcard")
        };
        let mut masks = active_policy
            .as_ref()
            .and_then(|policy| policy.settings.finalmask.as_ref())
            .map(|finalmask| finalmask.udp.clone())
            .unwrap_or_default();
        if !matches!(self.obfs, Hysteria2Obfs::None)
            && masks
                .iter()
                .any(|mask| matches!(mask, UdpMaskConfig::Salamander(_)))
        {
            return Err(invalid(
                "Hysteria 2 obfs conflicts with finalmask Salamander/Gecko",
            ));
        }
        if let Some(mask) = self.obfs.mask()? {
            masks.push(UdpMaskConfig::Salamander(mask));
        }
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
        let carrier = if masks.is_empty() {
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
        let abstract_socket = QuinnUdpSocket::new_with_pacing(
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
            abstract_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| invalid(format!("Hysteria 2 endpoint: {error}")))?;
        endpoint.set_default_client_config(client_config);

        let server_name = tls.sni.clone().unwrap_or_else(|| self.host.clone());
        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(|error| invalid(format!("Hysteria 2 connect: {error}")))?
            .await
            .map_err(|error| invalid(format!("Hysteria 2 handshake: {error}")))?;

        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (mut h3_driver, mut h3_sender) = h3::client::new(h3_connection)
            .await
            .map_err(|error| invalid(format!("Hysteria 2 HTTP/3 init: {error}")))?;
        tokio::spawn(async move {
            let _ = h3_driver.wait_idle().await;
        });

        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", self.password.as_str())
            .header("Hysteria-CC-RX", self.rx_bps.to_string())
            .header("Hysteria-Padding", random_padding(256, 2048))
            .body(())
            .map_err(|error| invalid(format!("Hysteria 2 auth request: {error}")))?;
        let mut auth_stream = h3_sender
            .send_request(request)
            .await
            .map_err(|error| invalid(format!("Hysteria 2 send auth: {error}")))?;
        auth_stream
            .finish()
            .await
            .map_err(|error| invalid(format!("Hysteria 2 finish auth: {error}")))?;
        let response = auth_stream
            .recv_response()
            .await
            .map_err(|error| invalid(format!("Hysteria 2 auth response: {error}")))?;
        let mut auth_body_bytes = 0usize;
        while let Some(data) = auth_stream
            .recv_data()
            .await
            .map_err(|error| invalid(format!("Hysteria 2 auth response body: {error}")))?
        {
            auth_body_bytes = auth_body_bytes
                .checked_add(data.remaining())
                .filter(|length| *length <= 65_536)
                .ok_or_else(|| invalid("Hysteria 2 auth response body exceeds 65536 bytes"))?;
        }
        auth_stream
            .recv_trailers()
            .await
            .map_err(|error| invalid(format!("Hysteria 2 auth response trailers: {error}")))?;
        if response.status().as_u16() != AUTH_STATUS_OK {
            connection.close(0x101u32.into(), b"authentication failed");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Hysteria 2 authentication status {}", response.status()),
            ));
        }
        let udp_enabled = parse_required_bool(response.headers(), "Hysteria-UDP")?;
        let peer_rx = parse_peer_rx(response.headers())?;
        applied_quic.finish_hysteria_negotiation(peer_rx);
        applied_quic.apply_max_receive_window(&connection);

        let udp_router =
            (udp_enabled && self.udp).then(|| Hysteria2UdpRouter::new(connection.clone()));
        Ok(Hysteria2Session {
            connection,
            endpoint,
            udp_enabled,
            udp_router,
        })
    }
}

#[async_trait]
impl OutboundAdapter for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "hysteria2"
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
            .map_err(|error| invalid(format!("Hysteria 2 open stream: {error}")))?;
        let address = join_host_port(&ctx.host, ctx.port);
        send.write_all(&encode_tcp_request(&address)?)
            .await
            .map_err(|error| invalid(format!("Hysteria 2 write request: {error}")))?;
        send.flush().await?;

        if self.fast_open {
            return Ok(Box::pin(Hysteria2TcpStream::new(send, recv)));
        }
        let mut stream = Hysteria2TcpStream::new(send, recv);
        stream.establish().await?;
        Ok(Box::pin(stream))
    }

    async fn dial_udp(&self, _ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria 2 UDP is disabled by configuration",
            ));
        }
        let session = self.ensure_session().await?;
        if !session.udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria 2 server did not advertise UDP relay",
            ));
        }
        let router = session
            .udp_router
            .as_ref()
            .ok_or_else(|| invalid("Hysteria 2 UDP router is unavailable"))?
            .clone();
        Ok(Box::new(router.open()?))
    }
}

#[derive(Debug)]
struct Hysteria2Session {
    connection: quinn::Connection,
    /// Quinn endpoints own their UDP event loop; retaining this is executable
    /// lifetime state, not an unused configuration field.
    endpoint: Endpoint,
    udp_enabled: bool,
    udp_router: Option<Arc<Hysteria2UdpRouter>>,
}

impl Hysteria2Session {
    fn is_closed(&self) -> bool {
        let _keep_endpoint_alive = &self.endpoint;
        self.connection.close_reason().is_some()
    }
}

/* ---------------- TCP request/response ---------------- */

fn encode_tcp_request(address: &str) -> io::Result<Vec<u8>> {
    if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
        return Err(invalid("Hysteria 2 target address length is invalid"));
    }
    let padding = random_padding(64, 512);
    let mut output = Vec::with_capacity(address.len() + padding.len() + 16);
    put_varint(&mut output, FRAME_TYPE_TCP_REQUEST)?;
    put_varint(&mut output, address.len() as u64)?;
    output.extend_from_slice(address.as_bytes());
    put_varint(&mut output, padding.len() as u64)?;
    output.extend_from_slice(padding.as_bytes());
    Ok(output)
}

enum TcpResponseParse {
    NeedMore,
    Invalid(&'static str),
    Done {
        ok: bool,
        message: String,
        consumed: usize,
    },
}

fn parse_tcp_response(input: &[u8]) -> TcpResponseParse {
    let Some(&status) = input.first() else {
        return TcpResponseParse::NeedMore;
    };
    let Some((message_len, message_varint)) = get_varint(&input[1..]) else {
        return TcpResponseParse::NeedMore;
    };
    let Ok(message_len) = usize::try_from(message_len) else {
        return TcpResponseParse::Invalid("message length overflow");
    };
    if message_len > MAX_MESSAGE_LENGTH {
        return TcpResponseParse::Invalid("message exceeds protocol limit");
    }
    let message_start = 1 + message_varint;
    let Some(message_end) = message_start.checked_add(message_len) else {
        return TcpResponseParse::Invalid("message length overflow");
    };
    if input.len() < message_end {
        return TcpResponseParse::NeedMore;
    }
    let Some((padding_len, padding_varint)) = get_varint(&input[message_end..]) else {
        return TcpResponseParse::NeedMore;
    };
    let Ok(padding_len) = usize::try_from(padding_len) else {
        return TcpResponseParse::Invalid("padding length overflow");
    };
    if padding_len > MAX_PADDING_LENGTH {
        return TcpResponseParse::Invalid("padding exceeds protocol limit");
    }
    let Some(consumed) = message_end
        .checked_add(padding_varint)
        .and_then(|offset| offset.checked_add(padding_len))
    else {
        return TcpResponseParse::Invalid("padding length overflow");
    };
    if input.len() < consumed {
        return TcpResponseParse::NeedMore;
    }
    let Ok(message) = std::str::from_utf8(&input[message_start..message_end]) else {
        return TcpResponseParse::Invalid("message is not UTF-8");
    };
    TcpResponseParse::Done {
        ok: status == 0,
        message: message.to_owned(),
        consumed,
    }
}

pub struct Hysteria2TcpStream {
    send: SendStream,
    recv: RecvStream,
    response_done: bool,
    scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_offset: usize,
}

impl Hysteria2TcpStream {
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
            match parse_tcp_response(&self.scratch) {
                TcpResponseParse::Done {
                    ok,
                    message,
                    consumed,
                } => {
                    if !ok {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Hysteria 2 server rejected TCP request: {message}"),
                        )));
                    }
                    self.leftover = self.scratch.split_off(consumed);
                    self.scratch.clear();
                    self.response_done = true;
                }
                TcpResponseParse::Invalid(reason) => {
                    return Poll::Ready(Err(invalid(format!(
                        "malformed Hysteria 2 TCP response: {reason}"
                    ))));
                }
                TcpResponseParse::NeedMore => {
                    let mut buffer = [0u8; 512];
                    let mut read = ReadBuf::new(&mut buffer);
                    match Pin::new(&mut self.recv).poll_read(context, &mut read) {
                        Poll::Ready(Ok(())) if read.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Hysteria 2 stream closed before TCP response",
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

impl AsyncRead for Hysteria2TcpStream {
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

impl AsyncWrite for Hysteria2TcpStream {
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

/// Raw Quinn bidirectional stream used by other QUIC protocols after their own
/// handshake framing has been consumed.
#[derive(Debug)]
pub struct QuinnBiStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuinnBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, output)
    }
}

impl AsyncWrite for QuinnBiStream {
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

/* ---------------- UDP relay ---------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hysteria2UdpMessage {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: String,
    data: Vec<u8>,
}

impl Hysteria2UdpMessage {
    fn header_size(&self) -> io::Result<usize> {
        if self.address.is_empty() || self.address.len() > MAX_ADDRESS_LENGTH {
            return Err(invalid("Hysteria 2 UDP address length is invalid"));
        }
        Ok(8 + varint_len(self.address.len() as u64)? + self.address.len())
    }

    fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(self.header_size()? + self.data.len());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.push(self.fragment_id);
        output.push(self.fragment_count);
        put_varint(&mut output, self.address.len() as u64)?;
        output.extend_from_slice(self.address.as_bytes());
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    fn parse(input: &[u8]) -> io::Result<Self> {
        if input.len() < 9 {
            return Err(invalid("Hysteria 2 UDP datagram is truncated"));
        }
        let session_id = u32::from_be_bytes(input[0..4].try_into().expect("four bytes"));
        let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("two bytes"));
        let fragment_id = input[6];
        let fragment_count = input[7];
        if fragment_count == 0 || fragment_id >= fragment_count {
            return Err(invalid("Hysteria 2 UDP fragment metadata is invalid"));
        }
        let (address_len, encoded_len) =
            get_varint(&input[8..]).ok_or_else(|| invalid("invalid UDP address varint"))?;
        let address_len =
            usize::try_from(address_len).map_err(|_| invalid("UDP address length overflow"))?;
        if address_len == 0 || address_len > MAX_ADDRESS_LENGTH {
            return Err(invalid("Hysteria 2 UDP address length is invalid"));
        }
        let address_start = 8 + encoded_len;
        let address_end = address_start
            .checked_add(address_len)
            .ok_or_else(|| invalid("UDP address length overflow"))?;
        if input.len() <= address_end {
            return Err(invalid("Hysteria 2 UDP datagram has no payload"));
        }
        let address = std::str::from_utf8(&input[address_start..address_end])
            .map_err(|_| invalid("Hysteria 2 UDP address is not UTF-8"))?
            .to_owned();
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            data: input[address_end..].to_vec(),
        })
    }
}

#[derive(Default)]
struct Hysteria2Defragger {
    packet_id: u16,
    fragments: Vec<Option<Hysteria2UdpMessage>>,
    received: usize,
    size: usize,
}

impl Hysteria2Defragger {
    fn feed(&mut self, message: Hysteria2UdpMessage) -> Option<Hysteria2UdpMessage> {
        if message.fragment_count <= 1 {
            return Some(message);
        }
        if message.fragment_id >= message.fragment_count {
            return None;
        }
        if message.packet_id != self.packet_id
            || self.fragments.len() != usize::from(message.fragment_count)
        {
            self.packet_id = message.packet_id;
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
            self.received = 0;
            self.size = 0;
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
struct Hysteria2UdpRouter {
    connection: quinn::Connection,
    sessions: Mutex<HashMap<u32, mpsc::Sender<Hysteria2UdpMessage>>>,
    next_id: AtomicU32,
}

impl Hysteria2UdpRouter {
    fn new(connection: quinn::Connection) -> Arc<Self> {
        let router = Arc::new(Self {
            connection: connection.clone(),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        });
        let weak = Arc::downgrade(&router);
        tokio::spawn(async move {
            receive_hysteria2_datagrams(connection, weak).await;
        });
        router
    }

    fn open(self: &Arc<Self>) -> io::Result<Hysteria2Udp> {
        let (sender, receiver) = mpsc::channel(UDP_QUEUE_PACKETS);
        let id = loop {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed);
            // Session ID zero is reserved by convention and, after u32 wrap,
            // an old live session may still occupy the next candidate.
            if candidate == 0 {
                continue;
            }
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Entry::Vacant(entry) = sessions.entry(candidate) {
                entry.insert(sender);
                break candidate;
            }
        };
        Ok(Hysteria2Udp {
            router: self.clone(),
            id,
            receive: AsyncMutex::new(Hysteria2UdpReceive {
                receiver,
                defragger: Hysteria2Defragger::default(),
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

    fn dispatch(&self, message: Hysteria2UdpMessage) {
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

async fn receive_hysteria2_datagrams(
    connection: quinn::Connection,
    router: Weak<Hysteria2UdpRouter>,
) {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                if let Ok(message) = Hysteria2UdpMessage::parse(&datagram) {
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

struct Hysteria2UdpReceive {
    receiver: mpsc::Receiver<Hysteria2UdpMessage>,
    defragger: Hysteria2Defragger,
}

struct Hysteria2Udp {
    router: Arc<Hysteria2UdpRouter>,
    id: u32,
    receive: AsyncMutex<Hysteria2UdpReceive>,
    closed: AtomicBool,
}

impl Hysteria2Udp {
    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::ErrorKind::NotConnected.into())
        } else {
            Ok(())
        }
    }

    fn send_message(&self, message: Hysteria2UdpMessage) -> io::Result<()> {
        let encoded = message.serialize()?;
        match self.router.connection.send_datagram(Bytes::from(encoded)) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                let maximum = self
                    .router
                    .connection
                    .max_datagram_size()
                    .unwrap_or(MAX_DATAGRAM_FRAME_SIZE);
                self.send_fragmented(message, maximum)
            }
            Err(error) => Err(invalid(format!("Hysteria 2 UDP send: {error}"))),
        }
    }

    fn send_fragmented(&self, mut message: Hysteria2UdpMessage, maximum: usize) -> io::Result<()> {
        let header = message.header_size()?;
        let payload_max = maximum
            .checked_sub(header)
            .filter(|size| *size > 0)
            .ok_or_else(|| invalid("Hysteria 2 UDP datagram limit is smaller than its header"))?;
        let fragment_count = message.data.len().div_ceil(payload_max);
        if fragment_count == 0 || fragment_count > u8::MAX as usize {
            return Err(invalid("Hysteria 2 UDP packet requires too many fragments"));
        }
        message.packet_id = rand::rng().random_range(1..=u16::MAX);
        message.fragment_count = fragment_count as u8;
        let payload = std::mem::take(&mut message.data);
        for (index, chunk) in payload.chunks(payload_max).enumerate() {
            let mut fragment = message.clone();
            fragment.fragment_id = index as u8;
            fragment.data = chunk.to_vec();
            self.router
                .connection
                .send_datagram(Bytes::from(fragment.serialize()?))
                .map_err(|error| invalid(format!("Hysteria 2 UDP fragment send: {error}")))?;
        }
        Ok(())
    }
}

impl Drop for Hysteria2Udp {
    fn drop(&mut self) {
        self.router.remove(self.id);
    }
}

#[async_trait]
impl UdpSocketLike for Hysteria2Udp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        self.check_open()?;
        if payload.is_empty() || payload.len() > MAX_UDP_SIZE {
            return Err(invalid(format!(
                "Hysteria 2 UDP payload must be 1..={MAX_UDP_SIZE} bytes"
            )));
        }
        self.send_message(Hysteria2UdpMessage {
            session_id: self.id,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            address: join_host_port(target, port),
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
                        "Hysteria 2 UDP received {} bytes into {} byte buffer",
                        message.data.len(),
                        output.len()
                    ),
                ));
            }
            output[..message.data.len()].copy_from_slice(&message.data);
            return Ok((message.data.len(), message.address.parse().ok()));
        }
    }

    fn supports_multi_target(&self) -> bool {
        true
    }

    async fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.router.remove(self.id);
        }
        Ok(())
    }
}

/* ---------------- helpers ---------------- */

impl Hysteria2Obfs {
    fn mask(&self) -> io::Result<Option<SalamanderMaskConfig>> {
        match self {
            Self::None => Ok(None),
            Self::Salamander { password } => {
                validate_obfs_password(password)?;
                Ok(Some(SalamanderMaskConfig {
                    password: password.clone(),
                    ..SalamanderMaskConfig::default()
                }))
            }
            Self::Gecko {
                password,
                min_packet_size,
                max_packet_size,
            } => {
                validate_obfs_password(password)?;
                if *min_packet_size <= 0
                    || min_packet_size > max_packet_size
                    || *max_packet_size > 2048
                {
                    return Err(invalid("Hysteria 2 Gecko packet size range is invalid"));
                }
                Ok(Some(SalamanderMaskConfig {
                    password: password.clone(),
                    packet_size: I32Range::new(*min_packet_size, *max_packet_size),
                }))
            }
        }
    }
}

fn validate_obfs_password(password: &str) -> io::Result<()> {
    if password.as_bytes().len() < 4 {
        Err(invalid(
            "Hysteria 2 Salamander/Gecko password must be at least 4 bytes",
        ))
    } else {
        Ok(())
    }
}

fn bandwidth_value(bytes_per_second: u64) -> io::Result<BandwidthValue> {
    if bytes_per_second == 0 {
        return Ok(BandwidthValue::Empty);
    }
    bytes_per_second
        .checked_mul(8)
        .map(BandwidthValue::Number)
        .ok_or_else(|| invalid("Hysteria bandwidth overflows bits per second"))
}

fn parse_required_bool(headers: &http::HeaderMap, name: &str) -> io::Result<bool> {
    let value = headers
        .get(name)
        .ok_or_else(|| invalid(format!("Hysteria 2 auth response is missing {name}")))?
        .to_str()
        .map_err(|_| invalid(format!("Hysteria 2 {name} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| invalid(format!("Hysteria 2 {name} is not a boolean")))
}

fn parse_peer_rx(headers: &http::HeaderMap) -> io::Result<HysteriaPeerRx> {
    let value = headers
        .get("Hysteria-CC-RX")
        .ok_or_else(|| invalid("Hysteria 2 auth response is missing Hysteria-CC-RX"))?
        .to_str()
        .map_err(|_| invalid("Hysteria 2 Hysteria-CC-RX is not ASCII"))?;
    if value == "auto" {
        Ok(HysteriaPeerRx::Auto)
    } else {
        value
            .parse::<u64>()
            .map(HysteriaPeerRx::Rate)
            .map_err(|_| invalid("Hysteria 2 Hysteria-CC-RX is neither uint nor auto"))
    }
}

fn random_padding(minimum: usize, maximum: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let length = rng.random_range(minimum..maximum);
    (0..length)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

fn put_varint(output: &mut Vec<u8>, value: u64) -> io::Result<()> {
    match varint_len(value)? {
        1 => output.push(value as u8),
        2 => {
            let value = value as u16;
            output.push(0x40 | (value >> 8) as u8);
            output.push(value as u8);
        }
        4 => {
            let value = value as u32;
            output.push(0x80 | (value >> 24) as u8);
            output.extend_from_slice(&(value as u32).to_be_bytes()[1..]);
        }
        8 => {
            output.push(0xc0 | (value >> 56) as u8);
            output.extend_from_slice(&value.to_be_bytes()[1..]);
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn varint_len(value: u64) -> io::Result<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=4_611_686_018_427_387_903 => Ok(8),
        _ => Err(invalid("value exceeds QUIC varint")),
    }
}

fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn join_host_port(host: &str, port: u16) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
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
        .ok_or_else(|| invalid("Hysteria 2 server resolved to no address"))
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_tcp_response_layout_uses_status_byte_and_padding() {
        let bytes = b"\x00\x0bhello world\x05xxxxx";
        match parse_tcp_response(bytes) {
            TcpResponseParse::Done {
                ok,
                message,
                consumed,
            } => {
                assert!(ok);
                assert_eq!(message, "hello world");
                assert_eq!(consumed, bytes.len());
            }
            _ => panic!("official response must parse"),
        }
    }

    #[test]
    fn official_tcp_request_prefix_and_nonzero_padding() {
        let request = encode_tcp_request("google.com:443").unwrap();
        assert_eq!(&request[..3], &[0x44, 0x01, 0x0e]);
        let padding_offset = 3 + "google.com:443".len();
        let (padding, encoded) = get_varint(&request[padding_offset..]).unwrap();
        assert!((64..512).contains(&(padding as usize)));
        assert_eq!(request.len(), padding_offset + encoded + padding as usize);
    }

    #[test]
    fn official_udp_golden_vector_round_trips() {
        let message = Hysteria2UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:80".into(),
            data: b"GET /nothing HTTP/1.1\r\n".to_vec(),
        };
        let expected = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x0e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x38, 0x30, 0x47, 0x45, 0x54, 0x20, 0x2f,
            0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
            0x2e, 0x31, 0x0d, 0x0a,
        ];
        assert_eq!(message.serialize().unwrap(), expected);
        assert_eq!(Hysteria2UdpMessage::parse(&expected).unwrap(), message);
    }

    #[test]
    fn numeric_zero_and_auto_are_distinct_cc_values() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Hysteria-CC-RX", "0".parse().unwrap());
        assert_eq!(parse_peer_rx(&headers).unwrap(), HysteriaPeerRx::Rate(0));
        headers.insert("Hysteria-CC-RX", "auto".parse().unwrap());
        assert_eq!(parse_peer_rx(&headers).unwrap(), HysteriaPeerRx::Auto);
    }

    #[test]
    fn obfs_types_compile_to_distinct_packet_masks() {
        let salamander = Hysteria2Obfs::Salamander {
            password: "secret".into(),
        }
        .mask()
        .unwrap()
        .unwrap();
        assert_eq!(salamander.packet_size, I32Range::default());
        let gecko = Hysteria2Obfs::Gecko {
            password: "secret".into(),
            min_packet_size: 512,
            max_packet_size: 1200,
        }
        .mask()
        .unwrap()
        .unwrap();
        assert_eq!(gecko.packet_size, I32Range::new(512, 1200));
    }
}
