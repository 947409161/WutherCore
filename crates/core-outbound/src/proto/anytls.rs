//! AnyTLS v2 client.
//!
//! The wire behaviour in this module follows the official `sing-anytls`
//! reference implementation.  The `anytls` crate is deliberately used only
//! for its protocol core (command IDs, frame encoding and padding-scheme
//! parser); its client runtime has different pooling and update semantics.
//!
//! Protocol reference:
//! <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>

use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::IpAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ::anytls::core::{CHECK_MARK, Command, Frame, HEADER_OVERHEAD_SIZE, PaddingFactory};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{Mutex, RwLock, mpsc, oneshot},
    time,
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

const PROTOCOL_VERSION: u8 = 2;
const MAX_FRAME_DATA_LEN: usize = u16::MAX as usize;
const MAX_PADDING_SCHEME_LEN: usize = u16::MAX as usize;
const STREAM_BUFFER_SIZE: usize = 64 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const SYN_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_SESSION_DURATION: Duration = Duration::from_secs(5);
const DEFAULT_SESSION_DURATION: Duration = Duration::from_secs(30);
const UOT_V2_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

#[derive(Debug, Clone)]
pub struct AnyTlsClientOptions {
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
    pub udp_over_tcp: bool,
}

impl Default for AnyTlsClientOptions {
    fn default() -> Self {
        Self {
            idle_session_check_interval: DEFAULT_SESSION_DURATION,
            idle_session_timeout: DEFAULT_SESSION_DURATION,
            min_idle_session: 0,
            disable_reuse: false,
            udp_over_tcp: true,
        }
    }
}

#[derive(Clone)]
pub struct AnyTlsOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    /// AnyTLS itself does not negotiate an application protocol. Empty is the
    /// interoperable default; callers may explicitly configure an ALPN list.
    pub alpn: Vec<String>,
    pub fingerprint: String,
    pub enable_session_resumption: bool,
    pub options: AnyTlsClientOptions,
    client: Arc<Mutex<Option<Arc<AnyTlsClient>>>>,
}

impl AnyTlsOutbound {
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
            sni: None,
            insecure: false,
            alpn: Vec::new(),
            // The official Go client uses the standard crypto/tls ClientHello.
            // "unsafe" means ordinary rustls rather than this project's uTLS
            // Chrome-auto default.
            fingerprint: "unsafe".into(),
            enable_session_resumption: false,
            options: AnyTlsClientOptions::default(),
            client: Arc::new(Mutex::new(None)),
        }
    }

    async fn client(&self) -> io::Result<Arc<AnyTlsClient>> {
        if self.password.is_empty() {
            return Err(invalid_input("AnyTLS password must not be empty"));
        }
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        let client = AnyTlsClient::new(AnyTlsRuntimeConfig {
            host: self.host.clone(),
            port: self.port,
            password_sha256: Sha256::digest(self.password.as_bytes()).into(),
            tls: TlsOptions {
                enabled: true,
                sni: self.sni.clone(),
                insecure: self.insecure,
                alpn: self.alpn.clone(),
                enable_session_resumption: self.enable_session_resumption,
                fingerprint: self.fingerprint.clone(),
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                xray_settings: None,
                resolved_ech_config_list: None,
            },
            options: self.options.clone(),
        });
        *slot = Some(client.clone());
        Ok(client)
    }
}

#[async_trait]
impl OutboundAdapter for AnyTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "anytls"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.options.udp_over_tcp,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> io::Result<BoxedStream> {
        let target = encode_socks_address(&ctx.host, ctx.port)?;
        self.client().await?.create_proxy(target).await
    }

    async fn dial_udp(&self, ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.options.udp_over_tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AnyTLS UDP requires udp-over-tcp",
            ));
        }

        let magic = encode_socks_address(UOT_V2_MAGIC, 0)?;
        let mut stream = self.client().await?.create_proxy(magic).await?;
        let request = encode_uot_request(&ctx.host, ctx.port)?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(AnyTlsUdp {
            target: normalize_host(&ctx.host),
            port: ctx.port,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }))
    }
}

#[derive(Clone)]
struct AnyTlsRuntimeConfig {
    host: String,
    port: u16,
    password_sha256: [u8; 32],
    tls: TlsOptions,
    options: AnyTlsClientOptions,
}

#[derive(Default)]
struct ClientState {
    sessions: BTreeMap<u64, Arc<AnyTlsSession>>,
    /// Keyed by monotonically increasing sequence number. Taking the last key
    /// implements the official "reuse newest idle session first" rule.
    idle: BTreeMap<u64, Instant>,
}

struct AnyTlsClient {
    config: AnyTlsRuntimeConfig,
    padding: Arc<RwLock<PaddingFactory>>,
    next_session: AtomicU64,
    closed: AtomicBool,
    state: Mutex<ClientState>,
}

impl AnyTlsClient {
    fn new(mut config: AnyTlsRuntimeConfig) -> Arc<Self> {
        if config.options.idle_session_check_interval <= MIN_SESSION_DURATION {
            config.options.idle_session_check_interval = DEFAULT_SESSION_DURATION;
        }
        if config.options.idle_session_timeout <= MIN_SESSION_DURATION {
            config.options.idle_session_timeout = DEFAULT_SESSION_DURATION;
        }

        let client = Arc::new(Self {
            config,
            padding: Arc::new(RwLock::new(PaddingFactory::default())),
            next_session: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            state: Mutex::new(ClientState::default()),
        });
        if !client.config.options.disable_reuse {
            Self::spawn_idle_cleanup(&client);
        }
        client
    }

    fn spawn_idle_cleanup(client: &Arc<Self>) {
        let weak = Arc::downgrade(client);
        let interval = client.config.options.idle_session_check_interval;
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            // tokio's first interval tick is immediate; the reference client
            // sleeps once before its first cleanup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(client) = weak.upgrade() else {
                    break;
                };
                client.cleanup_idle().await;
            }
        });
    }

    async fn create_proxy(self: &Arc<Self>, target: Vec<u8>) -> io::Result<BoxedStream> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }

        let mut reused = false;
        let session = if self.config.options.disable_reuse {
            self.create_session().await?
        } else if let Some(session) = self.take_newest_idle().await {
            reused = true;
            session
        } else {
            self.create_session().await?
        };

        match session.open_stream(target, !reused).await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                session
                    .close(format!("failed to open AnyTLS stream: {error}"))
                    .await;
                Err(error)
            }
        }
    }

    async fn take_newest_idle(&self) -> Option<Arc<AnyTlsSession>> {
        let mut state = self.state.lock().await;
        while let Some((&seq, _)) = state.idle.last_key_value() {
            state.idle.remove(&seq);
            let Some(session) = state.sessions.get(&seq).cloned() else {
                continue;
            };
            if !session.is_closed() {
                return Some(session);
            }
            state.sessions.remove(&seq);
        }
        None
    }

    async fn create_session(self: &Arc<Self>) -> io::Result<Arc<AnyTlsSession>> {
        let transport = TlsTransport::new(self.config.tls.clone());
        let mut connection = transport
            .connect(&self.config.host, self.config.port)
            .await?;

        let padding = self.padding.read().await.clone();
        let auth = build_authentication(&self.config.password_sha256, &padding)?;
        time::timeout(WRITE_TIMEOUT, connection.write_all(&auth))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "AnyTLS authentication timed out")
            })??;
        connection.flush().await?;

        let seq = self.next_session.fetch_add(1, Ordering::Relaxed) + 1;
        let (reader, writer) = tokio::io::split(connection);
        let session = AnyTlsSession::new(seq, writer, self.padding.clone(), Arc::downgrade(self));
        self.state
            .lock()
            .await
            .sessions
            .insert(seq, session.clone());
        AnyTlsSession::spawn_reader(&session, reader);
        Ok(session)
    }

    async fn release_session(&self, session: Arc<AnyTlsSession>) {
        if session.is_closed()
            || self.closed.load(Ordering::Acquire)
            || self.config.options.disable_reuse
        {
            self.remove_session(session.seq).await;
            if !session.is_closed() {
                session
                    .close("AnyTLS session reuse is disabled".into())
                    .await;
            }
            return;
        }
        self.state
            .lock()
            .await
            .idle
            .insert(session.seq, Instant::now());
    }

    async fn remove_session(&self, seq: u64) {
        let mut state = self.state.lock().await;
        state.idle.remove(&seq);
        state.sessions.remove(&seq);
    }

    async fn cleanup_idle(&self) {
        let expiration = Instant::now() - self.config.options.idle_session_timeout;
        let mut close = Vec::new();
        {
            let mut state = self.state.lock().await;
            // Keep the newest `min_idle_session` sessions, even if expired;
            // expired sessions after those are closed from newest to oldest,
            // matching sing-anytls' reverse-sequence skip-list traversal.
            let idle = state
                .idle
                .iter()
                .rev()
                .map(|(&seq, &since)| (seq, since))
                .collect::<Vec<_>>();
            let mut retained = 0usize;
            for (seq, since) in idle {
                if since >= expiration {
                    retained += 1;
                    continue;
                }
                if retained < self.config.options.min_idle_session {
                    state.idle.insert(seq, Instant::now());
                    retained += 1;
                    continue;
                }
                state.idle.remove(&seq);
                if let Some(session) = state.sessions.remove(&seq) {
                    close.push(session);
                }
            }
        }
        for session in close {
            session.close("AnyTLS idle session expired".into()).await;
        }
    }
}

struct AnyTlsSession {
    seq: u64,
    writer: Mutex<SessionWriter<WriteHalf<BoxedStream>>>,
    padding: Arc<RwLock<PaddingFactory>>,
    client: Weak<AnyTlsClient>,
    streams: SyncMutex<HashMap<u32, mpsc::UnboundedSender<InboundEvent>>>,
    syn_acks: SyncMutex<HashMap<u32, oneshot::Sender<SynAck>>>,
    reader_abort: SyncMutex<Option<tokio::task::AbortHandle>>,
    next_stream: AtomicU32,
    peer_version: AtomicU8,
    closed: AtomicBool,
}

impl AnyTlsSession {
    fn new(
        seq: u64,
        writer: WriteHalf<BoxedStream>,
        padding: Arc<RwLock<PaddingFactory>>,
        client: Weak<AnyTlsClient>,
    ) -> Arc<Self> {
        Arc::new(Self {
            seq,
            writer: Mutex::new(SessionWriter::new(writer, padding.clone())),
            padding,
            client,
            streams: SyncMutex::new(HashMap::new()),
            syn_acks: SyncMutex::new(HashMap::new()),
            reader_abort: SyncMutex::new(None),
            next_stream: AtomicU32::new(0),
            peer_version: AtomicU8::new(0),
            closed: AtomicBool::new(false),
        })
    }

    fn spawn_reader(session: &Arc<Self>, reader: ReadHalf<BoxedStream>) {
        let task_session = session.clone();
        let handle = tokio::spawn(async move {
            let result = task_session.recv_loop(reader).await;
            let reason = match result {
                Ok(()) => "AnyTLS session closed by peer".to_string(),
                Err(error) => format!("AnyTLS receive loop failed: {error}"),
            };
            task_session.close_from_reader(reason).await;
        });
        let abort = handle.abort_handle();
        *session.reader_abort.lock() = Some(abort.clone());
        if session.is_closed() {
            abort.abort();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn open_stream(
        self: &Arc<Self>,
        target: Vec<u8>,
        fresh: bool,
    ) -> io::Result<BoxedStream> {
        if self.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }

        let sid = self
            .next_stream
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| io::Error::other("AnyTLS stream-id space exhausted"))?
            + 1;
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        self.streams.lock().insert(sid, inbound_tx);

        let ack = if !fresh && self.peer_version.load(Ordering::Acquire) >= PROTOCOL_VERSION {
            let (tx, rx) = oneshot::channel();
            self.syn_acks.lock().insert(sid, tx);
            Some(rx)
        } else {
            None
        };

        let write_result = if fresh {
            let padding_md5 = self.padding.read().await.md5().to_owned();
            let settings = format!(
                "v={PROTOCOL_VERSION}\nclient=WutherCore/{}\npadding-md5={padding_md5}",
                env!("CARGO_PKG_VERSION")
            );
            let mut packet = Vec::new();
            append_frame(&mut packet, Command::Settings, 0, settings.as_bytes())?;
            append_frame(&mut packet, Command::Syn, sid, &[])?;
            append_frame(&mut packet, Command::Psh, sid, &target)?;
            self.write_packet(&packet).await
        } else {
            // The official reused-session path emits SYN and the first PSH as
            // two separate TLS writes, so they consume separate padding packet
            // counters.
            let syn = frame_bytes(Command::Syn, sid, &[])?;
            self.write_packet(&syn).await?;
            self.write_data(sid, &target).await.map(|_| ())
        };

        if let Err(error) = write_result {
            self.streams.lock().remove(&sid);
            self.syn_acks.lock().remove(&sid);
            return Err(error);
        }

        if let Some(ack) = ack {
            Self::spawn_syn_ack_timeout(self, sid, ack);
        }

        let (application, internal) = tokio::io::duplex(STREAM_BUFFER_SIZE);
        Self::spawn_stream_bridge(self, sid, internal, inbound_rx);
        Ok(Box::pin(application))
    }

    fn spawn_syn_ack_timeout(session: &Arc<Self>, sid: u32, ack: oneshot::Receiver<SynAck>) {
        let weak = Arc::downgrade(session);
        tokio::spawn(async move {
            match time::timeout(SYN_ACK_TIMEOUT, ack).await {
                Ok(Ok(SynAck::Success)) | Ok(Err(_)) => {}
                Ok(Ok(SynAck::Failure(message))) => {
                    if let Some(session) = weak.upgrade() {
                        session.signal_stream(sid, InboundEvent::Error(message));
                    }
                }
                Err(_) => {
                    if let Some(session) = weak.upgrade() {
                        session
                            .close(format!("AnyTLS SYNACK timed out for reused stream {sid}"))
                            .await;
                    }
                }
            }
        });
    }

    fn spawn_stream_bridge(
        session: &Arc<Self>,
        sid: u32,
        stream: DuplexStream,
        mut inbound: mpsc::UnboundedReceiver<InboundEvent>,
    ) {
        let session = session.clone();
        tokio::spawn(async move {
            let (mut application_reader, mut application_writer) = tokio::io::split(stream);
            let mut buffer = vec![0u8; STREAM_BUFFER_SIZE];
            let mut notify_remote = true;
            let mut fatal_error = None;
            let mut session_fatal = false;

            loop {
                tokio::select! {
                    biased;
                    event = inbound.recv() => {
                        match event {
                            Some(InboundEvent::Data(data)) => {
                                if let Err(error) = application_writer.write_all(&data).await {
                                    fatal_error = Some(format!("AnyTLS local stream delivery failed: {error}"));
                                    break;
                                }
                            }
                            Some(InboundEvent::RemoteFin) | None => {
                                notify_remote = false;
                                break;
                            }
                            Some(InboundEvent::Error(message)) => {
                                fatal_error = Some(message);
                                break;
                            }
                        }
                    }
                    read = application_reader.read(&mut buffer) => {
                        match read {
                            Ok(0) => break,
                            Ok(length) => {
                                if let Err(error) = session.write_data(sid, &buffer[..length]).await {
                                    fatal_error = Some(format!("AnyTLS stream write failed: {error}"));
                                    session_fatal = true;
                                    break;
                                }
                            }
                            Err(error) => {
                                fatal_error = Some(format!("AnyTLS local stream read failed: {error}"));
                                break;
                            }
                        }
                    }
                }
            }

            session.streams.lock().remove(&sid);
            session.syn_acks.lock().remove(&sid);
            if notify_remote
                && !session.is_closed()
                && let Err(error) = session.write_control(Command::Fin, sid, &[]).await
            {
                fatal_error.get_or_insert_with(|| {
                    format!("failed to send AnyTLS FIN for stream {sid}: {error}")
                });
                session_fatal = true;
            }
            let _ = application_writer.shutdown().await;

            if let Some(error) = fatal_error.as_deref() {
                tracing::debug!(target: "anytls", session = session.seq, stream = sid, %error);
            }
            if session_fatal {
                session
                    .close(fatal_error.unwrap_or_else(|| "AnyTLS stream transport failed".into()))
                    .await;
            } else if let Some(client) = session.client.upgrade() {
                client.release_session(session).await;
            }
        });
    }

    async fn recv_loop(self: &Arc<Self>, mut reader: ReadHalf<BoxedStream>) -> io::Result<()> {
        loop {
            let mut header = [0u8; HEADER_OVERHEAD_SIZE];
            reader.read_exact(&mut header).await?;
            let command = Command::from(header[0]);
            let sid = u32::from_be_bytes(header[1..5].try_into().expect("fixed header"));
            let length = usize::from(u16::from_be_bytes(
                header[5..7].try_into().expect("fixed header"),
            ));
            let mut data = vec![0u8; length];
            reader.read_exact(&mut data).await?;

            match command {
                Command::Psh => {
                    if !data.is_empty() {
                        self.signal_stream(sid, InboundEvent::Data(data));
                    }
                }
                Command::Fin => {
                    if let Some(stream) = self.streams.lock().remove(&sid) {
                        let _ = stream.send(InboundEvent::RemoteFin);
                    }
                }
                Command::Waste => {}
                Command::Syn | Command::Settings => {
                    tracing::debug!(
                        target: "anytls",
                        session = self.seq,
                        stream = sid,
                        command = %command,
                        "ignored server-only-invalid AnyTLS frame"
                    );
                }
                Command::Alert => {
                    let message = String::from_utf8_lossy(&data);
                    tracing::warn!(
                        target: "anytls",
                        session = self.seq,
                        alert = %message,
                        "AnyTLS server rejected the session"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("AnyTLS server alert: {message}"),
                    ));
                }
                Command::UpdatePaddingScheme => match parse_padding_scheme(&data) {
                    Ok(padding) => {
                        let md5 = padding.md5().to_owned();
                        *self.padding.write().await = padding;
                        tracing::debug!(
                            target: "anytls",
                            session = self.seq,
                            %md5,
                            "AnyTLS padding scheme updated for this server"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "anytls",
                            session = self.seq,
                            %error,
                            "ignored invalid AnyTLS padding scheme"
                        );
                    }
                },
                Command::SynAck => {
                    let ack = if data.is_empty() {
                        SynAck::Success
                    } else {
                        SynAck::Failure(format!(
                            "AnyTLS remote target handshake failed: {}",
                            String::from_utf8_lossy(&data)
                        ))
                    };
                    if let Some(sender) = self.syn_acks.lock().remove(&sid) {
                        let _ = sender.send(ack);
                    } else if let SynAck::Failure(message) = ack {
                        self.signal_stream(sid, InboundEvent::Error(message));
                    }
                }
                Command::HeartRequest => {
                    self.write_control(Command::HeartResponse, sid, &[]).await?;
                }
                Command::HeartResponse => {}
                Command::ServerSettings => {
                    if let Some(version) = parse_settings(&data)
                        .get("v")
                        .and_then(|value| value.parse::<u8>().ok())
                    {
                        self.peer_version.store(version, Ordering::Release);
                    }
                }
                Command::Unknown(value) => {
                    tracing::debug!(
                        target: "anytls",
                        session = self.seq,
                        stream = sid,
                        command = value,
                        length,
                        "ignored unknown AnyTLS command"
                    );
                }
            }
        }
    }

    fn signal_stream(&self, sid: u32, event: InboundEvent) {
        if let Some(stream) = self.streams.lock().get(&sid).cloned() {
            let _ = stream.send(event);
        }
    }

    async fn write_control(&self, command: Command, sid: u32, data: &[u8]) -> io::Result<()> {
        let packet = frame_bytes(command, sid, data)?;
        self.write_packet(&packet).await
    }

    async fn write_data(&self, sid: u32, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let packet = encode_data_frames(sid, data)?;
        self.write_packet(&packet).await?;
        Ok(data.len())
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        time::timeout(WRITE_TIMEOUT, self.writer.lock().await.write_packet(packet))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS write timed out"))?
    }

    async fn close(self: &Arc<Self>, reason: String) {
        self.close_inner(reason, true).await;
    }

    async fn close_from_reader(self: &Arc<Self>, reason: String) {
        self.close_inner(reason, false).await;
    }

    async fn close_inner(self: &Arc<Self>, reason: String, abort_reader: bool) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        tracing::debug!(target: "anytls", session = self.seq, %reason, "closing AnyTLS session");

        if abort_reader {
            if let Some(abort) = self.reader_abort.lock().take() {
                abort.abort();
            }
        } else {
            self.reader_abort.lock().take();
        }
        let streams = std::mem::take(&mut *self.streams.lock());
        for (_, stream) in streams {
            let _ = stream.send(InboundEvent::Error(reason.clone()));
        }
        self.syn_acks.lock().clear();
        let _ = self.writer.lock().await.shutdown().await;
        if let Some(client) = self.client.upgrade() {
            client.remove_session(self.seq).await;
        }
    }
}

enum InboundEvent {
    Data(Vec<u8>),
    RemoteFin,
    Error(String),
}

enum SynAck {
    Success,
    Failure(String),
}

struct SessionWriter<W> {
    inner: W,
    padding: Arc<RwLock<PaddingFactory>>,
    packet_counter: u32,
    send_padding: bool,
}

impl<W> SessionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(inner: W, padding: Arc<RwLock<PaddingFactory>>) -> Self {
        Self {
            inner,
            padding,
            packet_counter: 0,
            send_padding: true,
        }
    }

    async fn write_packet(&mut self, mut payload: &[u8]) -> io::Result<()> {
        if self.send_padding {
            self.packet_counter = self.packet_counter.saturating_add(1);
            let padding = self.padding.read().await.clone();
            if self.packet_counter < padding.stop() {
                for record_size in padding.generate_record_payload_sizes(self.packet_counter) {
                    if record_size == CHECK_MARK {
                        if payload.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let record_size = usize::try_from(record_size)
                        .map_err(|_| invalid_data("negative AnyTLS padding record size"))?;
                    let remaining = payload.len();
                    if remaining > record_size {
                        self.inner.write_all(&payload[..record_size]).await?;
                        payload = &payload[record_size..];
                    } else if remaining > 0 {
                        let padding_length =
                            record_size.saturating_sub(remaining + HEADER_OVERHEAD_SIZE);
                        if padding_length > 0 {
                            let waste = waste_frame(padding_length)?;
                            let mut record = Vec::with_capacity(remaining + waste.len());
                            record.extend_from_slice(payload);
                            record.extend_from_slice(&waste);
                            self.inner.write_all(&record).await?;
                        } else {
                            self.inner.write_all(payload).await?;
                        }
                        payload = &[];
                    } else {
                        let waste = waste_frame(record_size)?;
                        self.inner.write_all(&waste).await?;
                    }
                }
                if !payload.is_empty() {
                    self.inner.write_all(payload).await?;
                }
                self.inner.flush().await?;
                return Ok(());
            }
            self.send_padding = false;
        }

        self.inner.write_all(payload).await?;
        self.inner.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

struct AnyTlsUdp {
    target: String,
    port: u16,
    reader: Mutex<ReadHalf<BoxedStream>>,
    writer: Mutex<WriteHalf<BoxedStream>>,
}

#[async_trait]
impl UdpSocketLike for AnyTlsUdp {
    async fn send_to(&self, packet: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if normalize_host(target) != self.target || port != self.port {
            return Err(invalid_input(
                "AnyTLS UoT association cannot send to a different target",
            ));
        }
        let length = u16::try_from(packet.len())
            .map_err(|_| invalid_input("AnyTLS UoT datagram exceeds 65535 bytes"))?;
        let mut writer = self.writer.lock().await;
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(packet).await?;
        writer.flush().await?;
        Ok(packet.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.lock().await;
        let length = usize::from(reader.read_u16().await?);
        if length > output.len() {
            let mut remaining = length;
            let mut discard = [0u8; 2048];
            while remaining > 0 {
                let count = remaining.min(discard.len());
                reader.read_exact(&mut discard[..count]).await?;
                remaining -= count;
            }
            return Err(invalid_input(format!(
                "AnyTLS UoT receive buffer is too small: {} < {length}",
                output.len()
            )));
        }
        reader.read_exact(&mut output[..length]).await?;
        Ok(length)
    }

    async fn close(&self) -> io::Result<()> {
        self.writer.lock().await.shutdown().await
    }
}

fn build_authentication(
    password_sha256: &[u8; 32],
    padding: &PaddingFactory,
) -> io::Result<Vec<u8>> {
    let padding_length = padding
        .generate_record_payload_sizes(0)
        .first()
        .copied()
        .unwrap_or(0);
    let padding_length = u16::try_from(padding_length)
        .map_err(|_| invalid_data("AnyTLS authentication padding exceeds 65535 bytes"))?;
    let mut auth = Vec::with_capacity(34 + usize::from(padding_length));
    auth.extend_from_slice(password_sha256);
    auth.extend_from_slice(&padding_length.to_be_bytes());
    auth.resize(auth.len() + usize::from(padding_length), 0);
    Ok(auth)
}

fn frame_bytes(command: Command, sid: u32, data: &[u8]) -> io::Result<Bytes> {
    if data.len() > MAX_FRAME_DATA_LEN {
        return Err(invalid_input(format!(
            "AnyTLS {} frame payload exceeds 65535 bytes",
            command.name()
        )));
    }
    Ok(Frame::with_data(command, sid, Bytes::copy_from_slice(data)).to_bytes())
}

fn append_frame(output: &mut Vec<u8>, command: Command, sid: u32, data: &[u8]) -> io::Result<()> {
    output.extend_from_slice(&frame_bytes(command, sid, data)?);
    Ok(())
}

fn encode_data_frames(sid: u32, data: &[u8]) -> io::Result<Vec<u8>> {
    let frame_count = data.len().div_ceil(MAX_FRAME_DATA_LEN);
    let mut output = Vec::with_capacity(
        data.len()
            .saturating_add(frame_count.saturating_mul(HEADER_OVERHEAD_SIZE)),
    );
    for chunk in data.chunks(MAX_FRAME_DATA_LEN) {
        append_frame(&mut output, Command::Psh, sid, chunk)?;
    }
    Ok(output)
}

fn waste_frame(padding_length: usize) -> io::Result<Bytes> {
    if padding_length > MAX_FRAME_DATA_LEN {
        return Err(invalid_data(format!(
            "AnyTLS waste-frame padding exceeds 65535 bytes: {padding_length}"
        )));
    }
    frame_bytes(Command::Waste, 0, &vec![0u8; padding_length])
}

fn parse_padding_scheme(raw: &[u8]) -> io::Result<PaddingFactory> {
    validate_padding_scheme(raw)?;
    PaddingFactory::new(raw).ok_or_else(|| invalid_data("invalid AnyTLS padding scheme"))
}

fn validate_padding_scheme(raw: &[u8]) -> io::Result<()> {
    if raw.is_empty() || raw.len() > MAX_PADDING_SCHEME_LEN {
        return Err(invalid_data(format!(
            "AnyTLS padding scheme length must be 1..={MAX_PADDING_SCHEME_LEN}"
        )));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| invalid_data("AnyTLS padding scheme is not valid UTF-8"))?;
    let mut stop = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "stop" {
            let value = value
                .parse::<u32>()
                .map_err(|_| invalid_data("invalid AnyTLS padding stop value"))?;
            stop = Some(value);
            continue;
        }
        if key.parse::<u32>().is_err() {
            continue;
        }
        for record in value.split(',') {
            if record == "c" {
                continue;
            }
            let Some((minimum, maximum)) = record.split_once('-') else {
                continue;
            };
            for endpoint in [minimum, maximum] {
                let endpoint = endpoint
                    .parse::<u32>()
                    .map_err(|_| invalid_data("invalid AnyTLS padding record range"))?;
                if endpoint == 0 || endpoint > MAX_FRAME_DATA_LEN as u32 {
                    return Err(invalid_data(format!(
                        "AnyTLS padding record size must be 1..={MAX_FRAME_DATA_LEN}"
                    )));
                }
            }
        }
    }
    if stop.is_none() {
        return Err(invalid_data("AnyTLS padding scheme has no stop value"));
    }
    Ok(())
}

fn parse_settings(data: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn encode_uot_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let address = encode_socks_address(host, port)?;
    let mut request = Vec::with_capacity(1 + address.len());
    request.push(1); // UoT v2 connect mode
    request.extend_from_slice(&address);
    Ok(request)
}

fn encode_socks_address(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let normalized = normalize_host(host);
    let mut output = Vec::with_capacity(normalized.len() + 4);
    match normalized.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let length = u8::try_from(normalized.len())
                .map_err(|_| invalid_input("SOCKS domain exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid_input("SOCKS domain must not be empty"));
            }
            output.push(3);
            output.push(length);
            output.extend_from_slice(normalized.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(output)
}

fn normalize_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_uses_official_v2_command_ids() {
        assert_eq!(u8::from(Command::Waste), 0);
        assert_eq!(u8::from(Command::Syn), 1);
        assert_eq!(u8::from(Command::Psh), 2);
        assert_eq!(u8::from(Command::Fin), 3);
        assert_eq!(u8::from(Command::Settings), 4);
        assert_eq!(u8::from(Command::Alert), 5);
        assert_eq!(u8::from(Command::UpdatePaddingScheme), 6);
        assert_eq!(u8::from(Command::SynAck), 7);
        assert_eq!(u8::from(Command::HeartRequest), 8);
        assert_eq!(u8::from(Command::HeartResponse), 9);
        assert_eq!(u8::from(Command::ServerSettings), 10);
    }

    #[test]
    fn authentication_matches_official_layout() {
        let padding = parse_padding_scheme(b"stop=2\n0=9-9").unwrap();
        let hash: [u8; 32] = Sha256::digest(b"secret").into();
        let auth = build_authentication(&hash, &padding).unwrap();
        assert_eq!(&auth[..32], &hash);
        assert_eq!(&auth[32..34], &[0, 9]);
        assert_eq!(auth.len(), 43);
        assert!(auth[34..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn first_packet_has_settings_then_syn_then_target_psh() {
        let mut packet = Vec::new();
        append_frame(&mut packet, Command::Settings, 0, b"v=2").unwrap();
        append_frame(&mut packet, Command::Syn, 1, &[]).unwrap();
        append_frame(
            &mut packet,
            Command::Psh,
            1,
            &encode_socks_address("example.com", 443).unwrap(),
        )
        .unwrap();

        let first = Frame::from_bytes(&packet).unwrap();
        assert_eq!(first.cmd, Command::Settings);
        let second_offset = HEADER_OVERHEAD_SIZE + first.data.len();
        let second = Frame::from_bytes(&packet[second_offset..]).unwrap();
        assert_eq!(second.cmd, Command::Syn);
        let third_offset = second_offset + HEADER_OVERHEAD_SIZE;
        let third = Frame::from_bytes(&packet[third_offset..]).unwrap();
        assert_eq!(third.cmd, Command::Psh);
        assert_eq!(third.sid, 1);
        assert_eq!(third.data[0], 3);
    }

    #[test]
    fn large_write_is_split_into_u16_sized_psh_frames() {
        let data = vec![7u8; MAX_FRAME_DATA_LEN + 13];
        let encoded = encode_data_frames(8, &data).unwrap();
        let first = Frame::from_bytes(&encoded).unwrap();
        assert_eq!(first.data.len(), MAX_FRAME_DATA_LEN);
        let offset = HEADER_OVERHEAD_SIZE + first.data.len();
        let second = Frame::from_bytes(&encoded[offset..]).unwrap();
        assert_eq!(second.data.len(), 13);
        assert_eq!(second.sid, 8);
    }

    #[tokio::test]
    async fn writer_uses_waste_frames_to_reach_scheme_record_size() {
        let padding = Arc::new(RwLock::new(
            parse_padding_scheme(b"stop=3\n1=30-30").unwrap(),
        ));
        let (writer_side, mut reader_side) = tokio::io::duplex(128);
        let mut writer = SessionWriter::new(writer_side, padding);
        let syn = frame_bytes(Command::Syn, 1, &[]).unwrap();

        writer.write_packet(&syn).await.unwrap();
        let mut wire = [0u8; 30];
        reader_side.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire[..syn.len()], syn.as_ref());
        let waste = Frame::from_bytes(&wire[syn.len()..]).unwrap();
        assert_eq!(waste.cmd, Command::Waste);
        assert_eq!(waste.sid, 0);
        assert_eq!(waste.data.len(), 16);
        assert!(waste.data.iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn active_writer_observes_server_updated_shared_scheme() {
        let padding = Arc::new(RwLock::new(
            parse_padding_scheme(b"stop=4\n1=30-30\n2=30-30").unwrap(),
        ));
        let (writer_side, mut reader_side) = tokio::io::duplex(256);
        let mut writer = SessionWriter::new(writer_side, padding.clone());
        let syn = frame_bytes(Command::Syn, 1, &[]).unwrap();

        writer.write_packet(&syn).await.unwrap();
        let mut first = [0u8; 30];
        reader_side.read_exact(&mut first).await.unwrap();

        *padding.write().await = parse_padding_scheme(b"stop=4\n1=30-30\n2=40-40").unwrap();
        writer.write_packet(&syn).await.unwrap();
        let mut second = [0u8; 40];
        reader_side.read_exact(&mut second).await.unwrap();
        let waste = Frame::from_bytes(&second[syn.len()..]).unwrap();
        assert_eq!(waste.cmd, Command::Waste);
        assert_eq!(waste.data.len(), 26);
    }

    #[tokio::test]
    async fn session_round_trip_matches_official_frame_lifecycle() {
        let fixed = parse_padding_scheme(b"stop=4\n1=300-300\n2=200-200").unwrap();
        let padding = Arc::new(RwLock::new(fixed));
        let (client_side, mut server_side) = tokio::io::duplex(2048);
        let client_side: BoxedStream = Box::pin(client_side);
        let (reader, writer) = tokio::io::split(client_side);
        let session = AnyTlsSession::new(1, writer, padding, Weak::new());
        AnyTlsSession::spawn_reader(&session, reader);

        let target = encode_socks_address("example.com", 443).unwrap();
        let mut application = session.open_stream(target.clone(), true).await.unwrap();

        let settings = read_wire_frame(&mut server_side).await;
        let syn = read_wire_frame(&mut server_side).await;
        let target_frame = read_wire_frame(&mut server_side).await;
        let waste = read_wire_frame(&mut server_side).await;
        assert_eq!(settings.cmd, Command::Settings);
        assert_eq!(
            parse_settings(&settings.data).get("v").map(String::as_str),
            Some("2")
        );
        assert_eq!(syn.cmd, Command::Syn);
        assert_eq!(syn.sid, 1);
        assert_eq!(target_frame.cmd, Command::Psh);
        assert_eq!(target_frame.data.as_ref(), target.as_slice());
        assert_eq!(waste.cmd, Command::Waste);

        server_side
            .write_all(&frame_bytes(Command::ServerSettings, 0, b"v=2").unwrap())
            .await
            .unwrap();
        server_side
            .write_all(&frame_bytes(Command::Psh, 1, b"from-server").unwrap())
            .await
            .unwrap();
        let mut inbound = [0u8; 11];
        application.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"from-server");

        application.write_all(b"from-client").await.unwrap();
        application.flush().await.unwrap();
        let outbound = read_wire_frame(&mut server_side).await;
        let waste = read_wire_frame(&mut server_side).await;
        assert_eq!(outbound.cmd, Command::Psh);
        assert_eq!(outbound.sid, 1);
        assert_eq!(outbound.data.as_ref(), b"from-client");
        assert_eq!(waste.cmd, Command::Waste);

        server_side
            .write_all(&frame_bytes(Command::HeartRequest, 99, &[]).unwrap())
            .await
            .unwrap();
        let heartbeat = read_wire_frame(&mut server_side).await;
        assert_eq!(heartbeat.cmd, Command::HeartResponse);
        assert_eq!(heartbeat.sid, 99);

        server_side
            .write_all(&frame_bytes(Command::Fin, 1, &[]).unwrap())
            .await
            .unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(application.read(&mut eof).await.unwrap(), 0);
        session.close("test complete".into()).await;
    }

    #[tokio::test]
    async fn reused_stream_emits_separate_syn_and_target_and_honours_synack_error() {
        let padding = Arc::new(RwLock::new(parse_padding_scheme(b"stop=1\n0=1-1").unwrap()));
        let (client_side, mut server_side) = tokio::io::duplex(1024);
        let client_side: BoxedStream = Box::pin(client_side);
        let (reader, writer) = tokio::io::split(client_side);
        let session = AnyTlsSession::new(1, writer, padding, Weak::new());
        session
            .peer_version
            .store(PROTOCOL_VERSION, Ordering::Release);
        AnyTlsSession::spawn_reader(&session, reader);

        let target = encode_socks_address("reused.example", 80).unwrap();
        let mut application = session.open_stream(target.clone(), false).await.unwrap();
        let syn = read_wire_frame(&mut server_side).await;
        let target_frame = read_wire_frame(&mut server_side).await;
        assert_eq!(syn.cmd, Command::Syn);
        assert_eq!(target_frame.cmd, Command::Psh);
        assert_eq!(target_frame.data.as_ref(), target.as_slice());

        server_side
            .write_all(&frame_bytes(Command::SynAck, syn.sid, b"connection refused").unwrap())
            .await
            .unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(application.read(&mut eof).await.unwrap(), 0);
        let fin = read_wire_frame(&mut server_side).await;
        assert_eq!(fin.cmd, Command::Fin);
        assert_eq!(fin.sid, syn.sid);
        session.close("test complete".into()).await;
    }

    async fn read_wire_frame<R>(reader: &mut R) -> Frame
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut header = [0u8; HEADER_OVERHEAD_SIZE];
        reader.read_exact(&mut header).await.unwrap();
        let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        let mut wire = Vec::with_capacity(HEADER_OVERHEAD_SIZE + length);
        wire.extend_from_slice(&header);
        wire.resize(wire.len() + length, 0);
        reader
            .read_exact(&mut wire[HEADER_OVERHEAD_SIZE..])
            .await
            .unwrap();
        Frame::from_bytes(&wire).unwrap()
    }

    #[test]
    fn uot_request_is_connect_byte_plus_socks_target() {
        let request = encode_uot_request("1.2.3.4", 53).unwrap();
        assert_eq!(request, vec![1, 1, 1, 2, 3, 4, 0, 53]);
    }

    #[test]
    fn invalid_server_padding_is_bounded() {
        assert!(parse_padding_scheme(b"stop=8\n1=1-70000").is_err());
        assert!(parse_padding_scheme(b"stop=4294967295\n1=1-2").is_ok());
    }
}
