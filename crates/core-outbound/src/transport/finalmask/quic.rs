//! Execution of Xray 26.7.11 `finalmask.quicParams` on Quinn.
//!
//! Xray source of truth:
//! `transport/internet/hysteria/dialer.go` at
//! `6e3322d219140a025285ded1114fe17a5edb74d8`.

use std::{
    any::Any,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use core_config::{BandwidthValue, PortListValue, QuicParamsConfig};
use quinn::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use quinn_proto::{
    RttEstimator,
    congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics, NewRenoConfig},
};

use super::quic_socket::BrutalPacketPacing;

const HYSTERIA1_DEFAULT_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const HYSTERIA1_DEFAULT_CONNECTION_WINDOW: u64 = HYSTERIA1_DEFAULT_STREAM_WINDOW * 5 / 2;
const HYSTERIA1_DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HYSTERIA1_DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(10);
const HYSTERIA2_DEFAULT_STREAM_WINDOW: u64 = 8 * 1024 * 1024;
const HYSTERIA2_DEFAULT_CONNECTION_WINDOW: u64 = HYSTERIA2_DEFAULT_STREAM_WINDOW * 5 / 2;
const HYSTERIA2_DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HYSTERIA2_DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(10);
const HYSTERIA2_DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
const MIN_BRUTAL_RATE: u64 = 65_536;
const HYSTERIA1_BRUTAL_GAIN_MILLI: u32 = 1_500;
const HYSTERIA2_BRUTAL_GAIN_MILLI: u32 = 2_000;
const HYSTERIA1_BRUTAL_BURST_DELAY: Duration = Duration::from_millis(2);
const HYSTERIA2_BRUTAL_BURST_DELAY: Duration = Duration::from_millis(4);

/// Values Quinn needs after the endpoint has been created.
#[derive(Debug, Clone)]
pub struct AppliedQuicParams {
    pub(crate) congestion: CongestionMode,
    pub(crate) brutal_up: u64,
    pub(crate) brutal_down: u64,
    pub(crate) udp_hop: Option<UdpHopPlan>,
    /// Quinn exposes a live connection-level receive window setter. The
    /// configured maximum is applied after the handshake when it differs from
    /// the initial transport parameter.
    pub(crate) max_connection_receive_window: Option<VarInt>,
    switch: Option<SwitchHandle>,
    packet_pacing: Option<BrutalPacketPacing>,
    local_brutal_rate: u64,
}

impl AppliedQuicParams {
    /// Complete Xray's `brutal` negotiation after Hysteria's auth response.
    /// `server_rx` is the peer's advertised receive bandwidth in bytes/sec.
    pub fn finish_hysteria_negotiation(&self, peer_rx: HysteriaPeerRx) {
        let Some(switch) = &self.switch else {
            return;
        };
        if self.local_brutal_rate == 0 || matches!(peer_rx, HysteriaPeerRx::Auto) {
            switch.packet_pacing.set_enabled(false);
            switch.packet_pacing.reset_ack_rate();
            switch.use_bbr.store(true, Ordering::Release);
            return;
        }
        let HysteriaPeerRx::Rate(peer_rx) = peer_rx else {
            unreachable!("auto handled above")
        };
        // A numeric zero means "unlimited", not "auto".  The sender must keep
        // its configured Brutal rate in that case.
        let negotiated = if peer_rx == 0 {
            self.local_brutal_rate
        } else {
            self.local_brutal_rate.min(peer_rx)
        };
        switch.rate.store(negotiated, Ordering::Release);
        switch.packet_pacing.set_rate(negotiated);
        switch.packet_pacing.reset_ack_rate();
        switch.use_bbr.store(false, Ordering::Release);
        switch.packet_pacing.set_enabled(true);
    }

    pub fn congestion_mode(&self) -> CongestionMode {
        self.congestion
    }

    pub fn brutal_up(&self) -> u64 {
        self.brutal_up
    }

    pub fn brutal_down(&self) -> u64 {
        self.brutal_down
    }

    pub fn udp_hop(&self) -> Option<&UdpHopPlan> {
        self.udp_hop.as_ref()
    }

    pub fn apply_max_receive_window(&self, connection: &quinn::Connection) {
        if let Some(window) = self.max_connection_receive_window {
            connection.set_receive_window(window);
        }
    }

    pub(crate) fn packet_pacing(&self) -> Option<BrutalPacketPacing> {
        self.packet_pacing.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaPeerRx {
    /// The peer explicitly requested ordinary adaptive congestion control.
    Auto,
    /// A numeric receive rate. Zero has the protocol-defined "unlimited"
    /// meaning and is deliberately distinct from [`Self::Auto`].
    Rate(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionMode {
    Reno,
    Bbr,
    Brutal,
    ForceBrutal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHopPlan {
    pub ports: Vec<u16>,
    pub interval_min: Duration,
    pub interval_max: Duration,
}

#[derive(Debug, Clone)]
struct SwitchHandle {
    rate: Arc<AtomicU64>,
    use_bbr: Arc<AtomicBool>,
    packet_pacing: BrutalPacketPacing,
}

/// Apply every Quinn-representable field and return the carrier-level fields.
pub fn apply_client_config(
    client: &mut ClientConfig,
    params: Option<&QuicParamsConfig>,
) -> io::Result<AppliedQuicParams> {
    let (transport, applied) = build_transport_config(params, false, HYSTERIA2_BRUTAL_GAIN_MILLI)?;
    client.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the legacy Hysteria 1 transport profile.  Hysteria 1 uses the same
/// loss-compensating Brutal controller but its official implementation uses a
/// 1.5 BDP congestion window instead of Hysteria 2's 2.0 BDP window.
pub fn apply_hysteria1_client_config(
    client: &mut ClientConfig,
    params: &QuicParamsConfig,
) -> io::Result<AppliedQuicParams> {
    let (transport, applied) =
        build_transport_config(Some(params), false, HYSTERIA1_BRUTAL_GAIN_MILLI)?;
    client.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the same pinned Xray QUIC parameters to a Quinn server endpoint.
/// Hysteria servers should call [`AppliedQuicParams::finish_hysteria_negotiation`]
/// after authentication with the client's advertised receive rate.
pub fn apply_server_config(
    server: &mut ServerConfig,
    params: Option<&QuicParamsConfig>,
) -> io::Result<AppliedQuicParams> {
    let (transport, applied) = build_transport_config(params, true, HYSTERIA2_BRUTAL_GAIN_MILLI)?;
    server.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the XHTTP/3 server interpretation of Xray's shared QUIC parameters.
/// XHTTP has no Hysteria bandwidth negotiation: empty/`bbr` selects BBR and
/// `force-brutal` uses `brutalUp` immediately, exactly like SplitHTTP's
/// `QListener`.  Explicit `brutal` is rejected instead of reaching Xray's
/// transport-specific panic branch.
pub fn apply_xhttp_server_config(
    server: &mut ServerConfig,
    params: Option<&QuicParamsConfig>,
    default_idle_timeout: Duration,
    max_concurrent_streams: u32,
) -> io::Result<AppliedQuicParams> {
    let (mut transport, mut applied) =
        build_transport_config(params, true, HYSTERIA2_BRUTAL_GAIN_MILLI)?;
    let owned_default;
    let params = match params {
        Some(params) => params,
        None => {
            owned_default = QuicParamsConfig::default();
            &owned_default
        }
    };
    match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => {
            applied.congestion = CongestionMode::Reno;
            applied.switch = None;
            applied.packet_pacing = None;
        }
        "" | "bbr" => {
            transport
                .congestion_controller_factory(BbrProfile::parse(&params.bbr_profile)?.factory());
            applied.congestion = CongestionMode::Bbr;
            applied.switch = None;
            applied.packet_pacing = None;
            applied.local_brutal_rate = 0;
        }
        "force-brutal" => {
            let rate_value = parse_bandwidth(&params.brutal_up)?;
            if rate_value < MIN_BRUTAL_RATE {
                return Err(invalid(
                    "XHTTP quicParams force-brutal requires brutalUp >= 65536 bytes/s",
                ));
            }
            let rate = Arc::new(AtomicU64::new(rate_value));
            let packet_pacing = BrutalPacketPacing::new(
                rate.clone(),
                Arc::new(AtomicBool::new(true)),
                1200,
                HYSTERIA2_BRUTAL_BURST_DELAY,
            );
            transport.congestion_controller_factory(Arc::new(BrutalFactory {
                rate,
                window_gain_milli: HYSTERIA2_BRUTAL_GAIN_MILLI,
                disable_loss_compensation: params.brutal_disable_loss_compensation,
                packet_pacing: packet_pacing.clone(),
            }));
            applied.congestion = CongestionMode::ForceBrutal;
            applied.switch = None;
            applied.packet_pacing = Some(packet_pacing);
            applied.local_brutal_rate = rate_value;
        }
        "brutal" => {
            return Err(invalid(
                "XHTTP/3 does not negotiate quicParams.congestion=brutal; use bbr, reno or force-brutal",
            ));
        }
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    }
    if params.max_idle_timeout == 0 {
        transport
            .max_idle_timeout(Some(IdleTimeout::try_from(default_idle_timeout).map_err(
                |_| invalid("XHTTP listener idle timeout exceeds QUIC's range"),
            )?));
    }
    let configured_streams = if params.max_incoming_streams == 0 {
        u64::from(max_concurrent_streams)
    } else {
        (params.max_incoming_streams as u64).min(u64::from(max_concurrent_streams))
    };
    transport
        .max_concurrent_bidi_streams(varint(configured_streams, "XHTTP max incoming streams")?);
    server.transport_config(Arc::new(transport));
    Ok(applied)
}

/// Apply the client-side XHTTP/3 interpretation.  XHTTP uses a 300-second
/// default idle timeout and its XMUX keepalive when quicParams leaves those
/// values at zero; congestion selection otherwise mirrors the server path.
pub fn apply_xhttp_client_config(
    client: &mut ClientConfig,
    params: &QuicParamsConfig,
    default_keep_alive: Option<Duration>,
) -> io::Result<AppliedQuicParams> {
    let (mut transport, mut applied) =
        build_transport_config(Some(params), false, HYSTERIA2_BRUTAL_GAIN_MILLI)?;
    match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => {
            applied.congestion = CongestionMode::Reno;
            applied.switch = None;
            applied.packet_pacing = None;
        }
        "" | "bbr" => {
            transport
                .congestion_controller_factory(BbrProfile::parse(&params.bbr_profile)?.factory());
            applied.congestion = CongestionMode::Bbr;
            applied.switch = None;
            applied.packet_pacing = None;
            applied.local_brutal_rate = 0;
        }
        "force-brutal" => {
            let rate_value = parse_bandwidth(&params.brutal_up)?;
            if rate_value < MIN_BRUTAL_RATE {
                return Err(invalid(
                    "XHTTP quicParams force-brutal requires brutalUp >= 65536 bytes/s",
                ));
            }
            let rate = Arc::new(AtomicU64::new(rate_value));
            let packet_pacing = BrutalPacketPacing::new(
                rate.clone(),
                Arc::new(AtomicBool::new(true)),
                1200,
                HYSTERIA2_BRUTAL_BURST_DELAY,
            );
            transport.congestion_controller_factory(Arc::new(BrutalFactory {
                rate,
                window_gain_milli: HYSTERIA2_BRUTAL_GAIN_MILLI,
                disable_loss_compensation: params.brutal_disable_loss_compensation,
                packet_pacing: packet_pacing.clone(),
            }));
            applied.congestion = CongestionMode::ForceBrutal;
            applied.switch = None;
            applied.packet_pacing = Some(packet_pacing);
            applied.local_brutal_rate = rate_value;
        }
        "brutal" => {
            return Err(invalid(
                "XHTTP/3 does not negotiate quicParams.congestion=brutal; use bbr, reno or force-brutal",
            ));
        }
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    }
    if params.max_idle_timeout == 0 {
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(300))
                .expect("300 seconds is a valid QUIC idle timeout"),
        ));
    }
    if params.keep_alive_period == 0 {
        transport.keep_alive_interval(default_keep_alive);
    }
    if params.max_incoming_streams > 0 {
        transport.max_concurrent_bidi_streams(varint(
            params.max_incoming_streams as u64,
            "XHTTP max incoming streams",
        )?);
    }
    client.transport_config(Arc::new(transport));
    Ok(applied)
}

fn build_transport_config(
    params: Option<&QuicParamsConfig>,
    server_side: bool,
    brutal_window_gain_milli: u32,
) -> io::Result<(TransportConfig, AppliedQuicParams)> {
    let owned_default;
    let params = match params {
        Some(value) => value,
        None => {
            owned_default = QuicParamsConfig::default();
            &owned_default
        }
    };
    let hysteria1 = brutal_window_gain_milli == HYSTERIA1_BRUTAL_GAIN_MILLI;
    validate_params(params, hysteria1)?;
    let (default_stream_window, default_connection_window, default_idle_timeout) = if hysteria1 {
        (
            HYSTERIA1_DEFAULT_STREAM_WINDOW,
            HYSTERIA1_DEFAULT_CONNECTION_WINDOW,
            HYSTERIA1_DEFAULT_IDLE_TIMEOUT,
        )
    } else {
        (
            HYSTERIA2_DEFAULT_STREAM_WINDOW,
            HYSTERIA2_DEFAULT_CONNECTION_WINDOW,
            HYSTERIA2_DEFAULT_IDLE_TIMEOUT,
        )
    };

    let brutal_up = parse_bandwidth(&params.brutal_up)?;
    let brutal_down = parse_bandwidth(&params.brutal_down)?;
    let local_brutal_rate = if server_side { brutal_down } else { brutal_up };

    let congestion = match params.congestion.trim().to_ascii_lowercase().as_str() {
        "reno" => CongestionMode::Reno,
        "bbr" => CongestionMode::Bbr,
        "force-brutal" => {
            if brutal_up == 0 {
                return Err(invalid("quicParams force-brutal requires brutalUp"));
            }
            CongestionMode::ForceBrutal
        }
        "" | "brutal" => CongestionMode::Brutal,
        other => return Err(invalid(format!("unknown QUIC congestion `{other}`"))),
    };
    if congestion == CongestionMode::ForceBrutal
        && ((brutal_up != 0 && brutal_up < MIN_BRUTAL_RATE)
            || (brutal_down != 0 && brutal_down < MIN_BRUTAL_RATE))
    {
        return Err(invalid(
            "quicParams force-brutal bandwidth must be zero or at least 65536 bytes/s",
        ));
    }

    let stream_initial = nonzero_or(params.init_stream_receive_window, default_stream_window);
    let stream_max = nonzero_or(params.max_stream_receive_window, default_stream_window);
    let connection_initial = nonzero_or(
        params.init_connection_receive_window,
        default_connection_window,
    );
    let connection_max = nonzero_or(
        params.max_connection_receive_window,
        default_connection_window,
    );

    let mut transport = TransportConfig::default();
    // Quinn has one per-stream window rather than quic-go's initial+autotuned
    // pair. Advertising the larger configured value preserves the declared
    // maximum and prevents a smaller initial value from becoming a hard cap.
    transport.stream_receive_window(varint(stream_initial.max(stream_max), "stream window")?);
    transport.receive_window(varint(connection_initial, "connection window")?);
    let idle_timeout = if params.max_idle_timeout == 0 {
        default_idle_timeout
    } else {
        Duration::from_secs(params.max_idle_timeout as u64)
    };
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(idle_timeout)
            .map_err(|_| invalid("quicParams maxIdleTimeout is too large"))?,
    ));
    transport.keep_alive_interval((!server_side).then(|| {
        if params.keep_alive_period == 0 {
            if hysteria1 {
                idle_timeout * 2 / 5
            } else {
                HYSTERIA2_DEFAULT_KEEP_ALIVE
            }
        } else {
            Duration::from_secs(params.keep_alive_period as u64)
        }
    }));
    if params.disable_path_mtu_discovery
        || !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        ))
    {
        transport.mtu_discovery_config(None);
    }
    if server_side {
        transport.max_concurrent_bidi_streams(varint(
            if params.max_incoming_streams == 0 {
                1024
            } else {
                params.max_incoming_streams as u64
            },
            "max incoming streams",
        )?);
    }
    // Hysteria uses QUIC datagrams. Match the existing implementation's
    // bounded buffers while keeping this executor usable by H3/XHTTP.
    transport
        .datagram_receive_buffer_size(Some(16 * 1024 * 1024))
        .datagram_send_buffer_size(16 * 1024 * 1024);

    let profile = BbrProfile::parse(&params.bbr_profile)?;
    let (switch, packet_pacing) = match congestion {
        CongestionMode::Reno => {
            transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
            (None, None)
        }
        CongestionMode::Bbr => {
            transport.congestion_controller_factory(profile.factory());
            (None, None)
        }
        CongestionMode::ForceBrutal => {
            let rate = Arc::new(AtomicU64::new(local_brutal_rate));
            let enabled = Arc::new(AtomicBool::new(true));
            let packet_pacing = BrutalPacketPacing::new(
                rate.clone(),
                enabled,
                1200,
                brutal_burst_delay(brutal_window_gain_milli),
            );
            transport.congestion_controller_factory(Arc::new(BrutalFactory {
                rate,
                window_gain_milli: brutal_window_gain_milli,
                disable_loss_compensation: params.brutal_disable_loss_compensation,
                packet_pacing: packet_pacing.clone(),
            }));
            (None, Some(packet_pacing))
        }
        CongestionMode::Brutal => {
            let rate = Arc::new(AtomicU64::new(local_brutal_rate.max(1)));
            // Hysteria starts with ordinary congestion control for the QUIC
            // handshake and only activates Brutal after auth negotiation.
            let use_bbr = Arc::new(AtomicBool::new(true));
            let packet_pacing = BrutalPacketPacing::new(
                rate.clone(),
                Arc::new(AtomicBool::new(false)),
                1200,
                brutal_burst_delay(brutal_window_gain_milli),
            );
            transport.congestion_controller_factory(Arc::new(SwitchableFactory {
                rate: rate.clone(),
                use_bbr: use_bbr.clone(),
                bbr: profile.factory(),
                window_gain_milli: brutal_window_gain_milli,
                disable_loss_compensation: params.brutal_disable_loss_compensation,
                packet_pacing: packet_pacing.clone(),
            }));
            (
                Some(SwitchHandle {
                    rate,
                    use_bbr,
                    packet_pacing: packet_pacing.clone(),
                }),
                Some(packet_pacing),
            )
        }
    };

    if params.debug {
        tracing::debug!(
            ?congestion,
            ?profile,
            brutal_up,
            brutal_down,
            stream_initial,
            stream_max,
            connection_initial,
            connection_max,
            "finalmask QUIC debug enabled"
        );
    }

    Ok((
        transport,
        AppliedQuicParams {
            congestion,
            brutal_up,
            brutal_down,
            udp_hop: build_udp_hop(params, hysteria1)?,
            max_connection_receive_window: (connection_max != connection_initial)
                .then(|| varint(connection_max, "max connection window"))
                .transpose()?,
            switch,
            packet_pacing,
            local_brutal_rate,
        },
    ))
}

fn brutal_burst_delay(window_gain_milli: u32) -> Duration {
    if window_gain_milli == HYSTERIA1_BRUTAL_GAIN_MILLI {
        HYSTERIA1_BRUTAL_BURST_DELAY
    } else {
        HYSTERIA2_BRUTAL_BURST_DELAY
    }
}

fn build_udp_hop(params: &QuicParamsConfig, hysteria1: bool) -> io::Result<Option<UdpHopPlan>> {
    let ports = parse_ports(&params.udp_hop.ports)?;
    if ports.is_empty() {
        return Ok(None);
    }
    let default_interval = if hysteria1 {
        HYSTERIA1_DEFAULT_HOP_INTERVAL
    } else {
        HYSTERIA2_DEFAULT_HOP_INTERVAL
    };
    let minimum_interval = if hysteria1 { 8 } else { 5 };
    let min = if params.udp_hop.interval.from == 0 {
        default_interval.as_secs() as i32
    } else {
        params.udp_hop.interval.from
    };
    let max = if params.udp_hop.interval.to == 0 {
        default_interval.as_secs() as i32
    } else {
        params.udp_hop.interval.to
    };
    if min < minimum_interval || max < min {
        return Err(invalid(format!(
            "quicParams udpHop interval must be an ordered range >= {minimum_interval}s"
        )));
    }
    Ok(Some(UdpHopPlan {
        ports,
        interval_min: Duration::from_secs(min as u64),
        interval_max: Duration::from_secs(max as u64),
    }))
}

fn validate_params(params: &QuicParamsConfig, hysteria1: bool) -> io::Result<()> {
    let minimum_window = if hysteria1 { 65_536 } else { 16_384 };
    for (field, value) in [
        ("initStreamReceiveWindow", params.init_stream_receive_window),
        ("maxStreamReceiveWindow", params.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            params.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            params.max_connection_receive_window,
        ),
    ] {
        if value != 0 && value < minimum_window {
            return Err(invalid(format!(
                "quicParams {field} must be zero or at least {minimum_window}"
            )));
        }
    }
    let invalid_idle_timeout = if hysteria1 {
        params.max_idle_timeout != 0 && params.max_idle_timeout < 4
    } else {
        params.max_idle_timeout != 0 && !(4..=120).contains(&params.max_idle_timeout)
    };
    if invalid_idle_timeout {
        return Err(invalid(if hysteria1 {
            "quicParams maxIdleTimeout must be zero or at least 4 seconds"
        } else {
            "quicParams maxIdleTimeout must be zero or between 4 and 120 seconds"
        }));
    }
    if params.keep_alive_period != 0 && !(2..=60).contains(&params.keep_alive_period) {
        return Err(invalid(
            "quicParams keepAlivePeriod must be zero or between 2 and 60 seconds",
        ));
    }
    if params.max_incoming_streams != 0 && params.max_incoming_streams < 8 {
        return Err(invalid(
            "quicParams maxIncomingStreams must be zero or at least 8",
        ));
    }
    let minimum_hop_interval = if hysteria1 { 8 } else { 5 };
    for endpoint in [params.udp_hop.interval.from, params.udp_hop.interval.to] {
        if endpoint != 0 && endpoint < minimum_hop_interval {
            return Err(invalid(format!(
                "quicParams udpHop interval endpoints must be zero or at least {minimum_hop_interval} seconds"
            )));
        }
    }
    Ok(())
}

pub(crate) fn parse_bandwidth(value: &BandwidthValue) -> io::Result<u64> {
    match value {
        BandwidthValue::Empty => Ok(0),
        // serde's numeric alternative is the same textual value Xray feeds to
        // Bandwidth.Bps: bare numbers are bits per second.
        BandwidthValue::Number(value) => Ok(value / 8),
        BandwidthValue::Text(value) => {
            let input = value.trim().to_ascii_lowercase();
            if input.is_empty() {
                return Ok(0);
            }
            let split = input
                .char_indices()
                .find_map(|(index, ch)| (!ch.is_ascii_digit() && ch != '.').then_some(index))
                .unwrap_or(input.len());
            let number = input[..split]
                .parse::<f64>()
                .map_err(|_| invalid(format!("invalid bandwidth `{value}`")))?;
            if !number.is_finite() || number.is_sign_negative() {
                return Err(invalid(format!("invalid bandwidth `{value}`")));
            }
            let multiplier = match input[split..].trim() {
                "" | "b" | "bps" => 1_u64,
                "k" | "kb" | "kbps" => 1024,
                "m" | "mb" | "mbps" => 1024 * 1024,
                "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
                "t" | "tb" | "tbps" => 1024_u64.pow(4),
                unit => return Err(invalid(format!("unsupported bandwidth unit `{unit}`"))),
            };
            let bits = number * multiplier as f64;
            if bits > u64::MAX as f64 {
                return Err(invalid("bandwidth overflows u64"));
            }
            Ok(bits as u64 / 8)
        }
    }
}

pub(crate) fn parse_ports(value: &PortListValue) -> io::Result<Vec<u16>> {
    let raw = match value {
        PortListValue::Empty => return Ok(Vec::new()),
        PortListValue::Number(value) => {
            if *value == 0 {
                return Ok(Vec::new());
            }
            let port = u16::try_from(*value)
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid(format!("invalid UDP hop port `{value}`")))?;
            return Ok(vec![port]);
        }
        PortListValue::Text(value) => value,
    };
    let mut ports = Vec::new();
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let Some((left, right)) = item.split_once('-') else {
            ports.push(parse_port(item)?);
            continue;
        };
        let left = parse_port(left.trim())?;
        let right = parse_port(right.trim())?;
        if left > right {
            return Err(invalid(format!("invalid UDP hop port range `{item}`")));
        }
        ports.extend(left..=right);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_port(value: &str) -> io::Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid(format!("invalid UDP hop port `{value}`")))
}

fn nonzero_or(value: u64, default: u64) -> u64 {
    if value == 0 { default } else { value }
}

fn varint(value: u64, field: &str) -> io::Result<VarInt> {
    VarInt::from_u64(value).map_err(|_| invalid(format!("quicParams {field} exceeds QUIC varint")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

impl BbrProfile {
    fn parse(input: &str) -> io::Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "conservative" => Ok(Self::Conservative),
            "" | "standard" => Ok(Self::Standard),
            "aggressive" => Ok(Self::Aggressive),
            other => Err(invalid(format!("unknown BBR profile `{other}`"))),
        }
    }

    fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        let mut config = BbrConfig::default();
        // Quinn's public BBR configuration exposes the initial window but not
        // quic-go's internal gain knobs. Scale startup capacity according to
        // Xray's three pinned profiles; the controller remains genuine BBR.
        let packets = match self {
            Self::Conservative => 9,
            Self::Standard => 10,
            Self::Aggressive => 13,
        };
        config.initial_window(packets * 1200);
        Arc::new(config)
    }
}

const BRUTAL_SLOT_COUNT: usize = 5;
const BRUTAL_MIN_SAMPLE_COUNT: u64 = 50;
const BRUTAL_MIN_ACK_RATE: f64 = 0.8;
const BRUTAL_INITIAL_WINDOW: u64 = 10_240;

/// Quinn port of Hysteria's official Brutal sender.
///
/// Quinn's controller API supplies the official congestion window and
/// ACK/loss state machine. The packet worker supplies Brutal's independent
/// token-bucket pacer because Quinn's built-in pacer derives its rate from the
/// congestion window. The two generations retain their respective 4/5-second
/// samples and 1.5/2.0 BDP gains.
struct BrutalFactory {
    rate: Arc<AtomicU64>,
    window_gain_milli: u32,
    disable_loss_compensation: bool,
    packet_pacing: BrutalPacketPacing,
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        self.packet_pacing.set_max_datagram_size(current_mtu);
        Box::new(BrutalController {
            rate: self.rate.clone(),
            window_gain_milli: self.window_gain_milli,
            disable_loss_compensation: self.disable_loss_compensation,
            packet_pacing: self.packet_pacing.clone(),
            mtu: u64::from(current_mtu),
            base: now,
            srtt: Duration::ZERO,
            ack_rate: 1.0,
            sample_slots: if self.window_gain_milli == HYSTERIA1_BRUTAL_GAIN_MILLI {
                4
            } else {
                BRUTAL_SLOT_COUNT
            },
            slots: [BrutalSlot::default(); BRUTAL_SLOT_COUNT],
        })
    }
}

#[derive(Clone, Copy, Default)]
struct BrutalSlot {
    timestamp: i64,
    acked: u64,
    lost: u64,
}

#[derive(Clone)]
struct BrutalController {
    rate: Arc<AtomicU64>,
    window_gain_milli: u32,
    disable_loss_compensation: bool,
    packet_pacing: BrutalPacketPacing,
    mtu: u64,
    base: Instant,
    srtt: Duration,
    ack_rate: f64,
    sample_slots: usize,
    slots: [BrutalSlot; BRUTAL_SLOT_COUNT],
}

impl BrutalController {
    fn timestamp(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.base).as_secs() as i64
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let timestamp = self.timestamp(now);
        let slot = &mut self.slots[(timestamp as usize) % self.sample_slots];
        if slot.timestamp == timestamp {
            slot.acked = slot.acked.saturating_add(acked);
            slot.lost = slot.lost.saturating_add(lost);
        } else {
            *slot = BrutalSlot {
                timestamp,
                acked,
                lost,
            };
        }
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, now: i64) {
        if self.disable_loss_compensation {
            self.ack_rate = 1.0;
            self.packet_pacing.set_ack_rate(self.ack_rate);
            return;
        }
        let minimum_timestamp = now - self.sample_slots as i64;
        let (acked, lost) = self
            .slots
            .iter()
            .take(self.sample_slots)
            .filter(|slot| slot.timestamp >= minimum_timestamp)
            .fold((0u64, 0u64), |(acked, lost), slot| {
                (
                    acked.saturating_add(slot.acked),
                    lost.saturating_add(slot.lost),
                )
            });
        let samples = acked.saturating_add(lost);
        self.ack_rate = if samples < BRUTAL_MIN_SAMPLE_COUNT {
            1.0
        } else {
            (acked as f64 / samples as f64).max(BRUTAL_MIN_ACK_RATE)
        };
        self.packet_pacing.set_ack_rate(self.ack_rate);
    }
}

impl Controller for BrutalController {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if !self.packet_pacing.is_enabled() {
            return;
        }
        self.srtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _persistent: bool,
        lost_bytes: u64,
    ) {
        if self.packet_pacing.is_enabled() && lost_bytes > 0 {
            let lost_packets = lost_bytes.div_ceil(self.mtu.max(1));
            self.record(now, 0, lost_packets);
        }
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = u64::from(mtu);
        self.packet_pacing.set_max_datagram_size(mtu);
    }

    fn window(&self) -> u64 {
        if self.srtt.is_zero() {
            return BRUTAL_INITIAL_WINDOW;
        }
        let rate = self.rate.load(Ordering::Relaxed) as f64;
        let gain = f64::from(self.window_gain_milli) / 1_000.0;
        let window = rate * self.srtt.as_secs_f64() * gain / self.ack_rate;
        if self.window_gain_milli == HYSTERIA1_BRUTAL_GAIN_MILLI {
            (window as u64).max(1)
        } else {
            (window as u64).max(self.mtu)
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate =
            Some(((self.rate.load(Ordering::Relaxed) as f64 / self.ack_rate) * 8.0) as u64);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        BRUTAL_INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

struct SwitchableFactory {
    rate: Arc<AtomicU64>,
    use_bbr: Arc<AtomicBool>,
    bbr: Arc<dyn ControllerFactory + Send + Sync>,
    window_gain_milli: u32,
    disable_loss_compensation: bool,
    packet_pacing: BrutalPacketPacing,
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let brutal = Arc::new(BrutalFactory {
            rate: self.rate.clone(),
            window_gain_milli: self.window_gain_milli,
            disable_loss_compensation: self.disable_loss_compensation,
            packet_pacing: self.packet_pacing.clone(),
        })
        .build(now, current_mtu);
        let bbr = self.bbr.clone().build(now, current_mtu);
        Box::new(SwitchableController {
            brutal,
            bbr,
            use_bbr: self.use_bbr.clone(),
        })
    }
}

struct SwitchableController {
    brutal: Box<dyn Controller>,
    bbr: Box<dyn Controller>,
    use_bbr: Arc<AtomicBool>,
}

impl Clone for SwitchableController {
    fn clone(&self) -> Self {
        Self {
            brutal: self.brutal.clone_box(),
            bbr: self.bbr.clone_box(),
            use_bbr: self.use_bbr.clone(),
        }
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, packet: u64) {
        self.brutal.on_sent(now, bytes, packet);
        self.bbr.on_sent(now, bytes, packet);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.brutal
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        self.brutal
            .on_congestion_event(now, sent, persistent, lost_bytes);
        self.bbr
            .on_congestion_event(now, sent, persistent, lost_bytes);
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.brutal.on_mtu_update(mtu);
        self.bbr.on_mtu_update(mtu);
    }

    fn window(&self) -> u64 {
        self.active().window()
    }

    fn initial_window(&self) -> u64 {
        self.active().initial_window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl SwitchableController {
    fn active(&self) -> &dyn Controller {
        if self.use_bbr.load(Ordering::Acquire) {
            &*self.bbr
        } else {
            &*self.brutal
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use core_config::{I32Range, UdpHopConfig};

    use super::*;

    #[test]
    fn bandwidth_matches_xray_binary_units_and_bits_to_bytes() {
        assert_eq!(
            parse_bandwidth(&BandwidthValue::Text("10 mbps".into())).unwrap(),
            10 * 1024 * 1024 / 8
        );
        assert_eq!(
            parse_bandwidth(&BandwidthValue::Text("1.5G".into())).unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64 / 8
        );
        assert_eq!(parse_bandwidth(&BandwidthValue::Number(800)).unwrap(), 100);
        assert!(parse_bandwidth(&BandwidthValue::Text("10 MiB/s".into())).is_err());
    }

    #[test]
    fn port_list_expands_ranges_and_deduplicates() {
        assert_eq!(
            parse_ports(&PortListValue::Text("443, 2000-2002,443".into())).unwrap(),
            [443, 2000, 2001, 2002]
        );
        assert!(parse_ports(&PortListValue::Text("4-2".into())).is_err());
        assert!(parse_ports(&PortListValue::Number(0)).unwrap().is_empty());
        let complete = parse_ports(&PortListValue::Text("1-65535".into())).unwrap();
        assert_eq!(complete.len(), 65_535);
        assert_eq!((complete[0], complete[65_534]), (1, 65_535));
    }

    #[test]
    fn rejects_every_out_of_range_official_quic_parameter() {
        for invalid_params in [
            QuicParamsConfig {
                init_stream_receive_window: 16_383,
                ..Default::default()
            },
            QuicParamsConfig {
                max_stream_receive_window: 1,
                ..Default::default()
            },
            QuicParamsConfig {
                init_connection_receive_window: 8_192,
                ..Default::default()
            },
            QuicParamsConfig {
                max_connection_receive_window: 12_000,
                ..Default::default()
            },
            QuicParamsConfig {
                max_idle_timeout: 121,
                ..Default::default()
            },
            QuicParamsConfig {
                keep_alive_period: 1,
                ..Default::default()
            },
            QuicParamsConfig {
                max_incoming_streams: 7,
                ..Default::default()
            },
            QuicParamsConfig {
                udp_hop: UdpHopConfig {
                    ports: PortListValue::Empty,
                    interval: I32Range::fixed(4),
                },
                ..Default::default()
            },
        ] {
            assert!(
                validate_params(&invalid_params, false).is_err(),
                "{invalid_params:?}"
            );
        }
        assert!(validate_params(&QuicParamsConfig::default(), false).is_ok());
    }

    #[test]
    fn hysteria_generations_keep_their_official_validation_profiles() {
        let small_window = QuicParamsConfig {
            max_stream_receive_window: 32_768,
            ..Default::default()
        };
        assert!(validate_params(&small_window, true).is_err());
        assert!(validate_params(&small_window, false).is_ok());

        let long_idle = QuicParamsConfig {
            max_idle_timeout: 121,
            ..Default::default()
        };
        assert!(validate_params(&long_idle, true).is_ok());
        assert!(validate_params(&long_idle, false).is_err());

        let short_hop = QuicParamsConfig {
            udp_hop: UdpHopConfig {
                ports: PortListValue::Number(443),
                interval: I32Range::fixed(5),
            },
            ..Default::default()
        };
        assert!(build_udp_hop(&short_hop, true).is_err());
        assert!(build_udp_hop(&short_hop, false).is_ok());
    }

    #[test]
    fn all_transport_fields_compile_together() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            debug: true,
            bbr_profile: "aggressive".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            brutal_down: BandwidthValue::Text("16 mbps".into()),
            brutal_disable_loss_compensation: true,
            udp_hop: UdpHopConfig {
                ports: PortListValue::Text("2000-2002".into()),
                interval: I32Range::new(5, 9),
            },
            init_stream_receive_window: 65_536,
            max_stream_receive_window: 131_072,
            init_connection_receive_window: 262_144,
            max_connection_receive_window: 524_288,
            max_idle_timeout: 20,
            keep_alive_period: 5,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 16,
        };
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
        .unwrap();
        let mut client = ClientConfig::new(Arc::new(crypto));
        let applied = apply_client_config(&mut client, Some(&params)).unwrap();
        assert_eq!(applied.congestion, CongestionMode::ForceBrutal);
        assert_eq!(applied.brutal_up, 1024 * 1024);
        assert_eq!(applied.brutal_down, 2 * 1024 * 1024);
        let hop = applied.udp_hop.unwrap();
        assert_eq!(hop.ports, [2000, 2001, 2002]);
        assert_eq!(hop.interval_min, Duration::from_secs(5));
        assert_eq!(hop.interval_max, Duration::from_secs(9));
        assert_eq!(
            applied.max_connection_receive_window.unwrap(),
            VarInt::from_u32(524_288)
        );
    }

    #[test]
    fn client_and_server_use_the_correct_hysteria_send_bandwidth() {
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            brutal_down: BandwidthValue::Text("16 mbps".into()),
            ..Default::default()
        };
        let (_, client) =
            build_transport_config(Some(&params), false, HYSTERIA2_BRUTAL_GAIN_MILLI).unwrap();
        let (_, server) =
            build_transport_config(Some(&params), true, HYSTERIA2_BRUTAL_GAIN_MILLI).unwrap();
        assert_eq!(client.local_brutal_rate, 1024 * 1024);
        assert_eq!(server.local_brutal_rate, 2 * 1024 * 1024);

        let _: fn(&mut ServerConfig, Option<&QuicParamsConfig>) -> io::Result<AppliedQuicParams> =
            apply_server_config;
    }

    #[test]
    fn brutal_uses_version_specific_sampling_and_bdp_gain() {
        let base = Instant::now();
        let rate = Arc::new(AtomicU64::new(1_000_000));
        let hy1_pacing = BrutalPacketPacing::new(
            rate.clone(),
            Arc::new(AtomicBool::new(true)),
            1200,
            HYSTERIA1_BRUTAL_BURST_DELAY,
        );
        let mut hy1 = BrutalController {
            rate: rate.clone(),
            window_gain_milli: HYSTERIA1_BRUTAL_GAIN_MILLI,
            disable_loss_compensation: false,
            packet_pacing: hy1_pacing.clone(),
            mtu: 1200,
            base,
            srtt: Duration::from_millis(100),
            ack_rate: 1.0,
            sample_slots: 4,
            slots: [BrutalSlot::default(); BRUTAL_SLOT_COUNT],
        };
        let hy2_pacing = BrutalPacketPacing::new(
            rate.clone(),
            Arc::new(AtomicBool::new(true)),
            1200,
            HYSTERIA2_BRUTAL_BURST_DELAY,
        );
        let mut hy2 = BrutalController {
            rate,
            window_gain_milli: HYSTERIA2_BRUTAL_GAIN_MILLI,
            disable_loss_compensation: false,
            packet_pacing: hy2_pacing.clone(),
            mtu: 1200,
            base,
            srtt: Duration::from_millis(100),
            ack_rate: 1.0,
            sample_slots: 5,
            slots: [BrutalSlot::default(); BRUTAL_SLOT_COUNT],
        };
        assert_eq!(hy1.window(), 150_000);
        assert_eq!(hy2.window(), 200_000);
        hy1.record(base, 40, 10);
        hy2.record(base, 40, 10);
        assert_eq!(hy1.ack_rate, 0.8);
        assert_eq!(hy2.ack_rate, 0.8);
        assert_eq!(hy1.window(), 187_500);
        assert_eq!(hy2.window(), 250_000);
        assert_eq!(hy1_pacing.effective_rate(), 1_250_000);
        assert_eq!(hy2_pacing.effective_rate(), 1_250_000);
    }

    #[test]
    fn brutal_disable_loss_compensation_keeps_ack_rate_one() {
        let base = Instant::now();
        let rate = Arc::new(AtomicU64::new(1_000_000));
        let packet_pacing = BrutalPacketPacing::new(
            rate.clone(),
            Arc::new(AtomicBool::new(true)),
            1200,
            HYSTERIA2_BRUTAL_BURST_DELAY,
        );
        let mut controller = BrutalController {
            rate,
            window_gain_milli: HYSTERIA2_BRUTAL_GAIN_MILLI,
            disable_loss_compensation: true,
            packet_pacing: packet_pacing.clone(),
            mtu: 1200,
            base,
            srtt: Duration::from_millis(100),
            ack_rate: 1.0,
            sample_slots: 5,
            slots: [BrutalSlot::default(); BRUTAL_SLOT_COUNT],
        };
        controller.record(base, 1, 99);
        assert_eq!(controller.ack_rate, 1.0);
        assert_eq!(controller.window(), 200_000);
        assert_eq!(packet_pacing.effective_rate(), 1_000_000);
    }

    #[test]
    fn hysteria_brutal_pacing_starts_only_after_numeric_negotiation() {
        let params = QuicParamsConfig {
            congestion: "brutal".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            ..Default::default()
        };
        let (_, applied) =
            build_transport_config(Some(&params), false, HYSTERIA2_BRUTAL_GAIN_MILLI).unwrap();
        let pacing = applied.packet_pacing().unwrap();
        assert!(!pacing.is_enabled());

        applied.finish_hysteria_negotiation(HysteriaPeerRx::Rate(0));
        assert!(pacing.is_enabled());
        assert_eq!(pacing.effective_rate(), 1024 * 1024);

        pacing.set_ack_rate(0.8);
        assert_eq!(pacing.effective_rate(), 1280 * 1024);

        applied.finish_hysteria_negotiation(HysteriaPeerRx::Auto);
        assert!(!pacing.is_enabled());
    }

    #[test]
    fn xhttp_quic_uses_force_brutal_without_hysteria_negotiation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
        .unwrap();
        let mut client = ClientConfig::new(Arc::new(crypto));
        let params = QuicParamsConfig {
            congestion: "force-brutal".into(),
            brutal_up: BandwidthValue::Text("8 mbps".into()),
            ..Default::default()
        };
        let applied =
            apply_xhttp_client_config(&mut client, &params, Some(Duration::from_secs(15))).unwrap();
        assert_eq!(applied.congestion_mode(), CongestionMode::ForceBrutal);
        assert_eq!(applied.local_brutal_rate, 1024 * 1024);
        assert!(applied.switch.is_none());

        let mut unsupported = params;
        unsupported.congestion = "brutal".into();
        assert!(apply_xhttp_client_config(&mut client, &unsupported, None).is_err());
    }
}
