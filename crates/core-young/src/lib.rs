//! Young v1: an authenticated proxy protocol carried by Mozilla Neqo.
//!
//! The public API deliberately separates the Young wire format from the
//! Firefox HTTP/3/WebTransport carrier.  `codec` can be tested without NSS;
//! `client` and `server` drive Neqo on dedicated current-thread runtimes
//! because Neqo mirrors Firefox's `Rc<RefCell<_>>` integration model.

#![forbid(unsafe_code)]

#[cfg(feature = "firefox-stack")]
mod client;
mod codec;
#[cfg(feature = "firefox-stack")]
mod server;

#[cfg(feature = "firefox-stack")]
pub use client::{YoungClient, YoungClientConfig, YoungUdpChannel};
pub use codec::{
    DEFAULT_CLOCK_SKEW_SECS, DEFAULT_PADDING_MAX, DEFAULT_PADDING_MIN,
    DEFAULT_PADDING_SCHEME_LENGTH, DataFrame, FlowKind, FlowOpen, FlowResponse, KeyRing,
    MAX_DATA_PAYLOAD_BYTES, MAX_PADDING_BYTES, MAX_PADDING_SCHEME_LENGTH, PaddingDirection,
    PaddingScheme, ReplayCache, SessionKey, Status, Target, UdpReassembler, VERSION, YoungKey,
    create_authorization, decode_data_frame, decode_flow_open, decode_flow_open_padded,
    decode_flow_response, decode_padding_scheme, decode_udp_fragment, decode_udp_fragment_padded,
    derive_rotating_path, derive_session_key, encode_data_frames, encode_flow_open,
    encode_flow_response, encode_legacy_padding_scheme, encode_padding_scheme,
    encode_udp_fragments, encode_udp_fragments_padded, generate_padding_scheme,
    padding_cursor_for_flow, server_accept_proof, verify_authorization, verify_server_accept_proof,
};
#[cfg(feature = "firefox-stack")]
pub use server::{YoungServerConfig, YoungServerHandle};
