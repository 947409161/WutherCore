//! core-inbound 入站监听、协议解析与连接桥接。
//!
//! Protocol listeners and transparent TUN/TProxy/redirect ingress share this
//! public module. The lower-level `core-capture` crate remains an internal
//! platform backend and is re-exported through [`transparent`] when enabled.

#![deny(unsafe_code)]

#[cfg(all(feature = "with_ebpf", any(target_os = "linux", target_os = "android")))]
#[allow(unsafe_code)]
pub mod ebpf;
#[cfg(feature = "with_grpc")]
pub mod grpc;
pub mod listener;
pub mod mixed;
pub mod privilege;
#[cfg(feature = "with_reality")]
pub mod reality;
#[cfg(feature = "with_shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "with_tun")]
pub mod transparent;
pub mod vless;
#[cfg(feature = "with_xhttp")]
pub mod xhttp;
#[cfg(feature = "with_xhttp")]
mod xhttp_body_budget;
#[cfg(feature = "with_xhttp")]
mod xhttp_cors;
#[cfg(feature = "with_xhttp")]
pub mod xhttp_listener;
#[cfg(feature = "tls_inbound")]
mod xhttp_tls;

#[cfg(feature = "with_grpc")]
pub use grpc::{GrpcListener, run_grpc, run_grpc_with_cancellation};
pub use listener::{bind_with_fallback, select_bind_addr};
pub use mixed::{MixedListener, run_mixed};
pub use privilege::{
    PrivilegeLevel, PrivilegeReport, ensure_best_effort_privilege, try_request_root_android,
};
#[cfg(feature = "with_reality")]
pub use reality::{RealityListener, run_reality};
#[cfg(feature = "with_shadowsocks")]
pub use shadowsocks::{
    ShadowsocksListenerHandle, start_shadowsocks_listener, start_shadowsocks_listeners,
};
pub use vless::{VlessConnectionContext, VlessInboundConfig, serve_vless_stream};
#[cfg(feature = "with_xhttp")]
pub use xhttp_listener::{XhttpListenerHandle, start_xhttp_listener, start_xhttp_listeners};
#[cfg(feature = "tls_inbound")]
pub use xhttp_tls::{XrayServerTlsAcceptor, XrayServerTlsCarrier, XrayServerTlsStream};
