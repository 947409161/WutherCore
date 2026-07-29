//! Transparent inbound facade.
//!
//! Platform TUN, TProxy and redirect internals live in `core-capture`, but
//! applications consume them through `core-inbound` so every ingress type has
//! one public ownership boundary.

pub use core_capture::*;

pub type TransparentInboundSupervisor = core_capture::CaptureSupervisor;
pub type TransparentInboundPlan = core_capture::CapturePlan;
pub type TransparentInboundCapabilities = core_capture::CaptureCapabilities;
pub type TransparentInboundError = core_capture::CaptureError;
pub type TransparentInboundEvent = core_capture::CaptureEvent;
