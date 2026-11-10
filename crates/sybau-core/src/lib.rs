//! SYBAU-CORE engine.
//!
//! [`Engine`] turns a [`sybau_config::Config`] into running inbounds and
//! outbounds, relays traffic between them and exposes the control API used
//! by both the `sybau` executable and the C library.

pub mod control;
pub mod dispatch;
pub mod engine;
pub mod inbound;
pub mod logging;
pub mod outbound;
pub mod relay;
pub mod stats;

pub use engine::{Engine, EngineOptions, RpcError};

/// Product name shown in file properties and logs.
pub const PRODUCT: &str = "SYBAU-CORE";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
