//! TLS 1.3 client of SYBAU-CORE with browser fingerprints and REALITY.
//!
//! The ClientHello is rebuilt from templates sampled from uTLS (see
//! `tools/utls-dump`), so it matches what Xray sends for the same
//! fingerprint name.

pub mod fingerprint;
pub mod handshake;
pub mod keys;
pub mod keyshare;
pub mod reality;
pub mod stream;
pub mod verify;

pub use fingerprint::Fingerprint;
pub use handshake::{connect, ClientConfig, Trust};
pub use reality::RealityParams;
pub use stream::TlsStream;
