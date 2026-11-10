//! Proxy protocol codecs of SYBAU-CORE.
//!
//! Header encoders and decoders are plain functions over byte slices so
//! that they can be fuzzed; the stream types wrap them for tokio.
//!
//! Convention shared by all client streams: nothing is sent until the
//! first write or flush, so the protocol header leaves together with the
//! first payload.

pub mod crypto;
pub mod packet;
pub mod shadowsocks;
pub mod trojan;
pub mod uuid;
pub mod vision;
pub mod vless;
pub mod vmess;
pub mod xudp;
