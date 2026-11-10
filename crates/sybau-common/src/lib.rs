//! Shared building blocks of SYBAU-CORE: addresses, stream and datagram
//! traits, session metadata and the system (direct) dialer.

pub mod addr;
pub mod net;
pub mod session;
pub mod stream;

pub use addr::{Host, Target};
pub use net::{Dialer, Resolver, SocketOpts, SystemDialer, SystemResolver};
pub use session::{Network, Session};
pub use stream::{
    poll_drain, ArcPacketConn, AsyncStream, BoxStream, HeaderStream, PacketConn, PrefixedStream,
};

use std::io;

/// Shorthand for building an `io::Error` with a formatted message.
pub fn io_err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

/// `InvalidData` error: the peer sent something that violates the protocol.
pub fn proto_err(msg: impl Into<String>) -> io::Error {
    io_err(io::ErrorKind::InvalidData, msg)
}

pub mod outbound;
pub use outbound::{Outbound, OutboundDialer};
pub use stream::RawSwitch;
