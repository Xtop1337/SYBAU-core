//! DNS for SYBAU-CORE: message codec, upstream clients (UDP, TCP, DoT,
//! DoH) that can run through outbounds, a TTL cache and the fake-ip pool.

pub mod cache;
pub mod fakeip;
pub mod message;
pub mod quic;
pub mod upstream;

pub use message::{Message, Question, Record, RecordData};
