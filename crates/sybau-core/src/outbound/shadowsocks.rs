//! Shadowsocks outbound: classic AEAD, Shadowsocks 2022 and `none`.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use sybau_common::addr::{parse_socks_addr, put_socks_addr};
use sybau_common::{
    ArcPacketConn, BoxStream, Dialer, HeaderStream, Outbound, PacketConn, Session, Target,
};
use sybau_config::ShadowsocksOutbound;
use sybau_proto::crypto::AeadKind;
use sybau_proto::shadowsocks::aead::{SsAeadPacketConn, SsAeadStream};
use sybau_proto::shadowsocks::ss2022::{Ss2022PacketConn, Ss2022Stream};
use sybau_proto::shadowsocks::{evp_bytes_to_key, parse_2022_keys, parse_method, Method};

enum Keys {
    None,
    Aead(AeadKind, Vec<u8>),
    Ss2022(AeadKind, Vec<Vec<u8>>),
}

pub struct Shadowsocks {
    tag: Arc<str>,
    dialer: Arc<dyn Dialer>,
    server: Target,
    keys: Keys,
}

impl Shadowsocks {
    pub fn new(tag: Arc<str>, cfg: &ShadowsocksOutbound, dialer: Arc<dyn Dialer>) -> Result<Self> {
        if cfg.server.is_empty() || cfg.port == 0 {
            bail!("`server` and `port` are required");
        }
        let method = parse_method(&cfg.method).ok_or_else(|| {
            anyhow!("unsupported Shadowsocks method `{}` (stream ciphers such as aes-256-cfb or rc4-md5 are insecure and not implemented)", cfg.method)
        })?;
        let keys = match method {
            Method::None => Keys::None,
            Method::Aead(kind) => {
                if cfg.password.is_empty() {
                    bail!("`password` is empty");
                }
                Keys::Aead(
                    kind,
                    evp_bytes_to_key(cfg.password.as_bytes(), kind.key_len()),
                )
            }
            Method::Ss2022(kind) => Keys::Ss2022(
                kind,
                parse_2022_keys(&cfg.password, kind).map_err(|e| anyhow!("{e}"))?,
            ),
        };
        Ok(Self {
            tag,
            dialer,
            server: Target::from_host(&cfg.server, cfg.port),
            keys,
        })
    }
}

#[async_trait]
impl Outbound for Shadowsocks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let io = self.dialer.dial_tcp(&self.server).await?;
        Ok(match &self.keys {
            Keys::None => {
                let mut addr = BytesMut::new();
                put_socks_addr(&mut addr, &sess.target);
                Box::new(HeaderStream::new(addr.freeze(), io))
            }
            Keys::Aead(kind, key) => {
                Box::new(SsAeadStream::new(io, *kind, key.clone(), &sess.target))
            }
            Keys::Ss2022(kind, keys) => {
                Box::new(Ss2022Stream::new(io, *kind, keys.clone(), &sess.target))
            }
        })
    }

    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        let inner = self.dialer.dial_udp(&self.server).await?;
        let server = self.server.clone();
        Ok(match &self.keys {
            Keys::None => Arc::new(PlainPacketConn { inner, server }),
            Keys::Aead(kind, key) => {
                Arc::new(SsAeadPacketConn::new(inner, server, *kind, key.clone()))
            }
            Keys::Ss2022(kind, keys) => {
                Arc::new(Ss2022PacketConn::new(inner, server, *kind, keys.clone()))
            }
        })
    }
}

/// UDP of the `none` method: `addr | payload` without encryption.
struct PlainPacketConn {
    inner: ArcPacketConn,
    server: Target,
}

#[async_trait]
impl PacketConn for PlainPacketConn {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let mut packet = BytesMut::with_capacity(buf.len() + 32);
        put_socks_addr(&mut packet, dst);
        packet.extend_from_slice(buf);
        self.inner.send_to(&packet, &self.server).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut scratch = vec![0u8; 65535];
        loop {
            let (n, _) = self.inner.recv_from(&mut scratch).await?;
            let Ok(Some((from, used))) = parse_socks_addr(&scratch[..n]) else {
                continue;
            };
            let len = (n - used).min(buf.len());
            buf[..len].copy_from_slice(&scratch[used..used + len]);
            return Ok((len, from));
        }
    }
}
