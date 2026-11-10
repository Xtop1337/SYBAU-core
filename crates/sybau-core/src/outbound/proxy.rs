//! VLESS, VMess and Trojan outbounds.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use sybau_common::{ArcPacketConn, BoxStream, Dialer, HeaderStream, Outbound, Session, Target};
use sybau_config::{TrojanOutbound, VlessOutbound, VmessOutbound};
use sybau_proto::packet::{FramedPacketConn, LengthPrefixed, MessagePacketConn};
use sybau_proto::{trojan, uuid, vless, vmess};
use sybau_transport::Connector;

use super::udp::PerDestination;

fn server_target(server: &str, port: u16) -> Result<Target> {
    if server.is_empty() {
        bail!("`server` is empty");
    }
    if port == 0 {
        bail!("`port` must not be 0");
    }
    Ok(Target::from_host(server, port))
}

pub struct Vless {
    tag: Arc<str>,
    connector: Arc<Connector>,
    uuid: [u8; 16],
}

impl Vless {
    pub fn new(tag: Arc<str>, cfg: &VlessOutbound, dialer: Arc<dyn Dialer>) -> Result<Self> {
        let uuid = uuid::parse(&cfg.uuid).ok_or_else(|| anyhow!("invalid uuid `{}`", cfg.uuid))?;
        let server = server_target(&cfg.server, cfg.port)?;
        let connector = Arc::new(Connector::new(
            dialer,
            server,
            cfg.tls.as_ref(),
            cfg.transport.as_ref(),
        )?);
        Ok(Self {
            tag,
            connector,
            uuid,
        })
    }
}

#[async_trait]
impl Outbound for Vless {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vless"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let io = self.connector.connect().await?;
        Ok(Box::new(vless::VlessStream::new(
            io,
            &self.uuid,
            None,
            vless::CMD_TCP,
            &sess.target,
        )))
    }

    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        let (connector, uuid) = (self.connector.clone(), self.uuid);
        Ok(Arc::new(PerDestination::new(move |dst: Target| {
            let connector = connector.clone();
            async move {
                let io = connector.connect().await?;
                let stream: BoxStream = Box::new(vless::VlessStream::new(
                    io,
                    &uuid,
                    None,
                    vless::CMD_UDP,
                    &dst,
                ));
                Ok(
                    Arc::new(FramedPacketConn::new(stream, LengthPrefixed { peer: dst }))
                        as ArcPacketConn,
                )
            }
        })))
    }
}

pub struct Vmess {
    tag: Arc<str>,
    connector: Arc<Connector>,
    uuid: [u8; 16],
    security: vmess::Security,
    global_padding: bool,
}

impl Vmess {
    pub fn new(tag: Arc<str>, cfg: &VmessOutbound, dialer: Arc<dyn Dialer>) -> Result<Self> {
        let uuid = uuid::parse(&cfg.uuid).ok_or_else(|| anyhow!("invalid uuid `{}`", cfg.uuid))?;
        if cfg.alter_id != 0 {
            bail!(
                "alter_id {} is not supported: only VMess AEAD (alter_id 0) is implemented",
                cfg.alter_id
            );
        }
        let security = vmess::Security::parse(&cfg.security).ok_or_else(|| {
            anyhow!("unsupported VMess security `{}` (use auto, aes-128-gcm, chacha20-poly1305, none or zero)", cfg.security)
        })?;
        let server = server_target(&cfg.server, cfg.port)?;
        let connector = Arc::new(Connector::new(
            dialer,
            server,
            cfg.tls.as_ref(),
            cfg.transport.as_ref(),
        )?);
        Ok(Self {
            tag,
            connector,
            uuid,
            security,
            global_padding: cfg.global_padding,
        })
    }
}

#[async_trait]
impl Outbound for Vmess {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vmess"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let io = self.connector.connect().await?;
        Ok(Box::new(vmess::VmessStream::new(
            io,
            &self.uuid,
            self.security,
            self.global_padding,
            vmess::CMD_TCP,
            &sess.target,
        )))
    }

    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        let (connector, uuid, security, padding) = (
            self.connector.clone(),
            self.uuid,
            self.security,
            self.global_padding,
        );
        // `zero` has no chunks and therefore no datagram boundaries.
        let security = if security == vmess::Security::Zero {
            vmess::Security::None
        } else {
            security
        };
        Ok(Arc::new(PerDestination::new(move |dst: Target| {
            let connector = connector.clone();
            async move {
                let io = connector.connect().await?;
                let stream: BoxStream = Box::new(vmess::VmessStream::new(
                    io,
                    &uuid,
                    security,
                    padding,
                    vmess::CMD_UDP,
                    &dst,
                ));
                Ok(Arc::new(MessagePacketConn::new(stream, dst)) as ArcPacketConn)
            }
        })))
    }
}

pub struct Trojan {
    tag: Arc<str>,
    connector: Connector,
    hash: [u8; 56],
}

impl Trojan {
    pub fn new(tag: Arc<str>, cfg: &TrojanOutbound, dialer: Arc<dyn Dialer>) -> Result<Self> {
        if cfg.password.is_empty() {
            bail!("`password` is empty");
        }
        let server = server_target(&cfg.server, cfg.port)?;
        let connector = Connector::new(dialer, server, cfg.tls.as_ref(), cfg.transport.as_ref())?;
        Ok(Self {
            tag,
            connector,
            hash: trojan::password_hash(&cfg.password),
        })
    }
}

#[async_trait]
impl Outbound for Trojan {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "trojan"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let io = self.connector.connect().await?;
        let header = trojan::encode_request(&self.hash, trojan::CMD_CONNECT, &sess.target);
        Ok(Box::new(HeaderStream::new(header.freeze(), io)))
    }

    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn> {
        let io = self.connector.connect().await?;
        let header = trojan::encode_request(&self.hash, trojan::CMD_UDP_ASSOCIATE, &sess.target);
        let stream: BoxStream = Box::new(HeaderStream::new(header.freeze(), io));
        Ok(Arc::new(FramedPacketConn::new(
            stream,
            trojan::TrojanPacketCodec,
        )))
    }
}
