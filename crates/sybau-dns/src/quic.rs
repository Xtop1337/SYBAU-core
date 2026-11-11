//! QUIC for DNS upstreams (DoQ, DoH3). The QUIC endpoint runs on a
//! packet connection of an outbound, so a server is reached directly
//! (with the core's socket options) or through a proxy, like every other
//! upstream.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rustls::pki_types::ServerName;
use sybau_common::{io_err, ArcPacketConn, Host, Network, Outbound, Session, Target};
use sybau_config::TlsConfig;
use sybau_tls::verify::{build_verifier, provider, VerifyOptions};
use tokio::sync::mpsc;

const QUEUE: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A quinn socket that sends every datagram to one target through a
/// packet connection. quinn knows the server by `peer`, a stand-in when
/// the target is a domain (resolved at the end of a proxy).
struct PacketSocket {
    peer: SocketAddr,
    local: SocketAddr,
    out: mpsc::Sender<Bytes>,
    incoming: parking_lot::Mutex<mpsc::Receiver<Bytes>>,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

impl fmt::Debug for PacketSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketSocket")
            .field("peer", &self.peer)
            .finish()
    }
}

impl PacketSocket {
    fn new(conn: ArcPacketConn, target: Target) -> Self {
        let peer = match target.host {
            Host::Ip(ip) => SocketAddr::new(ip, target.port),
            // Any unicast address works: quinn only hands it back to us.
            Host::Domain(_) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)), target.port)
            }
        };
        let local = if peer.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let (out, mut out_rx) = mpsc::channel::<Bytes>(QUEUE);
        let (in_tx, incoming) = mpsc::channel::<Bytes>(QUEUE);
        let sender = {
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Some(datagram) = out_rx.recv().await {
                    if let Err(e) = conn.send_to(&datagram, &target).await {
                        tracing::debug!(target: "sybau::dns", "QUIC send: {e}");
                    }
                }
            })
        };
        let receiver = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match conn.recv_from(&mut buf).await {
                    // Datagrams beyond the queue are dropped, as a busy
                    // socket would; QUIC recovers.
                    Ok((n, _)) => {
                        let _ = in_tx.try_send(Bytes::copy_from_slice(&buf[..n]));
                    }
                    Err(e) => {
                        tracing::debug!(target: "sybau::dns", "QUIC receive: {e}");
                        return;
                    }
                }
            }
        });
        Self {
            peer,
            local,
            out,
            incoming: parking_lot::Mutex::new(incoming),
            tasks: [sender, receiver],
        }
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
    }
}

/// Sends never block (a full queue drops the datagram), so the socket is
/// always writable.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for PacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // One datagram per transmit: max_transmit_segments is 1.
        let _ = self.out.try_send(Bytes::copy_from_slice(transmit.contents));
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.incoming.lock().poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                let n = datagram.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&datagram[..n]);
                meta[0] = RecvMeta {
                    addr: self.peer,
                    len: n,
                    stride: n,
                    ..Default::default()
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io_err(
                io::ErrorKind::BrokenPipe,
                "packet connection closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// Opens and reuses one QUIC connection to a server.
pub struct QuicConnector {
    server: Target,
    server_name: String,
    outbound: Arc<dyn Outbound>,
    config: quinn::ClientConfig,
    current: tokio::sync::Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
}

impl QuicConnector {
    /// `alpn` is the protocol the server expects (`doq`, `h3`).
    pub fn new(
        server: Target,
        outbound: Arc<dyn Outbound>,
        tls: Option<&TlsConfig>,
        alpn: &str,
    ) -> Result<Self> {
        let tls = tls.cloned().unwrap_or_default();
        let server_name = tls
            .server_name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| server.host_string());
        ServerName::try_from(server_name.clone())
            .map_err(|_| anyhow!("invalid TLS server name `{server_name}`"))?;
        let verify = VerifyOptions {
            verify_names: tls.verify_names.clone(),
            ..VerifyOptions::from_strings(
                tls.insecure,
                &tls.pinned_cert_sha256,
                &tls.pinned_cert_chain_sha256,
            )?
        };
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| anyhow!("TLS configuration: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(build_verifier(&verify)?)
            .with_no_client_auth();
        crypto.alpn_protocols = if tls.alpn.is_empty() {
            vec![alpn.as_bytes().to_vec()]
        } else {
            tls.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        };
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow!("QUIC TLS configuration: {e}"))?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("small timeout")));
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            server,
            server_name,
            outbound,
            config,
            current: tokio::sync::Mutex::new(None),
        })
    }

    /// The live connection, or a new one. `fresh` drops the current one
    /// first (a query failed on it).
    pub async fn connection(&self, fresh: bool) -> io::Result<quinn::Connection> {
        let mut current = self.current.lock().await;
        if let Some((_, conn)) = current.as_ref() {
            if !fresh && conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        *current = None;
        let packets = self
            .outbound
            .bind(&Session::new(
                Network::Udp,
                Arc::from("dns"),
                None,
                self.server.clone(),
            ))
            .await?;
        let socket = Arc::new(PacketSocket::new(packets, self.server.clone()));
        let peer = socket.peer;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let connecting = endpoint
            .connect_with(self.config.clone(), peer, &self.server_name)
            .map_err(|e| io_err(io::ErrorKind::InvalidInput, e.to_string()))?;
        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| io_err(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
            .map_err(|e| io_err(io::ErrorKind::ConnectionRefused, format!("QUIC: {e}")))?;
        *current = Some((endpoint, conn.clone()));
        Ok(conn)
    }
}

pub fn quic_err(e: impl fmt::Display) -> io::Error {
    io_err(io::ErrorKind::ConnectionAborted, format!("QUIC: {e}"))
}
