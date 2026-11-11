//! The TUN interface and the packet I/O the userspace stack reads from.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

#[derive(Clone, Debug, Default)]
pub struct TunOptions {
    pub name: String,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    /// A file descriptor handed over by the platform (Android VpnService).
    pub fd: Option<i32>,
    /// Path of `wintun.dll` (Windows).
    pub wintun_file: Option<String>,
}

pub struct Tun {
    device: Arc<AsyncDevice>,
    name: String,
    mtu: u16,
}

impl Tun {
    pub fn open(opts: &TunOptions) -> Result<Self> {
        let device = match opts.fd {
            #[cfg(unix)]
            Some(fd) => {
                // The platform keeps its descriptor (and closes it when the
                // VPN ends); the core works on a duplicate, so stopping or
                // reloading the core never closes the platform's one.
                // SAFETY: `dup` has no memory-safety requirements.
                let own = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if own < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("the TUN file descriptor is not usable");
                }
                // SAFETY: `own` is an open descriptor that nothing else owns.
                unsafe { AsyncDevice::from_fd(own) }
                    .context("cannot use the TUN file descriptor")?
            }
            #[cfg(not(unix))]
            Some(_) => anyhow::bail!("a TUN file descriptor can only be used on Unix"),
            None => {
                let mut builder = tun_rs::DeviceBuilder::new()
                    .name(opts.name.clone())
                    .mtu(opts.mtu);
                if let Some((ip, prefix)) = opts.ipv4 {
                    builder = builder.ipv4(ip, prefix, None);
                }
                if let Some((ip, prefix)) = opts.ipv6 {
                    builder = builder.ipv6(ip, prefix);
                }
                #[cfg(windows)]
                if let Some(path) = &opts.wintun_file {
                    builder = builder.wintun_file(path.clone());
                }
                builder.build_async().with_context(|| format!("cannot create the TUN interface `{}` (root or administrator rights are needed)", opts.name))?
            }
        };
        let name = device.name().unwrap_or_else(|_| opts.name.clone());
        Ok(Self {
            device: Arc::new(device),
            name,
            mtu: opts.mtu,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Starts the userspace TCP/IP stack on this interface.
    pub fn into_stack(self, udp_timeout: std::time::Duration) -> ipstack::IpStack {
        let mut config = ipstack::IpStackConfig::default();
        config.mtu_unchecked(self.mtu.max(1280));
        config.udp_timeout(udp_timeout);
        ipstack::IpStack::new(config, PacketIo::new(self.device))
    }
}

/// One packet per read and per write, as the stack expects.
struct PacketIo {
    incoming: mpsc::Receiver<io::Result<Bytes>>,
    outgoing: mpsc::UnboundedSender<Bytes>,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

impl PacketIo {
    fn new(device: Arc<AsyncDevice>) -> Self {
        let (in_tx, incoming) = mpsc::channel(1024);
        let (outgoing, mut out_rx) = mpsc::unbounded_channel::<Bytes>();
        let reader = {
            let device = device.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let r = device
                        .recv(&mut buf)
                        .await
                        .map(|n| Bytes::copy_from_slice(&buf[..n]));
                    let failed = r.is_err();
                    if in_tx.send(r).await.is_err() || failed {
                        return;
                    }
                }
            })
        };
        let writer = tokio::spawn(async move {
            while let Some(packet) = out_rx.recv().await {
                if let Err(e) = device.send(&packet).await {
                    tracing::debug!(target: "sybau::tun", "write to TUN: {e}");
                }
            }
        });
        Self {
            incoming,
            outgoing,
            tasks: [reader, writer],
        }
    }
}

impl Drop for PacketIo {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
    }
}

impl AsyncRead for PacketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.incoming.poll_recv(cx) {
            Poll::Ready(Some(Ok(packet))) => {
                let n = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.outgoing.send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
