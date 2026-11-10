//! UDP helper for protocols whose streams are bound to one destination
//! (VLESS, VMess): one stream per destination, replies merged into one
//! [`PacketConn`].

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use sybau_common::{io_err, ArcPacketConn, PacketConn, Target};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

type OpenFuture = Pin<Box<dyn Future<Output = io::Result<ArcPacketConn>> + Send>>;
type OpenFn = Box<dyn Fn(Target) -> OpenFuture + Send + Sync>;

/// Upper bound of simultaneously open per-destination streams.
const MAX_DESTINATIONS: usize = 128;

pub struct PerDestination {
    open: OpenFn,
    conns: Mutex<HashMap<Target, ArcPacketConn>>,
    tx: mpsc::Sender<io::Result<(Bytes, Target)>>,
    rx: Mutex<mpsc::Receiver<io::Result<(Bytes, Target)>>>,
    readers: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl PerDestination {
    pub fn new<F, Fut>(open: F) -> Self
    where
        F: Fn(Target) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<ArcPacketConn>> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(64);
        Self {
            open: Box::new(move |t| Box::pin(open(t))),
            conns: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(rx),
            readers: parking_lot::Mutex::new(Vec::new()),
        }
    }

    async fn conn_for(&self, dst: &Target) -> io::Result<ArcPacketConn> {
        let mut conns = self.conns.lock().await;
        if let Some(c) = conns.get(dst) {
            return Ok(c.clone());
        }
        if conns.len() >= MAX_DESTINATIONS {
            return Err(io_err(
                io::ErrorKind::Other,
                "too many UDP destinations in one association",
            ));
        }
        let conn = (self.open)(dst.clone()).await?;
        conns.insert(dst.clone(), conn.clone());
        let (reader, tx) = (conn.clone(), self.tx.clone());
        self.readers.lock().push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match reader.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if tx
                            .send(Ok((Bytes::copy_from_slice(&buf[..n]), from)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    // One destination closing does not end the association.
                    Err(_) => return,
                }
            }
        }));
        Ok(conn)
    }
}

impl Drop for PerDestination {
    fn drop(&mut self) {
        self.readers.lock().iter().for_each(JoinHandle::abort);
    }
}

#[async_trait]
impl PacketConn for PerDestination {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let conn = self.conn_for(dst).await?;
        match conn.send_to(buf, dst).await {
            Ok(n) => Ok(n),
            Err(e) => {
                // Forget the broken stream; the next datagram opens a new one.
                self.conns.lock().await.remove(dst);
                Err(e)
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        match self.rx.lock().await.recv().await {
            Some(Ok((data, from))) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, from))
            }
            Some(Err(e)) => Err(e),
            None => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }
}
