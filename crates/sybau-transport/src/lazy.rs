//! Stream whose connection is established on the first write, so that the
//! first payload can travel inside the transport handshake (0-RTT).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll, Waker};

use bytes::Bytes;
use sybau_common::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
type ConnectFn = Box<dyn FnOnce(Bytes) -> ConnectFuture + Send>;

enum State {
    Idle(Option<ConnectFn>),
    Connecting(ConnectFuture),
    Ready(BoxStream),
    Failed(io::ErrorKind, String),
}

pub struct LazyStream {
    state: State,
    max_early: usize,
    /// The read and the write half may be polled by different tasks, but
    /// the connect future only remembers the last one. Both are kept here
    /// and woken when the connection attempt finishes.
    reader: Option<Waker>,
    writer: Option<Waker>,
}

#[derive(Clone, Copy)]
enum Side {
    Read,
    Write,
}

impl LazyStream {
    /// `connect` receives the early data (possibly empty) and must deliver
    /// it to the peer as part of connection establishment.
    pub fn new<F, Fut>(max_early: usize, connect: F) -> Self
    where
        F: FnOnce(Bytes) -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<BoxStream>> + Send + 'static,
    {
        Self {
            state: State::Idle(Some(Box::new(move |early| Box::pin(connect(early))))),
            max_early,
            reader: None,
            writer: None,
        }
    }

    fn start(&mut self, early: Bytes) {
        if let State::Idle(connect) = &mut self.state {
            let connect = connect.take().expect("connect function is taken once");
            self.state = State::Connecting(connect(early));
            if let Some(w) = self.reader.take() {
                w.wake();
            }
        }
    }

    fn wake_all(&mut self) {
        for w in [self.reader.take(), self.writer.take()]
            .into_iter()
            .flatten()
        {
            w.wake();
        }
    }

    /// Drives the connection attempt. `Ready(Ok(false))` means idle.
    fn poll_connected(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<bool>> {
        match &mut self.state {
            State::Idle(_) => Poll::Ready(Ok(false)),
            State::Ready(_) => Poll::Ready(Ok(true)),
            State::Failed(kind, msg) => Poll::Ready(Err(io::Error::new(*kind, msg.clone()))),
            State::Connecting(fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    let slot = match side {
                        Side::Read => &mut self.reader,
                        Side::Write => &mut self.writer,
                    };
                    *slot = Some(cx.waker().clone());
                    Poll::Pending
                }
                Poll::Ready(Ok(stream)) => {
                    self.state = State::Ready(stream);
                    self.wake_all();
                    Poll::Ready(Ok(true))
                }
                Poll::Ready(Err(e)) => {
                    self.state = State::Failed(e.kind(), e.to_string());
                    self.wake_all();
                    Poll::Ready(Err(e))
                }
            },
        }
    }

    fn stream(&mut self) -> Pin<&mut BoxStream> {
        match &mut self.state {
            State::Ready(s) => Pin::new(s),
            _ => unreachable!("only called after poll_connected returned true"),
        }
    }
}

impl AsyncRead for LazyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !ready!(self.poll_connected(cx, Side::Read))? {
            self.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.stream().poll_read(cx, buf)
    }
}

impl AsyncWrite for LazyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.state, State::Idle(_)) {
            let n = buf.len().min(self.max_early);
            self.start(Bytes::copy_from_slice(&buf[..n]));
            if n > 0 {
                // The early bytes are owned by the connect future now.
                let _ = self.poll_connected(cx, Side::Write)?;
                return Poll::Ready(Ok(n));
            }
        }
        ready!(self.poll_connected(cx, Side::Write))?;
        self.stream().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.start(Bytes::new());
        ready!(self.poll_connected(cx, Side::Write))?;
        self.stream().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !ready!(self.poll_connected(cx, Side::Write))? {
            return Poll::Ready(Ok(()));
        }
        self.stream().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn first_write_becomes_early_data() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (a, mut b) = tokio::io::duplex(64);
        let mut lazy = LazyStream::new(4, move |early| async move {
            let _ = tx.send(early);
            Ok(Box::new(a) as BoxStream)
        });
        lazy.write_all(b"abcdefgh").await.unwrap();
        lazy.flush().await.unwrap();
        assert_eq!(&rx.await.unwrap()[..], b"abcd");
        let mut rest = [0u8; 4];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"efgh");
    }

    #[tokio::test]
    async fn reader_waits_and_flush_connects_without_early_data() {
        let (a, mut b) = tokio::io::duplex(64);
        let lazy = LazyStream::new(16, move |early| async move {
            assert!(early.is_empty());
            Ok(Box::new(a) as BoxStream)
        });
        let (mut r, mut w) = tokio::io::split(lazy);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf).await.unwrap();
            buf
        });
        tokio::task::yield_now().await;
        w.flush().await.unwrap();
        b.write_all(b"hi").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"hi");
    }

    /// Reader and writer live in different tasks and the connection takes
    /// a while: whoever polled the connect future first must not be lost.
    #[tokio::test]
    async fn both_halves_are_woken_when_a_slow_connect_finishes() {
        for reader_polls_last in [false, true] {
            let (a, mut b) = tokio::io::duplex(64);
            let lazy = LazyStream::new(16, move |_early| async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok(Box::new(a) as BoxStream)
            });
            let (mut r, mut w) = tokio::io::split(lazy);
            let reader = tokio::spawn(async move {
                if reader_polls_last {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                let mut buf = [0u8; 2];
                r.read_exact(&mut buf).await.unwrap();
                buf
            });
            let writer = tokio::spawn(async move {
                if !reader_polls_last {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                w.write_all(b"x").await.unwrap();
                w.flush().await.unwrap();
                w
            });
            let _w = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
                .await
                .expect("writer stuck")
                .unwrap();
            b.write_all(b"hi").await.unwrap();
            let got = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
                .await
                .expect("reader stuck")
                .unwrap();
            assert_eq!(&got, b"hi");
        }
    }

    #[tokio::test]
    async fn connect_error_surfaces_on_later_operations() {
        let mut lazy = LazyStream::new(8, |_| async {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "nope"))
        });
        let _ = lazy.write(b"x").await;
        assert_eq!(
            lazy.flush().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            lazy.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
    }
}
