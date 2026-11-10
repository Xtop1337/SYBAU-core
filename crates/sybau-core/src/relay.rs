//! Bidirectional relay with idle detection.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// No traffic in either direction for this long closes the connection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// After one side finished sending, the other side gets this long between
/// packets to finish too. Servers that never close would otherwise leak.
pub const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

const BUF_SIZE: usize = 32 * 1024;

struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    async fn idle_for(&self, limit: Duration) {
        loop {
            let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
            let idle = self.start.elapsed().saturating_sub(last);
            if idle >= limit {
                return;
            }
            tokio::time::sleep(limit - idle).await;
        }
    }
}

async fn copy_half<R, W>(mut r: R, mut w: W, activity: &Activity) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        activity.touch();
    }
}

/// Copies data both ways until both sides are done, an error occurs or the
/// connection has been idle for too long.
pub async fn relay<A, B>(a: A, b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let activity = Activity {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
    };
    let up = copy_half(ar, bw, &activity);
    let down = copy_half(br, aw, &activity);
    tokio::pin!(up, down);
    let (mut up_done, mut down_done) = (false, false);
    while !(up_done && down_done) {
        let limit = if up_done || down_done {
            HALF_CLOSE_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        tokio::select! {
            r = &mut up, if !up_done => { r?; up_done = true; }
            r = &mut down, if !down_done => { r?; down_done = true; }
            _ = activity.idle_for(limit) => return Ok(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relays_both_directions_and_propagates_eof() {
        let (mut client, a) = duplex(1024);
        let (b, mut server) = duplex(1024);
        let task = tokio::spawn(relay(a, b));
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        client.shutdown().await.unwrap();
        assert_eq!(server.read(&mut buf).await.unwrap(), 0);
        server.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }
}
