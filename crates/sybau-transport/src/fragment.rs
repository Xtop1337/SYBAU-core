//! Splits the first writes of a TCP connection into small pieces sent with
//! pauses, so that DPI boxes that only look at single packets do not see
//! a whole TLS ClientHello. Behaviour follows Xray's `fragment` setting.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, Bytes};
use rand::Rng;
use sybau_config::FragmentConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min: u64,
    pub max: u64,
}

impl Range {
    /// Parses `"100-200"` or `"100"`.
    pub fn parse(text: &str) -> Result<Self> {
        let parse = |s: &str| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("`{text}` is not a number or a range like 10-20"))
        };
        let (min, max) = match text.split_once('-') {
            Some((a, b)) => (parse(a)?, parse(b)?),
            None => (parse(text)?, parse(text)?),
        };
        if min > max {
            bail!("range `{text}` is reversed");
        }
        Ok(Self { min, max })
    }

    fn pick(self) -> u64 {
        rand::thread_rng().gen_range(self.min..=self.max)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Re-frame the ClientHello into several TLS records.
    TlsHello,
    /// Cut writes number `from..=to` (1-based) into TCP segments.
    Packets { from: u64, to: u64 },
}

/// Parsed `fragment` settings.
#[derive(Clone, Copy, Debug)]
pub struct Fragment {
    mode: Mode,
    length: Range,
    interval_ms: Range,
    /// Upper bound of pieces per write; 0 = unlimited.
    max_split: Range,
}

impl Fragment {
    pub fn from_config(cfg: &FragmentConfig) -> Result<Self> {
        let mode = match cfg.packets.trim().to_ascii_lowercase().as_str() {
            "tlshello" => Mode::TlsHello,
            other => {
                let r = Range::parse(other).map_err(|_| {
                    anyhow!("fragment.packets must be `tlshello` or a range like 1-3")
                })?;
                if r.min == 0 {
                    bail!("fragment.packets counts writes from 1");
                }
                Mode::Packets {
                    from: r.min,
                    to: r.max,
                }
            }
        };
        let length = Range::parse(&cfg.length)?;
        if length.min == 0 {
            bail!("fragment.length must be at least 1");
        }
        Ok(Self {
            mode,
            length,
            interval_ms: Range::parse(&cfg.interval)?,
            max_split: match &cfg.max_split {
                Some(m) => Range::parse(m)?,
                None => Range { min: 0, max: 0 },
            },
        })
    }

    /// Cuts `data` into pieces of random length within `self.length`.
    fn cut(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let max_split = self.max_split.pick();
        let mut pieces = Vec::new();
        let mut from = 0;
        while from < data.len() {
            let mut to = from + self.length.pick() as usize;
            if to > data.len() || (max_split > 0 && pieces.len() as u64 + 1 >= max_split) {
                to = data.len();
            }
            pieces.push((from, to));
            from = to;
        }
        pieces
    }

    /// Plans how write number `count` (1-based) with content `b` is sent:
    /// a list of segments, each followed by a pause. `None` = unchanged.
    fn plan(&self, count: u64, b: &[u8]) -> Option<Vec<Bytes>> {
        match self.mode {
            Mode::TlsHello => {
                if count != 1 || b.len() <= 5 || b[0] != 22 {
                    return None;
                }
                let record_len = 5 + u16::from_be_bytes([b[3], b[4]]) as usize;
                if b.len() < record_len {
                    return None;
                }
                let data = &b[5..record_len];
                let mut segments: Vec<Bytes> = self
                    .cut(data)
                    .into_iter()
                    .map(|(from, to)| {
                        let mut record = Vec::with_capacity(5 + to - from);
                        record.extend_from_slice(&b[..3]);
                        record.extend_from_slice(&((to - from) as u16).to_be_bytes());
                        record.extend_from_slice(&data[from..to]);
                        Bytes::from(record)
                    })
                    .collect();
                if self.interval_ms.max == 0 {
                    // No pauses: all records leave in one segment.
                    segments = vec![Bytes::from(segments.concat())];
                }
                if b.len() > record_len {
                    segments.push(Bytes::copy_from_slice(&b[record_len..]));
                }
                Some(segments)
            }
            Mode::Packets { from, to } => {
                if count < from || count > to {
                    return None;
                }
                Some(
                    self.cut(b)
                        .into_iter()
                        .map(|(f, t)| Bytes::copy_from_slice(&b[f..t]))
                        .collect(),
                )
            }
        }
    }
}

enum Step {
    Write,
    Flush,
    Pause(Pin<Box<Sleep>>),
}

struct Job {
    segments: std::collections::VecDeque<Bytes>,
    step: Step,
    /// Bytes of the caller's buffer this job stands for.
    accepted: usize,
}

/// Applies [`Fragment`] to the writes of `inner`.
pub struct FragmentStream<S> {
    inner: S,
    fragment: Fragment,
    /// Number of writes seen so far.
    count: u64,
    /// The previous call accepted only part of its buffer, so the next
    /// call continues the same write.
    continuing: bool,
    job: Option<Job>,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S, fragment: Fragment) -> Self {
        Self {
            inner,
            fragment,
            count: 0,
            continuing: false,
            job: None,
        }
    }
}

impl<S: AsyncWrite + Unpin> FragmentStream<S> {
    /// Sends the pending segments; `Ready(Ok(n))` when all are out.
    fn poll_job(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let job = self.job.as_mut().expect("called with a job");
        loop {
            match &mut job.step {
                Step::Write => {
                    let Some(segment) = job.segments.front_mut() else {
                        let accepted = job.accepted;
                        self.job = None;
                        return Poll::Ready(Ok(accepted));
                    };
                    let n = ready!(Pin::new(&mut self.inner).poll_write(cx, segment))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    segment.advance(n);
                    if segment.is_empty() {
                        job.segments.pop_front();
                        job.step = Step::Flush;
                    }
                }
                Step::Flush => {
                    // The flush is what turns a segment into its own packet
                    // (the socket has TCP_NODELAY set).
                    ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
                    let pause = self.fragment.interval_ms.pick();
                    job.step = if pause == 0 || job.segments.is_empty() {
                        Step::Write
                    } else {
                        Step::Pause(Box::pin(tokio::time::sleep(Duration::from_millis(pause))))
                    };
                }
                Step::Pause(sleep) => {
                    ready!(sleep.as_mut().poll(cx));
                    job.step = Step::Write;
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.job.is_none() {
            let plan = if this.continuing {
                None
            } else {
                this.fragment.plan(this.count + 1, buf)
            };
            match plan {
                Some(segments) => {
                    this.count += 1;
                    this.job = Some(Job {
                        segments: segments.into(),
                        step: Step::Write,
                        accepted: buf.len(),
                    });
                }
                None => {
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
                    if !this.continuing {
                        this.count += 1;
                    }
                    this.continuing = n < buf.len();
                    return Poll::Ready(Ok(n));
                }
            }
        }
        this.poll_job(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.job.is_some() {
            // A write returned Pending and will be polled again; a flush in
            // between must not report success for data not yet sent.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    /// Sink that remembers every segment between flushes.
    #[derive(Clone, Default)]
    struct Recorder {
        segments: Arc<Mutex<Vec<Vec<u8>>>>,
        current: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // Accept a few bytes at a time to exercise partial writes.
            let n = buf.len().min(7);
            self.current.lock().unwrap().extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut current = self.current.lock().unwrap();
            if !current.is_empty() {
                self.segments
                    .lock()
                    .unwrap()
                    .push(std::mem::take(&mut *current));
            }
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn config(packets: &str, length: &str, interval: &str) -> Fragment {
        Fragment::from_config(&FragmentConfig {
            packets: packets.into(),
            length: length.into(),
            interval: interval.into(),
            max_split: None,
        })
        .unwrap()
    }

    fn client_hello(len: usize) -> Vec<u8> {
        let mut v = vec![22, 3, 1, (len >> 8) as u8, len as u8];
        v.extend((0..len).map(|i| i as u8));
        v
    }

    #[tokio::test(start_paused = true)]
    async fn tls_hello_becomes_several_valid_records() {
        let rec = Recorder::default();
        let mut s = FragmentStream::new(rec.clone(), config("tlshello", "10-20", "1-2"));
        let hello = client_hello(300);
        s.write_all(&hello).await.unwrap();
        s.flush().await.unwrap();
        // Later writes pass through untouched.
        s.write_all(&client_hello(50)).await.unwrap();
        s.flush().await.unwrap();

        let segments = rec.segments.lock().unwrap().clone();
        let (last, records) = segments.split_last().unwrap();
        assert_eq!(last, &client_hello(50));
        assert!(records.len() >= 300 / 20, "got {} records", records.len());
        let mut payload = Vec::new();
        for r in records {
            assert_eq!(&r[..3], &[22, 3, 1]);
            let len = u16::from_be_bytes([r[3], r[4]]) as usize;
            assert_eq!(r.len(), 5 + len);
            assert!((1..=20).contains(&len));
            payload.extend_from_slice(&r[5..]);
        }
        assert_eq!(payload, hello[5..]);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_interval_keeps_records_in_one_segment() {
        let rec = Recorder::default();
        let mut s = FragmentStream::new(rec.clone(), config("tlshello", "50", "0"));
        s.write_all(&client_hello(200)).await.unwrap();
        s.flush().await.unwrap();
        let segments = rec.segments.lock().unwrap().clone();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].len(), 200 + 4 * 5);
    }

    #[tokio::test(start_paused = true)]
    async fn packet_range_cuts_only_selected_writes() {
        let rec = Recorder::default();
        let mut s = FragmentStream::new(rec.clone(), config("2-3", "4", "5"));
        for payload in [
            &b"first write"[..],
            &b"second write"[..],
            &b"third"[..],
            &b"fourth write"[..],
        ] {
            s.write_all(payload).await.unwrap();
            s.flush().await.unwrap();
        }
        let segments = rec.segments.lock().unwrap().clone();
        let texts: Vec<String> = segments
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        assert_eq!(
            texts,
            [
                "first write",
                "seco",
                "nd w",
                "rite",
                "thir",
                "d",
                "fourth write"
            ]
        );
    }

    #[tokio::test]
    async fn non_tls_first_write_is_left_alone_and_config_is_validated() {
        let rec = Recorder::default();
        let mut s = FragmentStream::new(rec.clone(), config("tlshello", "5", "1"));
        s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        s.flush().await.unwrap();
        assert_eq!(rec.segments.lock().unwrap().len(), 1);

        let bad = |packets: &str, length: &str, interval: &str| {
            Fragment::from_config(&FragmentConfig {
                packets: packets.into(),
                length: length.into(),
                interval: interval.into(),
                max_split: None,
            })
            .is_err()
        };
        assert!(bad("hello", "1-2", "1"));
        assert!(bad("0-1", "1-2", "1"));
        assert!(bad("tlshello", "0", "1"));
        assert!(bad("tlshello", "9-3", "1"));
        assert!(bad("tlshello", "5", "x"));
        assert_eq!(Range::parse("7").unwrap(), Range { min: 7, max: 7 });
    }
}
