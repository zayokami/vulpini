//! Traffic accounting: counting streams, per-tag counters, and 1 Hz
//! snapshot ticks on the engine's event bus.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::BoxedStream;

/// One broadcast tick per second while the engine runs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsSnapshot {
    pub up_rate: u64,
    pub down_rate: u64,
    pub total_up: u64,
    pub total_down: u64,
    pub active_connections: u32,
}

#[derive(Debug, Clone)]
pub enum CoreEvent {
    Stats(StatsSnapshot),
}

struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

/// Byte counters for the whole engine and per outbound tag.
pub struct StatsRegistry {
    global: Arc<Counters>,
    per_tag: Mutex<HashMap<String, Arc<Counters>>>,
    active_connections: AtomicU64,
}

impl StatsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(StatsRegistry {
            global: Arc::new(Counters {
                up: AtomicU64::new(0),
                down: AtomicU64::new(0),
            }),
            per_tag: Mutex::new(HashMap::new()),
            active_connections: AtomicU64::new(0),
        })
    }

    fn tag_counters(&self, tag: &str) -> Arc<Counters> {
        self.per_tag
            .lock()
            .expect("stats poisoned")
            .entry(tag.to_string())
            .or_insert_with(|| {
                Arc::new(Counters {
                    up: AtomicU64::new(0),
                    down: AtomicU64::new(0),
                })
            })
            .clone()
    }

    pub fn conn_open(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Wrap a dialed stream so every byte is accounted globally and
    /// under `tag`.
    pub fn wrap(&self, tag: &str, stream: BoxedStream) -> BoxedStream {
        Box::pin(CountingStream {
            inner: stream,
            global: self.global.clone(),
            tagged: self.tag_counters(tag),
        })
    }

    /// Current totals plus rates against the previous call (used by the
    /// 1 Hz tick; the mutex only guards the previous-tick values).
    pub fn snapshot(&self) -> StatsSnapshot {
        let up = self.global.up.load(Ordering::Relaxed);
        let down = self.global.down.load(Ordering::Relaxed);
        StatsSnapshot {
            up_rate: up, // rate computed by the tick loop against its own previous snapshot
            down_rate: down,
            total_up: up,
            total_down: down,
            active_connections: self.active_connections.load(Ordering::Relaxed) as u32,
        }
    }
}

struct CountingStream {
    inner: BoxedStream,
    global: Arc<Counters>,
    tagged: Arc<Counters>,
}

impl CountingStream {
    fn count_up(&self, n: usize) {
        self.global.up.fetch_add(n as u64, Ordering::Relaxed);
        self.tagged.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn count_down(&self, n: usize) {
        self.global.down.fetch_add(n as u64, Ordering::Relaxed);
        self.tagged.down.fetch_add(n as u64, Ordering::Relaxed);
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    self.count_down(n);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.count_up(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
