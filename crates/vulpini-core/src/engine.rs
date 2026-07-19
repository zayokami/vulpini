use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::common::{BoxedStream, CoreError, Session};
use crate::inbound::{self, InboundKind};
use crate::outbound::{OutboundRegistry, TAG_DIRECT};
use crate::relay::relay;

const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// A running engine: owns the listener task and all live connection tasks.
/// Dropping it does nothing — call [`EngineHandle::shutdown`].
pub struct EngineHandle {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    accept_task: tokio::task::JoinHandle<()>,
    conns: Arc<Mutex<JoinSet<()>>>,
}

impl EngineHandle {
    pub async fn start(
        listen: SocketAddr,
        registry: Arc<OutboundRegistry>,
    ) -> Result<Self, CoreError> {
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let conns: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));

        let accept_task = tokio::spawn(accept_loop(
            listener,
            registry,
            shutdown.clone(),
            conns.clone(),
        ));

        info!(%local_addr, "engine listening");
        Ok(Self {
            local_addr,
            shutdown,
            accept_task,
            conns,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting, drain live connections with a grace period, then
    /// abort whatever remains. Idempotent-ish: consumes the handle.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.accept_task.await;

        let mut conns = self.conns.lock().await;
        let drain = async { while conns.join_next().await.is_some() {} };
        if tokio::time::timeout(DRAIN_GRACE, drain).await.is_err() {
            warn!("drain timed out, aborting live connections");
            conns.abort_all();
        }
        info!("engine stopped");
    }
}

async fn accept_loop(
    listener: TcpListener,
    registry: Arc<OutboundRegistry>,
    token: CancellationToken,
    conns: Arc<Mutex<JoinSet<()>>>,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept = listener.accept() => match accept {
                Ok((stream, _peer)) => {
                    let registry = registry.clone();
                    conns.lock().await.spawn(async move {
                        if let Err(e) = handle_connection(stream, &registry).await {
                            debug!(error = %e, "connection closed with error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    registry: &OutboundRegistry,
) -> Result<(), CoreError> {
    stream.set_nodelay(true).ok();
    let kind = inbound::detect(&stream).await?;
    let mut stream: BoxedStream = Box::pin(stream);

    let (target, tag) = match kind {
        InboundKind::Socks5 => (inbound::socks5::handshake(&mut stream).await?, "socks5"),
        InboundKind::Http => (inbound::http::handshake(&mut stream).await?, "http"),
    };
    let session = Session::tcp(target, tag);
    debug!(target = %session.target, inbound = tag, "session");

    // The router arrives in milestone M4a; until then everything is direct.
    let outbound = registry.get(TAG_DIRECT)?;
    let upstream = match outbound.dial_tcp(&session).await {
        Ok(upstream) => upstream,
        Err(e) => {
            inbound::reply_err(&mut stream, kind, &e).await.ok();
            return Err(e);
        }
    };
    inbound::reply_ok(&mut stream, kind).await?;

    relay(stream, upstream).await?;
    Ok(())
}
