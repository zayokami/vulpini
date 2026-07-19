use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::common::{BoxedStream, CoreError, Session};
use crate::inbound::{self, InboundKind};
use crate::outbound::OutboundRegistry;
use crate::relay::relay;
use crate::router::Router;

const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// A running engine: owns the listener task and all live connection tasks.
/// Dropping it does nothing — call [`EngineHandle::shutdown`].
pub struct EngineHandle {
    local_addr: SocketAddr,
    router: Arc<ArcSwap<Router>>,
    shutdown: CancellationToken,
    accept_task: tokio::task::JoinHandle<()>,
    conns: Arc<Mutex<JoinSet<()>>>,
}

impl EngineHandle {
    /// Start the engine with the given router. Routing decisions are made
    /// per session; swapping the router later takes effect immediately.
    pub async fn start(
        listen: SocketAddr,
        registry: Arc<OutboundRegistry>,
        router: Router,
    ) -> Result<Self, CoreError> {
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let conns: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));
        let router = Arc::new(ArcSwap::from_pointee(router));

        let accept_task = tokio::spawn(accept_loop(
            listener,
            registry,
            router.clone(),
            shutdown.clone(),
            conns.clone(),
        ));

        info!(%local_addr, "engine listening");
        Ok(Self {
            local_addr,
            router,
            shutdown,
            accept_task,
            conns,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Hot-swap the router (mode or rule changes). In-flight connections
    /// keep their already-dialed outbounds; new sessions use the new rules.
    pub fn set_router(&self, router: Router) {
        self.router.store(Arc::new(router));
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
    router: Arc<ArcSwap<Router>>,
    token: CancellationToken,
    conns: Arc<Mutex<JoinSet<()>>>,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept = listener.accept() => match accept {
                Ok((stream, _peer)) => {
                    let registry = registry.clone();
                    let router = router.clone();
                    conns.lock().await.spawn(async move {
                        if let Err(e) = handle_connection(stream, &registry, &router).await {
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
    router: &ArcSwap<Router>,
) -> Result<(), CoreError> {
    stream.set_nodelay(true).ok();
    let kind = inbound::detect(&stream).await?;
    let mut stream: BoxedStream = Box::pin(stream);

    let (target, tag) = match kind {
        InboundKind::Socks5 => (inbound::socks5::handshake(&mut stream).await?, "socks5"),
        InboundKind::Http => (inbound::http::handshake(&mut stream).await?, "http"),
    };
    let session = Session::tcp(target, tag);
    let route = router.load().route(&session);
    debug!(target = %session.target, inbound = tag, outbound = %route, "session");

    let outbound = registry.get(&route)?;
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
