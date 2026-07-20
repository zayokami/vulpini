use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::common::{BoxedStream, CoreError, Session};
use crate::inbound::{self, InboundKind};
use crate::outbound::OutboundRegistry;
use crate::relay::relay;
use crate::router::Router;
use crate::stats::{CoreEvent, StatsRegistry, StatsSnapshot};

const DRAIN_GRACE: Duration = Duration::from_secs(5);
const EVENT_CAPACITY: usize = 64;
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// A running engine: owns the listener task and all live connection tasks.
/// Dropping it does nothing — call [`EngineHandle::shutdown`].
pub struct EngineHandle {
    local_addr: SocketAddr,
    router: Arc<ArcSwap<Router>>,
    shutdown: CancellationToken,
    accept_task: tokio::task::JoinHandle<()>,
    tick_task: tokio::task::JoinHandle<()>,
    conns: Arc<Mutex<JoinSet<()>>>,
    events_tx: broadcast::Sender<CoreEvent>,
    stats: Arc<StatsRegistry>,
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
        Self::from_listener(listener, registry, router).await
    }

    /// Start with port fallback: try `listen`, then the next few ports,
    /// then let the OS assign a free port. Windows reserves whole port
    /// ranges (Hyper-V/WSL/Docker), so a fixed port can be unusable for
    /// reasons the user cannot see. The actual address is available via
    /// [`EngineHandle::local_addr`] — callers should persist it.
    pub async fn start_with_fallback(
        listen: SocketAddr,
        registry: Arc<OutboundRegistry>,
        router: Router,
    ) -> Result<Self, CoreError> {
        let mut first_err: Option<CoreError> = None;
        for offset in 0u16..=2 {
            let Some(port) = listen.port().checked_add(offset) else {
                break;
            };
            let candidate = SocketAddr::new(listen.ip(), port);
            match TcpListener::bind(candidate).await {
                Ok(listener) => return Self::from_listener(listener, registry, router).await,
                Err(e) => {
                    warn!(addr = %candidate, error = %e, "listen address unavailable");
                    if first_err.is_none() {
                        first_err = Some(e.into());
                    }
                }
            }
        }
        // OS-assigned port as the last resort: always outside reservations.
        let wildcard = SocketAddr::new(listen.ip(), 0);
        match TcpListener::bind(wildcard).await {
            Ok(listener) => {
                let actual = listener.local_addr()?;
                warn!(addr = %actual, "falling back to an OS-assigned port");
                Self::from_listener(listener, registry, router).await
            }
            Err(e) => Err(first_err.unwrap_or_else(|| e.into())),
        }
    }

    async fn from_listener(
        listener: TcpListener,
        registry: Arc<OutboundRegistry>,
        router: Router,
    ) -> Result<Self, CoreError> {
        let local_addr = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let conns: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));
        let router = Arc::new(ArcSwap::from_pointee(router));
        let stats = StatsRegistry::new();
        let (events_tx, _) = broadcast::channel(EVENT_CAPACITY);

        let accept_task = tokio::spawn(accept_loop(
            listener,
            registry,
            router.clone(),
            stats.clone(),
            shutdown.clone(),
            conns.clone(),
        ));
        let tick_task = tokio::spawn(tick_loop(
            stats.clone(),
            events_tx.clone(),
            shutdown.clone(),
        ));

        info!(%local_addr, "engine listening");
        Ok(Self {
            local_addr,
            router,
            shutdown,
            accept_task,
            tick_task,
            conns,
            events_tx,
            stats,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Subscribe to engine events (1 Hz stats snapshots).
    pub fn events(&self) -> broadcast::Receiver<CoreEvent> {
        self.events_tx.subscribe()
    }

    /// One-shot stats pull (for initial UI paint).
    pub fn stats_snapshot(&self) -> StatsSnapshot {
        self.stats.snapshot()
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
        let _ = self.tick_task.await;

        let mut conns = self.conns.lock().await;
        let drain = async { while conns.join_next().await.is_some() {} };
        if tokio::time::timeout(DRAIN_GRACE, drain).await.is_err() {
            warn!("drain timed out, aborting live connections");
            conns.abort_all();
        }
        info!("engine stopped");
    }
}

async fn tick_loop(
    stats: Arc<StatsRegistry>,
    events_tx: broadcast::Sender<CoreEvent>,
    token: CancellationToken,
) {
    let mut previous = stats.snapshot();
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(TICK_INTERVAL) => {
                let current = stats.snapshot();
                let snap = StatsSnapshot {
                    up_rate: current.total_up - previous.total_up,
                    down_rate: current.total_down - previous.total_down,
                    ..current.clone()
                };
                previous = current;
                // No receivers is normal (headless CLI); ignore.
                let _ = events_tx.send(CoreEvent::Stats(snap));
            }
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    registry: Arc<OutboundRegistry>,
    router: Arc<ArcSwap<Router>>,
    stats: Arc<StatsRegistry>,
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
                    let stats = stats.clone();
                    conns.lock().await.spawn(async move {
                        stats.conn_open();
                        if let Err(e) = handle_connection(stream, &registry, &router, &stats).await {
                            debug!(error = %e, "connection closed with error");
                        }
                        stats.conn_close();
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
    stats: &StatsRegistry,
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

    relay(stream, stats.wrap(&route, upstream)).await?;
    Ok(())
}
