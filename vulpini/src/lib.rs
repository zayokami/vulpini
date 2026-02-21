pub mod traffic_analyzer;
pub mod ip_manager;
pub mod behavior_monitor;
pub mod smart_router;
pub mod anomaly_detector;
pub mod protocol;
pub mod config;
pub mod logger;
pub mod utils;
pub mod api;

pub use traffic_analyzer::{TrafficAnalyzer, TrafficStats};
pub use ip_manager::{IPManager, IPInfo, RotationStrategy, HealthStatus, AddIPRequest, UpdateIPRequest, IPStatsSnapshot};
pub use behavior_monitor::{BehaviorMonitor, BehaviorRecord, BehaviorPattern};
pub use smart_router::{SmartRouter, RoutingDecision, RouteType};
pub use anomaly_detector::{AnomalyDetector, AnomalyEvent, AnomalyType};
pub use config::{ConfigManager, ProxyConfig};
pub use logger::{Logger, LogLevel, LogEntry};
pub use protocol::{Socks5Protocol, HttpProtocol};
pub use api::{AppState, api_router};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "Vulpini";
