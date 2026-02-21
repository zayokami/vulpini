use std::sync::Arc;
use parking_lot::Mutex;
use std::time::Duration;
use std::path::PathBuf;

use vulpini::config::ConfigManager;
use vulpini::traffic_analyzer::TrafficAnalyzer;
use vulpini::ip_manager::IPManager;
use vulpini::behavior_monitor::BehaviorMonitor;
use vulpini::smart_router::SmartRouter;
use vulpini::anomaly_detector::AnomalyDetector;
use vulpini::logger::Logger;
use vulpini::protocol::socks5::Socks5Protocol;
use vulpini::protocol::http::HttpProtocol;
use vulpini::api::{AppState, api_router};

const DEFAULT_CONFIG_PATH: &str = "vulpini.toml";

async fn ip_health_check_task(
    ip_manager: Arc<Mutex<IPManager>>,
    interval_secs: u64,
) {
    let interval = Duration::from_secs(interval_secs);
    loop {
        tokio::time::sleep(interval).await;

        // Snapshot all IPs so we don't hold the lock during TCP connects.
        let ips: Vec<(String, u16)> = {
            let manager = ip_manager.lock();
            manager.get_all_ips().iter()
                .map(|ip| (ip.address.clone(), ip.port))
                .collect()
        };

        for (address, port) in ips {
            let target = format!("{}:{}", address, port);
            let start = std::time::Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(&target),
            ).await;
            let latency = start.elapsed();

            let success = matches!(result, Ok(Ok(_)));
            ip_manager.lock().record_result(&address, success, latency);
        }
    }
}

async fn anomaly_check_task(
    traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
    anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    interval_secs: u64,
) {
    let interval = Duration::from_secs(interval_secs);
    loop {
        tokio::time::sleep(interval).await;

        let stats: vulpini::traffic_analyzer::TrafficStats = {
            let analyzer = traffic_analyzer.lock();
            analyzer.get_stats().clone()
        };

        let mut detector = anomaly_detector.lock();
        let events = detector.detect(
            stats.requests_per_second,
            stats.avg_latency,
            stats.error_rate,
            stats.active_connections as u32,
        );

        for event in events {
            println!("[ANOMALY] {:?} - {}", event.severity, event.description);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let logger: Logger = Logger::new("vulpini.log", log::LevelFilter::Info)?;

    logger.info(&format!("Vulpini {} starting...", vulpini::VERSION));

    let config_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    };

    let mut config_manager = ConfigManager::new(config_path.clone());
    let config = config_manager.load_or_default().await?;

    logger.info(&format!("Configuration loaded from: {}", config_path.display()));

    // Create shared components
    let traffic_analyzer = Arc::new(Mutex::new(TrafficAnalyzer::new(Duration::from_secs(60))));
    let behavior_monitor = Arc::new(BehaviorMonitor::new(Duration::from_secs(1800)));
    let ip_manager = Arc::new(Mutex::new(IPManager::new(config.ip_pool.clone())));
    let smart_router = Arc::new(Mutex::new(SmartRouter::new(config.routing.clone())));
    let anomaly_detector = Arc::new(Mutex::new(AnomalyDetector::new(config.anomaly_detection.clone())));

    // Start background tasks
    if config.ip_pool.health_check_interval_secs > 0 {
        let health_ip_manager = ip_manager.clone();
        tokio::spawn(async move {
            ip_health_check_task(health_ip_manager, config.ip_pool.health_check_interval_secs).await;
        });
    }

    if config.anomaly_detection.check_interval_secs > 0 {
        let anomaly_traffic = traffic_analyzer.clone();
        let anomaly_detector = anomaly_detector.clone();
        tokio::spawn(async move {
            anomaly_check_task(
                anomaly_traffic,
                anomaly_detector,
                config.anomaly_detection.check_interval_secs,
            ).await;
        });
    }

    // Periodic session cleanup (runs every 60s)
    {
        let bm = behavior_monitor.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(60);
            loop {
                tokio::time::sleep(interval).await;
                bm.cleanup_stale_sessions();
            }
        });
    }

    // Create protocols with shared components (respect enabled flags)
    let socks5_task = if config.socks5.enabled {
        let socks5_protocol = Socks5Protocol::new(
            config.socks5.clone(),
            traffic_analyzer.clone(),
            behavior_monitor.clone(),
            ip_manager.clone(),
            smart_router.clone(),
        );
        let socks5_addr = format!("{}:{}", config.socks5.listen_address, config.socks5.listen_port);
        logger.info(&format!("SOCKS5 server listening on {}", socks5_addr));
        Some(tokio::spawn(async move {
            if let Err(e) = socks5_protocol.start().await {
                eprintln!("SOCKS5 server error: {}", e);
            }
        }))
    } else {
        logger.info("SOCKS5 server disabled by config");
        None
    };

    let http_task = if config.http_proxy.enabled {
        let http_protocol = HttpProtocol::new(
            config.http_proxy.clone(),
            traffic_analyzer.clone(),
            behavior_monitor.clone(),
            smart_router.clone(),
            ip_manager.clone(),
        );
        let http_addr = format!("{}:{}", config.http_proxy.listen_address, config.http_proxy.listen_port);
        logger.info(&format!("HTTP proxy server listening on {}", http_addr));
        Some(tokio::spawn(async move {
            if let Err(e) = http_protocol.start().await {
                eprintln!("HTTP proxy server error: {}", e);
            }
        }))
    } else {
        logger.info("HTTP proxy server disabled by config");
        None
    };

    let config_manager_arc = Arc::new(Mutex::new(config_manager));

    let api_state = AppState {
        traffic_analyzer: traffic_analyzer.clone(),
        ip_manager: ip_manager.clone(),
        anomaly_detector: anomaly_detector.clone(),
        config_manager: config_manager_arc.clone(),
        start_time: std::time::Instant::now(),
    };

    let api_addr = "127.0.0.1:9090";
    let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
    logger.info(&format!("API server listening on {}", api_addr));

    let api_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, api_router(api_state)).await {
            eprintln!("API server error: {}", e);
        }
    });

    logger.info("All servers running. Press Ctrl+C to stop.");

    let socks5_wait = async move {
        if let Some(task) = socks5_task {
            let _ = task.await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    let http_wait = async move {
        if let Some(task) = http_task {
            let _ = task.await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        _ = socks5_wait => eprintln!("SOCKS5 server exited unexpectedly"),
        _ = http_wait => eprintln!("HTTP proxy server exited unexpectedly"),
        _ = api_task => eprintln!("API server exited unexpectedly"),
        _ = tokio::signal::ctrl_c() => {
            logger.info("Shutdown signal received, exiting...");
        }
    }

    Ok(())
}
