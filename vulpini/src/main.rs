use std::env;
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

const DEFAULT_CONFIG_PATH: &str = "vulpini.toml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    let logger: Logger = Logger::new("vulpini.log", log::LevelFilter::Info)?;
    
    logger.info(&format!("Vulpini {} starting...", vulpini::VERSION));
    
    let config_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    };
    
    let config_manager = ConfigManager::new(config_path.clone());
    let config = config_manager.load_or_default().await?;
    
    logger.info(&format!("Configuration loaded from: {}", config_path.display()));
    
    let _traffic_analyzer = TrafficAnalyzer::new(std::time::Duration::from_secs(60));
    let _ip_manager = IPManager::new(config.ip_pool.clone());
    let _behavior_monitor = BehaviorMonitor::new(std::time::Duration::from_secs(1800));
    let mut _smart_router = SmartRouter::new(config.routing.clone());
    let _anomaly_detector = AnomalyDetector::new(config.anomaly_detection.clone());
    
    let socks5_config = config.socks5;
    let socks5_protocol = Socks5Protocol::new(socks5_config.clone());
    
    let socks5_addr = format!("{}:{}", socks5_config.listen_address, socks5_config.listen_port);
    logger.info(&format!("SOCKS5 server listening on {}", socks5_addr));
    
    let socks5_task = tokio::spawn(async move {
        if let Err(e) = socks5_protocol.start(&socks5_addr).await {
            eprintln!("SOCKS5 server error: {}", e);
        }
    });
    
    let http_config = config.http_proxy;
    let http_protocol = HttpProtocol::new(http_config.clone());
    
    let http_addr = format!("{}:{}", http_config.listen_address, http_config.listen_port);
    logger.info(&format!("HTTP proxy server listening on {}", http_addr));
    
    let http_task = tokio::spawn(async move {
        if let Err(e) = http_protocol.start(&http_addr).await {
            eprintln!("HTTP proxy server error: {}", e);
        }
    });
    
    tokio::try_join!(socks5_task, http_task)?;
    
    Ok(())
}
