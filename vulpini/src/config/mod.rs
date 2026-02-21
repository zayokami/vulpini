use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub socks5: Socks5Config,
    pub http_proxy: HttpProxyConfig,
    pub ip_pool: IPPoolConfig,
    pub routing: RoutingConfig,
    pub anomaly_detection: AnomalyDetectionConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub enabled: bool,
    pub listen_address: String,
    pub listen_port: u16,
    pub auth_enabled: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub enabled: bool,
    pub listen_address: String,
    pub listen_port: u16,
    pub auth_enabled: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPPoolConfig {
    pub ips: Vec<IPConfig>,
    pub health_check_interval_secs: u64,
    pub auto_rotate_interval_secs: u64,
    pub strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPConfig {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub max_latency_threshold_ms: u64,
    pub min_reliability_threshold: f64,
    pub load_balancing: String,
    pub fallback_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub spike_threshold: f64,
    pub latency_threshold_ms: u64,
    pub error_rate_threshold: f64,
    pub connection_threshold: u32,
    pub check_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_enabled: bool,
    pub file_path: String,
    pub console_enabled: bool,
}

const VALID_IP_STRATEGIES: &[&str] = &["random", "roundrobin", "leastused", "performance"];
const VALID_LB_STRATEGIES: &[&str] = &["roundrobin", "leastconnections", "fastest"];
const VALID_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

impl ProxyConfig {
    /// Validate configuration values after deserialization.
    /// Returns a list of warnings/errors. An empty vec means all good.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Port conflicts
        if self.socks5.enabled && self.http_proxy.enabled
            && self.socks5.listen_address == self.http_proxy.listen_address
            && self.socks5.listen_port == self.http_proxy.listen_port
        {
            errors.push("SOCKS5 and HTTP proxy are bound to the same address:port".into());
        }

        // Auth requires credentials
        if self.socks5.auth_enabled
            && (self.socks5.username.is_none() || self.socks5.password.is_none())
        {
            errors.push("SOCKS5 auth is enabled but username/password not set".into());
        }
        if self.http_proxy.auth_enabled
            && (self.http_proxy.username.is_none() || self.http_proxy.password.is_none())
        {
            errors.push("HTTP proxy auth is enabled but username/password not set".into());
        }

        // IP pool strategy
        if !VALID_IP_STRATEGIES.contains(&self.ip_pool.strategy.as_str()) {
            errors.push(format!(
                "Unknown IP rotation strategy '{}', valid: {:?}",
                self.ip_pool.strategy, VALID_IP_STRATEGIES,
            ));
        }

        // Routing
        if !VALID_LB_STRATEGIES.contains(&self.routing.load_balancing.as_str()) {
            errors.push(format!(
                "Unknown load-balancing strategy '{}', valid: {:?}",
                self.routing.load_balancing, VALID_LB_STRATEGIES,
            ));
        }
        if !(0.0..=1.0).contains(&self.routing.min_reliability_threshold) {
            errors.push(format!(
                "min_reliability_threshold ({}) must be in [0.0, 1.0]",
                self.routing.min_reliability_threshold,
            ));
        }

        // Anomaly detection thresholds
        if self.anomaly_detection.spike_threshold <= 0.0 {
            errors.push("spike_threshold must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.anomaly_detection.error_rate_threshold) {
            errors.push(format!(
                "error_rate_threshold ({}) must be in [0.0, 1.0]",
                self.anomaly_detection.error_rate_threshold,
            ));
        }

        // Logging level
        if !VALID_LOG_LEVELS.contains(&self.logging.level.to_lowercase().as_str()) {
            errors.push(format!(
                "Unknown log level '{}', valid: {:?}",
                self.logging.level, VALID_LOG_LEVELS,
            ));
        }

        errors
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            socks5: Socks5Config {
                enabled: true,
                listen_address: "127.0.0.1".to_string(),
                listen_port: 1080,
                auth_enabled: false,
                username: None,
                password: None,
                max_connections: 1000,
            },
            http_proxy: HttpProxyConfig {
                enabled: true,
                listen_address: "127.0.0.1".to_string(),
                listen_port: 8080,
                auth_enabled: false,
                username: None,
                password: None,
                max_connections: 1000,
            },
            ip_pool: IPPoolConfig {
                ips: Vec::new(),
                health_check_interval_secs: 60,
                auto_rotate_interval_secs: 300,
                strategy: "performance".to_string(),
            },
            routing: RoutingConfig {
                max_latency_threshold_ms: 1000,
                min_reliability_threshold: 0.8,
                load_balancing: "fastest".to_string(),
                fallback_enabled: true,
            },
            anomaly_detection: AnomalyDetectionConfig {
                enabled: true,
                spike_threshold: 3.0,
                latency_threshold_ms: 5000,
                error_rate_threshold: 0.1,
                connection_threshold: 500,
                check_interval_secs: 10,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_enabled: true,
                file_path: "vulpini.log".to_string(),
                console_enabled: true,
            },
        }
    }
}

pub struct ConfigManager {
    config_path: std::path::PathBuf,
    config_tx: Arc<watch::Sender<ProxyConfig>>,
    config_rx: watch::Receiver<ProxyConfig>,
}

impl ConfigManager {
    pub fn new(config_path: std::path::PathBuf) -> Self {
        let (tx, rx) = watch::channel(ProxyConfig::default());
        Self {
            config_path,
            config_tx: Arc::new(tx),
            config_rx: rx,
        }
    }

    pub async fn load_or_default(&mut self) -> Result<ProxyConfig, std::io::Error> {
        if self.config_path.exists() {
            match tokio::fs::read_to_string(&self.config_path).await {
                Ok(content) => {
                    let config: ProxyConfig = toml::from_str(&content)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    for warn in config.validate() {
                        eprintln!("[CONFIG WARNING] {}", warn);
                    }
                    self.config_tx.send(config.clone()).ok();
                    Ok(config)
                }
                Err(e) => Err(e),
            }
        } else {
            let config = ProxyConfig::default();
            self.config_tx.send(config.clone()).ok();
            Ok(config)
        }
    }

    pub async fn save(&self, config: &ProxyConfig) -> Result<(), std::io::Error> {
        let content = toml::to_string_pretty(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(&self.config_path, content).await
    }

    pub fn subscribe(&self) -> watch::Receiver<ProxyConfig> {
        self.config_rx.clone()
    }

    pub fn reload(&mut self) -> Result<ProxyConfig, std::io::Error> {
        if self.config_path.exists() {
            let content = std::fs::read_to_string(&self.config_path)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let config: ProxyConfig = toml::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            for warn in config.validate() {
                eprintln!("[CONFIG WARNING] {}", warn);
            }
            self.config_tx.send(config.clone()).ok();
            Ok(config)
        } else {
            Ok(ProxyConfig::default())
        }
    }
}
