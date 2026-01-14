use serde::{Deserialize, Serialize};

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
}

impl ConfigManager {
    pub fn new(config_path: std::path::PathBuf) -> Self {
        Self { config_path }
    }

    pub async fn load_or_default(&self) -> Result<ProxyConfig, std::io::Error> {
        if self.config_path.exists() {
            match tokio::fs::read_to_string(&self.config_path).await {
                Ok(content) => {
                    toml::from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(ProxyConfig::default())
        }
    }

    pub async fn save(&self, config: &ProxyConfig) -> Result<(), std::io::Error> {
        let content = toml::to_string_pretty(config).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(&self.config_path, content).await
    }
}
