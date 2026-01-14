#[cfg(test)]
mod tests {
use tempfile::TempDir;

    #[tokio::test]
    async fn test_config_default() {
        let config = vulpini::config::ProxyConfig::default();

        // Test SOCKS5 defaults
        assert!(config.socks5.enabled);
        assert_eq!(config.socks5.listen_address, "127.0.0.1");
        assert_eq!(config.socks5.listen_port, 1080);
        assert!(!config.socks5.auth_enabled);

        // Test HTTP proxy defaults
        assert!(config.http_proxy.enabled);
        assert_eq!(config.http_proxy.listen_address, "127.0.0.1");
        assert_eq!(config.http_proxy.listen_port, 8080);

        // Test IP pool defaults
        assert_eq!(config.ip_pool.health_check_interval_secs, 60);
        assert_eq!(config.ip_pool.auto_rotate_interval_secs, 300);
        assert_eq!(config.ip_pool.strategy, "performance");

        // Test routing defaults
        assert_eq!(config.routing.max_latency_threshold_ms, 1000);
        assert_eq!(config.routing.min_reliability_threshold, 0.8);
        assert_eq!(config.routing.load_balancing, "fastest");
        assert!(config.routing.fallback_enabled);

        // Test anomaly detection defaults
        assert!(config.anomaly_detection.enabled);
        assert_eq!(config.anomaly_detection.spike_threshold, 3.0);
        assert_eq!(config.anomaly_detection.latency_threshold_ms, 5000);
        assert_eq!(config.anomaly_detection.error_rate_threshold, 0.1);
        assert_eq!(config.anomaly_detection.connection_threshold, 500);
        assert_eq!(config.anomaly_detection.check_interval_secs, 10);

        // Test logging defaults
        assert_eq!(config.logging.level, "info");
        assert!(config.logging.file_enabled);
        assert!(config.logging.console_enabled);
    }

    #[tokio::test]
    async fn test_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");

        let mut config = vulpini::config::ProxyConfig::default();

        // Modify some values
        config.socks5.listen_port = 9999;
        config.socks5.auth_enabled = true;
        config.socks5.username = Some("testuser".to_string());
        config.routing.load_balancing = "roundrobin".to_string();

        // Save config
        let config_manager = vulpini::config::ConfigManager::new(config_path.clone());
        config_manager.save(&config).await.unwrap();

        // Load config
        let mut loaded_config_manager = vulpini::config::ConfigManager::new(config_path.clone());
        let loaded_config = loaded_config_manager.load_or_default().await.unwrap();

        // Verify values
        assert_eq!(loaded_config.socks5.listen_port, 9999);
        assert!(loaded_config.socks5.auth_enabled);
        assert_eq!(loaded_config.socks5.username, Some("testuser".to_string()));
        assert_eq!(loaded_config.routing.load_balancing, "roundrobin");
    }

    #[tokio::test]
    async fn test_config_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent.toml");

        let mut config_manager = vulpini::config::ConfigManager::new(config_path.clone());
        let config = config_manager.load_or_default().await.unwrap();

        // Should return defaults
        assert_eq!(config.socks5.listen_port, 1080);
        assert!(config.socks5.enabled);
    }

    #[tokio::test]
    async fn test_config_reload() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        // Create initial config
        let mut config = vulpini::config::ProxyConfig::default();
        config.socks5.listen_port = 1080;

        let config_manager = vulpini::config::ConfigManager::new(config_path.clone());
        config_manager.save(&config).await.unwrap();

        // Load and modify
        let mut loaded_manager = vulpini::config::ConfigManager::new(config_path.clone());
        loaded_manager.load_or_default().await.unwrap();

        // Update file
        let mut updated_config = vulpini::config::ProxyConfig::default();
        updated_config.socks5.listen_port = 5555;
        let config_manager2 = vulpini::config::ConfigManager::new(config_path.clone());
        config_manager2.save(&updated_config).await.unwrap();

        // Reload
        let reloaded_config = loaded_manager.reload().unwrap();
        assert_eq!(reloaded_config.socks5.listen_port, 5555);
    }

    #[test]
    fn test_ip_config_default() {
        let ip_config = vulpini::config::IPConfig {
            address: "192.168.1.1".to_string(),
            port: 1080,
            country: Some("US".to_string()),
            isp: Some("TestISP".to_string()),
        };

        assert_eq!(ip_config.address, "192.168.1.1");
        assert_eq!(ip_config.port, 1080);
        assert_eq!(ip_config.country, Some("US".to_string()));
        assert_eq!(ip_config.isp, Some("TestISP".to_string()));
    }

    #[test]
    fn test_socks5_config() {
        let config = vulpini::config::Socks5Config {
            enabled: true,
            listen_address: "0.0.0.0".to_string(),
            listen_port: 1080,
            auth_enabled: true,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            max_connections: 500,
        };

        assert!(config.auth_enabled);
        assert_eq!(config.max_connections, 500);
        assert_eq!(config.username, Some("user".to_string()));
    }

    #[test]
    fn test_http_proxy_config() {
        let config = vulpini::config::HttpProxyConfig {
            enabled: true,
            listen_address: "0.0.0.0".to_string(),
            listen_port: 8080,
            auth_enabled: false,
            username: None,
            password: None,
            max_connections: 1000,
        };

        assert!(!config.auth_enabled);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_routing_config() {
        let config = vulpini::config::RoutingConfig {
            max_latency_threshold_ms: 500,
            min_reliability_threshold: 0.9,
            load_balancing: "leastconnections".to_string(),
            fallback_enabled: false,
        };

        assert_eq!(config.max_latency_threshold_ms, 500);
        assert_eq!(config.min_reliability_threshold, 0.9);
        assert_eq!(config.load_balancing, "leastconnections");
        assert!(!config.fallback_enabled);
    }

    #[test]
    fn test_anomaly_detection_config() {
        let config = vulpini::config::AnomalyDetectionConfig {
            enabled: false,
            spike_threshold: 5.0,
            latency_threshold_ms: 3000,
            error_rate_threshold: 0.05,
            connection_threshold: 100,
            check_interval_secs: 30,
        };

        assert!(!config.enabled);
        assert_eq!(config.spike_threshold, 5.0);
        assert_eq!(config.latency_threshold_ms, 3000);
        assert_eq!(config.error_rate_threshold, 0.05);
        assert_eq!(config.connection_threshold, 100);
        assert_eq!(config.check_interval_secs, 30);
    }
}
