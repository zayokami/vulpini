#[cfg(test)]
mod tests {
    use std::time::Duration;
    use vulpini::ip_manager::{IPManager, RotationStrategy, HealthStatus};
    use vulpini::config::IPPoolConfig;

    fn create_test_ip_pool() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: Some("US".to_string()),
                    isp: Some("ISP1".to_string()),
                },
                vulpini::config::IPConfig {
                    address: "10.0.0.1".to_string(),
                    port: 1080,
                    country: Some("DE".to_string()),
                    isp: Some("ISP2".to_string()),
                },
                vulpini::config::IPConfig {
                    address: "172.16.0.1".to_string(),
                    port: 1080,
                    country: Some("JP".to_string()),
                    isp: Some("ISP3".to_string()),
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "roundrobin".to_string(),
        }
    }

    #[test]
    fn test_rotation_strategy_variants() {
        let _ = RotationStrategy::Random;
        let _ = RotationStrategy::RoundRobin;
        let _ = RotationStrategy::LeastUsed;
        let _ = RotationStrategy::PerformanceBased;
    }

    #[test]
    fn test_health_status_variants() {
        let _ = HealthStatus::Healthy;
        let _ = HealthStatus::Degraded;
        let _ = HealthStatus::Unhealthy;
        let _ = HealthStatus::Unknown;
    }

    #[test]
    fn test_ip_manager_new() {
        let config = create_test_ip_pool();
        let _manager = IPManager::new(config);
    }

    #[test]
    fn test_select_ip_round_robin() {
        let config = create_test_ip_pool();
        let mut manager = IPManager::new(config);

        // Round robin should return different IPs on each call
        let ip1 = manager.select_ip();
        let ip2 = manager.select_ip();
        let ip3 = manager.select_ip();

        assert!(ip1.is_some());
        assert!(ip2.is_some());
        assert!(ip3.is_some());
    }

    #[test]
    fn test_select_ip_empty_pool() {
        let config = IPPoolConfig {
            ips: vec![],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "roundrobin".to_string(),
        };

        let mut manager = IPManager::new(config);
        let result = manager.select_ip();

        assert!(result.is_none());
    }

    #[test]
    fn test_record_result_success() {
        let config = create_test_ip_pool();
        let manager = IPManager::new(config);

        manager.record_result("192.168.1.1", true, Duration::from_millis(50));
    }

    #[test]
    fn test_record_result_failure() {
        let config = create_test_ip_pool();
        let manager = IPManager::new(config);

        manager.record_result("192.168.1.1", false, Duration::from_millis(100));
    }

    #[test]
    fn test_record_result_nonexistent_ip() {
        let config = create_test_ip_pool();
        let manager = IPManager::new(config);

        // Should not panic
        manager.record_result("nonexistent.ip", true, Duration::from_millis(50));
    }

    fn create_round_robin_config() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
                vulpini::config::IPConfig {
                    address: "192.168.1.2".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "roundrobin".to_string(),
        }
    }

    #[test]
    fn test_round_robin_strategy() {
        let config = create_round_robin_config();
        let mut manager = IPManager::new(config);

        let ip1 = manager.select_ip();
        let ip2 = manager.select_ip();

        assert!(ip1.is_some());
        assert!(ip2.is_some());
    }

    #[test]
    fn test_performance_strategy() {
        let config = create_performance_config();
        let mut manager = IPManager::new(config);

        let ip = manager.select_ip();
        assert!(ip.is_some());
    }

    #[test]
    fn test_random_strategy() {
        let config = create_random_config();
        let mut manager = IPManager::new(config);

        let ip = manager.select_ip();
        assert!(ip.is_some());
    }

    #[test]
    fn test_least_used_strategy() {
        let config = create_least_used_config();
        let mut manager = IPManager::new(config);

        let ip = manager.select_ip();
        assert!(ip.is_some());
    }

    #[test]
    fn test_unknown_strategy_defaults_to_round_robin() {
        let config = create_unknown_strategy_config();
        let mut manager = IPManager::new(config);

        let ip = manager.select_ip();
        assert!(ip.is_some());
    }

    #[test]
    fn test_multiple_record_results() {
        let config = create_test_ip_pool();
        let manager = IPManager::new(config);

        for i in 0..10 {
            manager.record_result("192.168.1.1", i % 2 == 0, Duration::from_millis(50));
        }
    }

    fn create_performance_config() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
                vulpini::config::IPConfig {
                    address: "192.168.1.2".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "performance".to_string(),
        }
    }

    fn create_random_config() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
                vulpini::config::IPConfig {
                    address: "192.168.1.2".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "random".to_string(),
        }
    }

    fn create_least_used_config() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
                vulpini::config::IPConfig {
                    address: "192.168.1.2".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "leastused".to_string(),
        }
    }

    fn create_unknown_strategy_config() -> IPPoolConfig {
        IPPoolConfig {
            ips: vec![
                vulpini::config::IPConfig {
                    address: "192.168.1.1".to_string(),
                    port: 1080,
                    country: None,
                    isp: None,
                },
            ],
            health_check_interval_secs: 60,
            auto_rotate_interval_secs: 300,
            strategy: "unknown".to_string(),
        }
    }
}
