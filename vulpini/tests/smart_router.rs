#[cfg(test)]
mod tests {
    use std::time::Duration;
    use vulpini::smart_router::{SmartRouter, RouteTarget, RoutingDecision, RouteType};
    use vulpini::config::RoutingConfig;

    fn create_test_config() -> RoutingConfig {
        RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_route_type_variants() {
        let _ = RouteType::Direct;
        let _ = RouteType::Proxy;
    }

    #[test]
    fn test_smart_router_new() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        let decision = router.select_route();
        assert!(decision.selected_target.is_none());
    }

    #[test]
    fn test_add_target() {
        let mut config = create_test_config();
        let mut router = SmartRouter::new(config.clone());

        router.add_target("192.168.1.1", 1080);

        let decision = router.select_route();
        assert!(decision.selected_target.is_some());
        assert_eq!(decision.selected_target.unwrap().ip, "192.168.1.1");
    }

    #[test]
    fn test_select_route_no_targets() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        let decision = router.select_route();

        assert!(decision.selected_target.is_none());
        assert_eq!(decision.route_type, RouteType::Direct);
        assert_eq!(decision.estimated_latency, Duration::MAX);
        assert!(decision.fallback_targets.is_empty());
    }

    #[test]
    fn test_record_result() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);

        router.record_result("192.168.1.1", true, Duration::from_millis(50));
        router.record_result("192.168.1.1", true, Duration::from_millis(100));
        router.record_result("192.168.1.1", false, Duration::from_millis(200));
    }

    #[test]
    fn test_record_result_nonexistent() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);

        router.record_result("nonexistent", true, Duration::from_millis(50));
    }

    #[test]
    fn test_fastest_response_selection() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        router.record_result("192.168.1.1", true, Duration::from_millis(100));
        router.record_result("192.168.1.2", true, Duration::from_millis(50));

        let decision = router.select_route();

        assert!(decision.selected_target.is_some());
        assert_eq!(decision.route_type, RouteType::Proxy);
    }

    #[test]
    fn test_round_robin_selection() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "roundrobin".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        let _ = router.select_route();
        let _ = router.select_route();
    }

    #[test]
    fn test_fallback_targets() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        let decision = router.select_route();

        assert!(!decision.fallback_targets.is_empty());
    }

    #[test]
    fn test_route_target_structure() {
        let target = RouteTarget {
            ip: "10.0.0.1".to_string(),
            port: 8080,
            latency: Duration::from_millis(25),
            reliability: 0.99,
            load: 0.5,
        };

        assert_eq!(target.ip, "10.0.0.1");
        assert_eq!(target.port, 8080);
        assert_eq!(target.latency, Duration::from_millis(25));
        assert_eq!(target.reliability, 0.99);
        assert_eq!(target.load, 0.5);
    }

    #[test]
    fn test_routing_decision_structure() {
        let target = RouteTarget {
            ip: "192.168.1.1".to_string(),
            port: 1080,
            latency: Duration::from_millis(50),
            reliability: 0.95,
            load: 0.3,
        };

        let decision = RoutingDecision {
            selected_target: Some(target),
            route_type: RouteType::Proxy,
            estimated_latency: Duration::from_millis(50),
            fallback_targets: vec![],
        };

        assert!(decision.selected_target.is_some());
        assert_eq!(decision.route_type, RouteType::Proxy);
        assert_eq!(decision.estimated_latency, Duration::from_millis(50));
    }

    #[test]
    fn test_latency_threshold_filtering() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 100,
            min_reliability_threshold: 0.8,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        router.record_result("192.168.1.1", true, Duration::from_millis(200));
        router.record_result("192.168.1.2", true, Duration::from_millis(300));

        let decision = router.select_route();

        assert!(decision.selected_target.is_some());
    }

    #[test]
    fn test_least_connections_selection() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "leastconnections".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        let decision = router.select_route();

        assert!(decision.selected_target.is_some());
    }

    #[test]
    fn test_unknown_load_balancing_defaults_to_fastest() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.8,
            load_balancing: "unknown".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);

        let decision = router.select_route();

        assert!(decision.selected_target.is_some());
    }
}
