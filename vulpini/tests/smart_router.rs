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
        let router = SmartRouter::new(config);

        let decision = router.select_route();
        assert!(decision.selected_target.is_none());
    }

    #[test]
    fn test_add_target() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);

        let decision = router.select_route();
        assert!(decision.selected_target.is_some());
        assert_eq!(decision.selected_target.unwrap().ip, "192.168.1.1");
    }

    #[test]
    fn test_add_duplicate_target() {
        let config = create_test_config();
        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.1", 1080);

        // Should still only have one target — fallback list empty.
        let decision = router.select_route();
        assert!(decision.selected_target.is_some());
        assert!(decision.fallback_targets.is_empty());
    }

    #[test]
    fn test_select_route_no_targets() {
        let config = create_test_config();
        let router = SmartRouter::new(config);

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

        // Should be a no-op, not a panic.
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

        // The target with lower latency (192.168.1.2 at 50ms) should be selected.
        assert_eq!(decision.selected_target.unwrap().ip, "192.168.1.2");
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

        let d1 = router.select_route();
        let d2 = router.select_route();

        // Round-robin should cycle through different targets.
        assert!(d1.selected_target.is_some());
        assert!(d2.selected_target.is_some());
        assert_ne!(
            d1.selected_target.unwrap().ip,
            d2.selected_target.unwrap().ip,
        );
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
            min_reliability_threshold: 0.0,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);

        router.add_target("192.168.1.1", 1080);
        router.add_target("192.168.1.2", 1080);

        // Push both targets over the 100ms threshold.
        router.record_result("192.168.1.1", true, Duration::from_millis(200));
        router.record_result("192.168.1.2", true, Duration::from_millis(300));

        let decision = router.select_route();

        // All targets exceed the threshold → fallback returns the first.
        assert!(decision.selected_target.is_some());
    }

    #[test]
    fn test_reliability_updates_from_stats() {
        let config = RoutingConfig {
            max_latency_threshold_ms: 1000,
            min_reliability_threshold: 0.5,
            load_balancing: "fastest".to_string(),
            fallback_enabled: true,
        };

        let mut router = SmartRouter::new(config);
        router.add_target("192.168.1.1", 1080);

        // 1 success out of 4 requests → 25% reliability, below threshold.
        router.record_result("192.168.1.1", true, Duration::from_millis(50));
        router.record_result("192.168.1.1", false, Duration::from_millis(50));
        router.record_result("192.168.1.1", false, Duration::from_millis(50));
        router.record_result("192.168.1.1", false, Duration::from_millis(50));

        let decision = router.select_route();

        // Below min_reliability_threshold, so available is empty → fallback.
        assert!(decision.selected_target.is_some());
        assert!(decision.fallback_targets.is_empty());
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
