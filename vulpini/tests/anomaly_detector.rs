#[cfg(test)]
mod tests {
    use std::time::Duration;
    use vulpini::anomaly_detector::{AnomalyDetector, AnomalyType, Severity, AnomalyEvent};
    use vulpini::config::AnomalyDetectionConfig;

    fn create_test_config() -> AnomalyDetectionConfig {
        AnomalyDetectionConfig {
            enabled: true,
            spike_threshold: 3.0,
            latency_threshold_ms: 5000,
            error_rate_threshold: 0.1,
            connection_threshold: 500,
            check_interval_secs: 10,
        }
    }

    #[test]
    fn test_anomaly_type_variants() {
        let _ = AnomalyType::TrafficSpike;
        let _ = AnomalyType::LatencySpike;
        let _ = AnomalyType::ErrorRateHigh;
        let _ = AnomalyType::ConnectionFlood;
    }

    #[test]
    fn test_severity_variants() {
        let _ = Severity::Low;
        let _ = Severity::Medium;
        let _ = Severity::High;
    }

    #[test]
    fn test_anomaly_detector_new() {
        let config = create_test_config();
        let detector = AnomalyDetector::new(config.clone());

        let events = detector.get_event_history();
        assert!(events.is_empty());
    }

    #[test]
    fn test_detect_normal_conditions() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        let events = detector.detect(
            50.0,
            Duration::from_millis(100),
            0.01,
            100,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn test_detect_traffic_spike() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        for _ in 0..10 {
            detector.detect(10.0, Duration::from_millis(100), 0.01, 100);
        }

        let events = detector.detect(
            100.0,
            Duration::from_millis(100),
            0.01,
            100,
        );

        let spike_event = events.iter().find(|e| matches!(e.anomaly_type, AnomalyType::TrafficSpike));
        assert!(spike_event.is_some());
    }

    #[test]
    fn test_detect_high_latency() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        detector.detect(50.0, Duration::from_millis(100), 0.01, 100);

        let events = detector.detect(
            50.0,
            Duration::from_millis(6000),
            0.01,
            100,
        );

        let latency_event = events.iter().find(|e| matches!(e.anomaly_type, AnomalyType::LatencySpike));
        assert!(latency_event.is_some());
        assert_eq!(latency_event.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_detect_high_error_rate() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        detector.detect(50.0, Duration::from_millis(100), 0.01, 100);

        let events = detector.detect(
            50.0,
            Duration::from_millis(100),
            0.2,
            100,
        );

        let error_event = events.iter().find(|e| matches!(e.anomaly_type, AnomalyType::ErrorRateHigh));
        assert!(error_event.is_some());
        assert_eq!(error_event.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detect_connection_flood() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        detector.detect(50.0, Duration::from_millis(100), 0.01, 100);

        let events = detector.detect(
            50.0,
            Duration::from_millis(100),
            0.01,
            600,
        );

        let flood_event = events.iter().find(|e| matches!(e.anomaly_type, AnomalyType::ConnectionFlood));
        assert!(flood_event.is_some());
        assert_eq!(flood_event.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detect_multiple_anomalies() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        for _ in 0..10 {
            detector.detect(10.0, Duration::from_millis(100), 0.01, 100);
        }

        let events = detector.detect(
            100.0,
            Duration::from_millis(6000),
            0.2,
            600,
        );

        assert!(events.len() >= 3);
    }

    #[test]
    fn test_event_history_limit() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        for _ in 0..10 {
            detector.detect(10.0, Duration::from_millis(100), 0.01, 100);
        }

        // Even triggering extreme values many times, cooldown limits event count.
        for _ in 0..300 {
            detector.detect(100.0, Duration::from_millis(6000), 0.2, 600);
        }

        let events = detector.get_event_history();
        assert!(events.len() <= 200);
    }

    #[test]
    fn test_anomaly_event_structure() {
        let event = AnomalyEvent {
            id: "test-id".to_string(),
            timestamp: std::time::Instant::now(),
            anomaly_type: AnomalyType::TrafficSpike,
            value: 100.0,
            threshold: 30.0,
            description: "Test event".to_string(),
            severity: Severity::High,
        };

        assert_eq!(event.id, "test-id");
        assert_eq!(event.value, 100.0);
        assert_eq!(event.threshold, 30.0);
        assert_eq!(event.description, "Test event");
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn test_disabled_anomaly_detection() {
        let config = AnomalyDetectionConfig {
            enabled: false,
            spike_threshold: 3.0,
            latency_threshold_ms: 5000,
            error_rate_threshold: 0.1,
            connection_threshold: 500,
            check_interval_secs: 10,
        };

        let mut detector = AnomalyDetector::new(config);

        // With `enabled: false`, detect() should always return empty.
        let events = detector.detect(1000.0, Duration::from_secs(10), 1.0, 10000);
        assert!(events.is_empty());
        assert!(detector.get_event_history().is_empty());
    }

    #[test]
    fn test_alert_cooldown() {
        let config = create_test_config();
        let mut detector = AnomalyDetector::new(config);

        // First call: high latency triggers.
        let events1 = detector.detect(50.0, Duration::from_millis(6000), 0.01, 100);
        assert!(events1.iter().any(|e| matches!(e.anomaly_type, AnomalyType::LatencySpike)));

        // Immediate second call with same extreme values: cooldown suppresses.
        let events2 = detector.detect(50.0, Duration::from_millis(6000), 0.01, 100);
        assert!(!events2.iter().any(|e| matches!(e.anomaly_type, AnomalyType::LatencySpike)));
    }

    #[test]
    fn test_spike_severity_levels() {
        let config = AnomalyDetectionConfig {
            enabled: true,
            spike_threshold: 3.0,
            latency_threshold_ms: 5000,
            error_rate_threshold: 0.1,
            connection_threshold: 500,
            check_interval_secs: 10,
        };
        let mut detector = AnomalyDetector::new(config);

        for _ in 0..10 {
            detector.detect(10.0, Duration::from_millis(100), 0.01, 100);
        }

        // Medium spike (3x average)
        let events = detector.detect(30.0, Duration::from_millis(100), 0.01, 100);
        let medium_spike = events.iter().find(|e| matches!(e.anomaly_type, AnomalyType::TrafficSpike));
        if let Some(event) = medium_spike {
            assert_eq!(event.severity, Severity::Medium);
        }
    }
}
