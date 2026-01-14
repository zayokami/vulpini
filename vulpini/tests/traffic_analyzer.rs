#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};
    use vulpini::traffic_analyzer::{TrafficAnalyzer, TrafficStats, RequestInfo};

    #[test]
    fn test_traffic_stats_default() {
        let stats = TrafficStats::default();

        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_bytes_in, 0);
        assert_eq!(stats.total_bytes_out, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.requests_per_second, 0.0);
        assert_eq!(stats.bytes_per_second, 0.0);
        assert_eq!(stats.avg_latency, Duration::ZERO);
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.error_rate, 0.0);
    }

    #[test]
    fn test_traffic_analyzer_new() {
        let analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[test]
    fn test_record_request() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        let request = RequestInfo {
            timestamp: Instant::now(),
            size: 1024,
            latency: Duration::from_millis(50),
            protocol: "http".to_string(),
        };

        analyzer.record_request(request);

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_requests, 1);
    }

    #[test]
    fn test_record_bytes() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        // Record bytes with a request to trigger stats update
        analyzer.record_bytes(2048, 1024);

        // Also record a request to trigger stats calculation
        let request = RequestInfo {
            timestamp: Instant::now(),
            size: 100,
            latency: Duration::from_millis(10),
            protocol: "http".to_string(),
        };
        analyzer.record_request(request);

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_bytes_in, 2048);
        assert_eq!(stats.total_bytes_out, 1024);
    }

    #[test]
    fn test_update_connections() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        analyzer.update_connections(100);

        let stats = analyzer.get_stats();
        assert_eq!(stats.active_connections, 100);
    }

    #[test]
    fn test_multiple_requests() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        for i in 1..=10 {
            let request = RequestInfo {
                timestamp: Instant::now(),
                size: i * 100,
                latency: Duration::from_millis(i * 10),
                protocol: "socks5".to_string(),
            };
            analyzer.record_request(request);
        }

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_requests, 10);
    }

    #[test]
    fn test_request_info() {
        let now = Instant::now();
        let request = RequestInfo {
            timestamp: now,
            size: 512,
            latency: Duration::from_millis(25),
            protocol: "http".to_string(),
        };

        assert_eq!(request.size, 512);
        assert_eq!(request.protocol, "http");
        assert!(request.latency < Duration::from_millis(100));
    }

    #[test]
    fn test_traffic_stats_clone() {
        let stats = TrafficStats::default();
        let cloned = stats.clone();

        assert_eq!(stats.total_requests, cloned.total_requests);
        assert_eq!(stats.total_bytes_in, cloned.total_bytes_in);
        assert_eq!(stats.avg_latency, cloned.avg_latency);
    }

    #[test]
    fn test_analyzer_with_different_window_sizes() {
        let analyzer_30s = TrafficAnalyzer::new(Duration::from_secs(30));
        let analyzer_120s = TrafficAnalyzer::new(Duration::from_secs(120));

        let stats_30s = analyzer_30s.get_stats();
        let stats_120s = analyzer_120s.get_stats();

        assert_eq!(stats_30s.total_requests, stats_120s.total_requests);
    }

    #[test]
    fn test_bytes_accumulation() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        for _ in 0..5 {
            analyzer.record_bytes(1000, 500);
            // Record a request to trigger stats update
            let request = RequestInfo {
                timestamp: Instant::now(),
                size: 100,
                latency: Duration::from_millis(10),
                protocol: "http".to_string(),
            };
            analyzer.record_request(request);
        }

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_bytes_in, 5000);
        assert_eq!(stats.total_bytes_out, 2500);
    }

    #[test]
    fn test_request_size_tracking() {
        let mut analyzer = TrafficAnalyzer::new(Duration::from_secs(60));

        let requests = vec![
            RequestInfo {
                timestamp: Instant::now(),
                size: 100,
                latency: Duration::from_millis(10),
                protocol: "http".to_string(),
            },
            RequestInfo {
                timestamp: Instant::now(),
                size: 200,
                latency: Duration::from_millis(20),
                protocol: "http".to_string(),
            },
            RequestInfo {
                timestamp: Instant::now(),
                size: 300,
                latency: Duration::from_millis(30),
                protocol: "http".to_string(),
            },
        ];

        for request in requests {
            analyzer.record_request(request);
        }

        let stats = analyzer.get_stats();
        assert_eq!(stats.total_requests, 3);
    }
}
