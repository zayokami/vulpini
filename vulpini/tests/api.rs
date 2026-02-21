#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use parking_lot::Mutex;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use http_body_util::BodyExt;

    use vulpini::traffic_analyzer::TrafficAnalyzer;
    use vulpini::ip_manager::{IPManager, AddIPRequest};
    use vulpini::anomaly_detector::AnomalyDetector;
    use vulpini::config::{
        ProxyConfig, ConfigManager,
    };
    use vulpini::api::{AppState, api_router};

    fn make_state() -> AppState {
        let config = ProxyConfig::default();
        let traffic_analyzer = Arc::new(Mutex::new(TrafficAnalyzer::new(Duration::from_secs(60))));
        let ip_manager = Arc::new(Mutex::new(IPManager::new(config.ip_pool.clone())));
        let anomaly_detector = Arc::new(Mutex::new(AnomalyDetector::new(config.anomaly_detection.clone())));
        let config_manager = Arc::new(Mutex::new(
            ConfigManager::new(std::path::PathBuf::from("nonexistent.toml")),
        ));

        AppState {
            traffic_analyzer,
            ip_manager,
            anomaly_detector,
            config_manager,
            start_time: Instant::now(),
        }
    }

    async fn body_bytes(body: Body) -> Vec<u8> {
        let collected = body.collect().await.unwrap();
        collected.to_bytes().to_vec()
    }

    async fn body_json(body: Body) -> serde_json::Value {
        let bytes = body_bytes(body).await;
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Health ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp.into_body()).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["status"], "healthy");
    }

    // ── Stats ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_stats_endpoint() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp.into_body()).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["total_requests"], 0);
        assert_eq!(json["data"]["active_connections"], 0);
    }

    // ── IPs CRUD ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_ips_empty() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/api/ips").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp.into_body()).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["total"], 0);
    }

    #[tokio::test]
    async fn test_add_and_get_ip() {
        let state = make_state();

        // Add an IP
        let app = api_router(state.clone());
        let add_body = serde_json::json!({
            "address": "10.0.0.1",
            "port": 1080,
            "country": "US",
            "isp": "TestISP"
        });
        let resp = app
            .oneshot(
                Request::post("/api/ips")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&add_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["address"], "10.0.0.1");

        // Verify via GET
        let app = api_router(state.clone());
        let resp = app
            .oneshot(Request::get("/api/ips").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["data"]["total"], 1);
    }

    #[tokio::test]
    async fn test_add_duplicate_ip() {
        let state = make_state();
        let add_body = serde_json::json!({
            "address": "10.0.0.1",
            "port": 1080
        });

        // First add
        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/api/ips")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&add_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Duplicate add — should return 409
        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::post("/api/ips")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&add_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_delete_ip() {
        let state = make_state();

        // Add first
        {
            let mut manager = state.ip_manager.lock();
            manager.add_node(AddIPRequest {
                address: "10.0.0.1".to_string(),
                port: 1080,
                country: None,
                isp: None,
                enabled: None,
            });
        }

        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::delete("/api/ips/10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify deleted
        assert_eq!(state.ip_manager.lock().len(), 0);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_ip() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(
                Request::delete("/api/ips/999.999.999.999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_toggle_ip() {
        let state = make_state();
        {
            let mut manager = state.ip_manager.lock();
            manager.add_node(AddIPRequest {
                address: "10.0.0.1".to_string(),
                port: 1080,
                country: None,
                isp: None,
                enabled: None,
            });
        }

        // Toggle off
        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::patch("/api/ips/10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["data"]["enabled"], false);

        // Toggle back on
        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::patch("/api/ips/10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["data"]["enabled"], true);
    }

    #[tokio::test]
    async fn test_toggle_nonexistent_ip() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(
                Request::patch("/api/ips/1.2.3.4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_ip() {
        let state = make_state();
        {
            let mut manager = state.ip_manager.lock();
            manager.add_node(AddIPRequest {
                address: "10.0.0.1".to_string(),
                port: 1080,
                country: None,
                isp: None,
                enabled: None,
            });
        }

        let update_body = serde_json::json!({
            "address": "10.0.0.1",
            "port": 2080,
            "country": "JP"
        });

        let app = api_router(state.clone());
        let resp = app
            .oneshot(
                Request::put("/api/ips/10.0.0.1")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&update_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify update
        let node = state.ip_manager.lock().get_node("10.0.0.1").unwrap();
        assert_eq!(node.port, 2080);
    }

    #[tokio::test]
    async fn test_update_nonexistent_ip() {
        let update_body = serde_json::json!({
            "address": "1.2.3.4",
            "port": 2080
        });

        let app = api_router(make_state());
        let resp = app
            .oneshot(
                Request::put("/api/ips/1.2.3.4")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&update_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Anomalies ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anomalies_endpoint_empty() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/api/anomalies").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["success"], true);
        let data = json["data"].as_array().unwrap();
        assert!(data.is_empty());
    }

    // ── PAC ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pac_endpoint() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/pac").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(content_type, "application/x-ns-proxy-autoconfig");

        let body = String::from_utf8(body_bytes(resp.into_body()).await).unwrap();
        assert!(body.contains("FindProxyForURL"));
        assert!(body.contains("SOCKS5"));
    }

    #[tokio::test]
    async fn test_proxy_pac_alias() {
        let app = api_router(make_state());
        let resp = app
            .oneshot(Request::get("/proxy.pac").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(resp.into_body()).await).unwrap();
        assert!(body.contains("FindProxyForURL"));
    }

    // ── Config reload ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_config_reload_no_file() {
        // Config file doesn't exist, reload returns default config (OK).
        let app = api_router(make_state());
        let resp = app
            .oneshot(
                Request::post("/api/config/reload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }
}
