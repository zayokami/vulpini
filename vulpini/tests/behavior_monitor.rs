#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};
    use vulpini::behavior_monitor::{
        ActionType, BehaviorMonitor, BehaviorRecord,
    };

    fn make_record(session_id: &str, action_type: ActionType, success: bool) -> BehaviorRecord {
        BehaviorRecord {
            session_id: session_id.to_string(),
            timestamp: Instant::now(),
            action_type,
            duration: Duration::from_millis(50),
            target: "example.com:443".to_string(),
            success,
        }
    }

    #[test]
    fn test_new_monitor_empty() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));
        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 0);
        assert_eq!(snap.total_patterns, 0);
        assert_eq!(snap.total_actions_tracked, 0);
    }

    #[test]
    fn test_record_single_action() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));
        let record = make_record("sess-1", ActionType::Connect, true);
        monitor.record_action("sess-1", &record);

        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 1);
        assert_eq!(snap.total_actions_tracked, 1);
    }

    #[test]
    fn test_record_multiple_actions_same_session() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));

        for _ in 0..5 {
            let record = make_record("sess-1", ActionType::Request, true);
            monitor.record_action("sess-1", &record);
        }

        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 1);
        assert_eq!(snap.total_actions_tracked, 5);
    }

    #[test]
    fn test_record_multiple_sessions() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));

        monitor.record_action("sess-1", &make_record("sess-1", ActionType::Connect, true));
        monitor.record_action("sess-2", &make_record("sess-2", ActionType::Request, true));
        monitor.record_action("sess-3", &make_record("sess-3", ActionType::Download, false));

        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 3);
        assert_eq!(snap.total_actions_tracked, 3);
    }

    #[test]
    fn test_action_type_variants() {
        let _connect = ActionType::Connect;
        let _request = ActionType::Request;
        let _login = ActionType::Login;
        let _download = ActionType::Download;
        let _upload = ActionType::Upload;
    }

    #[test]
    fn test_analyze_pattern_no_data() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));
        // No pattern saved yet (session is still active, not finalized).
        assert!(monitor.analyze_pattern("sess-1").is_none());
    }

    #[test]
    fn test_cleanup_stale_sessions_creates_patterns() {
        // Use a very short timeout so sessions become stale immediately.
        let monitor = BehaviorMonitor::new(Duration::from_millis(1));

        let record = BehaviorRecord {
            session_id: "sess-1".to_string(),
            // Use a timestamp slightly in the past so it's already stale.
            timestamp: Instant::now(),
            action_type: ActionType::Connect,
            duration: Duration::from_millis(50),
            target: "example.com:443".to_string(),
            success: true,
        };
        monitor.record_action("sess-1", &record);

        // Wait just a bit so the session becomes stale.
        std::thread::sleep(Duration::from_millis(5));

        monitor.cleanup_stale_sessions();

        // Session should have been moved to patterns.
        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 0);
        assert_eq!(snap.total_patterns, 1);
    }

    #[test]
    fn test_pattern_after_cleanup() {
        let monitor = BehaviorMonitor::new(Duration::from_millis(1));

        let now = Instant::now();
        for i in 0..3 {
            let record = BehaviorRecord {
                session_id: "sess-1".to_string(),
                timestamp: now,
                action_type: if i == 0 { ActionType::Connect } else { ActionType::Request },
                duration: Duration::from_millis(50),
                target: "example.com:443".to_string(),
                success: i != 2, // third action fails
            };
            monitor.record_action("sess-1", &record);
        }

        std::thread::sleep(Duration::from_millis(5));
        monitor.cleanup_stale_sessions();

        let pattern = monitor.analyze_pattern("sess-1");
        assert!(pattern.is_some());

        let p = pattern.unwrap();
        assert_eq!(p.session_id, "sess-1");
        assert_eq!(p.total_actions, 3);
        // 2 out of 3 successful = 0.666...
        assert!((p.success_rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_max_actions_triggers_finalization() {
        // Create a monitor with a very long timeout (won't expire).
        // The default max_actions_per_session is 1000.
        let monitor = BehaviorMonitor::new(Duration::from_secs(3600));

        // Record exactly 1000 actions.
        for _ in 0..1000 {
            monitor.record_action("sess-1", &make_record("sess-1", ActionType::Request, true));
        }

        // The 1001st action triggers finalization of the old session.
        monitor.record_action("sess-1", &make_record("sess-1", ActionType::Request, true));

        // Pattern should exist now (finalized after hitting 1000 limit).
        let pattern = monitor.analyze_pattern("sess-1");
        assert!(pattern.is_some());
        let p = pattern.unwrap();
        assert_eq!(p.total_actions, 1000);
    }

    #[test]
    fn test_snapshot_counts_all_actions() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(1800));

        monitor.record_action("a", &make_record("a", ActionType::Connect, true));
        monitor.record_action("a", &make_record("a", ActionType::Request, true));
        monitor.record_action("b", &make_record("b", ActionType::Download, true));

        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 2);
        assert_eq!(snap.total_actions_tracked, 3);
    }

    #[test]
    fn test_cleanup_preserves_active_sessions() {
        let monitor = BehaviorMonitor::new(Duration::from_secs(3600));

        let record = make_record("active-1", ActionType::Connect, true);
        monitor.record_action("active-1", &record);

        // Cleanup shouldn't remove this session — timeout is 3600s.
        monitor.cleanup_stale_sessions();

        let snap = monitor.snapshot();
        assert_eq!(snap.active_sessions, 1);
        assert_eq!(snap.total_patterns, 0);
    }

    #[test]
    fn test_action_distribution_in_pattern() {
        let monitor = BehaviorMonitor::new(Duration::from_millis(1));

        let now = Instant::now();
        // 3 Connect, 2 Request, 1 Download
        for _ in 0..3 {
            monitor.record_action("sess-1", &BehaviorRecord {
                session_id: "sess-1".to_string(),
                timestamp: now,
                action_type: ActionType::Connect,
                duration: Duration::from_millis(50),
                target: "example.com:443".to_string(),
                success: true,
            });
        }
        for _ in 0..2 {
            monitor.record_action("sess-1", &BehaviorRecord {
                session_id: "sess-1".to_string(),
                timestamp: now,
                action_type: ActionType::Request,
                duration: Duration::from_millis(50),
                target: "example.com:443".to_string(),
                success: true,
            });
        }
        monitor.record_action("sess-1", &BehaviorRecord {
            session_id: "sess-1".to_string(),
            timestamp: now,
            action_type: ActionType::Download,
            duration: Duration::from_millis(50),
            target: "example.com:443".to_string(),
            success: true,
        });

        std::thread::sleep(Duration::from_millis(5));
        monitor.cleanup_stale_sessions();

        let pattern = monitor.analyze_pattern("sess-1").unwrap();
        assert_eq!(pattern.total_actions, 6);

        // Check distribution counts.
        let find = |at: ActionType| -> u32 {
            pattern.action_distribution.iter()
                .find(|(t, _)| *t == at)
                .map(|(_, c)| *c)
                .unwrap_or(0)
        };
        assert_eq!(find(ActionType::Connect), 3);
        assert_eq!(find(ActionType::Request), 2);
        assert_eq!(find(ActionType::Download), 1);
    }
}
