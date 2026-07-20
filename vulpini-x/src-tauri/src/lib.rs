//! Vulpini X: Tauri shell around vulpini-core. Thin adaptation layer —
//! all proxy logic lives in the core; this file owns state, IPC commands
//! and event bridging.

use std::path::PathBuf;
use std::sync::Arc;

use tauri::Emitter;
use tokio::sync::{RwLock, broadcast};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use vulpini_core::config::{ConfigStore, SysProxyBackup};
use vulpini_core::logbus::LogEvent;
use vulpini_core::outbound::OutboundRegistry;
use vulpini_core::{EngineHandle, Router};

pub mod commands;

/// Everything shared between IPC commands. The engine is hot-swappable
/// (node/router changes never need a restart).
pub struct AppState {
    pub store: RwLock<ConfigStore>,
    pub engine: RwLock<Option<Arc<EngineHandle>>>,
    pub registry: Arc<OutboundRegistry>,
    pub log_tx: broadcast::Sender<LogEvent>,
}

impl AppState {
    /// Build a router from the current config plus geo data (when present).
    pub async fn build_router(&self) -> Router {
        let config = self.store.read().await.config().clone();
        let router = Router::from_config(config.mode, &config.rules).unwrap_or_else(|_| {
            Router::from_config(config.mode, &vulpini_core::router::default_rules())
                .expect("default rules parse")
        });
        let geo = vulpini_core::geo::GeoManager::new(config.geo.clone()).load();
        router.with_geo(geo)
    }

    /// Load the active node from config into the selector.
    pub async fn sync_selector(&self) {
        let active = {
            let store = self.store.read().await;
            let config = store.config();
            config
                .active_node
                .and_then(|id| config.nodes.iter().find(|n| n.id == id).cloned())
        };
        match active {
            Some(node) => match vulpini_core::outbound::build_outbound(&node.config) {
                Ok(outbound) => self.registry.selector().set(outbound),
                Err(e) => {
                    tracing::warn!(error = %e, node = %node.name, "active node unusable");
                    self.registry.selector().clear();
                }
            },
            None => self.registry.selector().clear(),
        }
    }

    /// Persist a system-proxy backup (keeps the ORIGINAL on self-heal).
    pub async fn save_sysproxy_backup(&self, enabled: bool, server: Option<String>) {
        let mut store = self.store.write().await;
        store.config_mut().system_proxy_enabled = enabled;
        store.config_mut().sysproxy_backup = server.map(|s| SysProxyBackup {
            enabled: true,
            server: Some(s),
        });
        if let Err(e) = store.save() {
            tracing::warn!(error = %e, "failed to save config");
        }
    }
}

pub fn run() {
    vulpini_core::ensure_crypto_provider();
    let (log_tx, log_rx) = vulpini_core::logbus::channel(1024);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(vulpini_core::logbus::BroadcastLayer::new(log_tx.clone()))
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::core_start,
            commands::core_stop,
            commands::core_status,
            commands::set_mode,
            commands::list_nodes,
            commands::import_share_links,
            commands::delete_node,
            commands::set_active_node,
            commands::list_subscriptions,
            commands::add_subscription,
            commands::delete_subscription,
            commands::update_subscription,
            commands::test_node_delay,
            commands::test_all_delays,
            commands::set_system_proxy,
            commands::get_system_proxy,
            commands::get_config,
            commands::patch_config,
            commands::get_stats_snapshot,
            commands::update_geo_data,
        ])
        .setup(move |app| {
            use tauri::Manager;

            let data_dir = app
                .path()
                .app_config_dir()
                .expect("app config dir")
                .join("vulpini");
            std::fs::create_dir_all(&data_dir).ok();
            let config_path: PathBuf = data_dir.join("config.json");

            let mut store = ConfigStore::load(&config_path).expect("load config");
            // Geo data lives in the app data dir, not the CWD.
            if store.config().geo.data_dir.as_os_str() == "vulpini-data" {
                store.config_mut().geo.data_dir = data_dir.join("data");
            }

            let state = AppState {
                store: RwLock::new(store),
                engine: RwLock::new(None),
                registry: Arc::new(OutboundRegistry::new()),
                log_tx: log_tx.clone(),
            };
            app.manage(state);

            // Log bus -> frontend "log:line".
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut rx = log_rx;
                while let Ok(event) = rx.recv().await {
                    let _ = app_handle.emit("log:line", event);
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                // Restore the user's proxy settings if we own them.
                use tauri::Manager;
                let state = app_handle.state::<AppState>();
                let store = state.store.blocking_read();
                let config = store.config();
                if config.system_proxy_enabled {
                    let backup = config
                        .sysproxy_backup
                        .clone()
                        .map(|b| vulpini_sysproxy::SysProxyStatus {
                            enabled: b.enabled,
                            server: b.server,
                        })
                        .unwrap_or(vulpini_sysproxy::SysProxyStatus {
                            enabled: false,
                            server: None,
                        });
                    if let Err(e) = vulpini_sysproxy::disable(&backup) {
                        tracing::warn!(error = %e, "failed to restore system proxy on exit");
                    } else {
                        tracing::info!("system proxy restored on exit");
                    }
                }
            }
        });
}
