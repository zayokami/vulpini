//! IPC commands: thin adapters over vulpini-core. All fallible commands
//! return `Result<T, String>` so the frontend gets plain error strings.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use vulpini_core::delay::{DEFAULT_PROBE_URL, DEFAULT_TIMEOUT};
use vulpini_core::node::{Node, NodeId, NodeSource, parse_link};
use vulpini_core::stats::StatsSnapshot;
use vulpini_core::{EngineHandle, Mode};

use crate::AppState;

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ── View types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CoreStatusView {
    running: bool,
    listen: String,
    mode: Mode,
    active_node: Option<String>,
}

#[derive(Serialize)]
pub struct NodeView {
    id: String,
    name: String,
    proto: String,
    server: String,
    port: u16,
    source: String,
    /// Subscription uuid when source is a subscription; used for grouping.
    source_id: Option<String>,
    delay_ms: Option<u64>,
    active: bool,
}

#[derive(Serialize)]
pub struct ImportFailure {
    line: String,
    error: String,
}

#[derive(Serialize)]
pub struct ImportResult {
    added: usize,
    failed: Vec<ImportFailure>,
}

#[derive(Serialize)]
pub struct SubscriptionView {
    id: String,
    name: String,
    url: String,
    node_count: usize,
    last_updated: Option<u64>,
    last_error: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigView {
    listen: String,
    mode: Mode,
    rules: Vec<String>,
    system_proxy_enabled: bool,
}

#[derive(Deserialize)]
pub struct ConfigPatch {
    listen: Option<String>,
    mode: Option<String>,
    rules: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct SysProxyView {
    supported: bool,
    enabled: bool,
    server: Option<String>,
}

#[derive(Serialize, Clone)]
struct DelayResultPayload {
    node_id: String,
    delay_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct SubscriptionUpdatedPayload {
    id: String,
    added: usize,
    removed: usize,
    error: Option<String>,
}

fn parse_mode(s: &str) -> CmdResult<Mode> {
    match s {
        "global" => Ok(Mode::Global),
        "rule" => Ok(Mode::Rule),
        "direct" => Ok(Mode::Direct),
        other => Err(format!("bad mode '{other}'")),
    }
}

fn parse_node_id(id: &str) -> CmdResult<NodeId> {
    uuid::Uuid::parse_str(id).map(NodeId).map_err(err)
}

// ── Core control ─────────────────────────────────────────────────────────

#[tauri::command]
pub async fn core_start(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let mut engine_guard = state.engine.write().await;
    if engine_guard.is_some() {
        return Err("core already running".into());
    }
    state.sync_selector().await;
    let router = state.build_router().await;
    let listen = state.store.read().await.config().listen;
    let engine = Arc::new(
        EngineHandle::start(listen, state.registry.clone(), router)
            .await
            .map_err(err)?,
    );

    let app2 = app.clone();
    let mut rx = engine.events();
    tauri::async_runtime::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            let vulpini_core::stats::CoreEvent::Stats(snap) = ev;
            let _ = app2.emit("stats:tick", snap);
        }
    });

    *engine_guard = Some(engine);
    let _ = app.emit("core:status", true);
    Ok(())
}

#[tauri::command]
pub async fn core_stop(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let engine = state.engine.write().await.take();
    match engine {
        Some(engine) => {
            match Arc::try_unwrap(engine) {
                Ok(handle) => handle.shutdown().await,
                Err(_) => return Err("engine still referenced".into()),
            }
            let _ = app.emit("core:status", false);
            Ok(())
        }
        None => Ok(()),
    }
}

#[tauri::command]
pub async fn core_status(state: State<'_, AppState>) -> CmdResult<CoreStatusView> {
    let store = state.store.read().await;
    let config = store.config();
    Ok(CoreStatusView {
        running: state.engine.read().await.is_some(),
        listen: config.listen.to_string(),
        mode: config.mode,
        active_node: config.active_node.map(|id| id.to_string()),
    })
}

#[tauri::command]
pub async fn set_mode(state: State<'_, AppState>, mode: String) -> CmdResult<()> {
    let mode = parse_mode(&mode)?;
    {
        let mut store = state.store.write().await;
        store.config_mut().mode = mode;
        store.save().map_err(err)?;
    }
    if state.engine.read().await.is_some() {
        let router = state.build_router().await;
        if let Some(engine) = state.engine.read().await.as_ref() {
            engine.set_router(router);
        }
    }
    Ok(())
}

// ── Nodes ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_nodes(state: State<'_, AppState>) -> CmdResult<Vec<NodeView>> {
    let store = state.store.read().await;
    let config = store.config();
    Ok(config
        .nodes
        .iter()
        .map(|n| NodeView {
            id: n.id.to_string(),
            name: n.name.clone(),
            proto: n.config.protocol().to_string(),
            server: n.config.server().to_string(),
            port: n.config.port(),
            source: match &n.source {
                NodeSource::Manual => "manual".into(),
                NodeSource::Subscription(_) => "subscription".into(),
            },
            source_id: match &n.source {
                NodeSource::Manual => None,
                NodeSource::Subscription(id) => Some(id.to_string()),
            },
            delay_ms: config.delay_history.get(&n.stable_key).copied(),
            active: config.active_node == Some(n.id),
        })
        .collect())
}

#[tauri::command]
pub async fn import_share_links(
    app: AppHandle,
    state: State<'_, AppState>,
    text: String,
) -> CmdResult<ImportResult> {
    let mut store = state.store.write().await;
    let mut added = 0usize;
    let mut failed = Vec::new();

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match parse_link(line) {
            Ok((name, config)) => {
                let node = Node::new(name, NodeSource::Manual, config);
                if store
                    .config()
                    .nodes
                    .iter()
                    .any(|n| n.stable_key == node.stable_key)
                {
                    continue; // duplicate: skip silently
                }
                store.config_mut().nodes.push(node);
                added += 1;
            }
            Err(e) => failed.push(ImportFailure {
                line: line.chars().take(60).collect(),
                error: e.to_string(),
            }),
        }
    }
    store.save().map_err(err)?;
    drop(store);
    let _ = app.emit("nodes:changed", ());
    Ok(ImportResult { added, failed })
}

#[tauri::command]
pub async fn delete_node(app: AppHandle, state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = parse_node_id(&id)?;
    let mut store = state.store.write().await;
    let was_active = store.config().active_node == Some(id);
    store.config_mut().nodes.retain(|n| n.id != id);
    if was_active {
        store.config_mut().active_node = None;
        state.registry.selector().clear();
    }
    store.save().map_err(err)?;
    drop(store);
    let _ = app.emit("nodes:changed", ());
    Ok(())
}

#[tauri::command]
pub async fn set_active_node(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<()> {
    let id = parse_node_id(&id)?;
    let node = {
        let store = state.store.read().await;
        store
            .config()
            .nodes
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .ok_or("node not found")?
    };
    let outbound = vulpini_core::outbound::build_outbound(&node.config).map_err(err)?;
    state.registry.selector().set(outbound);

    let mut store = state.store.write().await;
    store.config_mut().active_node = Some(id);
    store.save().map_err(err)?;
    drop(store);
    let _ = app.emit("nodes:changed", ());
    Ok(())
}

// ── Subscriptions ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_subscriptions(state: State<'_, AppState>) -> CmdResult<Vec<SubscriptionView>> {
    let store = state.store.read().await;
    Ok(store
        .config()
        .subscriptions
        .iter()
        .map(|s| SubscriptionView {
            id: s.id.to_string(),
            name: s.name.clone(),
            url: s.url.clone(),
            node_count: s.node_count,
            last_updated: s.last_updated,
            last_error: s.last_error.clone(),
        })
        .collect())
}

#[tauri::command]
pub async fn add_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    url: String,
) -> CmdResult<SubscriptionView> {
    let id = {
        let mut store = state.store.write().await;
        vulpini_core::node::subscription::add_subscription(&mut store, &name, &url).map_err(err)?
    };
    // Fetch immediately; report via event but don't fail the add.
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app2.state::<AppState>();
        let result = {
            let mut store = state.store.write().await;
            vulpini_core::node::subscription::update(&mut store, id).await
        };
        let payload = match &result {
            Ok(o) => SubscriptionUpdatedPayload {
                id: id.to_string(),
                added: o.added,
                removed: o.removed,
                error: None,
            },
            Err(e) => SubscriptionUpdatedPayload {
                id: id.to_string(),
                added: 0,
                removed: 0,
                error: Some(e.to_string()),
            },
        };
        let _ = app2.emit("subscription:updated", payload);
        let _ = app2.emit("nodes:changed", ());
    });

    let store = state.store.read().await;
    let sub = store
        .config()
        .subscriptions
        .iter()
        .find(|s| s.id == id)
        .ok_or("subscription vanished")?;
    Ok(SubscriptionView {
        id: sub.id.to_string(),
        name: sub.name.clone(),
        url: sub.url.clone(),
        node_count: sub.node_count,
        last_updated: sub.last_updated,
        last_error: sub.last_error.clone(),
    })
}

#[tauri::command]
pub async fn delete_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<()> {
    let id = uuid::Uuid::parse_str(&id).map_err(err)?;
    let mut store = state.store.write().await;
    let config = store.config_mut();
    config.subscriptions.retain(|s| s.id != id);
    config
        .nodes
        .retain(|n| n.source != NodeSource::Subscription(id));
    // Active node may have belonged to the deleted subscription.
    let active_gone = config
        .active_node
        .is_some_and(|active| !config.nodes.iter().any(|n| n.id == active));
    if active_gone {
        config.active_node = None;
        state.registry.selector().clear();
    }
    store.save().map_err(err)?;
    drop(store);
    let _ = app.emit("nodes:changed", ());
    Ok(())
}

#[tauri::command]
pub async fn update_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Option<String>,
) -> CmdResult<()> {
    let ids: Vec<uuid::Uuid> = {
        let store = state.store.read().await;
        match &id {
            Some(id) => {
                let parsed = uuid::Uuid::parse_str(id).map_err(err)?;
                if !store.config().subscriptions.iter().any(|s| s.id == parsed) {
                    return Err("subscription not found".into());
                }
                vec![parsed]
            }
            None => store.config().subscriptions.iter().map(|s| s.id).collect(),
        }
    };
    if ids.is_empty() {
        return Ok(());
    }

    for sub_id in ids {
        let result = {
            let mut store = state.store.write().await;
            vulpini_core::node::subscription::update(&mut store, sub_id).await
        };
        let payload = match &result {
            Ok(o) => SubscriptionUpdatedPayload {
                id: sub_id.to_string(),
                added: o.added,
                removed: o.removed,
                error: None,
            },
            Err(e) => SubscriptionUpdatedPayload {
                id: sub_id.to_string(),
                added: 0,
                removed: 0,
                error: Some(e.to_string()),
            },
        };
        let _ = app.emit("subscription:updated", payload);
        let _ = app.emit("nodes:changed", ());
    }
    // The update may have changed which node the stable_key resolves to.
    state.sync_selector().await;
    Ok(())
}

// ── Delay testing ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn test_node_delay(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<u64> {
    let id = parse_node_id(&id)?;
    let node = {
        let store = state.store.read().await;
        store
            .config()
            .nodes
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .ok_or("node not found")?
    };
    let result =
        vulpini_core::delay::test_delay(&node.config, DEFAULT_PROBE_URL, DEFAULT_TIMEOUT).await;

    let (ms, error) = match &result {
        Ok(d) => (Some(d.as_millis() as u64), None),
        Err(e) => (None, Some(e.to_string())),
    };
    if let Ok(d) = &result {
        let mut store = state.store.write().await;
        store
            .config_mut()
            .delay_history
            .insert(node.stable_key.clone(), d.as_millis() as u64);
        store.save().map_err(err)?;
    }
    let _ = app.emit(
        "delay:result",
        DelayResultPayload {
            node_id: id.to_string(),
            delay_ms: ms,
            error: error.clone(),
        },
    );
    match error {
        Some(e) => Err(e),
        None => Ok(ms.unwrap_or(0)),
    }
}

#[tauri::command]
pub async fn test_all_delays(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let nodes: Vec<_> = {
        let store = state.store.read().await;
        store
            .config()
            .nodes
            .iter()
            .map(|n| (n.id, n.config.clone(), n.stable_key.clone()))
            .collect()
    };
    if nodes.is_empty() {
        return Ok(());
    }

    use futures::StreamExt;
    let keys: std::collections::HashMap<_, _> =
        nodes.iter().map(|(id, _, k)| (*id, k.clone())).collect();
    let mut results = vulpini_core::delay::test_all(
        nodes.into_iter().map(|(id, c, _)| (id, c)).collect(),
        DEFAULT_PROBE_URL.to_string(),
        DEFAULT_TIMEOUT,
        8,
    );

    let mut history_updates = Vec::new();
    while let Some(result) = results.next().await {
        let (ms, error) = match &result.delay {
            Ok(d) => {
                history_updates.push((result.node_id, d.as_millis() as u64));
                (Some(d.as_millis() as u64), None)
            }
            Err(e) => (None, Some(e.clone())),
        };
        let _ = app.emit(
            "delay:result",
            DelayResultPayload {
                node_id: result.node_id.to_string(),
                delay_ms: ms,
                error,
            },
        );
    }

    let mut store = state.store.write().await;
    for (node_id, ms) in history_updates {
        if let Some(key) = keys.get(&node_id) {
            store.config_mut().delay_history.insert(key.clone(), ms);
        }
    }
    store.save().map_err(err)?;
    Ok(())
}

// ── System proxy ─────────────────────────────────────────────────────────

#[tauri::command]
pub async fn set_system_proxy(
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<SysProxyView> {
    if enabled {
        let listen = state.store.read().await.config().listen.to_string();
        let previous = vulpini_sysproxy::enable(&listen).map_err(err)?;
        let mut store = state.store.write().await;
        // Keep the ORIGINAL backup if we already own the setting (self-heal).
        if !store.config().system_proxy_enabled || store.config().sysproxy_backup.is_none() {
            store.config_mut().sysproxy_backup = Some(vulpini_core::config::SysProxyBackup {
                enabled: previous.enabled,
                server: previous.server,
            });
        }
        store.config_mut().system_proxy_enabled = true;
        store.save().map_err(err)?;
    } else {
        let backup = {
            let store = state.store.read().await;
            store
                .config()
                .sysproxy_backup
                .clone()
                .map(|b| vulpini_sysproxy::SysProxyStatus {
                    enabled: b.enabled,
                    server: b.server,
                })
                .unwrap_or(vulpini_sysproxy::SysProxyStatus {
                    enabled: false,
                    server: None,
                })
        };
        vulpini_sysproxy::disable(&backup).map_err(err)?;
        let mut store = state.store.write().await;
        store.config_mut().system_proxy_enabled = false;
        store.config_mut().sysproxy_backup = None;
        store.save().map_err(err)?;
    }
    get_system_proxy(state).await
}

#[tauri::command]
pub async fn get_system_proxy(state: State<'_, AppState>) -> CmdResult<SysProxyView> {
    let _ = state;
    match vulpini_sysproxy::status() {
        Ok(s) => Ok(SysProxyView {
            supported: true,
            enabled: s.enabled,
            server: s.server,
        }),
        Err(_) => Ok(SysProxyView {
            supported: false,
            enabled: false,
            server: None,
        }),
    }
}

// ── Config ───────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> CmdResult<ConfigView> {
    let store = state.store.read().await;
    let config = store.config();
    Ok(ConfigView {
        listen: config.listen.to_string(),
        mode: config.mode,
        rules: config.rules.clone(),
        system_proxy_enabled: config.system_proxy_enabled,
    })
}

#[tauri::command]
pub async fn patch_config(
    app: AppHandle,
    state: State<'_, AppState>,
    patch: ConfigPatch,
) -> CmdResult<ConfigView> {
    let mut listen_changed = false;
    {
        let mut store = state.store.write().await;
        let config = store.config_mut();
        if let Some(listen) = &patch.listen {
            let addr: std::net::SocketAddr = listen.parse().map_err(err)?;
            if addr != config.listen {
                config.listen = addr;
                listen_changed = true;
            }
        }
        if let Some(mode) = &patch.mode {
            config.mode = parse_mode(mode)?;
        }
        if let Some(rules) = &patch.rules {
            // Validate before persisting.
            vulpini_core::Router::from_config(config.mode, rules).map_err(err)?;
            config.rules = rules.clone();
        }
        store.save().map_err(err)?;
    }

    if state.engine.read().await.is_some() {
        if listen_changed {
            // Listen address changes require an engine restart.
            core_stop(app.clone(), state.clone()).await?;
            core_start(app, state.clone()).await?;
        } else {
            let router = state.build_router().await;
            if let Some(engine) = state.engine.read().await.as_ref() {
                engine.set_router(router);
            }
        }
    }
    get_config(state).await
}

#[tauri::command]
pub async fn get_stats_snapshot(state: State<'_, AppState>) -> CmdResult<Option<StatsSnapshot>> {
    let engine = state.engine.read().await;
    Ok(engine.as_ref().map(|e| e.stats_snapshot()))
}

#[tauri::command]
pub async fn update_geo_data(state: State<'_, AppState>) -> CmdResult<(u64, u64)> {
    let geo = {
        let store = state.store.read().await;
        store.config().geo.clone()
    };
    let sizes = vulpini_core::geo::GeoManager::new(geo)
        .update()
        .await
        .map_err(err)?;
    // New data should take effect on a running engine.
    if state.engine.read().await.is_some() {
        let router = state.build_router().await;
        if let Some(engine) = state.engine.read().await.as_ref() {
            engine.set_router(router);
        }
    }
    Ok(sizes)
}
