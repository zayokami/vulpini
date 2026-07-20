use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};

use vulpini_core::config::ConfigStore;
use vulpini_core::node::{Node, NodeSource, parse_link};

#[derive(Parser)]
#[command(
    name = "vulpini-cli",
    version,
    about = "Headless shell for the vulpini proxy core"
)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true, default_value = "vulpini.json")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy core in the foreground.
    Run {
        /// Listen address for the mixed SOCKS5/HTTP inbound.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Import nodes from share links (one per argument).
    Import {
        /// Share links to import (ss://, vmess://, vless://, trojan://).
        links: Vec<String>,
    },
    /// List configured nodes.
    List,
    /// Select the active node (by id prefix or exact name).
    Select {
        /// Node id prefix or name.
        node: String,
    },
    /// Show or set the routing mode.
    Mode {
        /// New mode; prints the current one when omitted.
        #[arg(value_enum)]
        mode: Option<ModeArg>,
    },
    /// Test latency of nodes through their real outbound path.
    Delay {
        /// Test every node.
        #[arg(long)]
        all: bool,
    },
    /// Manage subscriptions.
    #[command(name = "sub")]
    Sub {
        #[command(subcommand)]
        action: SubAction,
    },
    /// Manage geo rule data (geosite.dat / geoip.dat).
    Geo {
        #[command(subcommand)]
        action: GeoAction,
    },
    /// Toggle the Windows system proxy.
    Sysproxy {
        #[arg(value_enum)]
        action: SysproxyAction,
    },
}

#[derive(Subcommand)]
enum SubAction {
    /// Add a subscription (and fetch it immediately).
    Add { name: String, url: String },
    /// List subscriptions.
    List,
    /// Update one or all subscriptions.
    Update {
        /// Subscription name; updates all when omitted.
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum GeoAction {
    /// Download the latest geo data files.
    Update,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SysproxyAction {
    On,
    Off,
    Status,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    Global,
    Rule,
    Direct,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { listen } => {
            let store = ConfigStore::load(&cli.config)?;
            let addr = match listen {
                Some(l) => l.parse()?,
                None => store.config().listen,
            };
            let registry = vulpini_core::outbound::OutboundRegistry::new();

            // Load the active node into the selector ("proxy" outbound).
            let active = store
                .config()
                .active_node
                .and_then(|id| store.config().nodes.iter().find(|n| n.id == id));
            match active {
                Some(node) => match vulpini_core::outbound::build_outbound(&node.config) {
                    Ok(outbound) => {
                        println!(
                            "active node: {} [{}] {}",
                            node.name,
                            node.config.protocol(),
                            outbound.tag()
                        );
                        registry.selector().set(outbound);
                    }
                    Err(e) => {
                        eprintln!("warning: node '{}' unusable ({e})", node.name);
                    }
                },
                None => eprintln!("warning: no active node; 'proxy' outbound will fail"),
            }

            let config = store.config();
            let router = match vulpini_core::Router::from_config(config.mode, &config.rules) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warning: {e}; falling back to default rules");
                    vulpini_core::Router::from_config(
                        config.mode,
                        &vulpini_core::router::default_rules(),
                    )
                    .expect("default rules parse")
                }
            };
            let geo = vulpini_core::geo::GeoManager::new(config.geo.clone()).load();
            match &geo {
                Some(_) => println!("geo data loaded (geosite/geoip)"),
                None => println!("no geo data (run 'geo update' to download); geo rules inactive"),
            }
            let router = router.with_geo(geo);

            let engine =
                vulpini_core::EngineHandle::start(addr, Arc::new(registry), router).await?;
            println!(
                "vulpini listening on {} (mixed socks5/http)",
                engine.local_addr()
            );
            tokio::signal::ctrl_c().await?;
            println!("shutting down...");
            engine.shutdown().await;
        }
        Command::Import { links } => cmd_import(&cli.config, links)?,
        Command::List => cmd_list(&cli.config)?,
        Command::Select { node } => cmd_select(&cli.config, &node)?,
        Command::Mode { mode } => cmd_mode(&cli.config, mode)?,
        Command::Delay { all } => cmd_delay(&cli.config, all).await?,
        Command::Sub { action } => match action {
            SubAction::Add { name, url } => {
                let mut store = ConfigStore::load(&cli.config)?;
                let id =
                    vulpini_core::node::subscription::add_subscription(&mut store, &name, &url)?;
                println!("subscription added: {name}");
                match vulpini_core::node::subscription::update(&mut store, id).await {
                    Ok(o) => println!("fetched: {} nodes", o.added),
                    Err(e) => println!("warning: initial fetch failed: {e}"),
                }
            }
            SubAction::List => {
                let store = ConfigStore::load(&cli.config)?;
                if store.config().subscriptions.is_empty() {
                    println!("no subscriptions");
                }
                for sub in &store.config().subscriptions {
                    let updated = sub
                        .last_updated
                        .map(|t| format!("{t}"))
                        .unwrap_or_else(|| "never".into());
                    let err = sub
                        .last_error
                        .as_deref()
                        .map(|e| format!(" ERROR: {e}"))
                        .unwrap_or_default();
                    println!(
                        "{}  {} nodes  updated {}  {}{}",
                        &sub.id.simple().to_string()[..8],
                        sub.node_count,
                        updated,
                        sub.name,
                        err
                    );
                }
            }
            SubAction::Update { name } => {
                let mut store = ConfigStore::load(&cli.config)?;
                let ids: Vec<uuid::Uuid> = match &name {
                    Some(n) => {
                        let found: Vec<_> = store
                            .config()
                            .subscriptions
                            .iter()
                            .filter(|s| s.name == *n || s.id.to_string().starts_with(n))
                            .map(|s| (s.id, s.name.clone()))
                            .collect();
                        match found.len() {
                            0 => anyhow::bail!("no subscription matches '{n}'"),
                            1 => vec![found[0].0],
                            _ => anyhow::bail!("'{n}' matches {} subscriptions", found.len()),
                        }
                    }
                    None => store.config().subscriptions.iter().map(|s| s.id).collect(),
                };
                if ids.is_empty() {
                    println!("no subscriptions to update");
                }
                for id in ids {
                    match vulpini_core::node::subscription::update(&mut store, id).await {
                        Ok(o) => println!(
                            "updated {}: +{} -{}",
                            &id.simple().to_string()[..8],
                            o.added,
                            o.removed
                        ),
                        Err(e) => println!("failed {}: {e}", &id.simple().to_string()[..8]),
                    }
                }
            }
        },
        Command::Geo { action } => match action {
            GeoAction::Update => {
                let store = ConfigStore::load(&cli.config)?;
                let manager = vulpini_core::geo::GeoManager::new(store.config().geo.clone());
                println!("downloading geosite.dat and geoip.dat ...");
                let (site_len, ip_len) = manager.update().await?;
                println!("updated: geosite.dat {site_len} bytes, geoip.dat {ip_len} bytes");
            }
        },
        Command::Sysproxy { action } => match action {
            SysproxyAction::Status => match vulpini_sysproxy::status() {
                Ok(s) => println!("system proxy: {s:?}"),
                Err(e) => println!("system proxy status unavailable: {e}"),
            },
            _ => anyhow::bail!("sysproxy on/off is not implemented yet — see milestone M9"),
        },
    }
    Ok(())
}

fn cmd_import(path: &std::path::Path, links: Vec<String>) -> Result<()> {
    if links.is_empty() {
        anyhow::bail!("no links given (pass share links as arguments)");
    }
    let mut store = ConfigStore::load(path)?;
    let mut added = 0usize;
    let mut failed = 0usize;

    for link in &links {
        match parse_link(link) {
            Ok((name, config)) => {
                let node = Node::new(name, NodeSource::Manual, config);
                if store
                    .config()
                    .nodes
                    .iter()
                    .any(|n| n.stable_key == node.stable_key)
                {
                    println!("skip (duplicate): {}", node.name);
                    continue;
                }
                println!(
                    "added: {} [{}] {}:{}",
                    node.name,
                    node.config.protocol(),
                    node.config.server(),
                    node.config.port()
                );
                store.config_mut().nodes.push(node);
                added += 1;
            }
            Err(e) => {
                println!("failed: {e}");
                failed += 1;
            }
        }
    }
    store.save()?;
    println!("{added} added, {failed} failed");
    Ok(())
}

fn cmd_list(path: &std::path::Path) -> Result<()> {
    let store = ConfigStore::load(path)?;
    let config = store.config();
    if config.nodes.is_empty() {
        println!("no nodes configured (use 'import' to add some)");
        return Ok(());
    }
    println!(
        "{:<10} {:<10} {:<24} {:<32} {:<10} SOURCE",
        "ID", "PROTO", "NAME", "SERVER", "DELAY"
    );
    for node in &config.nodes {
        let active = if config.active_node == Some(node.id) {
            "*"
        } else {
            " "
        };
        let source = match &node.source {
            NodeSource::Manual => "manual".to_string(),
            NodeSource::Subscription(id) => format!("sub:{}", &id.simple().to_string()[..8]),
        };
        let delay = config
            .delay_history
            .get(&node.stable_key)
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".into());
        println!(
            "{}{:<9} {:<10} {:<24} {:<32} {:<10} {}",
            active,
            node.id.short(),
            node.config.protocol(),
            truncate(&node.name, 24),
            truncate(
                &format!("{}:{}", node.config.server(), node.config.port()),
                32
            ),
            delay,
            source
        );
    }
    Ok(())
}

async fn cmd_delay(path: &std::path::Path, all: bool) -> Result<()> {
    let mut store = ConfigStore::load(path)?;
    let targets: Vec<(vulpini_core::NodeId, vulpini_core::NodeConfig)> = if all {
        store
            .config()
            .nodes
            .iter()
            .map(|n| (n.id, n.config.clone()))
            .collect()
    } else {
        match store.config().active_node {
            Some(id) => match store.config().nodes.iter().find(|n| n.id == id) {
                Some(n) => vec![(n.id, n.config.clone())],
                None => anyhow::bail!("active node not found in node list"),
            },
            None => anyhow::bail!("no active node (use 'select' first, or 'delay --all')"),
        }
    };
    if targets.is_empty() {
        println!("no nodes to test");
        return Ok(());
    }

    use futures::StreamExt;
    let names: std::collections::HashMap<_, _> = store
        .config()
        .nodes
        .iter()
        .map(|n| (n.id, (n.name.clone(), n.stable_key.clone())))
        .collect();

    println!(
        "testing {} node(s) via {} ...",
        targets.len(),
        vulpini_core::delay::DEFAULT_PROBE_URL
    );
    let mut results = vulpini_core::delay::test_all(
        targets,
        vulpini_core::delay::DEFAULT_PROBE_URL.to_string(),
        vulpini_core::delay::DEFAULT_TIMEOUT,
        8,
    );
    while let Some(result) = results.next().await {
        let (name, stable_key) = names
            .get(&result.node_id)
            .map(|(n, k)| (n.clone(), k.clone()))
            .unwrap_or_else(|| ("?".into(), String::new()));
        match result.delay {
            Ok(d) => {
                println!("{name}: {} ms", d.as_millis());
                store
                    .config_mut()
                    .delay_history
                    .insert(stable_key, d.as_millis() as u64);
            }
            Err(e) => println!("{name}: FAIL ({e})"),
        }
    }
    store.save()?;
    Ok(())
}

fn cmd_mode(path: &std::path::Path, mode: Option<ModeArg>) -> Result<()> {
    let mut store = ConfigStore::load(path)?;
    match mode {
        None => println!("current mode: {:?}", store.config().mode),
        Some(m) => {
            store.config_mut().mode = match m {
                ModeArg::Global => vulpini_core::Mode::Global,
                ModeArg::Rule => vulpini_core::Mode::Rule,
                ModeArg::Direct => vulpini_core::Mode::Direct,
            };
            store.save()?;
            println!("mode set to {:?}", store.config().mode);
        }
    }
    Ok(())
}

fn cmd_select(path: &std::path::Path, query: &str) -> Result<()> {
    let mut store = ConfigStore::load(path)?;
    let matches: Vec<_> = store
        .config()
        .nodes
        .iter()
        .filter(|n| {
            n.id.to_string().starts_with(query)
                || n.id.0.simple().to_string().starts_with(query)
                || n.name == query
        })
        .map(|n| (n.id, n.name.clone()))
        .collect();

    match matches.len() {
        0 => anyhow::bail!("no node matches '{query}'"),
        1 => {
            let (id, name) = &matches[0];
            store.config_mut().active_node = Some(*id);
            store.save()?;
            println!("active node: {name} ({})", id.short());
            Ok(())
        }
        _ => anyhow::bail!(
            "'{query}' matches {} nodes, be more specific",
            matches.len()
        ),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}
