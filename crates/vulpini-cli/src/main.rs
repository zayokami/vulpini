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
    /// Toggle the Windows system proxy.
    Sysproxy {
        #[arg(value_enum)]
        action: SysproxyAction,
    },
}

#[derive(Subcommand)]
enum SubAction {
    /// Add a subscription.
    Add { name: String, url: String },
    /// Update one or all subscriptions.
    Update {
        /// Subscription name; updates all when omitted.
        name: Option<String>,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SysproxyAction {
    On,
    Off,
    Status,
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
            let registry = Arc::new(vulpini_core::outbound::OutboundRegistry::new());
            let engine = vulpini_core::EngineHandle::start(addr, registry).await?;
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
        Command::Delay { .. } => anyhow::bail!("delay is not implemented yet — see milestone M8"),
        Command::Sub { .. } => anyhow::bail!("sub is not implemented yet — see milestone M7"),
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
        "{:<10} {:<10} {:<24} {:<32} SOURCE",
        "ID", "PROTO", "NAME", "SERVER"
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
        println!(
            "{}{:<9} {:<10} {:<24} {:<32} {}",
            active,
            node.id.short(),
            node.config.protocol(),
            truncate(&node.name, 24),
            truncate(
                &format!("{}:{}", node.config.server(), node.config.port()),
                32
            ),
            source
        );
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
