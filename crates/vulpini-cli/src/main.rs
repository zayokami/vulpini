use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "vulpini-cli",
    version,
    about = "Headless shell for the vulpini proxy core"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy core in the foreground.
    Run {
        /// Listen address for the mixed SOCKS5/HTTP inbound.
        #[arg(long, default_value = "127.0.0.1:7890")]
        listen: String,
    },
    /// Import nodes from share links (one per line).
    Import {
        /// Share links to import (ss://, vmess://, vless://, trojan://).
        links: Vec<String>,
    },
    /// List configured nodes.
    List,
    /// Select the active node.
    Select {
        /// Node id or name.
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
            use std::sync::Arc;
            let addr: std::net::SocketAddr = listen.parse()?;
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
        Command::Import { .. } => anyhow::bail!("import is not implemented yet — see milestone M2"),
        Command::List => anyhow::bail!("list is not implemented yet — see milestone M2"),
        Command::Select { .. } => anyhow::bail!("select is not implemented yet — see milestone M2"),
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
