use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{EnvFilter, fmt};

mod broker;
mod config;
mod discovery;
mod error;
mod hostkeys;
mod paths;
mod secrets;
mod server;
mod ssh_config;
mod state;
mod tools;
mod transport;
mod ui;
#[cfg(any(windows, ssh_connect_wincheck))]
mod winsec;

use broker::Election;
use server::SshConnectServer;

const USAGE: &str = "\
SSH-Connect — MCP server for SSH / Telnet / Serial

Usage:
  ssh-connect                 run the MCP server on stdio (what MCP clients launch)
  ssh-connect ui [--port N] [--no-browser]
                              open the local page for managing saved hosts
  ssh-connect --version

Started by double-click (from a console, not by an MCP client), it opens the UI.";

enum Mode {
    Mcp,
    Ui(ui::UiOptions),
}

fn parse_args() -> Result<Mode> {
    use std::io::IsTerminal;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ui_opts = |rest: &[String]| -> Result<ui::UiOptions> {
        let mut opts = ui::UiOptions { port: 0, open_browser: true };
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--port" => {
                    let v = it.next().ok_or_else(|| anyhow::anyhow!("--port needs a value"))?;
                    opts.port = v.parse().map_err(|_| anyhow::anyhow!("invalid port '{v}'"))?;
                }
                "--no-browser" => opts.open_browser = false,
                other => anyhow::bail!("unknown option '{other}'\n\n{USAGE}"),
            }
        }
        Ok(opts)
    };
    match args.first().map(String::as_str) {
        None if std::io::stdin().is_terminal() => Ok(Mode::Ui(ui_opts(&[])?)),
        None => Ok(Mode::Mcp),
        Some("ui") => Ok(Mode::Ui(ui_opts(&args[1..])?)),
        Some("--version") | Some("-V") => {
            println!("ssh-connect {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("--help") | Some("-h") | Some("help") => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        Some(other) => anyhow::bail!("unknown argument '{other}'\n\n{USAGE}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // MCP uses stdout for JSON-RPC — all logging must go to stderr
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    if let Mode::Ui(opts) = parse_args()? {
        let rt = tokio::runtime::Handle::current();
        return tokio::task::spawn_blocking(move || ui::run(rt, opts)).await?;
    }

    tracing::info!("Starting SSH-Connect MCP Server");

    // Elect a broker role so multiple instances share one set of live sessions.
    let server = match broker::elect().await {
        #[cfg(any(windows, unix))]
        Election::Owner(listener) => {
            let owner = SshConnectServer::new();
            tokio::spawn(broker::serve_owner(listener, owner.clone()));
            owner
        }
        #[cfg(any(windows, unix))]
        Election::Proxy(peer) => SshConnectServer::new_proxy(peer),
        Election::OwnerLocal => SshConnectServer::new(),
    };

    let service = server
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("Server error: {:?}", e))?;

    service.waiting().await?;
    Ok(())
}
