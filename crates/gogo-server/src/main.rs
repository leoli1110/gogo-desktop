//! `gogo` - the Gogo Desktop program.

mod api;
mod config;
mod health;
mod security;
mod server;
mod state;
#[cfg(test)]
mod tests;
mod tls;
mod web;
#[cfg(windows)]
mod winacl;
#[cfg(windows)]
mod winservice;
#[cfg(windows)]
mod winsignin;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;

#[derive(Parser)]
#[command(name = "gogo", version, about = "Gogo Desktop - fast local file search in your browser")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Exit 0 if the local server answers (used by the Docker HEALTHCHECK).
    Healthcheck,
    /// Emergency administrator tools.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// List accounts.
    Users {
        #[command(subcommand)]
        cmd: UsersCmd,
    },
    /// Audit log tools.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Sign in to the web interface as the current Windows user (same PC only).
    #[cfg(windows)]
    Signin,
    /// Install or remove the Windows service.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Print a one-time code (valid 15 minutes) to reset an administrator's
    /// password, second factor and lockout at /recover.
    Reset,
}

#[derive(Subcommand)]
enum UsersCmd {
    /// List every account.
    List,
    /// Approve a pending Synology user (available from milestone M6).
    Approve { username: String },
    /// Show pending Synology users (available from milestone M6).
    Pending,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check the audit log's hash chain.
    Verify,
    /// Show the newest records.
    Tail {
        #[arg(short, default_value_t = 20)]
        n: usize,
        /// Only events starting with this prefix, e.g. "auth." or "user."
        #[arg(long)]
        r#type: Option<String>,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Install and start the "Gogo Desktop" service (run as administrator).
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Entry point used by the Windows service manager.
    #[command(hide = true)]
    Run,
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("GOGO_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
}

fn main() {
    let cli = Cli::parse();
    #[cfg(windows)]
    let is_service = matches!(cli.command, Some(Command::Service { cmd: ServiceCmd::Run }));
    #[cfg(not(windows))]
    let is_service = false;
    if !is_service {
        init_logging();
    }
    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gogo: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let cfg = Config::from_env()?;
            runtime()?.block_on(server::run(cfg, server::shutdown_signal()))?;
            Ok(0)
        }
        Command::Healthcheck => {
            let cfg = Config::from_env()?;
            Ok(if runtime()?.block_on(health::check(&cfg)) { 0 } else { 1 })
        }
        Command::Admin { cmd: AdminCmd::Reset } => {
            let cfg = Config::from_env()?;
            let store = gogo_auth::Store::open(&cfg.db_path())?;
            let code = store.create_reset_code()?;
            let audit = gogo_auth::audit::AuditLog::open(&cfg.audit_dir())?;
            audit.record("admin.reset_code_issued", Some("console"), None, serde_json::json!({}));
            println!("Reset code (valid 15 minutes, single use):\n\n    {code}\n");
            println!(
                "Open the web interface at /recover, enter the code, the administrator's username and a new password."
            );
            println!("This also clears the sign-in code app, the lockout, and ends that administrator's sessions.");
            Ok(0)
        }
        Command::Users { cmd } => {
            let cfg = Config::from_env()?;
            match cmd {
                UsersCmd::List => {
                    let store = gogo_auth::Store::open(&cfg.db_path())?;
                    println!("{:<6} {:<32} {:<8} {:<6} {:<5} STATUS", "ID", "USERNAME", "KIND", "ROLE", "2FA");
                    for u in store.list_users()? {
                        let status = if u.disabled {
                            "disabled"
                        } else if u.locked_until > gogo_auth::now() {
                            "locked"
                        } else {
                            "active"
                        };
                        println!(
                            "{:<6} {:<32} {:<8} {:<6} {:<5} {}",
                            u.id,
                            u.username,
                            format!("{:?}", u.kind).to_lowercase(),
                            u.role.as_str(),
                            if u.totp_enabled { "yes" } else { "no" },
                            status
                        );
                    }
                    Ok(0)
                }
                UsersCmd::Approve { .. } | UsersCmd::Pending => {
                    eprintln!("Synology sign-in and approvals arrive in milestone M6. Nothing to approve yet.");
                    Ok(1)
                }
            }
        }
        Command::Audit { cmd } => {
            let cfg = Config::from_env()?;
            match cmd {
                AuditCmd::Verify => match gogo_auth::audit::verify(&cfg.audit_dir()) {
                    Ok(n) => {
                        println!("audit log OK: {n} records checked");
                        Ok(0)
                    }
                    Err(e) => {
                        eprintln!("audit log problem: {e}");
                        Ok(1)
                    }
                },
                AuditCmd::Tail { n, r#type } => {
                    let log = gogo_auth::audit::AuditLog::open(&cfg.audit_dir())?;
                    for r in log.tail(n, r#type.as_deref())? {
                        println!("{}", serde_json::to_string(&r)?);
                    }
                    Ok(0)
                }
            }
        }
        #[cfg(windows)]
        Command::Signin => {
            let cfg = Config::from_env()?;
            winsignin::client(&cfg)?;
            Ok(0)
        }
        #[cfg(windows)]
        Command::Service { cmd } => {
            match cmd {
                ServiceCmd::Install => winservice::install()?,
                ServiceCmd::Uninstall => winservice::uninstall()?,
                ServiceCmd::Run => winservice::run()?,
            }
            Ok(0)
        }
    }
}
