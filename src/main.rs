//! Ember — a server control panel.
//!
//! Architecture in one breath: this Rust binary is the service. It supervises
//! esw-engine (the Ember Service Worker engine — its own pinned execution
//! engine, never the system PHP), terminates HTTP itself, speaks FastCGI to
//! that engine, authenticates against real system accounts, and exposes a
//! privileged control API that the unprivileged panel calls for anything it
//! cannot do itself.

mod accounts;
mod auth;
mod cert;
mod config;
mod daemon;
mod database;
mod esw;
mod files;
mod pages;
mod pam;
mod server;
mod store;
mod vhost;
mod worker;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "ember",
    version,
    about = "Ember — server control panel",
    long_about = "Ember runs the panel service: esw-engine, its own web server, \
                  and authentication against system accounts."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the panel service in the background
    Start {
        /// Port to listen on (overrides EMBER_PORT and the config file)
        #[arg(short, long)]
        port: Option<u16>,
        /// Address to bind
        #[arg(long)]
        host: Option<String>,
        /// Run in this terminal instead of detaching
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the running panel service
    Stop,
    /// Restart the panel service
    Restart {
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(long)]
        host: Option<String>,
    },
    /// Show whether the service is running
    Status {
        /// Emit JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Print a one-time login URL for a system user
    Login {
        /// System user to log in as (root only; defaults to you)
        #[arg(short, long)]
        user: Option<String>,
    },
    /// Manage esw-engine, the Ember Service Worker engine
    #[command(subcommand)]
    Esw(EswCommand),
    /// Inspect and manage the system accounts that can log into the panel
    #[command(subcommand)]
    Users(UserCommand),
    /// Manage TLS certificates from Let's Encrypt
    #[command(subcommand)]
    Cert(CertCommand),
    /// Reset panel access when you are locked out
    Recover {
        /// Account to restore; defaults to the existing administrator
        #[arg(short, long)]
        user: Option<String>,
    },
    /// Show the last lines of the service log
    Logs {
        /// How many lines to show
        #[arg(short = 'n', long, default_value_t = 40)]
        lines: usize,
    },
    /// Run the service in the foreground (used internally by `start`)
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        host: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// List system accounts that can log into the panel
    List {
        /// Lowest uid to treat as a login account
        #[arg(long, default_value_t = 1000)]
        uid_floor: u32,
        #[arg(long)]
        json: bool,
    },
    /// Create a system account (requires host mode and root)
    Create {
        name: String,
        /// Login shell for the new account
        #[arg(long, default_value = "/bin/bash")]
        shell: String,
    },
}

#[derive(Subcommand)]
enum CertCommand {
    /// Request a certificate for a domain
    Issue {
        /// The domain, as registered in the panel
        domain: String,
        /// Contact address for expiry notices
        #[arg(short, long)]
        email: Option<String>,
        /// Use Let's Encrypt staging: untrusted certificates, loose rate limits
        #[arg(long)]
        staging: bool,
    },
    /// Show certificate status for every domain
    List,
    /// Renew whatever is due
    Renew {
        /// Renew even if not yet due
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum EswCommand {
    /// Download and install esw-engine
    Install {
        /// Engine version to install
        #[arg(long)]
        version: Option<String>,
        /// Reinstall even if already present
        #[arg(long)]
        force: bool,
    },
    /// List esw-engine builds Ember has provisioned
    List,
    /// Run Ember's own PHP — for Composer, bin/console, and cron
    ///
    /// Everything after `--` is passed through untouched, so a server never
    /// needs a system PHP of its own.
    #[command(disable_help_flag = true)]
    Php {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print the path to Ember's PHP binaries
    Which,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Start {
            port,
            host,
            foreground,
        } => {
            let cfg = Config::resolve(host, port)?;
            if foreground {
                run_service(cfg)
            } else {
                let state = daemon::start_detached(&cfg)?;
                println!("ember started (pid {})", state.pid);
                println!("  panel   {}", cfg.url());
                println!("  engine  esw-engine {}", state.esw_version);
                println!("  mode    {}", describe_mode(&state.mode));
                println!("\nrun `ember login` for a one-time login URL.");
                Ok(())
            }
        }

        Command::Stop => {
            if daemon::stop()? {
                println!("ember stopped");
            } else {
                println!("ember is not running");
            }
            Ok(())
        }

        Command::Restart { port, host } => {
            if daemon::stop()? {
                println!("ember stopped");
            }
            let cfg = Config::resolve(host, port)?;
            let state = daemon::start_detached(&cfg)?;
            println!("ember started (pid {})", state.pid);
            println!("  panel   {}", cfg.url());
            Ok(())
        }

        Command::Status { json } => {
            print_status(json);
            Ok(())
        }

        Command::Login { user } => login(user.as_deref()),

        Command::Esw(EswCommand::Install { version, force }) => {
            let version = version.unwrap_or_else(|| {
                Config::resolve(None, None)
                    .map(|c| c.esw_version)
                    .unwrap_or_else(|_| config::DEFAULT_ESW_VERSION.to_string())
            });
            println!("installing esw-engine {version} (independent of any system PHP)");
            let path = esw::install(&version, force)?;
            println!("  installed {}", path.display());
            Ok(())
        }

        Command::Esw(EswCommand::Php { args }) => {
            let cfg = Config::resolve(None, None)?;
            let php = esw::esw_cli_binary(&cfg.esw_version)?;
            if !php.is_file() {
                anyhow::bail!("ember's PHP CLI is not installed — run `ember esw install`");
            }
            // Replace this process so exit status, signals, stdin and stdout
            // all belong to PHP rather than being relayed through ember.
            use std::os::unix::process::CommandExt;
            let error = std::process::Command::new(&php).args(&args).exec();
            Err(anyhow::anyhow!("could not run {}: {error}", php.display()))
        }

        Command::Esw(EswCommand::Which) => {
            let cfg = Config::resolve(None, None)?;
            println!("worker  {}", esw::esw_binary(&cfg.esw_version)?.display());
            println!(
                "cli     {}",
                esw::esw_cli_binary(&cfg.esw_version)?.display()
            );
            Ok(())
        }

        Command::Esw(EswCommand::List) => {
            let versions = esw::installed_versions()?;
            if versions.is_empty() {
                println!("esw-engine is not installed — run `ember esw install`");
            } else {
                for version in versions {
                    println!("{version}  {}", esw::esw_binary(&version)?.display());
                }
            }
            Ok(())
        }

        Command::Users(UserCommand::List { uid_floor, json }) => {
            let users = auth::list_system_users(uid_floor);
            if json {
                println!("{}", serde_json::to_string_pretty(&users)?);
            } else if users.is_empty() {
                println!("no login accounts at or above uid {uid_floor}");
            } else {
                println!("{:<20} {:>7}  HOME", "USER", "UID");
                for user in users {
                    println!("{:<20} {:>7}  {}", user.name, user.uid, user.home);
                }
            }
            Ok(())
        }

        Command::Users(UserCommand::Create { name, shell }) => {
            // The whole point of isolated mode: this refuses on a laptop.
            let cfg = Config::resolve(None, None)?;
            cfg.require_host_mode(&format!("create system user {name:?}"))?;
            auth::create_system_user(&name, &shell)?;
            println!("created system user {name:?}");
            println!("run `ember login --user {name}` for their login URL.");
            Ok(())
        }

        Command::Cert(command) => certificates(command),

        Command::Recover { user } => recover(user.as_deref()),

        Command::Logs { lines } => {
            println!("{}", daemon::tail_log(lines));
            Ok(())
        }

        Command::Serve { port, host } => {
            let cfg = Config::resolve(host, port)?;
            run_service(cfg)
        }
    }
}

/// Run the service in this process until it is told to stop.
fn run_service(cfg: Config) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    let result = rt.block_on(server::run(cfg));
    if result.is_err() {
        // The state file must not outlive a failed start, or `status` lies.
        daemon::clear_state();
    }
    result
}

fn print_status(json: bool) {
    match daemon::status() {
        Some(state) => {
            if json {
                let payload = serde_json::json!({
                    "status": "running",
                    "pid": state.pid,
                    "host": state.host,
                    "port": state.port,
                    "esw_version": state.esw_version,
                    "mode": state.mode,
                    "uptime_seconds": state.uptime_secs(),
                });
                println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            } else {
                println!("service:  running (pid {})", state.pid);
                println!("listen:   {}:{}", state.host, state.port);
                println!("engine:   esw-engine {}", state.esw_version);
                println!("mode:     {}", describe_mode(&state.mode));
                println!("uptime:   {}", daemon::format_uptime(state.uptime_secs()));
            }
        }
        None => {
            if json {
                println!("{}", serde_json::json!({ "status": "stopped" }));
            } else {
                println!("service:  stopped");
            }
        }
    }
}

/// TLS certificates, driven through certbot.
fn certificates(command: CertCommand) -> Result<()> {
    let cfg = Config::resolve(None, None)?;
    let conn = store::open()?;

    match command {
        CertCommand::Issue {
            domain,
            email,
            staging,
        } => {
            let record = store::list_domains(&conn, None)?
                .into_iter()
                .find(|d| d.name == domain)
                .ok_or_else(|| anyhow::anyhow!("{domain:?} is not a domain in this panel"))?;

            if staging {
                println!("using Let's Encrypt staging — the certificate will not be trusted");
            }
            println!("requesting a certificate for {domain} and www.{domain}");
            let output = cert::issue(&cfg, &record, email.as_deref(), staging)?;
            println!("{output}");

            // Only now does the vhost gain its TLS block.
            let path = vhost::write_config(&cfg, &record)?;
            println!("  vhost rewritten: {}", path.display());
            if let Ok(server) = vhost::WebServer::parse(&record.webserver) {
                println!("  {}", vhost::reload(server)?);
            }
            let hook = cert::install_renewal_hook(&cfg)?;
            println!("  renewal hook: {}", hook.display());
            Ok(())
        }

        CertCommand::List => {
            let domains = store::list_domains(&conn, None)?;
            if domains.is_empty() {
                println!("no domains yet");
                return Ok(());
            }

            println!("{:<32} {:<10} {:<26} DAYS", "DOMAIN", "TLS", "EXPIRES");
            for domain in domains {
                let status = cert::status(&domain.name);
                println!(
                    "{:<32} {:<10} {:<26} {}",
                    domain.name,
                    if status.present { "yes" } else { "—" },
                    status.expires_at.unwrap_or_else(|| "—".into()),
                    status
                        .days_remaining
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "—".into()),
                );
            }

            // The failure that matters is silent: renewal stops and nobody
            // notices until the certificate expires.
            match cert::renewal_timer_active() {
                Some(source) => println!("\nautomatic renewal: active via {source}"),
                None => println!(
                    "\nautomatic renewal: NOT scheduled — certificates will expire.\n\
                     enable it with: systemctl enable --now certbot.timer"
                ),
            }
            Ok(())
        }

        CertCommand::Renew { force } => {
            println!("{}", cert::renew_all(&cfg, force)?);
            Ok(())
        }
    }
}

/// Restore access to the panel. Running this requires being on the machine,
/// which is the same proof of possession `ember login` relies on.
fn recover(user: Option<&str>) -> Result<()> {
    let mut store = accounts::Store::load();

    let username = match user {
        Some(name) => name.to_string(),
        None => match store.list().iter().find(|a| a.is_admin) {
            Some(admin) => admin.username.clone(),
            None => "admin".to_string(),
        },
    };

    let password = prompt_new_password()?;

    // An existing local account is reset; anything else becomes a local
    // recovery account, which is the whole point of this command.
    match store.reset_password(&username, &password) {
        Ok(()) => println!("password reset for {username:?}"),
        Err(_) => {
            store.upsert_local_admin(&username, &password)?;
            println!("recovery administrator {username:?} is ready");
        }
    }

    println!("sign in at the panel with that username and password.");
    Ok(())
}

/// Read a password twice without echoing it to the terminal.
fn prompt_new_password() -> Result<String> {
    let first = read_hidden("New password: ")?;
    accounts::check_password_strength(&first)?;
    let second = read_hidden("Confirm password: ")?;
    if first != second {
        anyhow::bail!("the two passwords do not match");
    }
    Ok(first)
}

fn read_hidden(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};

    print!("{prompt}");
    std::io::stdout().flush().ok();

    // Turn off terminal echo around the read so the password is never shown.
    let echo_off = std::process::Command::new("stty")
        .args(["-echo"])
        .stdin(std::process::Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);

    if echo_off {
        let _ = std::process::Command::new("stty")
            .args(["echo"])
            .stdin(std::process::Stdio::inherit())
            .status();
        println!();
    }

    read.context("could not read the password")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Spell out what the mode actually permits — "isolated" alone is not obvious.
fn describe_mode(mode: &str) -> String {
    match mode {
        "host" => "host (may manage system accounts and services)".to_string(),
        _ => "isolated (manages nothing outside EMBER_HOME)".to_string(),
    }
}

/// Mint a one-time login URL for someone already on this machine.
fn login(user: Option<&str>) -> Result<()> {
    let Some(state) = daemon::status() else {
        anyhow::bail!("ember is not running — start it with `ember start`");
    };

    let (token, user) = auth::issue_login_token(user)?;
    let cfg = Config {
        host: state.host,
        port: state.port,
        esw_version: state.esw_version,
        mode: config::Mode::Isolated, // only `url()` is used below
    };

    println!("one-time login URL for system user {user:?}:\n");
    println!("  {}/login?token={token}\n", cfg.url());
    println!(
        "valid once, expires in {} seconds.",
        auth::LOGIN_TOKEN_TTL.as_secs()
    );
    Ok(())
}
