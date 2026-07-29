//! Customer databases.
//!
//! One MariaDB server hosts everything. Isolation is the server's own grant
//! system rather than anything Ember filters: a user granted rights on a single
//! database cannot see any other in `SHOW DATABASES`, so a customer connecting
//! with their own credentials sees exactly their own data and nothing else.
//! That means the boundary holds even for a customer connecting directly with
//! a MySQL client, not only through the panel.
//!
//! Ember drives the `mysql` client rather than linking a database driver, for
//! the same reason it drives certbot: administration is a small set of
//! statements, and the client already handles socket auth, TLS and version
//! differences. Statements go in over **stdin**, never as arguments, so a
//! password never appears in the process list.
//!
//! Postgres and Redis are named in [`Engine`] but not implemented; the shape is
//! here so adding them does not mean reworking the store or the API.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Which server a database lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    MariaDb,
    /// Recognised so records and the API do not need changing later.
    Postgres,
    Redis,
}

impl Engine {
    pub fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "mariadb" | "mysql" => Ok(Self::MariaDb),
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "redis" => Ok(Self::Redis),
            other => bail!("unknown database engine {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MariaDb => "mariadb",
            Self::Postgres => "postgres",
            Self::Redis => "redis",
        }
    }

    /// Refuse clearly rather than half-working on an engine with no support.
    fn require_supported(self) -> Result<()> {
        match self {
            Self::MariaDb => Ok(()),
            other => bail!(
                "{} is not supported yet — only mariadb is implemented",
                other.as_str()
            ),
        }
    }
}

/// Where the client and server are, if they are here at all.
pub fn client_path() -> Option<std::path::PathBuf> {
    for candidate in ["/usr/bin/mariadb", "/usr/bin/mysql", "/usr/local/bin/mysql"] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Is the server actually reachable, not merely installed?
///
/// Reported rather than assumed: "installed but not running" is the common
/// state on a fresh box and produces a much better message than a failed
/// statement halfway through creating something.
pub fn server_status() -> (bool, String) {
    let Some(client) = client_path() else {
        return (false, "the mariadb client is not installed".to_string());
    };

    match run_sql_raw(&client, "SELECT VERSION();") {
        Ok(output) => {
            let version = output
                .lines()
                .last()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            (true, format!("mariadb {version}"))
        }
        Err(err) => (false, format!("{err:#}")),
    }
}

/// Run SQL as the server administrator.
///
/// Statements arrive on stdin so nothing sensitive lands in the process list,
/// and authentication is the unix socket — on a default Debian or Ubuntu
/// install root authenticates that way, so Ember stores no database password
/// of its own.
fn run_sql_raw(client: &std::path::Path, sql: &str) -> Result<String> {
    use std::io::Write;

    let mut child = std::process::Command::new(client)
        .args([
            "--protocol=socket",
            "--user=root",
            "--batch",
            "--skip-column-names",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("could not run {}", client.display()))?;

    child
        .stdin
        .as_mut()
        .context("mysql stdin unavailable")?
        .write_all(sql.as_bytes())
        .context("could not send SQL")?;

    let output = child.wait_with_output().context("mysql did not complete")?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        let reason = stderr.trim();
        if reason.contains("Can't connect") || reason.contains("connect to local") {
            bail!("the mariadb server is not running");
        }
        if reason.contains("Access denied") {
            bail!("ember cannot administer mariadb: {reason}");
        }
        bail!(
            "{}",
            if reason.is_empty() {
                stdout.trim()
            } else {
                reason
            }
        );
    }

    Ok(stdout)
}

fn run_sql(sql: &str) -> Result<String> {
    let client = client_path().context("the mariadb client is not installed")?;
    run_sql_raw(&client, sql)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Names go into SQL as identifiers, so they are restricted rather than escaped.
///
/// Backtick-quoting an arbitrary string is a defence that has failed for other
/// people often enough to be worth not relying on. A closed character set makes
/// the question moot.
pub fn check_identifier(name: &str, kind: &str, max: usize) -> Result<()> {
    if name.is_empty() {
        bail!("{kind} cannot be empty");
    }
    if name.len() > max {
        bail!("{kind} must be at most {max} characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        bail!("{kind} may use lowercase letters, digits and '_' only");
    }
    if name.as_bytes()[0].is_ascii_digit() {
        bail!("{kind} may not start with a digit");
    }
    Ok(())
}

/// MariaDB caps database names at 64 characters and users at 80.
pub const MAX_DB_NAME: usize = 64;
pub const MAX_DB_USER: usize = 32;

/// A password safe to place inside a single-quoted SQL literal.
fn check_password(password: &str) -> Result<()> {
    if password.len() < 12 {
        bail!("database password must be at least 12 characters");
    }
    if password.len() > 128 {
        bail!("database password is too long");
    }
    // Excludes the quote and backslash entirely rather than escaping them.
    if password
        .bytes()
        .any(|b| b == b'\'' || b == b'\\' || b == b'`' || b < 0x20)
    {
        bail!("database password may not contain quotes, backslashes or control characters");
    }
    Ok(())
}

/// A password the operator does not have to invent.
pub fn generate_password() -> Result<String> {
    // Deliberately alphanumeric: it survives copy-paste, connection strings and
    // shell quoting, and the length carries the entropy instead.
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = crate::auth::random_bytes(24)?;
    Ok(bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect())
}

/// Prefix a name with its owner, so two customers can both want `wordpress`.
pub fn qualified_name(owner: &str, name: &str) -> String {
    if name.starts_with(&format!("{owner}_")) {
        name.to_string()
    } else {
        format!("{owner}_{name}")
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a database and a user that can reach it and nothing else.
pub fn create(
    cfg: &Config,
    engine: Engine,
    database: &str,
    user: &str,
    password: &str,
) -> Result<()> {
    cfg.require_host_mode(&format!("create the database {database}"))?;
    engine.require_supported()?;

    check_identifier(database, "database name", MAX_DB_NAME)?;
    check_identifier(user, "database user", MAX_DB_USER)?;
    check_password(password)?;

    if exists(database)? {
        bail!("a database named {database} already exists on this server");
    }

    // The grant names one database. That single line is what stops this user
    // seeing anything else on the server, including other customers'.
    let sql = format!(
        "CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{password}';\n\
         GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'localhost';\n\
         FLUSH PRIVILEGES;\n"
    );

    run_sql(&sql).with_context(|| format!("could not create {database}"))?;
    Ok(())
}

/// Remove a database and its user.
pub fn drop(cfg: &Config, engine: Engine, database: &str, user: &str) -> Result<()> {
    cfg.require_host_mode(&format!("drop the database {database}"))?;
    engine.require_supported()?;

    check_identifier(database, "database name", MAX_DB_NAME)?;
    check_identifier(user, "database user", MAX_DB_USER)?;

    let sql = format!(
        "DROP DATABASE IF EXISTS `{database}`;\n\
         DROP USER IF EXISTS '{user}'@'localhost';\n\
         FLUSH PRIVILEGES;\n"
    );

    run_sql(&sql).with_context(|| format!("could not drop {database}"))?;
    Ok(())
}

pub fn set_password(cfg: &Config, engine: Engine, user: &str, password: &str) -> Result<()> {
    cfg.require_host_mode(&format!("change the password for {user}"))?;
    engine.require_supported()?;

    check_identifier(user, "database user", MAX_DB_USER)?;
    check_password(password)?;

    run_sql(&format!(
        "ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}';\nFLUSH PRIVILEGES;\n"
    ))
    .with_context(|| format!("could not change the password for {user}"))?;
    Ok(())
}

pub fn exists(database: &str) -> Result<bool> {
    check_identifier(database, "database name", MAX_DB_NAME)?;
    let output = run_sql(&format!(
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{database}';"
    ))?;
    Ok(!output.trim().is_empty())
}

/// Size on disk, for display. `None` when the server cannot say.
pub fn size_bytes(database: &str) -> Option<u64> {
    check_identifier(database, "database name", MAX_DB_NAME).ok()?;
    let output = run_sql(&format!(
        "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.TABLES \
         WHERE table_schema = '{database}';"
    ))
    .ok()?;
    output.trim().parse().ok()
}

/// What a given user can actually reach — the isolation claim, checked against
/// the server rather than asserted.
pub fn grants_for(user: &str) -> Result<Vec<String>> {
    check_identifier(user, "database user", MAX_DB_USER)?;
    let output = run_sql(&format!("SHOW GRANTS FOR '{user}'@'localhost';"))?;
    Ok(output.lines().map(|l| l.trim().to_string()).collect())
}

/// Where the server itself lives, as opposed to the client.
fn server_binary() -> Option<std::path::PathBuf> {
    for candidate in [
        "/usr/sbin/mariadbd",
        "/usr/sbin/mysqld",
        "/usr/bin/mariadbd",
        "/usr/bin/mysqld",
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Start MariaDB if it is installed but not accepting connections.
///
/// On a normal server systemd owns this and the call is a no-op. It matters in
/// a container, where ember is PID 1 and there is no init to bring the database
/// up — without this, a container that ships MariaDB would still report no
/// database server.
///
/// Best effort by design: a database that will not start must not stop the
/// panel from serving, it must be reported.
pub fn ensure_running(cfg: &Config) -> String {
    if cfg.mode != crate::config::Mode::Host {
        return "isolated mode: not starting a database server".to_string();
    }

    let (up, status) = server_status();
    if up {
        return status;
    }
    if client_path().is_none() {
        return "not installed".to_string();
    }
    let Some(server) = server_binary() else {
        return "client present but no server installed".to_string();
    };

    // Prefer the service manager where there is one, so the database is
    // supervised by whatever supervises everything else on the box.
    let started = if std::path::Path::new("/run/systemd/system").is_dir() {
        std::process::Command::new("systemctl")
            .args(["start", "mariadb"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        // No init: launch it ourselves and let it daemonise.
        let launcher = ["/usr/bin/mariadbd-safe", "/usr/bin/mysqld_safe"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file());

        match launcher {
            Some(safe) => std::process::Command::new(safe)
                .arg("--user=mysql")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .is_ok(),
            None => std::process::Command::new(&server)
                .arg("--user=mysql")
                .arg("--daemonize")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .is_ok(),
        }
    };

    if !started {
        return "could not be started".to_string();
    }

    // Starting returns long before the socket accepts connections.
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let (up, status) = server_status();
        if up {
            // Harden here as well as in the installer. The installer cannot do
            // it while building an image — nothing is running yet — so without
            // this a container would keep whatever defaults the distribution
            // shipped, underneath the per-customer grants.
            if let Err(err) = harden() {
                crate::esw::log_line(&format!("database: could not harden: {err:#}"));
            }
            return status;
        }
    }

    "started but did not accept connections in 15s".to_string()
}

/// Remove the defaults that sit underneath the per-customer grants.
///
/// An anonymous account or a world-readable `test` database would let anyone
/// on the machine reach data regardless of who was granted what. Idempotent, so
/// running it again costs nothing.
pub fn harden() -> Result<()> {
    run_sql(
        "DELETE FROM mysql.global_priv WHERE User='';\n\
         DELETE FROM mysql.global_priv \
           WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');\n\
         DROP DATABASE IF EXISTS test;\n\
         DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';\n\
         FLUSH PRIVILEGES;\n",
    )?;
    Ok(())
}
