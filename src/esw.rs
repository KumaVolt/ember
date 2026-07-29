//! esw-engine — the Ember Service Worker engine.
//!
//! Deliberately never called "PHP" in anything a customer sees. Customers pick
//! PHP versions for their own sites; esw-engine is what executes the panel
//! itself, and conflating the two would be confusing.
//!
//! Under the hood it is a pinned static `php-fpm` build living in
//! `$EMBER_HOME/esw/`, with its own ini and pool config. The system PHP at
//! `/usr/bin/php` is never read, written, or executed.
//!
//! The panel pool is the first pool Ember supervises. Per-site PHP pools — each
//! with its own version and its own system user — reuse this same machinery.

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use crate::config::{self, Config};

const DOWNLOAD_BASE: &str = "https://dl.static-php.dev/static-php-cli/bulk";

/// Root of one provisioned esw-engine build.
pub fn esw_root(version: &str) -> Result<PathBuf> {
    Ok(config::esw_dir()?.join(version))
}

/// The esw-engine worker binary — serves the panel over FastCGI.
pub fn esw_binary(version: &str) -> Result<PathBuf> {
    Ok(esw_root(version)?.join("sbin").join("php-fpm"))
}

/// The matching command-line binary.
///
/// The panel needs one for Composer, `bin/console`, and later for queue workers
/// and cron. It is the *same* pinned build as the worker, so what the CLI
/// compiles is exactly what the worker runs — and a server still needs no
/// system PHP of its own.
pub fn esw_cli_binary(version: &str) -> Result<PathBuf> {
    Ok(esw_root(version)?.join("bin").join("php"))
}

pub fn is_installed(version: &str) -> bool {
    esw_binary(version).map(|p| p.is_file()).unwrap_or(false)
}

#[allow(dead_code)] // used by callers added alongside per-site pools
pub fn is_cli_installed(version: &str) -> bool {
    esw_cli_binary(version)
        .map(|p| p.is_file())
        .unwrap_or(false)
}

/// Config Ember generates for the panel pool.
pub fn panel_pool_conf() -> Result<PathBuf> {
    Ok(config::conf_dir()?.join("esw-pool.conf"))
}
pub fn panel_ini() -> Result<PathBuf> {
    Ok(config::conf_dir()?.join("esw.ini"))
}
pub fn panel_socket() -> Result<PathBuf> {
    Ok(config::run_dir()?.join("esw.sock"))
}
pub fn panel_log() -> Result<PathBuf> {
    Ok(config::log_dir()?.join("esw.log"))
}
fn panel_pid() -> Result<PathBuf> {
    Ok(config::run_dir()?.join("esw.pid"))
}

/// Where the panel pool listens.
///
/// A unix socket is preferred — no port to collide with, permissions enforced
/// by the filesystem. But `sockaddr_un.sun_path` holds only 104 bytes on macOS
/// and 108 on Linux, and a deep `$EMBER_HOME` blows past that, so we fall back
/// to loopback TCP rather than let the engine silently truncate the path.
#[derive(Debug, Clone)]
pub enum PoolAddr {
    Unix(PathBuf),
    Tcp(String),
}

/// Conservative bound: the shorter platform limit, with headroom.
const MAX_UNIX_SOCKET_PATH: usize = 100;

impl PoolAddr {
    fn listen_directive(&self) -> String {
        match self {
            Self::Unix(path) => path.display().to_string(),
            Self::Tcp(addr) => addr.clone(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Unix(path) => path.display().to_string(),
            Self::Tcp(addr) => format!("tcp://{addr}"),
        }
    }
}

/// Pick a loopback port the kernel confirms is free.
fn free_loopback_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("could not find a free loopback port for esw-engine")?;
    Ok(listener.local_addr()?.port())
}

fn choose_pool_addr() -> Result<PoolAddr> {
    let socket = panel_socket()?;
    if socket.as_os_str().len() <= MAX_UNIX_SOCKET_PATH {
        return Ok(PoolAddr::Unix(socket));
    }
    Ok(PoolAddr::Tcp(format!(
        "127.0.0.1:{}",
        free_loopback_port()?
    )))
}

/// `(os, arch)` slugs used by the download server.
fn platform_slug() -> Result<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        other => bail!("no prebuilt esw-engine for this platform: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => bail!("no prebuilt esw-engine for this architecture: {other}"),
    };
    Ok((os, arch))
}

/// `flavour` is the SAPI slug used by the download server: `fpm` or `cli`.
pub fn download_url(version: &str, flavour: &str) -> Result<String> {
    let (os, arch) = platform_slug()?;
    Ok(format!(
        "{DOWNLOAD_BASE}/php-{version}-{flavour}-{os}-{arch}.tar.gz"
    ))
}

/// Install both halves of the pinned build: the worker and the CLI.
pub fn install(version: &str, force: bool) -> Result<PathBuf> {
    let worker = fetch_binary(version, "fpm", "php-fpm", &esw_binary(version)?, force)?;
    fetch_binary(version, "cli", "php", &esw_cli_binary(version)?, force)?;
    Ok(worker)
}

/// Download one SAPI and extract the named binary out of its archive.
fn fetch_binary(
    version: &str,
    flavour: &str,
    entry_name: &str,
    binary: &PathBuf,
    force: bool,
) -> Result<PathBuf> {
    if binary.is_file() && !force {
        return Ok(binary.clone());
    }

    config::ensure_dirs()?;
    let url = download_url(version, flavour)?;
    println!("  fetching {url}");

    // The download host redirects to object storage and rejects requests that
    // arrive without a User-Agent, so identify ourselves explicitly.
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("ember/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(600))
        .build()?;
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("could not reach {url}"))?;

    if !response.status().is_success() {
        bail!(
            "download failed with HTTP {} — is esw-engine {version} ({flavour}) published for this platform?",
            response.status()
        );
    }

    let bytes = response.bytes().context("download interrupted")?;
    println!("  unpacking {:.1} MB", bytes.len() as f64 / 1_048_576.0);

    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes[..]));
    let mut archive = tar::Archive::new(decoder);

    // The tarball layout is not contractual, so pull the binary out wherever it
    // happens to sit rather than trusting a fixed path.
    if let Some(parent) = binary.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|n| n.to_str()) == Some(entry_name) {
            entry.unpack(binary)?;
            found = true;
            break;
        }
    }
    if !found {
        bail!("archive did not contain a {entry_name} binary");
    }

    make_executable(binary)?;
    Ok(binary.clone())
}

fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn running_as_root() -> bool {
    // SAFETY: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Write esw-engine's ini and pool config. Regenerated on every start so
/// the files on disk always match what Ember believes it configured.
pub fn write_configs(addr: &PoolAddr) -> Result<()> {
    config::ensure_dirs()?;

    let ini = panel_ini()?;
    std::fs::write(
        &ini,
        format!(
            "; Generated by ember — do not edit, changes are overwritten on start.\n\
             ; Applies ONLY to esw-engine, never to system PHP or customer site pools.\n\
             memory_limit = 256M\n\
             max_execution_time = 120\n\
             upload_max_filesize = 64M\n\
             post_max_size = 64M\n\
             expose_php = Off\n\
             display_errors = Off\n\
             log_errors = On\n\
             error_log = {}\n\
             date.timezone = UTC\n",
            panel_log()?.display()
        ),
    )
    .with_context(|| format!("could not write {}", ini.display()))?;

    // The engine refuses to run as root unless the pool names an unprivileged
    // user. Site pools will each get their own user; the panel pool gets one
    // only when Ember itself was started as root.
    let user_lines = if running_as_root() {
        let user = std::env::var("EMBER_ESW_USER").unwrap_or_else(|_| "nobody".to_string());
        if !crate::auth::system_user_exists(&user) {
            bail!(
                "esw-engine is configured to drop privileges to {user:?}, but that \
                 account does not exist — create it or set EMBER_ESW_USER"
            );
        }
        // The group name is not derivable from the user name: Debian pairs
        // `nobody` with `nogroup`, RHEL with `nobody`. Ask the user database.
        let group = std::env::var("EMBER_ESW_GROUP")
            .ok()
            .or_else(|| crate::auth::primary_group_of(&user))
            .unwrap_or_else(|| user.clone());
        format!("user = {user}\ngroup = {group}\n")
    } else {
        String::new()
    };

    let conf = panel_pool_conf()?;
    std::fs::write(
        &conf,
        format!(
            "; Generated by ember — do not edit, changes are overwritten on start.\n\
             [global]\n\
             pid = {pid}\n\
             error_log = {log}\n\
             daemonize = no\n\
             \n\
             [panel]\n\
             {user_lines}\
             listen = {listen}\n\
             listen.mode = 0660\n\
             pm = dynamic\n\
             pm.max_children = 10\n\
             pm.start_servers = 2\n\
             pm.min_spare_servers = 1\n\
             pm.max_spare_servers = 3\n\
             pm.max_requests = 500\n\
             catch_workers_output = yes\n\
             clear_env = no\n\
             php_admin_value[error_log] = {log}\n\
             php_admin_flag[log_errors] = on\n",
            pid = panel_pid()?.display(),
            log = panel_log()?.display(),
            listen = addr.listen_directive(),
        ),
    )
    .with_context(|| format!("could not write {}", conf.display()))?;

    // Placeholder front controller so the panel answers before Symfony lands.
    let index = config::panel_public_dir()?.join("index.php");
    if !index.exists() {
        std::fs::write(&index, include_str!("assets/index.php"))?;
    }

    Ok(())
}

/// A supervised esw-engine process.
pub struct EswProcess {
    child: Child,
    pub addr: PoolAddr,
}

impl EswProcess {
    /// Spawn the panel pool and wait for it to accept connections.
    pub async fn spawn(cfg: &Config) -> Result<Self> {
        let binary = esw_binary(&cfg.esw_version)?;
        if !binary.is_file() {
            bail!(
                "esw-engine {} is not installed yet — run `ember esw install`",
                cfg.esw_version
            );
        }

        let addr = choose_pool_addr()?;
        write_configs(&addr)?;

        // A stale socket from an unclean shutdown blocks the new bind.
        if let PoolAddr::Unix(path) = &addr {
            let _ = std::fs::remove_file(path);
        }

        let child = Command::new(&binary)
            .arg("--nodaemonize")
            .arg("--fpm-config")
            .arg(panel_pool_conf()?)
            .arg("-c")
            .arg(panel_ini()?)
            .arg("-p")
            .arg(config::ember_dir()?)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not start {}", binary.display()))?;

        let mut process = Self { child, addr };
        process.wait_until_ready().await?;
        Ok(process)
    }

    /// Can we actually open a connection to the pool right now?
    async fn probe(&self) -> bool {
        match &self.addr {
            PoolAddr::Unix(path) => tokio::net::UnixStream::connect(path).await.is_ok(),
            PoolAddr::Tcp(addr) => tokio::net::TcpStream::connect(addr).await.is_ok(),
        }
    }

    async fn wait_until_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "esw-engine exited immediately ({status}); see {}",
                    panel_log()?.display()
                );
            }
            if self.probe().await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!(
            "esw-engine did not start listening on {} within 15s; see {}",
            self.addr.describe(),
            panel_log()?.display()
        )
    }

    /// Ask the engine to finish in-flight requests, then stop.
    pub async fn shutdown(mut self) {
        if let Some(pid) = self.child.id() {
            // SAFETY: signalling a child we spawned; failure is ignorable.
            unsafe { libc::kill(pid as i32, libc::SIGQUIT) };
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.start_kill();
        if let PoolAddr::Unix(path) = &self.addr {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Which esw-engine builds are provisioned.
pub fn installed_versions() -> Result<Vec<String>> {
    let dir = config::esw_dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut versions: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|v| is_installed(v))
        .collect();
    versions.sort();
    Ok(versions)
}

/// Append a line to the service log without holding the file open.
pub fn log_line(message: &str) {
    if let Ok(path) = config::service_log_file()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(file, "{message}");
    }
}
