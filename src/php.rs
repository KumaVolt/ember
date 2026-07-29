//! Per-domain PHP: settings, pools, and the masters that run them.
//!
//! Each domain gets its own FPM pool, running as that domain's customer. That
//! is what makes the settings here safe to expose: a customer raising their own
//! `memory_limit` or listing `disable_functions` affects their pool and nobody
//! else's, and the process executing their code already has only their
//! privileges.
//!
//! One master process per PHP version, each including the pool files for the
//! domains using it — the arrangement every panel of this kind converges on,
//! because a master per domain would multiply idle processes for nothing.
//!
//! Masters daemonise and are tracked by pid file rather than being held as
//! child processes. Restarting Ember then does not take every customer site
//! down with it, and a settings change is a `SIGUSR2` reload rather than a
//! restart, so in-flight requests finish.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{config::Config, esw, store::Domain};

/// Everything the panel exposes for a domain's PHP.
///
/// Defaults are PHP's own where they are sensible and a shared-hosting value
/// where they are not — `max_children` especially, since PHP's default would
/// let one busy site exhaust the machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PhpSettings {
    // --- performance: the FPM pool ---
    /// `ondemand`, `dynamic` or `static`.
    pub pm: String,
    pub pm_max_children: u32,
    pub pm_start_servers: u32,
    pub pm_min_spare_servers: u32,
    pub pm_max_spare_servers: u32,
    pub pm_max_requests: u32,
    pub pm_process_idle_timeout: u32,

    // --- common settings ---
    pub memory_limit: String,
    pub max_execution_time: u32,
    pub max_input_time: i32,
    pub max_input_vars: u32,
    pub post_max_size: String,
    pub upload_max_filesize: String,
    pub file_uploads: bool,
    pub display_errors: bool,
    pub log_errors: bool,
    pub error_reporting: String,
    pub allow_url_fopen: bool,
    pub short_open_tag: bool,
    /// Empty means unrestricted; otherwise a colon-separated list.
    pub open_basedir: String,
    pub disable_functions: String,
    pub session_save_path: String,

    // --- opcache ---
    pub opcache_enable: bool,
    pub opcache_memory_consumption: u32,
    pub opcache_max_accelerated_files: u32,
    pub opcache_revalidate_freq: u32,
    pub opcache_validate_timestamps: bool,

    /// Anything not modelled above, appended verbatim.
    pub additional_directives: String,
}

impl Default for PhpSettings {
    fn default() -> Self {
        Self {
            pm: "ondemand".into(),
            // Modest on purpose: a shared machine runs many pools, and idle
            // workers cost memory whether or not the site gets traffic.
            pm_max_children: 10,
            pm_start_servers: 2,
            pm_min_spare_servers: 1,
            pm_max_spare_servers: 3,
            pm_max_requests: 500,
            pm_process_idle_timeout: 10,

            memory_limit: "128M".into(),
            max_execution_time: 30,
            // -1 means "use max_execution_time", PHP's own default.
            max_input_time: -1,
            max_input_vars: 1000,
            post_max_size: "8M".into(),
            upload_max_filesize: "2M".into(),
            file_uploads: true,
            // Off by default: a stack trace on a live site is an information
            // leak, and the log has the same content.
            display_errors: false,
            log_errors: true,
            error_reporting: "E_ALL & ~E_DEPRECATED & ~E_STRICT".into(),
            allow_url_fopen: true,
            short_open_tag: false,
            // Filled in per domain at generation time.
            open_basedir: String::new(),
            disable_functions: String::new(),
            session_save_path: String::new(),

            opcache_enable: true,
            opcache_memory_consumption: 128,
            opcache_max_accelerated_files: 10_000,
            opcache_revalidate_freq: 2,
            opcache_validate_timestamps: true,

            additional_directives: String::new(),
        }
    }
}

/// Functions worth offering as a one-click hardening set.
///
/// Not applied by default: plenty of legitimate applications call `exec`, and a
/// panel that silently breaks a customer's site is worse than one that offers
/// the option and explains it.
pub const SUGGESTED_DISABLED: &str =
    "exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source";

impl PhpSettings {
    /// Reject values that would produce a config php-fpm refuses to load.
    ///
    /// A rejected form is recoverable; a pool that will not start takes the
    /// site down until someone reads a log.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.pm.as_str(), "ondemand" | "dynamic" | "static") {
            bail!("process manager must be ondemand, dynamic or static");
        }
        if self.pm_max_children == 0 {
            bail!("max children must be at least 1");
        }
        if self.pm == "dynamic" {
            if self.pm_start_servers < self.pm_min_spare_servers
                || self.pm_start_servers > self.pm_max_spare_servers
            {
                bail!("start servers must sit between min and max spare servers");
            }
            if self.pm_max_spare_servers > self.pm_max_children {
                bail!("max spare servers cannot exceed max children");
            }
        }

        for (label, value) in [
            ("memory limit", &self.memory_limit),
            ("post max size", &self.post_max_size),
            ("upload max filesize", &self.upload_max_filesize),
        ] {
            check_size(label, value)?;
        }

        // These land in an ini file, so a newline would let one value inject
        // another directive.
        for (label, value) in [
            ("error reporting", &self.error_reporting),
            ("disable functions", &self.disable_functions),
            ("open basedir", &self.open_basedir),
            ("session save path", &self.session_save_path),
        ] {
            if value.contains('\n') || value.contains('\r') {
                bail!("{label} cannot contain line breaks");
            }
        }

        Ok(())
    }
}

/// `128M`, `1G`, `-1`, or a plain byte count.
fn check_size(label: &str, value: &str) -> Result<()> {
    let text = value.trim();
    if text == "-1" {
        return Ok(());
    }
    let (digits, suffix) = match text.chars().last() {
        Some(last) if last.is_ascii_alphabetic() => (&text[..text.len() - 1], Some(last)),
        _ => (text, None),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("{label} must be a number, optionally followed by K, M or G");
    }
    if let Some(suffix) = suffix
        && !matches!(suffix.to_ascii_uppercase(), 'K' | 'M' | 'G')
    {
        bail!("{label} suffix must be K, M or G");
    }
    Ok(())
}

fn on_off(value: bool) -> &'static str {
    if value { "On" } else { "Off" }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

pub fn pools_dir(version: &str) -> Result<PathBuf> {
    Ok(crate::config::conf_dir()?.join("pools").join(version))
}

pub fn pool_conf_path(version: &str, domain: &str) -> Result<PathBuf> {
    Ok(pools_dir(version)?.join(format!("{domain}.conf")))
}

pub fn master_conf_path(version: &str) -> Result<PathBuf> {
    Ok(crate::config::conf_dir()?.join(format!("fpm-{version}.conf")))
}

fn master_pid_path(version: &str) -> Result<PathBuf> {
    Ok(crate::config::run_dir()?.join(format!("fpm-{version}.pid")))
}

/// The socket a domain's pool listens on.
pub fn socket_path(domain: &str) -> Result<PathBuf> {
    Ok(crate::config::run_dir()?
        .join("pools")
        .join(format!("{domain}.sock")))
}

/// The group the web server runs as, so it can reach the pool socket.
///
/// The socket is owned by the customer and group-readable by the web server;
/// without the right group nginx gets a permission error on every request.
fn web_server_group() -> &'static str {
    for (group, marker) in [
        ("www-data", "/etc/nginx"),
        ("nginx", "/etc/nginx/nginx.conf"),
        ("apache", "/etc/httpd"),
    ] {
        if std::path::Path::new(marker).exists() && group_exists(group) {
            return group;
        }
    }
    if group_exists("www-data") {
        "www-data"
    } else {
        "nobody"
    }
}

fn group_exists(name: &str) -> bool {
    let Ok(cname) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: getgrnam takes a NUL-terminated string and returns a pointer we
    // only test for null.
    unsafe { !libc::getgrnam(cname.as_ptr()).is_null() }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// The pool file for one domain.
pub fn pool_conf(domain: &Domain, settings: &PhpSettings) -> Result<String> {
    let owner = domain
        .customer_username
        .clone()
        .context("domain has no owner")?;
    let socket = socket_path(&domain.name)?;
    let logs = format!("{}/logs", domain.root);

    // open_basedir defaults to the domain's own tree plus its temp directory.
    // Left unset, a script could read every other site on the machine.
    let open_basedir = if settings.open_basedir.trim().is_empty() {
        format!("{}/:{}/tmp/", domain.root, domain.root)
    } else {
        settings.open_basedir.trim().to_string()
    };

    let session_path = if settings.session_save_path.trim().is_empty() {
        format!("{}/tmp", domain.root)
    } else {
        settings.session_save_path.trim().to_string()
    };

    let mut conf = format!(
        "; Generated by ember for {name}. Do not edit — regenerated on change.\n\
         [{name}]\n\
         user = {owner}\n\
         group = {owner}\n\
         \n\
         listen = {socket}\n\
         ; Owned by the customer, readable by the web server, nobody else.\n\
         listen.owner = {owner}\n\
         listen.group = {web_group}\n\
         listen.mode = 0660\n\
         \n\
         pm = {pm}\n\
         pm.max_children = {max_children}\n",
        name = domain.name,
        socket = socket.display(),
        web_group = web_server_group(),
        pm = settings.pm,
        max_children = settings.pm_max_children,
    );

    // These directives are only legal for the process managers that use them;
    // php-fpm refuses to start if they appear for the wrong one.
    match settings.pm.as_str() {
        "dynamic" => {
            conf.push_str(&format!(
                "pm.start_servers = {}\n\
                 pm.min_spare_servers = {}\n\
                 pm.max_spare_servers = {}\n",
                settings.pm_start_servers,
                settings.pm_min_spare_servers,
                settings.pm_max_spare_servers,
            ));
        }
        "ondemand" => {
            conf.push_str(&format!(
                "pm.process_idle_timeout = {}s\n",
                settings.pm_process_idle_timeout
            ));
        }
        _ => {}
    }

    conf.push_str(&format!(
        "pm.max_requests = {max_requests}\n\
         \n\
         catch_workers_output = yes\n\
         php_admin_value[error_log] = {logs}/php.log\n\
         php_admin_flag[log_errors] = {log_errors}\n\
         \n\
         ; php_admin_* cannot be overridden by the application; php_value can.\n\
         php_admin_value[open_basedir] = {open_basedir}\n\
         php_admin_value[disable_functions] = {disable_functions}\n\
         php_admin_value[upload_tmp_dir] = {root}/tmp\n\
         php_admin_value[session.save_path] = {session_path}\n\
         \n\
         php_value[memory_limit] = {memory_limit}\n\
         php_value[max_execution_time] = {max_execution_time}\n\
         php_value[max_input_time] = {max_input_time}\n\
         php_value[max_input_vars] = {max_input_vars}\n\
         php_value[post_max_size] = {post_max_size}\n\
         php_value[upload_max_filesize] = {upload_max_filesize}\n\
         php_value[error_reporting] = {error_reporting}\n\
         php_flag[file_uploads] = {file_uploads}\n\
         php_flag[display_errors] = {display_errors}\n\
         php_flag[allow_url_fopen] = {allow_url_fopen}\n\
         php_flag[short_open_tag] = {short_open_tag}\n\
         \n\
         php_value[opcache.enable] = {opcache_enable}\n\
         php_value[opcache.memory_consumption] = {opcache_memory}\n\
         php_value[opcache.max_accelerated_files] = {opcache_files}\n\
         php_value[opcache.revalidate_freq] = {opcache_revalidate}\n\
         php_value[opcache.validate_timestamps] = {opcache_timestamps}\n",
        max_requests = settings.pm_max_requests,
        logs = logs,
        log_errors = on_off(settings.log_errors),
        open_basedir = open_basedir,
        disable_functions = settings.disable_functions.trim(),
        root = domain.root,
        session_path = session_path,
        memory_limit = settings.memory_limit.trim(),
        max_execution_time = settings.max_execution_time,
        max_input_time = settings.max_input_time,
        max_input_vars = settings.max_input_vars,
        post_max_size = settings.post_max_size.trim(),
        upload_max_filesize = settings.upload_max_filesize.trim(),
        error_reporting = settings.error_reporting.trim(),
        file_uploads = on_off(settings.file_uploads),
        display_errors = on_off(settings.display_errors),
        allow_url_fopen = on_off(settings.allow_url_fopen),
        short_open_tag = on_off(settings.short_open_tag),
        opcache_enable = u8::from(settings.opcache_enable),
        opcache_memory = settings.opcache_memory_consumption,
        opcache_files = settings.opcache_max_accelerated_files,
        opcache_revalidate = settings.opcache_revalidate_freq,
        opcache_timestamps = u8::from(settings.opcache_validate_timestamps),
    ));

    if !settings.additional_directives.trim().is_empty() {
        conf.push_str("\n; Additional directives, set by the operator.\n");
        conf.push_str(settings.additional_directives.trim());
        conf.push('\n');
    }

    Ok(conf)
}

/// The master config for one PHP version, including every pool that uses it.
fn master_conf(version: &str) -> Result<String> {
    Ok(format!(
        "; Generated by ember. Do not edit — regenerated on change.\n\
         [global]\n\
         pid = {pid}\n\
         error_log = {log}\n\
         daemonize = yes\n\
         ; Each pool file is one domain.\n\
         include = {pools}/*.conf\n",
        pid = master_pid_path(version)?.display(),
        log = crate::config::log_dir()?
            .join(format!("fpm-{version}.log"))
            .display(),
        pools = pools_dir(version)?.display(),
    ))
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

/// Which engine version a domain runs on.
pub fn version_for(domain: &Domain, cfg: &Config) -> String {
    domain
        .php_version
        .clone()
        .unwrap_or_else(|| cfg.esw_version.clone())
}

/// Write a domain's pool and bring its master up to date.
pub fn apply(cfg: &Config, domain: &Domain, settings: &PhpSettings) -> Result<String> {
    cfg.require_host_mode(&format!("configure PHP for {}", domain.name))?;
    settings.validate()?;

    let version = version_for(domain, cfg);
    if !esw::is_installed(&version) {
        bail!("PHP {version} is not installed — install it from Settings → Services");
    }

    let dir = pools_dir(&version)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    std::fs::create_dir_all(socket_path(&domain.name)?.parent().unwrap())?;

    // A domain that changed version leaves a pool behind under the old one,
    // which would keep serving with the previous settings.
    for other in esw::installed_versions()? {
        if other != version {
            let _ = std::fs::remove_file(pool_conf_path(&other, &domain.name)?);
        }
    }

    let path = pool_conf_path(&version, &domain.name)?;
    std::fs::write(&path, pool_conf(domain, settings)?)
        .with_context(|| format!("could not write {}", path.display()))?;

    reload_master(&version)
}

/// Remove a domain's pool and reload.
pub fn remove(cfg: &Config, domain: &Domain) -> Result<()> {
    cfg.require_host_mode(&format!("remove the PHP pool for {}", domain.name))?;

    for version in esw::installed_versions()? {
        let path = pool_conf_path(&version, &domain.name)?;
        if path.exists() {
            let _ = std::fs::remove_file(&path);
            let _ = reload_master(&version);
        }
    }
    let _ = std::fs::remove_file(socket_path(&domain.name)?);
    Ok(())
}

fn master_pid(version: &str) -> Option<i32> {
    let pid = std::fs::read_to_string(master_pid_path(version).ok()?)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()?;
    crate::daemon::process_alive(pid).then_some(pid)
}

/// Start the master for a version, or tell a running one to re-read its pools.
///
/// `SIGUSR2` is a graceful reload: workers finish what they are doing and the
/// new configuration applies to the next request, so a settings change does not
/// drop anyone's traffic.
pub fn reload_master(version: &str) -> Result<String> {
    let binary = esw::esw_binary(version)?;
    if !binary.is_file() {
        bail!("PHP {version} is not installed");
    }

    std::fs::create_dir_all(pools_dir(version)?)?;
    let conf = master_conf_path(version)?;
    std::fs::write(&conf, master_conf(version)?)?;

    if let Some(pid) = master_pid(version) {
        // SAFETY: signalling a pid read from our own pid file, checked alive.
        unsafe { libc::kill(pid, libc::SIGUSR2) };
        return Ok(format!("PHP {version} reloaded"));
    }

    // No pools means no reason to run a master at all.
    let has_pools = std::fs::read_dir(pools_dir(version)?)
        .map(|entries| entries.flatten().any(|e| e.path().extension().is_some()))
        .unwrap_or(false);
    if !has_pools {
        return Ok(format!("PHP {version}: no sites, master not started"));
    }

    let output = std::process::Command::new(&binary)
        .arg("--fpm-config")
        .arg(&conf)
        .arg("-c")
        .arg(esw::panel_ini()?)
        .output()
        .with_context(|| format!("could not start the PHP {version} master"))?;

    if !output.status.success() {
        bail!(
            "PHP {version} master failed to start: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(format!("PHP {version} started"))
}

/// Bring every master into line with the pools on disk.
///
/// Called at boot: masters daemonise and outlive Ember, so this reconciles
/// rather than assuming anything about what is already running.
pub fn reload_all(cfg: &Config) -> Vec<String> {
    if cfg.mode != crate::config::Mode::Host {
        return vec!["isolated mode: site pools not started".into()];
    }

    esw::installed_versions()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|version| match reload_master(&version) {
            Ok(message) if message.contains("no sites") => None,
            Ok(message) => Some(message),
            Err(err) => Some(format!("PHP {version}: {err}")),
        })
        .collect()
}
