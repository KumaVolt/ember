//! Process lifecycle: detaching the service, tracking it, stopping it.
//!
//! The running service records itself in `~/.ember/ember.json` only *after* it
//! has successfully bound its port and started esw-engine — so the presence of
//! that
//! file means "actually serving", not "was asked to serve".

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{self, Config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub pid: i32,
    pub host: String,
    pub port: u16,
    pub esw_version: String,
    pub mode: String,
    pub started_at: u64,
}

impl State {
    pub fn uptime_secs(&self) -> u64 {
        now_secs().saturating_sub(self.started_at)
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn write_state(state: &State) -> Result<()> {
    config::ensure_dirs()?;
    let path = config::state_file()?;
    std::fs::write(&path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

pub fn clear_state() {
    if let Ok(path) = config::state_file() {
        let _ = std::fs::remove_file(path);
    }
}

fn read_state() -> Option<State> {
    let path = config::state_file().ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Does this pid exist? `EPERM` counts as alive — the process is there, we
/// simply are not allowed to signal it.
pub fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 performs error checking only, it delivers nothing.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Current service state, with stale records cleaned up as a side effect.
pub fn status() -> Option<State> {
    let state = read_state()?;
    if process_alive(state.pid) {
        Some(state)
    } else {
        clear_state();
        None
    }
}

/// Fail early and clearly rather than letting the detached child die silently.
fn preflight(cfg: &Config) -> Result<()> {
    if let Some(state) = status() {
        bail!(
            "ember is already running (pid {}) on {}:{}",
            state.pid,
            state.host,
            state.port
        );
    }
    if !crate::esw::is_installed(&cfg.esw_version) {
        bail!(
            "esw-engine {} is not installed yet — run `ember esw install` first",
            cfg.esw_version
        );
    }
    std::net::TcpListener::bind(cfg.addr())
        .with_context(|| format!("cannot bind {} — is something else using it?", cfg.addr()))?;
    Ok(())
}

/// Launch the service in the background and wait for it to report ready.
pub fn start_detached(cfg: &Config) -> Result<State> {
    use std::os::unix::process::CommandExt;

    preflight(cfg)?;
    config::ensure_dirs()?;

    let log_path = config::service_log_file()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("could not open {}", log_path.display()))?;

    let exe = std::env::current_exe().context("could not locate the ember binary")?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("serve")
        .arg("--host")
        .arg(&cfg.host)
        .arg("--port")
        .arg(cfg.port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);

    // Detach from this terminal so the service outlives the shell that spawned it.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command
        .spawn()
        .context("could not spawn the ember service")?;
    let child_pid = child.id() as i32;

    // The child writes its state file once it is genuinely serving.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(state) = read_state()
            && state.pid == child_pid
        {
            return Ok(state);
        }
        if !process_alive(child_pid) {
            bail!(
                "the service exited during startup — last log lines:\n{}",
                tail_log(20)
            );
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    // SAFETY: cleaning up the child we just spawned.
    unsafe { libc::kill(child_pid, libc::SIGTERM) };
    bail!(
        "the service did not become ready within 30s — last log lines:\n{}",
        tail_log(20)
    )
}

/// Stop a running service. Returns false if nothing was running.
pub fn stop() -> Result<bool> {
    let Some(state) = status() else {
        return Ok(false);
    };

    // SAFETY: SIGTERM to a pid we recorded; the return value is checked below.
    unsafe { libc::kill(state.pid, libc::SIGTERM) };

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if !process_alive(state.pid) {
            clear_state();
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    eprintln!("service did not stop gracefully within 15s; sending SIGKILL");
    // SAFETY: same pid, forceful termination after the grace period.
    unsafe { libc::kill(state.pid, libc::SIGKILL) };
    std::thread::sleep(Duration::from_millis(300));
    clear_state();
    Ok(true)
}

/// Last `n` lines of the service log, for reporting startup failures.
pub fn tail_log(n: usize) -> String {
    let Ok(path) = config::service_log_file() else {
        return "(no log)".into();
    };
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return format!("(no log at {})", path.display());
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    let tail = lines[start..].join("\n");
    if tail.trim().is_empty() {
        "(log is empty)".into()
    } else {
        tail
    }
}

/// `1h 04m 12s` style duration for status output.
pub fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}
