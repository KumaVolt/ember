//! The machine itself: how it is doing, and turning it off.
//!
//! Statistics are read straight from `/proc` and `statvfs` rather than shelled
//! out to `top` or `df`, so there is nothing to parse loosely and nothing to
//! install. On anything that is not Linux the fields simply come back empty
//! rather than guessed at.
//!
//! Reboot and shutdown are here too. They are the most destructive things the
//! panel can do — every site on the box goes down, and a shutdown may not come
//! back without physical or console access — so both are gated on host mode and
//! on the caller naming the machine.

use anyhow::{Result, bail};
use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub hostname: String,
    pub kernel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<[f64; 3]>,
    pub cpus: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_free: Option<u64>,
    pub disks: Vec<Disk>,
}

#[derive(Debug, Serialize)]
pub struct Disk {
    pub path: String,
    pub total: u64,
    pub available: u64,
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "this server".to_string())
}

fn kernel() -> String {
    std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
                .into()
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

/// `/proc/meminfo` values are in kB; return bytes so callers need no unit lore.
fn meminfo() -> std::collections::HashMap<String, u64> {
    let mut values = std::collections::HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return values;
    };
    for line in text.lines() {
        if let Some((key, rest)) = line.split_once(':')
            && let Some(kb) = rest.split_whitespace().next()
            && let Ok(kb) = kb.parse::<u64>()
        {
            values.insert(key.to_string(), kb * 1024);
        }
    }
    values
}

/// Free space on a mount point, via `statvfs`.
fn disk_usage(path: &str) -> Option<Disk> {
    let c_path = std::ffi::CString::new(path).ok()?;
    // SAFETY: statvfs writes into a zeroed struct we own; the path is a valid
    // NUL-terminated string and the return code is checked.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };

    let block = stat.f_frsize as u64;
    Some(Disk {
        path: path.to_string(),
        total: stat.f_blocks as u64 * block,
        // f_bavail, not f_bfree: the reserved blocks are not usable by anyone
        // who would be filling this disk up.
        available: stat.f_bavail as u64 * block,
    })
}

pub fn stats() -> Stats {
    let memory = meminfo();

    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
        .map(|seconds| seconds as u64);

    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| {
            let mut parts = text.split_whitespace();
            Some([
                parts.next()?.parse().ok()?,
                parts.next()?.parse().ok()?,
                parts.next()?.parse().ok()?,
            ])
        });

    // The paths that matter for a control panel: the machine, the sites, and
    // the panel's own state.
    let mut disks = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in ["/", "/var/www", "/var/lib/ember"] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        if let Some(disk) = disk_usage(path)
            && seen.insert((disk.total, disk.available))
        {
            disks.push(disk);
        }
    }

    Stats {
        hostname: hostname(),
        kernel: kernel(),
        uptime_seconds: uptime,
        load,
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        memory_total: memory.get("MemTotal").copied(),
        memory_available: memory.get("MemAvailable").copied(),
        swap_total: memory.get("SwapTotal").copied(),
        swap_free: memory.get("SwapFree").copied(),
        disks,
    }
}

// ---------------------------------------------------------------------------
// Power
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum PowerAction {
    Restart,
    Shutdown,
}

impl PowerAction {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "restart" | "reboot" => Ok(Self::Restart),
            "shutdown" | "poweroff" => Ok(Self::Shutdown),
            other => bail!("unknown power action {other:?}"),
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Shutdown => "shut down",
        }
    }
}

/// Restart or shut down the machine.
///
/// `confirm` must be the hostname. Naming the machine is the point: an operator
/// with several panels open should not be able to take down the wrong one by
/// clicking in the wrong tab.
pub fn power(cfg: &Config, action: PowerAction, confirm: &str) -> Result<String> {
    cfg.require_host_mode(&format!("{} this machine", action.describe()))?;

    let host = hostname();
    if confirm != host {
        bail!(
            "confirmation required: type the hostname ({host}) to {} this machine",
            action.describe()
        );
    }

    let (unit_arg, fallback) = match action {
        PowerAction::Restart => ("reboot", vec!["-r", "now"]),
        PowerAction::Shutdown => ("poweroff", vec!["-h", "now"]),
    };

    // systemd where there is one; `shutdown` otherwise. Scheduled a moment out
    // so this response reaches the browser before the machine goes.
    let ran = if std::path::Path::new("/run/systemd/system").is_dir() {
        std::process::Command::new("systemd-run")
            .args([
                "--on-active=5s",
                "--timer-property=AccuracySec=1s",
                "systemctl",
                unit_arg,
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        false
    };

    if !ran {
        let ok = std::process::Command::new("shutdown")
            .args(&fallback)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            bail!(
                "could not {} the machine — neither systemd-run nor shutdown worked",
                action.describe()
            );
        }
    }

    crate::esw::log_line(&format!(
        "[{}] {} requested for {host}",
        crate::daemon::now_secs(),
        action.describe()
    ));

    Ok(match action {
        PowerAction::Restart => format!("{host} is restarting; the panel will be back shortly"),
        PowerAction::Shutdown => format!(
            "{host} is shutting down. It will not come back without console or \
             provider access."
        ),
    })
}

/// Extra PHP builds available to install alongside the one in use.
///
/// The panel runs on a pinned engine; customer sites will want other versions.
/// Offered rather than discovered so the list stays to builds known to exist
/// for the platform.
/// PHP builds offered, with the date each stops receiving security fixes.
///
/// The date is what matters, not a support tier: "security support" tells an
/// operator nothing about whether that is still true today.
pub const AVAILABLE_ENGINES: &[(&str, i64, &str)] = &[
    ("8.5.8", 1_924_905_600, "2030-12-31"),
    ("8.4.23", 1_861_747_200, "2028-12-31"),
    ("8.3.31", 1_830_211_200, "2027-12-31"),
    ("8.2.30", 1_798_675_200, "2026-12-31"),
    ("8.1.35", 1_767_139_200, "2025-12-31"),
];

/// Is this PHP version past its security-support date?
pub fn engine_end_of_life(version: &str) -> Option<(bool, &'static str)> {
    let now = crate::daemon::now_secs() as i64;
    AVAILABLE_ENGINES
        .iter()
        .find(|(candidate, _, _)| *candidate == version)
        .map(|(_, eol_at, date)| (now >= *eol_at, *date))
}

pub fn engine_versions() -> Result<Vec<serde_json::Value>> {
    let installed = crate::esw::installed_versions()?;
    let current = Config::resolve(None, None)?.esw_version;
    let now = crate::daemon::now_secs() as i64;

    Ok(AVAILABLE_ENGINES
        .iter()
        .map(|(version, eol_at, eol_date)| {
            serde_json::json!({
                "version": version,
                "installed": installed.iter().any(|v| v == version),
                "in_use": *version == current,
                "end_of_life": now >= *eol_at,
                "end_of_life_date": eol_date,
            })
        })
        .collect())
}
