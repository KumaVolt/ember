//! Optional components: what is installed, what could be, and what is running.
//!
//! A control panel is only as useful as the things it can turn on. This is the
//! catalogue behind Settings — extra PHP versions, database servers, web
//! servers, caches — with enough detection to report the truth rather than a
//! guess, and installation through the distribution's own package manager.
//!
//! Two deliberate limits:
//!
//! * Installing is gated on host mode, like every other change to the machine.
//! * Nothing is *removed* here. Uninstalling a database server out from under a
//!   customer's site is not something a panel should offer behind one click.

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::config::Config;

/// A component the operator can install.
#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub installed: bool,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// False when Ember has no way to install this here.
    pub installable: bool,
    /// Why not, when it cannot. "Unavailable" on its own explains nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// How to find, install and check one component.
struct Definition {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    description: &'static str,
    /// Any of these existing means it is installed.
    binaries: &'static [&'static str],
    /// Packages per manager: (apt, dnf/yum).
    packages: (&'static [&'static str], &'static [&'static str]),
    /// The unit whose state answers "is it running".
    unit: Option<&'static str>,
    /// Arguments that make the binary print its version.
    version_arg: Option<&'static str>,
}

const CATALOGUE: &[Definition] = &[
    Definition {
        id: "mariadb",
        name: "MariaDB",
        category: "Databases",
        description: "The default database server. Each customer gets a database and a \
                      user that can reach only that database.",
        binaries: &["/usr/sbin/mariadbd", "/usr/sbin/mysqld"],
        packages: (&["mariadb-server"], &["mariadb-server"]),
        unit: Some("mariadb"),
        version_arg: Some("--version"),
    },
    Definition {
        id: "postgresql",
        name: "PostgreSQL",
        category: "Databases",
        description: "An alternative database server.",
        binaries: &["/usr/lib/postgresql", "/usr/bin/postgres", "/usr/pgsql"],
        packages: (&["postgresql"], &["postgresql-server"]),
        unit: Some("postgresql"),
        version_arg: None,
    },
    Definition {
        id: "redis",
        name: "Redis",
        category: "Databases",
        description: "In-memory cache and key-value store.",
        binaries: &["/usr/bin/redis-server"],
        packages: (&["redis-server"], &["redis"]),
        unit: Some("redis-server"),
        version_arg: Some("--version"),
    },
    Definition {
        id: "nodejs",
        name: "Node.js",
        category: "Runtimes",
        description: "JavaScript runtime and npm. Needed by most modern PHP sites for \
                      their asset build — Laravel Mix, Vite, Tailwind and the like.",
        binaries: &["/usr/bin/node", "/usr/local/bin/node"],
        packages: (&["nodejs", "npm"], &["nodejs", "npm"]),
        // Not a service: nothing runs in the background after installing.
        unit: None,
        version_arg: Some("--version"),
    },
    Definition {
        id: "nginx",
        name: "nginx",
        category: "Web servers",
        description: "Serves customer domains. Ember writes a vhost per domain; \
                      the panel itself is served by Ember and does not use this.",
        binaries: &["/usr/sbin/nginx"],
        packages: (&["nginx"], &["nginx"]),
        unit: Some("nginx"),
        version_arg: Some("-v"),
    },
    Definition {
        id: "apache",
        name: "Apache",
        category: "Web servers",
        description: "Alternative for customer domains, for sites that need .htaccess.",
        binaries: &["/usr/sbin/apache2", "/usr/sbin/httpd"],
        packages: (&["apache2"], &["httpd"]),
        unit: Some("apache2"),
        version_arg: Some("-v"),
    },
    Definition {
        id: "certbot",
        name: "certbot",
        category: "Certificates",
        description: "Obtains and renews Let's Encrypt certificates.",
        binaries: &["/usr/bin/certbot", "/snap/bin/certbot"],
        packages: (&["certbot"], &["certbot"]),
        unit: None,
        version_arg: Some("--version"),
    },
];

/// Serialises package operations.
///
/// dpkg takes a machine-wide lock, so two installs at once means the second
/// fails with "unable to acquire the dpkg frontend lock". Queueing here makes a
/// second request wait its turn instead of erroring — the operator asked for
/// two things, not for one of them to fail.
static PACKAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How long apt itself waits for a lock held by something else.
///
/// A freshly booted cloud server is often running unattended-upgrades, which
/// holds the lock for minutes. Waiting is almost always right; failing is
/// almost always premature.
const DPKG_LOCK_WAIT: &str = "-oDPkg::Lock::Timeout=600";

fn package_manager() -> Option<&'static str> {
    for (manager, path) in [
        ("apt", "/usr/bin/apt-get"),
        ("dnf", "/usr/bin/dnf"),
        ("yum", "/usr/bin/yum"),
    ] {
        if std::path::Path::new(path).is_file() {
            return Some(manager);
        }
    }
    None
}

fn is_installed(definition: &Definition) -> bool {
    definition
        .binaries
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

/// Is the component actually running?
///
/// systemd is asked first where it exists, but it is not the only way a service
/// runs — in a container ember starts the database itself, and reporting
/// "stopped" for a server that is happily serving is worse than not reporting
/// at all. So a process check backs it up.
fn is_running(definition: &Definition) -> bool {
    if let Some(unit) = definition.unit
        && std::path::Path::new("/run/systemd/system").is_dir()
        && std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    {
        return true;
    }

    // Fall back to looking for the process itself, by the binary's own name.
    definition.binaries.iter().any(|path| {
        let Some(name) = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
        else {
            return false;
        };
        std::process::Command::new("pgrep")
            .args(["-x", name])
            .stdout(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}

fn version_of(definition: &Definition) -> Option<String> {
    let arg = definition.version_arg?;
    let binary = definition
        .binaries
        .iter()
        .find(|path| std::path::Path::new(path).is_file())?;

    let output = std::process::Command::new(binary).arg(arg).output().ok()?;
    // Some print to stderr, so take whichever produced something.
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    text.lines()
        .next()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

/// Everything in the catalogue, with its current state.
pub fn list() -> Vec<Service> {
    let manager = package_manager();

    CATALOGUE
        .iter()
        .map(|definition| {
            let installed = is_installed(definition);
            let packages = match manager {
                Some("apt") => definition.packages.0,
                Some("dnf") | Some("yum") => definition.packages.1,
                _ => &[],
            };

            Service {
                id: definition.id.to_string(),
                name: definition.name.to_string(),
                category: definition.category.to_string(),
                description: definition.description.to_string(),
                installed,
                running: installed && is_running(definition),
                version: if installed {
                    version_of(definition)
                } else {
                    None
                },
                installable: !packages.is_empty(),
                unavailable_reason: if packages.is_empty() {
                    Some(match manager {
                        None => format!(
                            "no supported package manager on this machine ({}), so ember \
                             cannot install anything here — this works on a Linux server",
                            std::env::consts::OS
                        ),
                        Some(manager) => {
                            format!("ember has no {manager} package for {}", definition.name)
                        }
                    })
                } else {
                    None
                },
            }
        })
        .collect()
}

/// Install one component through the distribution's package manager.
pub fn install(cfg: &Config, id: &str) -> Result<String> {
    cfg.require_host_mode(&format!("install {id}"))?;

    let definition = CATALOGUE
        .iter()
        .find(|d| d.id == id)
        .with_context(|| format!("unknown service {id:?}"))?;

    if is_installed(definition) {
        return Ok(format!("{} is already installed", definition.name));
    }

    let manager = package_manager().context("no supported package manager on this machine")?;
    let packages = match manager {
        "apt" => definition.packages.0,
        _ => definition.packages.1,
    };
    if packages.is_empty() {
        bail!(
            "ember has no packages for {} on this platform",
            definition.name
        );
    }

    // Held for the whole operation, so a second install waits rather than
    // colliding on dpkg's lock. Poisoning only means a previous install
    // panicked; the lock is still meaningful, so it is taken either way.
    let _queued = PACKAGE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let output = match manager {
        "apt" => {
            let mut command = std::process::Command::new("apt-get");
            command
                .env("DEBIAN_FRONTEND", "noninteractive")
                .arg(DPKG_LOCK_WAIT)
                .args(["install", "-y", "-qq", "--no-install-recommends"])
                .args(packages);
            command.output()
        }
        other => {
            let mut command = std::process::Command::new(other);
            command.args(["install", "-y", "-q"]).args(packages);
            command.output()
        }
    }
    .with_context(|| format!("could not run {manager}"))?;

    if !output.status.success() {
        bail!(
            "installing {} failed: {}",
            definition.name,
            explain_package_failure(&output.stderr, &output.stdout)
        );
    }

    // Installed but idle is a confusing state to leave someone in, so start it.
    let mut result = format!("{} installed", definition.name);
    if let Some(unit) = definition.unit
        && std::path::Path::new("/run/systemd/system").is_dir()
    {
        let started = std::process::Command::new("systemctl")
            .args(["enable", "--now", unit])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        result.push_str(if started {
            " and started"
        } else {
            "; start it with systemctl"
        });
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Node versions
// ---------------------------------------------------------------------------

/// Node releases offered for installation, with the date each stops receiving
/// security fixes.
///
/// Dates rather than labels like "LTS": a label is a claim that silently goes
/// stale, and "LTS" says nothing about whether that release is still getting
/// fixes today. Node 18 and 20 have both passed their date already.
pub const AVAILABLE_NODE: &[(&str, i64, &str)] = &[
    ("24", 1_840_665_600, "2028-04-30"),
    ("22", 1_809_043_200, "2027-04-30"),
    ("20", 1_777_507_200, "2026-04-30"),
    ("18", 1_745_971_200, "2025-04-30"),
];

/// Which Node is installed, if any.
pub fn node_version() -> Option<String> {
    for path in ["/usr/bin/node", "/usr/local/bin/node"] {
        if std::path::Path::new(path).is_file() {
            let output = std::process::Command::new(path)
                .arg("--version")
                .output()
                .ok()?;
            return Some(
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .trim_start_matches('v')
                    .to_string(),
            );
        }
    }
    None
}

/// The major version currently installed, for marking the list.
fn node_major() -> Option<String> {
    node_version()?.split('.').next().map(str::to_string)
}

pub fn node_versions() -> Vec<serde_json::Value> {
    let installed = node_major();
    let now = crate::daemon::now_secs() as i64;

    AVAILABLE_NODE
        .iter()
        .map(|(major, eol_at, eol_date)| {
            serde_json::json!({
                "major": major,
                "end_of_life": now >= *eol_at,
                "end_of_life_date": eol_date,
                "installed": installed.as_deref() == Some(*major),
            })
        })
        .collect()
}

/// Install a specific Node major from NodeSource.
///
/// Adding a third-party repository is a real decision, so it happens only when
/// a version is asked for by name — never as a side effect of installing
/// something else.
pub fn install_node(cfg: &Config, major: &str) -> Result<String> {
    cfg.require_host_mode(&format!("install Node {major}"))?;

    if !AVAILABLE_NODE.iter().any(|(known, _, _)| *known == major) {
        bail!("unknown Node version {major}");
    }
    if package_manager() != Some("apt") {
        bail!("installing a specific Node version is only implemented for apt systems");
    }

    let _queued = PACKAGE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // NodeSource ships a setup script per major that adds its repository and
    // key. Piping a remote script to a shell is what upstream documents; the
    // panel says so plainly rather than hiding it.
    let script = format!("https://deb.nodesource.com/setup_{major}.x");
    let setup = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("curl -fsSL {script} | bash -"))
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .context("could not run the NodeSource setup script")?;

    if !setup.status.success() {
        bail!(
            "could not add the NodeSource repository: {}",
            explain_package_failure(&setup.stderr, &setup.stdout)
        );
    }

    let install = std::process::Command::new("apt-get")
        .arg(DPKG_LOCK_WAIT)
        .args(["install", "-y", "-qq", "--no-install-recommends", "nodejs"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .context("could not run apt-get")?;

    if !install.status.success() {
        bail!(
            "installing Node {major} failed: {}",
            explain_package_failure(&install.stderr, &install.stdout)
        );
    }

    Ok(match node_version() {
        Some(version) => format!("Node {version} installed"),
        None => format!("Node {major} installed"),
    })
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct UpdateStatus {
    pub current: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    pub update_available: bool,
    pub checked: bool,
    pub detail: String,
}

/// Ask GitHub what the newest release is.
///
/// Network-dependent and therefore explicitly a check the operator triggers,
/// not something done on every page load: a control panel that phones home on
/// its own is exactly what this is meant to avoid.
pub fn check_for_update(repo: &str) -> UpdateStatus {
    let current = env!("CARGO_PKG_VERSION").to_string();

    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = match reqwest::blocking::Client::builder()
        .user_agent(concat!("ember/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return UpdateStatus {
                current,
                latest: None,
                update_available: false,
                checked: false,
                detail: format!("could not build an HTTP client: {err}"),
            };
        }
    };

    match client.get(&url).send().and_then(|r| r.error_for_status()) {
        Ok(response) => {
            // Parsed from text rather than reqwest's json feature, which would
            // pull in a second serde stack for one field.
            let body: serde_json::Value = response
                .text()
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or(serde_json::json!({}));
            let latest = body
                .get("tag_name")
                .and_then(|v| v.as_str())
                .map(|tag| tag.trim_start_matches('v').to_string());

            match latest {
                Some(latest) => UpdateStatus {
                    update_available: latest != current,
                    detail: if latest == current {
                        "running the newest release".to_string()
                    } else {
                        format!("{latest} is available")
                    },
                    current,
                    latest: Some(latest),
                    checked: true,
                },
                None => UpdateStatus {
                    current,
                    latest: None,
                    update_available: false,
                    checked: true,
                    detail: "no releases published yet".to_string(),
                },
            }
        }
        Err(err) => UpdateStatus {
            current,
            latest: None,
            update_available: false,
            checked: false,
            // A 404 here means no release exists, which is worth distinguishing
            // from being unable to reach GitHub at all.
            detail: if err.status().map(|s| s.as_u16()) == Some(404) {
                "no releases published yet".to_string()
            } else {
                format!("could not reach GitHub: {err}")
            },
        },
    }
}

/// How many packages the distribution says are upgradable.
pub fn system_updates() -> (bool, String) {
    match package_manager() {
        Some("apt") => {
            let output = std::process::Command::new("apt-get")
                .args(["--just-print", "upgrade"])
                .env("DEBIAN_FRONTEND", "noninteractive")
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let count = String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .filter(|line| line.starts_with("Inst "))
                        .count();
                    (
                        count > 0,
                        if count == 0 {
                            "system packages are up to date".to_string()
                        } else {
                            format!("{count} package(s) can be upgraded")
                        },
                    )
                }
                _ => (false, "could not check system packages".to_string()),
            }
        }
        Some(_) => (false, "checking is only implemented for apt".to_string()),
        None => (false, "no supported package manager".to_string()),
    }
}

/// Turn a package manager's last line into something worth reading.
///
/// The raw output is usually the least useful line of several, and the lock
/// message in particular tells the operator nothing they can act on.
fn explain_package_failure(stderr: &[u8], stdout: &[u8]) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(stderr),
        String::from_utf8_lossy(stdout)
    );

    if text.contains("dpkg frontend lock") || text.contains("Could not get lock") {
        return "another package operation is still running on this server — \
                usually unattended-upgrades on a freshly booted machine. It will \
                free up on its own; try again in a few minutes."
            .to_string();
    }
    if text.contains("Unable to locate package") {
        return "the package is not in this server's sources — the distribution \
                may not carry it, or `apt-get update` has never run."
            .to_string();
    }
    if text.contains("Temporary failure resolving") || text.contains("Could not resolve") {
        return "this server could not reach the package mirrors — check its DNS \
                and outbound network."
            .to_string();
    }

    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("unknown error")
        .trim()
        .to_string()
}
