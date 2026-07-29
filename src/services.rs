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
    /// False when Ember has no packages for this platform.
    pub installable: bool,
    /// Set when the component needs something said out loud before installing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
    note: Option<&'static str>,
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
        note: None,
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
        note: Some(
            "Ember can install PostgreSQL, but creating databases on it is not \
             implemented yet — only MariaDB is wired up.",
        ),
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
        note: Some(
            "Ember can install Redis, but per-customer instances are not \
             implemented yet.",
        ),
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
        note: None,
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
        note: None,
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
        note: None,
    },
];

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

fn is_running(unit: Option<&str>) -> bool {
    let Some(unit) = unit else { return false };
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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
                running: installed && is_running(definition.unit),
                version: if installed {
                    version_of(definition)
                } else {
                    None
                },
                installable: !packages.is_empty(),
                note: definition.note.map(str::to_string),
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

    let output = match manager {
        "apt" => {
            let mut command = std::process::Command::new("apt-get");
            command
                .env("DEBIAN_FRONTEND", "noninteractive")
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
        let reason = String::from_utf8_lossy(&output.stderr);
        bail!(
            "installing {} failed: {}",
            definition.name,
            reason.lines().last().unwrap_or("unknown error").trim()
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
