//! Where Ember keeps its runtime files, and how settings are resolved.
//!
//! Everything Ember owns lives under one directory (`~/.ember` by default).
//! Nothing here ever reads or writes system PHP locations.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Listen address defaults. Port is a placeholder until the panel's real port
/// is decided — override with `--port`, `EMBER_PORT`, or `~/.ember/config.json`.
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 7878;

/// The esw-engine build provisioned for the panel. Pinned on purpose: the panel
/// runs on a known engine, independent of what the host has installed.
pub const DEFAULT_ESW_VERSION: &str = "8.4.23";

/// Root of everything Ember owns: `$EMBER_HOME`, else `~/.ember`.
pub fn ember_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("EMBER_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").context("HOME is not set; set EMBER_HOME instead")?;
    Ok(PathBuf::from(home).join(".ember"))
}

fn sub(name: &str) -> Result<PathBuf> {
    Ok(ember_dir()?.join(name))
}

/// Provisioned esw-engine builds: `esw/<version>/`.
///
/// Separable from `$EMBER_HOME` via `EMBER_ESW_DIR` so a container image can
/// bake the engine into a read-only layer while state lives on a volume that
/// would otherwise mask it.
pub fn esw_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("EMBER_ESW_DIR") {
        return Ok(PathBuf::from(dir));
    }
    sub("esw")
}
/// Generated config Ember writes (esw-engine ini, pool configs).
pub fn conf_dir() -> Result<PathBuf> {
    sub("conf")
}
/// Sockets and pid files.
pub fn run_dir() -> Result<PathBuf> {
    sub("run")
}
/// Log output.
pub fn log_dir() -> Result<PathBuf> {
    sub("log")
}
/// The panel application itself — where Symfony gets installed.
pub fn panel_dir() -> Result<PathBuf> {
    sub("panel")
}
/// Document root served to the world.
pub fn panel_public_dir() -> Result<PathBuf> {
    Ok(panel_dir()?.join("public"))
}

pub fn state_file() -> Result<PathBuf> {
    Ok(ember_dir()?.join("ember.json"))
}
pub fn config_file() -> Result<PathBuf> {
    Ok(ember_dir()?.join("config.json"))
}
pub fn service_log_file() -> Result<PathBuf> {
    Ok(log_dir()?.join("ember.log"))
}

/// Create the directory skeleton. Idempotent.
pub fn ensure_dirs() -> Result<()> {
    for dir in [
        ember_dir()?,
        esw_dir()?,
        conf_dir()?,
        run_dir()?,
        log_dir()?,
        panel_public_dir()?,
    ] {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    Ok(())
}

/// On-disk config. Every field optional so a partial file stays valid.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub esw_version: Option<String>,
    pub mode: Option<Mode>,
    #[serde(default)]
    pub branding: Option<Branding>,
}

/// White-label settings.
///
/// Kept in config rather than in templates so an operator can rebrand the panel
/// without touching code, and so the Rust-rendered login pages and the Symfony
/// panel cannot drift apart — both read this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    /// Product name shown in the UI and page titles.
    #[serde(default = "default_brand_name")]
    pub name: String,
    /// One line under the name on the sign-in screen.
    #[serde(default = "default_tagline")]
    pub tagline: String,
    /// Primary accent, any CSS colour.
    #[serde(default = "default_accent")]
    pub accent: String,
    /// Optional logo URL. Falls back to the wordmark when unset.
    #[serde(default)]
    pub logo_url: Option<String>,
}

fn default_brand_name() -> String {
    "Ember".to_string()
}
fn default_tagline() -> String {
    "Server control panel".to_string()
}
/// A neutral blue rather than a product colour, so a rebrand is a one-line
/// change and the default looks deliberate rather than unbranded.
fn default_accent() -> String {
    "#2563eb".to_string()
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            name: default_brand_name(),
            tagline: default_tagline(),
            accent: default_accent(),
            logo_url: None,
        }
    }
}

impl Branding {
    /// Persist branding into `config.json`, leaving every other setting alone.
    ///
    /// Read-modify-write rather than serialising a whole `FileConfig`: the file
    /// belongs to the operator, and rewriting it wholesale would silently drop
    /// anything Ember does not currently model.
    pub fn save(&self) -> Result<()> {
        ensure_dirs()?;
        let path = config_file()?;

        let mut document: serde_json::Value = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_else(|| serde_json::json!({}));

        if !document.is_object() {
            document = serde_json::json!({});
        }
        document["branding"] = serde_json::to_value(self)?;

        std::fs::write(&path, serde_json::to_vec_pretty(&document)?)
            .with_context(|| format!("could not write {}", path.display()))?;
        Ok(())
    }

    /// Which values are pinned by the environment and so cannot be edited.
    ///
    /// Surfaced rather than hidden: a form that silently fails to save because
    /// an env var wins is worse than one that says so.
    pub fn env_overrides() -> Vec<&'static str> {
        [
            ("name", "EMBER_BRAND_NAME"),
            ("tagline", "EMBER_BRAND_TAGLINE"),
            ("accent", "EMBER_BRAND_ACCENT"),
            ("logo_url", "EMBER_BRAND_LOGO"),
        ]
        .iter()
        .filter(|(_, var)| std::env::var(var).is_ok())
        .map(|(field, _)| *field)
        .collect()
    }

    /// Environment wins over the config file, so a container can be rebranded
    /// without writing a config.
    pub fn resolve() -> Self {
        let mut branding = FileConfig::load().branding.unwrap_or_default();
        if let Ok(name) = std::env::var("EMBER_BRAND_NAME") {
            branding.name = name;
        }
        if let Ok(tagline) = std::env::var("EMBER_BRAND_TAGLINE") {
            branding.tagline = tagline;
        }
        if let Ok(accent) = std::env::var("EMBER_BRAND_ACCENT") {
            branding.accent = accent;
        }
        if let Ok(logo) = std::env::var("EMBER_BRAND_LOGO") {
            branding.logo_url = Some(logo);
        }
        branding
    }

    /// Guard against a colour from config breaking out of the style block.
    pub fn safe_accent(&self) -> String {
        let accent = self.accent.trim();
        let usable = !accent.is_empty()
            && accent.len() <= 32
            && accent
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"#(),.%- ".contains(&b));
        if usable {
            accent.to_string()
        } else {
            default_accent()
        }
    }
}

impl FileConfig {
    fn load() -> Self {
        let Ok(path) = config_file() else {
            return Self::default();
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str(&raw) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!("warning: ignoring {}: {err}", path.display());
                Self::default()
            }
        }
    }
}

/// How much of the surrounding machine Ember is allowed to touch.
///
/// The default is deliberately the safe one. Ember reads the system user
/// database in both modes — that is how login works — but it will not *modify*
/// the machine unless explicitly put in host mode. Developing on a laptop
/// should never risk creating or altering real accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Manage nothing outside `$EMBER_HOME`. The default.
    Isolated,
    /// May manage system accounts and services on the machine it runs on.
    Host,
}

impl Mode {
    /// Refuse anything that would modify the machine Ember runs on.
    ///
    /// Every privileged mutation — creating a system account, setting a system
    /// password, writing a unit file — goes through here. In isolated mode it
    /// refuses, so a development run cannot alter the developer's own machine
    /// even by mistake.
    pub fn require_host(self, action: &str) -> Result<()> {
        if self == Self::Host {
            return Ok(());
        }
        bail!(
            "refusing to {action}: ember is in isolated mode and will not modify \
             this machine.\nrun with EMBER_MODE=host (or use the container) if that \
             is genuinely what you want."
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Host => "host",
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "isolated" | "dev" => Ok(Self::Isolated),
            "host" | "managed" => Ok(Self::Host),
            other => bail!("unknown EMBER_MODE {other:?} — expected \"isolated\" or \"host\""),
        }
    }
}

/// Fully resolved settings for a service run.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub esw_version: String,
    pub mode: Mode,
}

impl Config {
    /// Precedence: CLI flag > environment > config file > built-in default.
    pub fn resolve(cli_host: Option<String>, cli_port: Option<u16>) -> Result<Self> {
        let file = FileConfig::load();

        let env_port = match std::env::var("EMBER_PORT") {
            Ok(raw) => Some(
                raw.parse::<u16>()
                    .with_context(|| format!("EMBER_PORT is not a valid port: {raw:?}"))?,
            ),
            Err(_) => None,
        };

        Ok(Self {
            host: cli_host
                .or_else(|| std::env::var("EMBER_HOST").ok())
                .or(file.host)
                .unwrap_or_else(|| DEFAULT_HOST.to_string()),
            port: cli_port.or(env_port).or(file.port).unwrap_or(DEFAULT_PORT),
            esw_version: std::env::var("EMBER_ESW_VERSION")
                .ok()
                .or(file.esw_version)
                .unwrap_or_else(|| DEFAULT_ESW_VERSION.to_string()),
            mode: Self::resolve_mode(file.mode)?,
        })
    }

    /// The mode in force right now, independent of any resolved `Config`.
    ///
    /// Exists so the functions that actually modify the machine can check for
    /// themselves rather than trusting every caller to remember.
    pub fn current_mode() -> Result<Mode> {
        Self::resolve_mode(FileConfig::load().mode)
    }

    fn resolve_mode(from_file: Option<Mode>) -> Result<Mode> {
        match std::env::var("EMBER_MODE") {
            Ok(raw) => Mode::parse(&raw),
            Err(_) => Ok(from_file.unwrap_or(Mode::Isolated)),
        }
    }

    /// Gate for anything that would modify the machine Ember runs on.
    pub fn require_host_mode(&self, action: &str) -> Result<()> {
        self.mode.require_host(action)
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// A URL a human can actually click.
    ///
    /// Behind a container port map or a proxy the bound address is not what the
    /// operator types, so `EMBER_PUBLIC_URL` wins when set.
    pub fn url(&self) -> String {
        if let Ok(public) = std::env::var("EMBER_PUBLIC_URL") {
            return public.trim_end_matches('/').to_string();
        }
        let host: &str = match self.host.as_str() {
            "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
            other => other,
        };
        format!("http://{host}:{}", self.port)
    }
}
