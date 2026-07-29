//! TLS certificates from Let's Encrypt, via certbot.
//!
//! Ember drives certbot rather than speaking ACME itself. Certificate issuance
//! has a lot of hard-won edge cases — rate limits, account recovery, revocation,
//! CA policy changes — and certbot has absorbed all of them. It also brings its
//! own renewal timer, so automatic renewal is a matter of configuring certbot
//! correctly rather than writing a scheduler that must never drift.
//!
//! Validation is HTTP-01 over the domain's own webroot: the challenge file is
//! written under `webroot/.well-known/acme-challenge/` and served by the
//! domain's normal vhost. Nothing needs to stop, and no port is taken over.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{config::Config, store::Domain};

/// Where certbot keeps live certificates.
const LIVE_DIR: &str = "/etc/letsencrypt/live";
/// Hooks certbot runs after a successful renewal.
const DEPLOY_HOOK_DIR: &str = "/etc/letsencrypt/renewal-hooks/deploy";

/// Renew this many days before expiry. Certbot's own default is 30; matching it
/// keeps Ember's reporting honest about when renewal will actually happen.
pub const RENEW_BEFORE_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateStatus {
    pub domain: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    /// True once inside the renewal window, so the UI can say "renewing soon"
    /// rather than implying something is wrong.
    pub renews_soon: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fullchain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privkey: Option<String>,
}

pub fn live_dir(domain: &str) -> PathBuf {
    PathBuf::from(LIVE_DIR).join(domain)
}

pub fn fullchain_path(domain: &str) -> PathBuf {
    live_dir(domain).join("fullchain.pem")
}

pub fn privkey_path(domain: &str) -> PathBuf {
    live_dir(domain).join("privkey.pem")
}

/// Does this domain have a usable certificate right now?
///
/// Both halves must exist: a certificate without its key would make the web
/// server refuse to start, which is worse than having no TLS at all.
pub fn has_certificate(domain: &str) -> bool {
    fullchain_path(domain).is_file() && privkey_path(domain).is_file()
}

pub fn certbot_available() -> bool {
    which_certbot().is_some()
}

fn which_certbot() -> Option<PathBuf> {
    for candidate in [
        "/usr/bin/certbot",
        "/usr/local/bin/certbot",
        "/snap/bin/certbot",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    // Fall back to PATH for less usual installs.
    std::process::Command::new("sh")
        .args(["-c", "command -v certbot"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string()))
        .filter(|path| path.is_file())
}

/// Read the expiry out of a certificate.
///
/// Shelling to openssl keeps this to one small dependency-free call; parsing
/// X.509 by hand to display a date would be a poor trade.
fn expiry_of(path: &Path) -> Option<(String, i64)> {
    let output = std::process::Command::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let stamp = text.trim().strip_prefix("notAfter=")?.trim().to_string();

    // `date` handles the RFC 822-ish format openssl emits on both GNU and BSD.
    let seconds = std::process::Command::new("date")
        .args(["-d", &stamp, "+%s"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .or_else(|| {
            std::process::Command::new("date")
                .args(["-j", "-f", "%b %e %T %Y %Z", &stamp, "+%s"])
                .output()
                .ok()
                .filter(|out| out.status.success())
        })?;

    let expires: i64 = String::from_utf8_lossy(&seconds.stdout)
        .trim()
        .parse()
        .ok()?;
    let remaining = (expires - crate::daemon::now_secs() as i64) / 86_400;

    Some((stamp, remaining))
}

pub fn status(domain: &str) -> CertificateStatus {
    if !has_certificate(domain) {
        return CertificateStatus {
            domain: domain.to_string(),
            present: false,
            expires_at: None,
            days_remaining: None,
            renews_soon: false,
            fullchain: None,
            privkey: None,
        };
    }

    let expiry = expiry_of(&fullchain_path(domain));
    let days = expiry.as_ref().map(|(_, days)| *days);

    CertificateStatus {
        domain: domain.to_string(),
        present: true,
        expires_at: expiry.as_ref().map(|(stamp, _)| stamp.clone()),
        days_remaining: days,
        renews_soon: days.is_some_and(|d| d <= RENEW_BEFORE_DAYS),
        fullchain: Some(fullchain_path(domain).to_string_lossy().into_owned()),
        privkey: Some(privkey_path(domain).to_string_lossy().into_owned()),
    }
}

/// Request a certificate for a domain and its `www` alias.
///
/// Returns certbot's own output, because when issuance fails the reason —
/// DNS not pointing here, port 80 unreachable, rate limit — is the only useful
/// thing to show, and paraphrasing it loses detail.
pub fn issue(cfg: &Config, domain: &Domain, email: Option<&str>, staging: bool) -> Result<String> {
    cfg.require_host_mode(&format!("request a certificate for {}", domain.name))?;

    let Some(certbot) = which_certbot() else {
        bail!("certbot is not installed — install it, or re-run install.sh which now does");
    };

    let webroot = PathBuf::from(&domain.docroot);
    if !webroot.is_dir() {
        bail!("{} does not exist", webroot.display());
    }

    // Make sure the challenge directory exists and is reachable before asking
    // the CA to fetch from it.
    let challenge = webroot.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&challenge)
        .with_context(|| format!("could not create {}", challenge.display()))?;

    let mut command = std::process::Command::new(&certbot);
    command
        .arg("certonly")
        .arg("--webroot")
        .arg("-w")
        .arg(&webroot)
        .arg("-d")
        .arg(&domain.name)
        .arg("-d")
        .arg(format!("www.{}", domain.name))
        .arg("--cert-name")
        .arg(&domain.name)
        .arg("--non-interactive")
        .arg("--agree-tos")
        // Keep going if the certificate already covers these names.
        .arg("--keep-until-expiring")
        .arg("--expand");

    match email {
        Some(address) if !address.trim().is_empty() => {
            command.arg("-m").arg(address.trim());
        }
        // No address means no expiry warnings from the CA; renewal is automatic
        // anyway, and demanding one would block issuance.
        _ => {
            command.arg("--register-unsafely-without-email");
        }
    }

    // Staging has far looser rate limits and issues untrusted certificates —
    // the right default for anyone trying this out on a domain that may not
    // resolve yet.
    if staging {
        command.arg("--staging");
    }

    let output = command
        .output()
        .with_context(|| format!("could not run {}", certbot.display()))?;

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() {
        bail!("certbot failed:\n{}", combined.trim());
    }

    Ok(combined.trim().to_string())
}

/// Renew anything close to expiry. Certbot decides what is due.
pub fn renew_all(cfg: &Config, force: bool) -> Result<String> {
    cfg.require_host_mode("renew certificates")?;

    let Some(certbot) = which_certbot() else {
        bail!("certbot is not installed");
    };

    let mut command = std::process::Command::new(&certbot);
    command.arg("renew").arg("--non-interactive");
    if force {
        command.arg("--force-renewal");
    }

    let output = command.output().context("could not run certbot renew")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() {
        bail!("certbot renew failed:\n{}", combined.trim());
    }
    Ok(combined.trim().to_string())
}

/// Drop a certificate entirely.
pub fn remove(cfg: &Config, domain: &str) -> Result<String> {
    cfg.require_host_mode(&format!("remove the certificate for {domain}"))?;

    let Some(certbot) = which_certbot() else {
        bail!("certbot is not installed");
    };

    let output = std::process::Command::new(&certbot)
        .args(["delete", "--non-interactive", "--cert-name", domain])
        .output()
        .context("could not run certbot delete")?;

    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_string())
}

/// Install the hook certbot runs after renewing anything.
///
/// This is what makes renewal actually take effect: certbot rewrites the files
/// on its own timer, but a running web server holds the old certificate open
/// until it is told to reload. Without this, certificates renew silently and
/// visitors keep seeing the expiring one until something restarts.
pub fn install_renewal_hook(cfg: &Config) -> Result<PathBuf> {
    cfg.require_host_mode("install the certificate renewal hook")?;

    let dir = PathBuf::from(DEPLOY_HOOK_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;

    let path = dir.join("ember-reload");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         # Installed by ember. Reloads the web servers so a renewed certificate\n\
         # is actually served; without this the old one stays live until restart.\n\
         set -eu\n\
         for unit in nginx apache2 httpd; do\n\
         \x20 if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet \"$unit\"; then\n\
         \x20   systemctl reload \"$unit\" || true\n\
         \x20 fi\n\
         done\n",
    )
    .with_context(|| format!("could not write {}", path.display()))?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

    Ok(path)
}

/// Is anything actually scheduled to run `certbot renew`?
///
/// Reported rather than assumed: a certificate that silently stops renewing is
/// the failure mode that matters, and it is invisible until the day it expires.
pub fn renewal_timer_active() -> Option<String> {
    // Deliberately not an early return on failure: `systemctl` is absent on
    // plenty of hosts, and treating that as "no renewal" would raise a false
    // alarm on every system where cron is doing the job perfectly well.
    let systemd_active = std::process::Command::new("systemctl")
        .args(["is-active", "certbot.timer"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "active")
        .unwrap_or(false);

    if systemd_active {
        return Some("certbot.timer".to_string());
    }

    // The Debian package ships a cron entry for systems without systemd.
    for path in ["/etc/cron.d/certbot", "/etc/crontab"] {
        if Path::new(path).exists()
            && std::fs::read_to_string(path)
                .map(|text| text.contains("certbot"))
                .unwrap_or(false)
        {
            return Some(path.to_string());
        }
    }

    None
}
