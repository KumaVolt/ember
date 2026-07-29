//! Per-domain hosting: the directory layout, ownership, and web server config.
//!
//! Every domain gets its own root, owned by the customer's system account:
//!
//! ```text
//! /var/www/vhosts/<domain>/
//!   httpdocs/     the site itself — the only thing served
//!   logs/         access.log, error.log for this domain alone
//!   conf/         the generated vhost config
//!   tmp/          per-domain scratch, kept off the shared /tmp
//! ```
//!
//! Ownership is the isolation boundary. Files belong to the customer's
//! user:group, so one customer cannot read another's, and the pool that runs
//! their code runs as that same account.
//!
//! Note the split: Ember serves the *panel* itself and never delegates that to
//! nginx. These configs are for customer domains only.

use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{config::Config, store::Domain};

/// Directories created inside a domain root, and whether the web server needs
/// to traverse them.
const LAYOUT: [&str; 4] = ["httpdocs", "logs", "conf", "tmp"];

/// A page to serve before the customer uploads anything.
const PLACEHOLDER_INDEX: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>{DOMAIN}</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#0e0f12; color:#e6e8ee;
         font:15px/1.6 ui-sans-serif, system-ui, sans-serif; text-align:center; }
  h1 { font-size:1.4rem; margin:0 0 .4rem; letter-spacing:-.01em; }
  p  { color:#8b90a0; margin:0; font-size:.9rem; }
  code { color:#c9cdd8; }
</style>
<div>
  <h1>{DOMAIN}</h1>
  <p>This domain is set up and ready. Upload your site to <code>httpdocs/</code>.</p>
</div>
"#;

/// Create the directory tree for a domain and hand it to its owner.
///
/// Gated on host mode: laying out `/var/www` is a change to the machine, so it
/// must not happen on a developer's laptop by accident.
pub fn provision(cfg: &Config, domain: &Domain, owner: &str) -> Result<()> {
    cfg.require_host_mode(&format!("create the hosting layout for {}", domain.name))?;

    let root = PathBuf::from(&domain.root);
    if root.exists() {
        // Adopt an existing tree rather than clobbering whatever is in it.
        return apply_ownership(&root, owner);
    }

    std::fs::create_dir_all(&root)
        .with_context(|| format!("could not create {}", root.display()))?;
    for dir in LAYOUT {
        std::fs::create_dir_all(root.join(dir))
            .with_context(|| format!("could not create {}/{dir}", root.display()))?;
    }

    let index = root.join("httpdocs").join("index.html");
    if !index.exists() {
        std::fs::write(&index, PLACEHOLDER_INDEX.replace("{DOMAIN}", &domain.name))
            .with_context(|| format!("could not write {}", index.display()))?;
    }

    apply_ownership(&root, owner)?;
    Ok(())
}

/// Remove a domain's files. Refuses anything that is not under the vhost root,
/// because this deletes a directory tree.
pub fn deprovision(cfg: &Config, domain: &Domain) -> Result<()> {
    cfg.require_host_mode(&format!("remove the hosting layout for {}", domain.name))?;

    let root = PathBuf::from(&domain.root);
    let expected = crate::store::root_for(&domain.name);
    if domain.root != expected {
        bail!(
            "refusing to delete {} — it is not the expected path {expected}",
            root.display()
        );
    }
    if !root.starts_with(crate::store::VHOST_ROOT) {
        bail!(
            "refusing to delete {} — outside the vhost root",
            root.display()
        );
    }

    if root.exists() {
        std::fs::remove_dir_all(&root)
            .with_context(|| format!("could not remove {}", root.display()))?;
    }
    Ok(())
}

/// Look up a system account's uid and gid.
fn ids_for(user: &str) -> Result<(u32, u32)> {
    let cname = CString::new(user).context("invalid username")?;
    // SAFETY: getpwnam takes a NUL-terminated string and returns a pointer we
    // null-check and only read from before any other libc call.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            bail!("no system account named {user:?}");
        }
        Ok(((*pw).pw_uid, (*pw).pw_gid))
    }
}

/// Give the tree to the customer, and make the modes sane.
///
/// `httpdocs` is group-readable so the web server can serve it; `logs` and
/// `conf` are not, because they are nobody else's business.
fn apply_ownership(root: &Path, owner: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (uid, gid) = ids_for(owner)?;
    chown_recursive(root, uid, gid)?;

    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o750))?;
    for (dir, mode) in [
        ("httpdocs", 0o750),
        ("logs", 0o750),
        ("conf", 0o750),
        ("tmp", 0o700),
    ] {
        let path = root.join(dir);
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("path is not usable: {}", path.display()))?;

    // SAFETY: lchown on a path we built; symlinks are changed rather than
    // followed, so a planted link cannot redirect ownership elsewhere.
    let rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not chown {}", path.display()));
    }

    if path.is_dir() && !path.is_symlink() {
        for entry in std::fs::read_dir(path)? {
            chown_recursive(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Web server configuration
// ---------------------------------------------------------------------------

/// The web servers Ember can write configuration for.
///
/// One trait-shaped enum rather than a trait object: there are exactly two, and
/// the difference is entirely in the text they emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebServer {
    Nginx,
    Apache,
}

impl WebServer {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "nginx" => Ok(Self::Nginx),
            "apache" => Ok(Self::Apache),
            other => bail!("unknown web server {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Apache => "apache",
        }
    }

    /// Where the running web server picks configs up from, if it is installed.
    fn sites_dir(self) -> Option<PathBuf> {
        let candidates: &[&str] = match self {
            Self::Nginx => &["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"],
            Self::Apache => &["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"],
        };
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_dir())
    }

    /// The generated config for one domain.
    ///
    /// PHP is wired to the domain's own pool socket, which runs as the
    /// customer's account — so a request for this domain executes with exactly
    /// that customer's privileges and no more.
    pub fn config_for(self, domain: &Domain) -> String {
        let name = &domain.name;
        let docroot = &domain.docroot;
        let logs = format!("{}/logs", domain.root);
        let socket = pool_socket_for(name);

        match self {
            Self::Nginx => format!(
                "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
                 server {{\n\
                 \x20   listen 80;\n\
                 \x20   listen [::]:80;\n\
                 \x20   server_name {name} www.{name};\n\
                 \n\
                 \x20   root {docroot};\n\
                 \x20   index index.php index.html;\n\
                 \n\
                 \x20   access_log {logs}/access.log;\n\
                 \x20   error_log  {logs}/error.log;\n\
                 \n\
                 \x20   location / {{\n\
                 \x20       try_files $uri $uri/ /index.php$is_args$args;\n\
                 \x20   }}\n\
                 \n\
                 \x20   location ~ \\.php$ {{\n\
                 \x20       include fastcgi_params;\n\
                 \x20       fastcgi_pass unix:{socket};\n\
                 \x20       fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n\
                 \x20       fastcgi_param DOCUMENT_ROOT $document_root;\n\
                 \x20   }}\n\
                 \n\
                 \x20   # Dotfiles are configuration, not content.\n\
                 \x20   location ~ /\\. {{ deny all; }}\n\
                 }}\n"
            ),
            Self::Apache => format!(
                "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
                 <VirtualHost *:80>\n\
                 \x20   ServerName {name}\n\
                 \x20   ServerAlias www.{name}\n\
                 \x20   DocumentRoot {docroot}\n\
                 \n\
                 \x20   CustomLog {logs}/access.log combined\n\
                 \x20   ErrorLog  {logs}/error.log\n\
                 \n\
                 \x20   <Directory {docroot}>\n\
                 \x20       AllowOverride All\n\
                 \x20       Require all granted\n\
                 \x20   </Directory>\n\
                 \n\
                 \x20   <FilesMatch \\.php$>\n\
                 \x20       SetHandler \"proxy:unix:{socket}|fcgi://localhost\"\n\
                 \x20   </FilesMatch>\n\
                 \n\
                 \x20   <FilesMatch \"^\\.\">\n\
                 \x20       Require all denied\n\
                 \x20   </FilesMatch>\n\
                 </VirtualHost>\n"
            ),
        }
    }
}

/// The FPM socket a domain's pool listens on.
pub fn pool_socket_for(domain: &str) -> String {
    format!("/run/ember/pools/{domain}.sock")
}

/// Write a domain's vhost config into its own `conf/` directory, and link it
/// into the web server's config directory when one is present.
///
/// Ember always writes its own copy so the config is inspectable even when the
/// web server is not installed — which is the normal case in a container.
pub fn write_config(cfg: &Config, domain: &Domain) -> Result<PathBuf> {
    cfg.require_host_mode(&format!("write the vhost config for {}", domain.name))?;

    let server = WebServer::parse(&domain.webserver)?;
    let conf_dir = PathBuf::from(&domain.root).join("conf");
    std::fs::create_dir_all(&conf_dir)?;

    let path = conf_dir.join(format!("{}.conf", server.as_str()));
    std::fs::write(&path, server.config_for(domain))
        .with_context(|| format!("could not write {}", path.display()))?;

    if let Some(sites) = server.sites_dir() {
        let link = sites.join(format!("{}.conf", domain.name));
        // Replace any previous link so a regenerated config takes effect.
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&path, &link).with_context(|| {
            format!("could not link {} into {}", path.display(), sites.display())
        })?;
    }

    Ok(path)
}

/// Remove a domain's config from the web server's directory.
pub fn remove_config(domain: &Domain) -> Result<()> {
    let Ok(server) = WebServer::parse(&domain.webserver) else {
        return Ok(());
    };
    if let Some(sites) = server.sites_dir() {
        let _ = std::fs::remove_file(sites.join(format!("{}.conf", domain.name)));
    }
    Ok(())
}

/// Ask the web server to pick up a changed configuration.
///
/// Reloading is deliberately best-effort and reported rather than fatal: a
/// domain that exists on disk but is not yet live is a recoverable state, while
/// a failed API call that already wrote files is not.
pub fn reload(server: WebServer) -> Result<String> {
    if server.sites_dir().is_none() {
        return Ok(format!("{} is not installed here", server.as_str()));
    }

    let unit = server.as_str();
    let output = std::process::Command::new("systemctl")
        .args(["reload", unit])
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(format!("{unit} reloaded")),
        Ok(out) => Ok(format!(
            "{unit} reload failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(err) => Ok(format!("could not run systemctl: {err}")),
    }
}
