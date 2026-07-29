//! Per-domain hosting: the directory layout, ownership, and web server config.
//!
//! Every domain gets its own root, owned by the customer's system account:
//!
//! ```text
//! /var/www/vhosts/<domain>/
//!   webroot/     the site itself — the only thing served
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

/// The standard layout created for every new domain.
///
/// Each entry is a directory and the mode it gets. The split matters: only
/// `webroot` is ever served, so anything a site needs to keep but must not
/// expose — credentials, uploads it processes, application storage — has an
/// obvious home in `private` that no URL can reach.
const LAYOUT: [(&str, u32); 7] = [
    // Served to the world. The default document root.
    ("webroot", 0o750),
    // Never served. Application storage, keys, anything private.
    ("private", 0o700),
    // This domain's access and error logs, nobody else's.
    ("logs", 0o750),
    // The vhost config ember generates.
    ("conf", 0o750),
    // Custom error pages, served for 403/404/500.
    ("error_docs", 0o750),
    // CGI scripts, kept out of the document root deliberately.
    ("cgi-bin", 0o750),
    // Per-domain scratch, off the shared /tmp so one site cannot read
    // another's temporary files.
    ("tmp", 0o700),
];

/// Error pages written once at provisioning, so a new domain never shows the
/// web server's default page with its version number on it.
const ERROR_PAGES: [(&str, &str, &str); 3] = [
    (
        "403.html",
        "403 — Forbidden",
        "You do not have permission to view this page.",
    ),
    ("404.html", "404 — Not found", "That page does not exist."),
    (
        "500.html",
        "500 — Server error",
        "Something went wrong on this server.",
    ),
];

fn error_page(title: &str, message: &str) -> String {
    format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n\
         <style>body{{margin:0;min-height:100vh;display:flex;align-items:center;\
         justify-content:center;background:#f1f5f9;color:#1a2230;text-align:center;\
         font:15px/1.6 ui-sans-serif,system-ui,sans-serif}}\
         h1{{font-size:1.3rem;margin:0 0 .4rem}}p{{color:#64748b;margin:0}}</style>\n\
         <div><h1>{title}</h1><p>{message}</p></div>\n"
    )
}

/// The page a domain serves until its owner uploads something.
///
/// Built here rather than shipped as an asset so it carries the operator's
/// branding, and so a freshly created domain answers with something deliberate
/// instead of the web server's default page.
fn default_page(domain: &str, branding: &crate::config::Branding) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{domain}</title>
<!-- Parked pages should not turn up in search results. -->
<meta name="robots" content="noindex,nofollow">
<style>
  :root {{ --accent: {accent}; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
          background:#f1f5f9; color:#1a2230; padding:2rem 1.25rem;
          font:15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ width:100%; max-width:34rem; background:#fff; border:1px solid #e3e8ef;
          border-radius:10px; box-shadow:0 1px 2px rgba(16,24,40,.05), 0 8px 24px rgba(16,24,40,.06);
          overflow:hidden; }}
  .head {{ padding:1.5rem 1.75rem; border-bottom:1px solid #e3e8ef; display:flex;
           align-items:center; gap:.7rem; }}
  .mark {{ width:30px; height:30px; border-radius:7px; flex:none; background:var(--accent);
           color:#fff; display:grid; place-items:center; font-weight:700; font-size:.9rem; }}
  .head h1 {{ font-size:1.15rem; margin:0; letter-spacing:-.02em; }}
  .head p {{ margin:.1rem 0 0; color:#64748b; font-size:.85rem; }}
  .body {{ padding:1.5rem 1.75rem; }}
  .body h2 {{ font-size:.95rem; margin:0 0 .5rem; }}
  .body p {{ margin:0 0 1rem; color:#475569; font-size:.9rem; }}
  ol {{ margin:0; padding-left:1.15rem; color:#475569; font-size:.9rem; }}
  li {{ margin-bottom:.5rem; }}
  code {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.83rem;
          background:#f8fafc; border:1px solid #e3e8ef; border-radius:4px; padding:.05rem .3rem; }}
  .foot {{ padding:.9rem 1.75rem; background:#f8fafc; border-top:1px solid #e3e8ef;
           color:#64748b; font-size:.8rem; }}
</style>
</head>
<body>
<main>
  <div class="head">
    <span class="mark">{initial}</span>
    <div>
      <h1>{domain}</h1>
      <p>This domain is set up and working.</p>
    </div>
  </div>

  <div class="body">
    <h2>You are seeing this because nothing has been uploaded yet</h2>
    <p>
      The domain resolves, the web server is serving it, and PHP is wired up.
      Replace this page and the site is live.
    </p>
    <ol>
      <li>Sign in to your {brand} control panel.</li>
      <li>Open <strong>Websites &amp; Domains</strong> and choose <strong>Files</strong>
          for this domain.</li>
      <li>Upload your site into <code>webroot/</code>, replacing
          <code>index.html</code>.</li>
    </ol>
    <p style="margin:0">
      Keep anything that should not be public — credentials, application storage —
      in <code>private/</code>, which is never served.
    </p>
  </div>

  <div class="foot">Default page &middot; {brand}</div>
</main>
</body>
</html>
"#,
        accent = branding.safe_accent(),
        brand = branding.name,
        initial = branding.name.chars().next().unwrap_or('E').to_uppercase(),
    )
}

/// Per-domain hosting configuration: what is served, and how.
///
/// These are the knobs that change the generated vhost rather than PHP. Kept
/// beside the generator so a setting can never drift from the config it is
/// supposed to produce.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HostingSettings {
    /// Relative to the domain root. A Symfony or Laravel site points at
    /// `webroot/public`.
    pub document_root: String,
    /// `www`, `root`, or `none` for no redirect between the two.
    pub preferred_domain: String,
    /// Redirect plain HTTP to HTTPS. Only meaningful once a certificate exists.
    pub force_https: bool,
    /// Serve the generated 403/404/500 pages.
    pub error_documents: bool,
    /// Whether the owning customer has a login shell.
    pub ssh_access: bool,
    /// Serve a suspension notice instead of the site.
    pub suspended: bool,
    /// Appended to the server block verbatim.
    pub additional_directives: String,
}

impl Default for HostingSettings {
    fn default() -> Self {
        Self {
            document_root: "webroot".into(),
            preferred_domain: "none".into(),
            // Off until a certificate exists, or the site redirects to a port
            // that refuses the connection.
            force_https: false,
            error_documents: true,
            // Off by default: a hosting account does not need a shell, and one
            // is a much larger surface than serving files.
            ssh_access: false,
            suspended: false,
            additional_directives: String::new(),
        }
    }
}

impl HostingSettings {
    pub fn validate(&self) -> Result<()> {
        let root = self.document_root.trim().trim_matches('/');
        if root.is_empty() {
            bail!("document root cannot be empty");
        }
        // It becomes a path under the domain root, so traversal is refused
        // rather than resolved.
        if root.split('/').any(|part| part == ".." || part.is_empty()) {
            bail!("document root must be a simple path inside the domain directory");
        }
        if !root
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        {
            bail!("document root may use letters, digits, '.', '_', '-' and '/' only");
        }
        if !matches!(self.preferred_domain.as_str(), "www" | "root" | "none") {
            bail!("preferred domain must be www, root or none");
        }
        Ok(())
    }

    /// The absolute document root for a domain.
    pub fn docroot_for(&self, domain_root: &str) -> String {
        format!(
            "{}/{}",
            domain_root,
            self.document_root.trim().trim_matches('/')
        )
    }
}

/// Give or remove a shell for the customer's account.
///
/// Shell access is a much larger surface than serving files, so it is a
/// deliberate switch rather than something that comes with an account.
pub fn set_shell(cfg: &Config, user: &str, enabled: bool) -> Result<String> {
    cfg.require_host_mode(&format!("change the shell for {user}"))?;

    let shell = if enabled {
        ["/bin/bash", "/bin/sh"]
            .iter()
            .find(|path| std::path::Path::new(path).exists())
            .unwrap_or(&"/bin/sh")
            .to_string()
    } else {
        ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]
            .iter()
            .find(|path| std::path::Path::new(path).exists())
            .unwrap_or(&"/bin/false")
            .to_string()
    };

    let status = std::process::Command::new("usermod")
        .args(["-s", &shell, user])
        .status()
        .context("could not run usermod")?;

    if !status.success() {
        bail!("could not change the shell for {user}");
    }
    Ok(format!("shell for {user} set to {shell}"))
}

/// Create a customer's webspace and hand it to them.
///
/// Made when the customer is, not when their first domain is: a customer with
/// no sites yet still has somewhere that belongs to them.
pub fn create_webspace(cfg: &Config, owner: &str) -> Result<String> {
    cfg.require_host_mode(&format!("create the webspace for {owner}"))?;

    let path = PathBuf::from(crate::store::customer_root(owner));
    std::fs::create_dir_all(&path)
        .with_context(|| format!("could not create {}", path.display()))?;
    apply_ownership_shallow(&path, owner)?;

    Ok(path.to_string_lossy().into_owned())
}

/// Create the directory tree for a domain and hand it to its owner.
///
/// Gated on host mode: laying out `/var/www` is a change to the machine, so it
/// must not happen on a developer's laptop by accident.
pub fn provision(cfg: &Config, domain: &Domain, owner: &str) -> Result<()> {
    cfg.require_host_mode(&format!("create the hosting layout for {}", domain.name))?;

    // The record can outlive the account: replacing a container keeps the
    // store on its volume and discards /etc/passwd, and an operator can remove
    // an account by hand. Recreate it here rather than failing with "no system
    // account named X", which describes a symptom and not the fix.
    if !crate::auth::system_user_exists(owner) {
        crate::auth::create_system_user(owner, "/usr/sbin/nologin").with_context(|| {
            format!("{owner} has no system account and one could not be created")
        })?;
        crate::esw::log_line(&format!(
            "[{}] recreated missing system account {owner}",
            crate::daemon::now_secs()
        ));
    }

    // The customer's webspace holds all their domains, so it has to exist and
    // be theirs before anything is put inside it.
    let webspace = PathBuf::from(crate::store::customer_root(owner));
    std::fs::create_dir_all(&webspace)
        .with_context(|| format!("could not create {}", webspace.display()))?;
    apply_ownership_shallow(&webspace, owner)?;

    let root = PathBuf::from(&domain.root);
    if root.exists() {
        // Adopt an existing tree rather than clobbering whatever is in it.
        return apply_ownership(&root, owner);
    }

    std::fs::create_dir_all(&root)
        .with_context(|| format!("could not create {}", root.display()))?;
    for (dir, _) in LAYOUT {
        std::fs::create_dir_all(root.join(dir))
            .with_context(|| format!("could not create {}/{dir}", root.display()))?;
    }

    // The document root may sit deeper than webroot — a Symfony or Laravel
    // site points at webroot/public — so create whatever was asked for.
    let docroot = PathBuf::from(&domain.docroot);
    std::fs::create_dir_all(&docroot)
        .with_context(|| format!("could not create {}", docroot.display()))?;

    let index = docroot.join("index.html");
    if !index.exists() {
        let branding = crate::config::Branding::resolve();
        std::fs::write(&index, default_page(&domain.name, &branding))
            .with_context(|| format!("could not write {}", index.display()))?;
    }

    for (name, title, message) in ERROR_PAGES {
        let path = root.join("error_docs").join(name);
        if !path.exists() {
            std::fs::write(&path, error_page(title, message))
                .with_context(|| format!("could not write {}", path.display()))?;
        }
    }

    // A README in private/ so the distinction is discoverable from the file
    // manager rather than only from documentation.
    let readme = root.join("private").join("README.txt");
    if !readme.exists() {
        let _ = std::fs::write(
            &readme,
            "Nothing in this directory is served over the web.\n\n\
             Put application storage, credentials and anything else that must \
             stay private here. Files under webroot are public.\n",
        );
    }

    apply_ownership(&root, owner)?;
    Ok(())
}

/// Remove a domain's files. Refuses anything that is not under the vhost root,
/// because this deletes a directory tree.
pub fn deprovision(cfg: &Config, domain: &Domain) -> Result<()> {
    cfg.require_host_mode(&format!("remove the hosting layout for {}", domain.name))?;

    let root = PathBuf::from(&domain.root);
    let owner = domain.customer_username.clone().unwrap_or_default();
    let expected = crate::store::root_for(&owner, &domain.name);
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
/// The group the web server runs as, so it can read what it serves.
fn web_group_id() -> Option<u32> {
    for group in ["www-data", "nginx", "apache", "http"] {
        let Ok(cname) = std::ffi::CString::new(group) else {
            continue;
        };
        // SAFETY: getgrnam takes a NUL-terminated string and returns a pointer
        // we null-check before reading.
        let gid = unsafe {
            let entry = libc::getgrnam(cname.as_ptr());
            if entry.is_null() {
                continue;
            }
            (*entry).gr_gid
        };
        return Some(gid);
    }
    None
}

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

/// Give the tree to the customer, with the web server's group.
///
/// The group matters as much as the owner. PHP runs as the customer through
/// their own pool, but *static* files are read by the web server process, which
/// runs as `www-data`. Owned `customer:customer` at 0750 the web server cannot
/// even traverse the directory, and every request returns 403.
///
/// `customer:www-data` at 0750 gives the customer full control, the web server
/// read and traverse, and everyone else — including every other customer —
/// nothing. `private` stays 0700, so the web server cannot read it either.
fn apply_ownership(root: &Path, owner: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (uid, _) = ids_for(owner)?;
    let gid = web_group_id().unwrap_or_else(|| ids_for(owner).map(|(_, g)| g).unwrap_or(0));
    chown_recursive(root, uid, gid)?;

    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o750))?;
    for (dir, mode) in LAYOUT {
        let path = root.join(dir);
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// Own one directory without touching what is already inside it.
///
/// Used for the customer webspace: it holds other domains, and recursing would
/// rewrite ownership across all of them on every provision.
fn apply_ownership_shallow(path: &Path, owner: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (uid, _) = ids_for(owner)?;
    let gid = web_group_id().unwrap_or_else(|| ids_for(owner).map(|(_, g)| g).unwrap_or(0));

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: lchown on a path we built from the customer's own name.
    unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))?;
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
    ///
    /// Both servers are generated from the same settings, so switching a domain
    /// between them changes how it is served and nothing about how it behaves.
    pub fn config_for(self, domain: &Domain, settings: &HostingSettings) -> String {
        let name = &domain.name;
        let docroot = settings.docroot_for(&domain.root);
        let logs = format!("{}/logs", domain.root);
        let errors = format!("{}/error_docs", domain.root);
        let socket = pool_socket_for(name);
        // Only redirect to HTTPS once there is a certificate to redirect to.
        let tls = crate::cert::has_certificate(name);
        let force_https = settings.force_https && tls;
        let fullchain = crate::cert::fullchain_path(name);
        let privkey = crate::cert::privkey_path(name);

        match self {
            Self::Nginx => nginx_config(NginxParts {
                name,
                docroot: &docroot,
                logs: &logs,
                errors: &errors,
                socket: &socket,
                tls,
                force_https,
                fullchain: &fullchain.to_string_lossy(),
                privkey: &privkey.to_string_lossy(),
                settings,
            }),
            Self::Apache => apache_config(ApacheParts {
                name,
                docroot: &docroot,
                logs: &logs,
                errors: &errors,
                socket: &socket,
                tls,
                force_https,
                fullchain: &fullchain.to_string_lossy(),
                privkey: &privkey.to_string_lossy(),
                settings,
            }),
        }
    }
}

struct NginxParts<'a> {
    name: &'a str,
    docroot: &'a str,
    logs: &'a str,
    errors: &'a str,
    socket: &'a str,
    tls: bool,
    force_https: bool,
    fullchain: &'a str,
    privkey: &'a str,
    settings: &'a HostingSettings,
}

/// The redirect between www and the bare name, if one was asked for.
fn preferred_redirect_nginx(name: &str, preference: &str) -> String {
    match preference {
        "www" => format!(
            "\x20   if ($host = {name}) {{ return 301 $scheme://www.{name}$request_uri; }}\n"
        ),
        "root" => format!(
            "\x20   if ($host = www.{name}) {{ return 301 $scheme://{name}$request_uri; }}\n"
        ),
        _ => String::new(),
    }
}

fn nginx_config(p: NginxParts<'_>) -> String {
    let (name, docroot, logs, errors, socket) = (p.name, p.docroot, p.logs, p.errors, p.socket);

    // Must be reachable over plain HTTP and matched before the dotfile rule,
    // or certificate renewal fails once TLS is on.
    let acme = format!(
        "\x20   location ^~ /.well-known/acme-challenge/ {{\n\
         \x20       root {docroot};\n\
         \x20       default_type \"text/plain\";\n\
         \x20   }}\n"
    );

    if p.settings.suspended {
        return format!(
            "# Generated by ember for {name}. Suspended.\n\
             server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             {acme}\
             \n\
             \x20   # 503 rather than 404: the site exists, it is turned off.\n\
             \x20   location / {{ return 503; }}\n\
             \x20   error_page 503 /__suspended.html;\n\
             \x20   location = /__suspended.html {{ internal; root {errors}; }}\n\
             }}\n"
        );
    }

    let error_pages = if p.settings.error_documents {
        format!(
            "\x20   error_page 403 /__errors/403.html;\n\
             \x20   error_page 404 /__errors/404.html;\n\
             \x20   error_page 500 502 503 504 /__errors/500.html;\n\
             \x20   location ^~ /__errors/ {{ internal; alias {errors}/; }}\n"
        )
    } else {
        String::new()
    };

    let extra = if p.settings.additional_directives.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\x20   # Operator directives.\n{}\n",
            p.settings
                .additional_directives
                .trim()
                .lines()
                .map(|line| format!("\x20   {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    let body = format!(
        "\x20   root {docroot};\n\
         \x20   index index.php index.html;\n\
         \n\
         \x20   access_log {logs}/access.log;\n\
         \x20   error_log  {logs}/error.log;\n\
         \n\
         {acme}\
         {redirect}\
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
         \x20       fastcgi_param HTTPS $https_flag;\n\
         \x20   }}\n\
         \n\
         {error_pages}\
         \x20   # Dotfiles are configuration, not content.\n\
         \x20   location ~ /\\. {{ deny all; }}\n\
         {extra}",
        redirect = preferred_redirect_nginx(name, &p.settings.preferred_domain),
    );

    let header = format!(
        "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
         map $scheme $https_flag {{ default off; https on; }}\n\n"
    );

    if p.tls && p.force_https {
        format!(
            "{header}\
             server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             {acme}\
             \n\
             \x20   location / {{ return 301 https://$host$request_uri; }}\n\
             }}\n\n\
             server {{\n\
             \x20   listen 443 ssl;\n\
             \x20   listen [::]:443 ssl;\n\
             \x20   http2 on;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             \x20   ssl_certificate     {fullchain};\n\
             \x20   ssl_certificate_key {privkey};\n\
             \x20   ssl_protocols TLSv1.2 TLSv1.3;\n\
             \x20   ssl_session_cache shared:SSL:10m;\n\
             \n\
             {body}\
             }}\n",
            fullchain = p.fullchain,
            privkey = p.privkey,
        )
    } else if p.tls {
        // A certificate but no forced redirect: serve both.
        format!(
            "{header}\
             server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             {body}\
             }}\n\n\
             server {{\n\
             \x20   listen 443 ssl;\n\
             \x20   listen [::]:443 ssl;\n\
             \x20   http2 on;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             \x20   ssl_certificate     {fullchain};\n\
             \x20   ssl_certificate_key {privkey};\n\
             \x20   ssl_protocols TLSv1.2 TLSv1.3;\n\
             \n\
             {body}\
             }}\n",
            fullchain = p.fullchain,
            privkey = p.privkey,
        )
    } else {
        format!(
            "{header}\
             server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {name} www.{name};\n\
             \n\
             {body}\
             }}\n"
        )
    }
}

struct ApacheParts<'a> {
    name: &'a str,
    docroot: &'a str,
    logs: &'a str,
    errors: &'a str,
    socket: &'a str,
    tls: bool,
    force_https: bool,
    fullchain: &'a str,
    privkey: &'a str,
    settings: &'a HostingSettings,
}

fn apache_config(p: ApacheParts<'_>) -> String {
    let (name, docroot, logs, errors, socket) = (p.name, p.docroot, p.logs, p.errors, p.socket);

    let acme = format!(
        "\x20   Alias /.well-known/acme-challenge/ {docroot}/.well-known/acme-challenge/\n\
         \x20   <Directory {docroot}/.well-known/acme-challenge/>\n\
         \x20       Require all granted\n\
         \x20   </Directory>\n"
    );

    if p.settings.suspended {
        return format!(
            "# Generated by ember for {name}. Suspended.\n\
             <VirtualHost *:80>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \x20   DocumentRoot {docroot}\n\
             \n\
             {acme}\
             \n\
             \x20   RewriteEngine On\n\
             \x20   RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/\n\
             \x20   RewriteRule ^ - [R=503,L]\n\
             \x20   ErrorDocument 503 /__errors/503.html\n\
             \x20   Alias /__errors/ {errors}/\n\
             </VirtualHost>\n"
        );
    }

    let error_docs = if p.settings.error_documents {
        format!(
            "\x20   Alias /__errors/ {errors}/\n\
             \x20   <Directory {errors}>\n\
             \x20       Require all granted\n\
             \x20   </Directory>\n\
             \x20   ErrorDocument 403 /__errors/403.html\n\
             \x20   ErrorDocument 404 /__errors/404.html\n\
             \x20   ErrorDocument 500 /__errors/500.html\n"
        )
    } else {
        String::new()
    };

    let redirect = match p.settings.preferred_domain.as_str() {
        "www" => format!(
            "\x20   RewriteEngine On\n\
             \x20   RewriteCond %{{HTTP_HOST}} ^{name}$ [NC]\n\
             \x20   RewriteRule ^(.*)$ %{{REQUEST_SCHEME}}://www.{name}$1 [R=301,L]\n"
        ),
        "root" => format!(
            "\x20   RewriteEngine On\n\
             \x20   RewriteCond %{{HTTP_HOST}} ^www\\.{name}$ [NC]\n\
             \x20   RewriteRule ^(.*)$ %{{REQUEST_SCHEME}}://{name}$1 [R=301,L]\n"
        ),
        _ => String::new(),
    };

    let extra = if p.settings.additional_directives.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\x20   # Operator directives.\n{}\n",
            p.settings
                .additional_directives
                .trim()
                .lines()
                .map(|line| format!("\x20   {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    let body = format!(
        "\x20   DocumentRoot {docroot}\n\
         \n\
         \x20   CustomLog {logs}/access.log combined\n\
         \x20   ErrorLog  {logs}/error.log\n\
         \n\
         {acme}\
         {redirect}\
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
         {error_docs}\
         \x20   <FilesMatch \"^\\\\.\">\n\
         \x20       Require all denied\n\
         \x20   </FilesMatch>\n\
         {extra}"
    );

    if p.tls && p.force_https {
        format!(
            "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
             <VirtualHost *:80>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \x20   DocumentRoot {docroot}\n\
             \n\
             {acme}\
             \n\
             \x20   RewriteEngine On\n\
             \x20   RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/\n\
             \x20   RewriteRule ^(.*)$ https://%{{HTTP_HOST}}$1 [R=301,L]\n\
             </VirtualHost>\n\n\
             <VirtualHost *:443>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \n\
             \x20   SSLEngine on\n\
             \x20   SSLCertificateFile    {fullchain}\n\
             \x20   SSLCertificateKeyFile {privkey}\n\
             \x20   SSLProtocol -all +TLSv1.2 +TLSv1.3\n\
             \n\
             {body}\
             </VirtualHost>\n",
            fullchain = p.fullchain,
            privkey = p.privkey,
        )
    } else if p.tls {
        format!(
            "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
             <VirtualHost *:80>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \n\
             {body}\
             </VirtualHost>\n\n\
             <VirtualHost *:443>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \n\
             \x20   SSLEngine on\n\
             \x20   SSLCertificateFile    {fullchain}\n\
             \x20   SSLCertificateKeyFile {privkey}\n\
             \x20   SSLProtocol -all +TLSv1.2 +TLSv1.3\n\
             \n\
             {body}\
             </VirtualHost>\n",
            fullchain = p.fullchain,
            privkey = p.privkey,
        )
    } else {
        format!(
            "# Generated by ember for {name}. Do not edit — regenerated on change.\n\
             <VirtualHost *:80>\n\
             \x20   ServerName {name}\n\
             \x20   ServerAlias www.{name}\n\
             \n\
             {body}\
             </VirtualHost>\n"
        )
    }
}

/// The FPM socket a domain's pool listens on.
///
/// Delegates to [`crate::php`], which is what actually creates the pool — a
/// second opinion on the path here is how the vhost ends up pointing at a
/// socket nothing listens on.
pub fn pool_socket_for(domain: &str) -> String {
    crate::php::socket_path(domain)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("/run/ember/pools/{domain}.sock"))
}

/// Write a domain's vhost config into its own `conf/` directory, and link it
/// into the web server's config directory when one is present.
///
/// Ember always writes its own copy so the config is inspectable even when the
/// web server is not installed — which is the normal case in a container.
pub fn write_config(cfg: &Config, domain: &Domain, settings: &HostingSettings) -> Result<PathBuf> {
    cfg.require_host_mode(&format!("write the vhost config for {}", domain.name))?;
    settings.validate()?;

    let server = WebServer::parse(&domain.webserver)?;
    let conf_dir = PathBuf::from(&domain.root).join("conf");
    std::fs::create_dir_all(&conf_dir)?;

    let path = conf_dir.join(format!("{}.conf", server.as_str()));
    std::fs::write(&path, server.config_for(domain, settings))
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

/// Start the web server if it is installed but not accepting connections.
///
/// The same reasoning as the database: on a normal server systemd owns this and
/// the call does nothing, but in a container ember is PID 1 and nothing else
/// would bring nginx up — leaving customer sites unserved on a box that has
/// everything installed.
pub fn ensure_running(cfg: &Config) -> String {
    if cfg.mode != crate::config::Mode::Host {
        return "isolated mode: not starting a web server".to_string();
    }

    for server in [WebServer::Nginx, WebServer::Apache] {
        let Some(binary) = server.binary() else {
            continue;
        };

        if is_listening(&server) {
            return format!("{} is running", server.as_str());
        }

        let started = if std::path::Path::new("/run/systemd/system").is_dir() {
            std::process::Command::new("systemctl")
                .args(["start", server.as_str()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            // No init: start it directly. nginx and apache both daemonise.
            let mut command = std::process::Command::new(&binary);
            if server == WebServer::Apache {
                command.arg("-k").arg("start");
            }
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if started {
            return format!("{} started", server.as_str());
        }
        return format!("{} is installed but would not start", server.as_str());
    }

    "no web server installed".to_string()
}

impl WebServer {
    fn binary(self) -> Option<PathBuf> {
        let candidates: &[&str] = match self {
            Self::Nginx => &["/usr/sbin/nginx"],
            Self::Apache => &["/usr/sbin/apache2", "/usr/sbin/httpd"],
        };
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }
}

/// Is a web server process actually up?
fn is_listening(server: &WebServer) -> bool {
    let name = match server {
        WebServer::Nginx => "nginx",
        WebServer::Apache => "apache2",
    };
    std::process::Command::new("pgrep")
        .args(["-x", name])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
