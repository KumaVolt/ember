//! Authentication against real system accounts.
//!
//! Panel users *are* Unix users — there is no separate user table. Ember, which
//! runs privileged, is the only thing that resolves identities; PHP never sees a
//! credential, it only receives an already-authenticated `REMOTE_USER`.
//!
//! `ember login` mints a single-use token and prints a URL. Redeeming that URL
//! exchanges the token for an HMAC-signed session cookie.

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io::Read,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{config, daemon::now_secs};

type HmacSha256 = Hmac<Sha256>;

/// How long a printed login URL stays usable.
pub const LOGIN_TOKEN_TTL: Duration = Duration::from_secs(180);
/// How long a browser session lasts before re-login.
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 12);

pub const SESSION_COOKIE: &str = "ember_session";

fn secret_file() -> Result<PathBuf> {
    Ok(config::ember_dir()?.join("secret.key"))
}

fn token_file() -> Result<PathBuf> {
    Ok(config::run_dir()?.join("login-tokens.json"))
}

/// Cryptographically random bytes straight from the kernel.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .context("could not open /dev/urandom")?
        .read_exact(&mut buf)
        .context("could not read random bytes")?;
    Ok(buf)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The server's signing key, created on first use with owner-only permissions.
///
/// Cached after the first read: every authenticated request verifies a cookie,
/// and re-reading the key from disk each time would be a syscall per request.
/// The signing key, for callers that derive their own key from it.
pub fn secret_key_bytes() -> Result<Vec<u8>> {
    secret_key()
}

fn secret_key() -> Result<Vec<u8>> {
    static CACHED: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(key) = CACHED.get() {
        return Ok(key.clone());
    }
    let key = load_or_create_secret_key()?;
    Ok(CACHED.get_or_init(|| key).clone())
}

fn load_or_create_secret_key() -> Result<Vec<u8>> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = secret_file()?;
    if let Ok(existing) = std::fs::read(&path)
        && existing.len() >= 32
    {
        return Ok(existing);
    }

    config::ensure_dirs()?;
    let key = random_bytes(32)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("could not create {}", path.display()))?;
    std::io::Write::write_all(&mut file, &key)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// System users
// ---------------------------------------------------------------------------

/// The system account Ember is currently running as.
pub fn current_username() -> Result<String> {
    // SAFETY: geteuid cannot fail; getpwuid returns a pointer we only read.
    unsafe {
        let uid = libc::geteuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            bail!("could not resolve the current system user (uid {uid})");
        }
        Ok(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

/// Does this name correspond to a real account in the system user database?
pub fn system_user_exists(name: &str) -> bool {
    let Ok(cname) = CString::new(name) else {
        return false;
    };
    // SAFETY: getpwnam takes a NUL-terminated string and returns a pointer we
    // only test for null.
    unsafe { !libc::getpwnam(cname.as_ptr()).is_null() }
}

/// Home directory of a system account, if it has one.
pub fn system_user_home(name: &str) -> Option<PathBuf> {
    let cname = CString::new(name).ok()?;
    // SAFETY: as above; pw_dir is read before any other libc call can clobber it.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(PathBuf::from(
            CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned(),
        ))
    }
}

/// The primary group of a system account, resolved through the user database.
///
/// Never guess this from the user name: on Debian `nobody`'s group is `nogroup`,
/// on RHEL it is `nobody`, and a dedicated account gets whatever it was created
/// with. Asking the system is the only portable answer.
pub fn primary_group_of(user: &str) -> Option<String> {
    let cname = CString::new(user).ok()?;
    // SAFETY: both lookups return pointers we test for null and only read from
    // before making any further libc call that could clobber the static buffer.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return None;
        }
        let group = libc::getgrgid((*pw).pw_gid);
        if group.is_null() {
            return None;
        }
        Some(
            CStr::from_ptr((*group).gr_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// A system account as the panel sees it.
#[derive(Debug, Clone, Serialize)]
pub struct SystemUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Regular login accounts, skipping the daemon/service entries.
///
/// The uid floor is where distributions start handing out human accounts (1000
/// on Debian and friends, 500 on older RHEL); root is included deliberately
/// because it is a legitimate panel login.
pub fn list_system_users(uid_floor: u32) -> Vec<SystemUser> {
    let mut users = Vec::new();
    // SAFETY: the getpwent walk is bracketed by setpwent/endpwent, and each
    // entry is copied out before the next call reuses the static buffer.
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() {
                break;
            }
            let uid = (*pw).pw_uid;
            if uid != 0 && uid < uid_floor {
                continue;
            }
            users.push(SystemUser {
                name: CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned(),
                uid,
                gid: (*pw).pw_gid,
                home: CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned(),
                shell: CStr::from_ptr((*pw).pw_shell)
                    .to_string_lossy()
                    .into_owned(),
            });
        }
        libc::endpwent();
    }
    users.sort_by_key(|u| u.uid);
    // macOS serves the same account from both /etc/passwd and Open Directory,
    // so the same name can come back twice.
    let mut seen = std::collections::HashSet::new();
    users.retain(|u| seen.insert(u.name.clone()));
    users
}

/// Create a system account for a panel user.
///
/// Gated on host mode by the caller — this is precisely the operation that must
/// never fire against a developer's own machine.
pub fn create_system_user(name: &str, shell: &str) -> Result<()> {
    // Checked here, not just at the call site: this is the function that runs
    // useradd, so this is where refusing has to be unconditional.
    crate::config::Config::current_mode()?.require_host("create a system user")?;
    if !running_as_root() {
        bail!("creating a system user requires root");
    }
    if system_user_exists(name) {
        bail!("system user {name:?} already exists");
    }
    // Guard against a name being smuggled into the useradd argument list.
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        || name.starts_with('-')
    {
        bail!("invalid system user name {name:?} — use lowercase letters, digits, '-' and '_'");
    }

    let status = std::process::Command::new("useradd")
        .args(["--create-home", "--shell", shell, name])
        .status()
        .context("could not run useradd — is it installed and are we root?")?;

    if !status.success() {
        bail!("useradd failed for {name:?} ({status})");
    }
    Ok(())
}

/// Set a system account's password.
///
/// Uses `chpasswd` so the hashing and shadow-file handling stay with the
/// system's own tooling rather than being reimplemented here.
pub fn set_system_password(user: &str, password: &str) -> Result<()> {
    use std::io::Write as _;

    crate::config::Config::current_mode()?.require_host("change a system password")?;
    if !running_as_root() {
        bail!("setting a system password requires root");
    }
    if !system_user_exists(user) {
        bail!("no system user named {user:?}");
    }
    if password.contains('\n') || user.contains(':') {
        bail!("invalid credentials for chpasswd");
    }

    let mut child = std::process::Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("could not run chpasswd")?;

    child
        .stdin
        .as_mut()
        .context("chpasswd stdin unavailable")?
        .write_all(format!("{user}:{password}\n").as_bytes())
        .context("could not write to chpasswd")?;

    let status = child.wait().context("chpasswd did not complete")?;
    if !status.success() {
        bail!("chpasswd failed ({status})");
    }
    Ok(())
}

pub fn running_as_root() -> bool {
    // SAFETY: geteuid is always safe and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---------------------------------------------------------------------------
// One-time login tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct TokenRecord {
    user: String,
    expires_at: u64,
}

/// Tokens are stored hashed, so a readable token file cannot be replayed.
fn hash_token(token: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(&secret_key()?).expect("hmac accepts any key length");
    mac.update(token.as_bytes());
    Ok(to_hex(&mac.finalize().into_bytes()))
}

fn load_tokens() -> HashMap<String, TokenRecord> {
    let Ok(path) = token_file() else {
        return HashMap::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_tokens(tokens: &HashMap<String, TokenRecord>) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    config::ensure_dirs()?;
    let path = token_file()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("could not write {}", path.display()))?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(tokens)?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Mint a single-use login token for a system account.
///
/// Root may issue a token for anyone; anyone else may only issue one for
/// themselves.
pub fn issue_login_token(requested_user: Option<&str>) -> Result<(String, String)> {
    let me = current_username()?;
    let user = match requested_user {
        None => me,
        Some(target) if target == me => me,
        Some(target) if running_as_root() => target.to_string(),
        Some(target) => bail!(
            "only root may issue a login link for another user (you are {me}, requested {target})"
        ),
    };

    if !system_user_exists(&user) {
        bail!("{user:?} is not a system user on this machine");
    }

    let token = to_hex(&random_bytes(32)?);
    let mut tokens = load_tokens();

    // Opportunistically drop anything already expired.
    let now = now_secs();
    tokens.retain(|_, record| record.expires_at > now);

    tokens.insert(
        hash_token(&token)?,
        TokenRecord {
            user: user.clone(),
            expires_at: now + LOGIN_TOKEN_TTL.as_secs(),
        },
    );
    save_tokens(&tokens)?;

    Ok((token, user))
}

/// Redeem a login token. Succeeds at most once per token.
pub fn consume_login_token(token: &str) -> Result<Option<String>> {
    let hashed = hash_token(token)?;
    let mut tokens = load_tokens();

    let Some(record) = tokens.remove(&hashed) else {
        return Ok(None);
    };
    save_tokens(&tokens)?;

    if record.expires_at <= now_secs() {
        return Ok(None);
    }
    // The account could have been removed between issuing and redeeming.
    if !system_user_exists(&record.user) {
        return Ok(None);
    }
    Ok(Some(record.user))
}

// ---------------------------------------------------------------------------
// Session cookies
// ---------------------------------------------------------------------------

/// `user|expires|signature` — signed, not encrypted; it carries no secret.
pub fn sign_session(user: &str, expires_at: u64) -> Result<String> {
    let payload = format!("{user}|{expires_at}");
    let mut mac = HmacSha256::new_from_slice(&secret_key()?).expect("hmac accepts any key length");
    mac.update(payload.as_bytes());
    Ok(format!(
        "{payload}|{}",
        to_hex(&mac.finalize().into_bytes())
    ))
}

/// Verify a session cookie and return the authenticated system user.
pub fn verify_session(cookie: &str) -> Result<Option<String>> {
    let mut parts = cookie.rsplitn(2, '|');
    let (Some(signature), Some(payload)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let Some(signature) = from_hex(signature) else {
        return Ok(None);
    };

    let mut mac = HmacSha256::new_from_slice(&secret_key()?).expect("hmac accepts any key length");
    mac.update(payload.as_bytes());
    // Constant-time comparison; a mismatch is an ordinary failed auth.
    if mac.verify_slice(&signature).is_err() {
        return Ok(None);
    }

    let Some((user, expires)) = payload.split_once('|') else {
        return Ok(None);
    };
    let Ok(expires) = expires.parse::<u64>() else {
        return Ok(None);
    };
    if expires <= now_secs() || !identity_still_valid(user) {
        return Ok(None);
    }
    Ok(Some(user.to_string()))
}

/// Is this identity still one the panel recognises?
///
/// Checked on every request so that deleting an account also revokes its live
/// sessions. Both identity sources count: a system user (the normal case, and
/// what `ember login` mints tokens for) or a panel account from the setup and
/// recovery store — which is not backed by a Unix account in isolated mode.
fn identity_still_valid(user: &str) -> bool {
    system_user_exists(user) || crate::accounts::Store::load().get(user).is_some()
}
