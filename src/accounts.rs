//! Panel accounts — the minimum needed for setup and recovery.
//!
//! This is deliberately **not** a parallel user system. Real panel users are
//! system users authenticated through PAM; this store exists for two jobs only:
//!
//! 1. **Setup** — bootstrap the very first administrator, before any system
//!    account has been designated as a panel user.
//! 2. **Recovery** — get back in when PAM or the system account is unusable.
//!
//! It also holds the handful of facts a Unix account cannot carry: an email
//! address, a display name, and whether the account administers the panel.
//!
//! A `Local` account stores an Argon2 hash here. A `System` account stores no
//! credential at all — the password lives in the system database where it
//! belongs, and PAM checks it.

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use serde::{Deserialize, Serialize};

use crate::{config, daemon::now_secs};

/// Where a password is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Verified against the system user database via PAM.
    System,
    /// Verified against an Argon2 hash stored here. Bootstrap and recovery only.
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub created_at: u64,
    /// Argon2 PHC string. Only ever set for `Source::Local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_hash: Option<String>,
}

impl Account {
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        match self.source {
            Source::System => {
                let service = crate::pam::default_service();
                crate::pam::authenticate(&service, &self.username, password)
            }
            Source::Local => {
                let Some(stored) = self.password_hash.as_deref() else {
                    return Ok(false);
                };
                let parsed = PasswordHash::new(stored)
                    .map_err(|err| anyhow::anyhow!("stored password hash is unreadable: {err}"))?;
                Ok(Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok())
            }
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    accounts: BTreeMap<String, Account>,
}

fn accounts_file() -> Result<PathBuf> {
    Ok(config::ember_dir()?.join("accounts.json"))
}

pub fn hash_password(password: &str) -> Result<String> {
    // Salt from /dev/urandom, the same source the session key uses — avoids
    // depending on argon2's optional RNG feature.
    let salt = SaltString::encode_b64(&crate::auth::random_bytes(16)?)
        .map_err(|err| anyhow::anyhow!("could not build a password salt: {err}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("could not hash password: {err}"))?
        .to_string())
}

/// Reject passwords that would make the panel trivially breakable.
pub fn check_password_strength(password: &str) -> Result<()> {
    if password.chars().count() < 12 {
        bail!("password must be at least 12 characters");
    }
    if password.chars().all(|c| c.is_ascii_digit()) {
        bail!("password must not be only digits");
    }
    const OBVIOUS: [&str; 6] = [
        "password", "changeme", "admin123", "12345678", "letmein", "ember",
    ];
    let lowered = password.to_ascii_lowercase();
    if OBVIOUS.iter().any(|bad| lowered == *bad) {
        bail!("that password is too easy to guess");
    }
    Ok(())
}

/// A username acceptable both here and as a future system account.
pub fn check_username(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        bail!("username must be between 1 and 32 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        || name.starts_with('-')
    {
        bail!("username may use lowercase letters, digits, '-' and '_' only");
    }
    Ok(())
}

impl Store {
    pub fn load() -> Self {
        let Ok(path) = accounts_file() else {
            return Self::default();
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str(&raw) {
            Ok(store) => store,
            Err(err) => {
                eprintln!("warning: ignoring {}: {err}", path.display());
                Self::default()
            }
        }
    }

    fn save(&self) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        config::ensure_dirs()?;
        let path = accounts_file()?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("could not write {}", path.display()))?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(self)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Has the panel been set up yet? Drives the first-run redirect.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    pub fn get(&self, username: &str) -> Option<&Account> {
        self.accounts.get(username)
    }

    pub fn list(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }

    /// Create the first administrator. Refuses once one exists, so the setup
    /// page cannot be replayed to mint a second admin.
    pub fn create_admin(
        &mut self,
        username: &str,
        password: &str,
        email: Option<String>,
        display_name: Option<String>,
        source: Source,
    ) -> Result<()> {
        if !self.is_empty() {
            bail!("the panel has already been set up");
        }
        check_username(username)?;
        check_password_strength(password)?;

        let password_hash = match source {
            Source::Local => Some(hash_password(password)?),
            // A system account's password lives in the system database.
            Source::System => None,
        };

        self.accounts.insert(
            username.to_string(),
            Account {
                username: username.to_string(),
                source,
                email,
                display_name,
                is_admin: true,
                created_at: now_secs(),
                password_hash,
            },
        );
        self.save()
    }

    /// Reset a local account's password — the recovery path, driven from the
    /// CLI so it requires being on the machine.
    pub fn reset_password(&mut self, username: &str, password: &str) -> Result<()> {
        check_password_strength(password)?;
        let Some(account) = self.accounts.get_mut(username) else {
            bail!("no panel account named {username:?}");
        };
        if account.source == Source::System {
            bail!(
                "{username:?} authenticates against the system password — \
                 change it with passwd(1), not here"
            );
        }
        account.password_hash = Some(hash_password(password)?);
        self.save()
    }

    /// Add a recovery account when the configured admin can no longer log in.
    pub fn upsert_local_admin(&mut self, username: &str, password: &str) -> Result<()> {
        check_username(username)?;
        check_password_strength(password)?;

        let hash = hash_password(password)?;
        self.accounts
            .entry(username.to_string())
            .and_modify(|account| {
                account.source = Source::Local;
                account.is_admin = true;
                account.password_hash = Some(hash.clone());
            })
            .or_insert_with(|| Account {
                username: username.to_string(),
                source: Source::Local,
                email: None,
                display_name: None,
                is_admin: true,
                created_at: now_secs(),
                password_hash: Some(hash),
            });
        self.save()
    }
}
