//! The panel's records: customers and their domains.
//!
//! Rust owns this store, not the panel. The PHP tier never holds a database
//! credential, so a fault in the web tier — an injection, an RCE — cannot reach
//! the data directly; it can only make control-API calls that Ember authorises.
//!
//! It also keeps the records next to the provisioning that creates them. A
//! customer row and the system account it names are written by the same code,
//! so the store cannot claim a domain exists when its vhost does not.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{config, daemon::now_secs};

/// Where a domain's files live. Everything for one domain sits under its own
/// root so it can be moved, backed up, or removed as a unit.
pub const VHOST_ROOT: &str = "/var/www/vhosts";
/// The subdirectory actually served to the world.
pub const DOCROOT_NAME: &str = "webroot";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: i64,
    /// The system account this customer owns. Files and pools run as this user.
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub status: String,
    pub created_at: u64,
    #[serde(default)]
    pub domain_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: i64,
    pub customer_id: i64,
    pub name: String,
    /// `/var/www/vhosts/<domain>`
    pub root: String,
    /// `/var/www/vhosts/<domain>/webroot`
    pub docroot: String,
    pub webserver: String,
    pub php_version: Option<String>,
    pub status: String,
    pub created_at: u64,
    /// Filled in when listing, so the UI need not join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_username: Option<String>,
}

pub fn database_file() -> Result<PathBuf> {
    Ok(config::ember_dir()?.join("ember.db"))
}

/// Open the store, applying the schema if it is not there yet.
pub fn open() -> Result<Connection> {
    config::ensure_dirs()?;
    let path = database_file()?;
    let conn =
        Connection::open(&path).with_context(|| format!("could not open {}", path.display()))?;

    // The store may be read by a request while another is writing it.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    migrate(&conn)?;

    // It records who owns what on this machine; nobody else needs to read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS customers (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL UNIQUE,
            display_name TEXT,
            email        TEXT,
            status       TEXT    NOT NULL DEFAULT 'active',
            created_at   INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS domains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL UNIQUE,
            root        TEXT    NOT NULL,
            docroot     TEXT    NOT NULL,
            webserver   TEXT    NOT NULL DEFAULT 'nginx',
            php_version TEXT,
            status      TEXT    NOT NULL DEFAULT 'active',
            created_at  INTEGER NOT NULL
         );

         CREATE INDEX IF NOT EXISTS domains_by_customer ON domains(customer_id);",
    )
    .context("could not apply the database schema")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// A hostname safe to put in a filesystem path and a server config.
///
/// Deliberately strict: this value becomes a directory name and is written into
/// a web server config, so anything exotic is rejected rather than escaped.
pub fn check_domain_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 253 {
        bail!("domain must be between 1 and 253 characters");
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        bail!("domain has an empty label");
    }
    if name.starts_with('-') || name.ends_with('-') {
        bail!("domain may not start or end with '-'");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        bail!("domain may use lowercase letters, digits, '.' and '-' only");
    }
    if !name.contains('.') {
        bail!("domain must include a dot, for example example.com");
    }
    Ok(())
}

/// The on-disk root for a domain.
pub fn root_for(name: &str) -> String {
    format!("{VHOST_ROOT}/{name}")
}

pub fn docroot_for(name: &str) -> String {
    format!("{VHOST_ROOT}/{name}/{DOCROOT_NAME}")
}

// ---------------------------------------------------------------------------
// Customers
// ---------------------------------------------------------------------------

pub fn list_customers(conn: &Connection) -> Result<Vec<Customer>> {
    let mut stmt = conn.prepare(
        "SELECT c.id, c.username, c.display_name, c.email, c.status, c.created_at,
                (SELECT COUNT(*) FROM domains d WHERE d.customer_id = c.id)
           FROM customers c
          ORDER BY c.username",
    )?;
    let rows = stmt.query_map([], row_to_customer)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn find_customer(conn: &Connection, id: i64) -> Result<Option<Customer>> {
    let mut stmt = conn.prepare(
        "SELECT c.id, c.username, c.display_name, c.email, c.status, c.created_at,
                (SELECT COUNT(*) FROM domains d WHERE d.customer_id = c.id)
           FROM customers c WHERE c.id = ?1",
    )?;
    Ok(stmt.query_row(params![id], row_to_customer).optional()?)
}

fn row_to_customer(row: &rusqlite::Row<'_>) -> rusqlite::Result<Customer> {
    Ok(Customer {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        email: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get::<_, i64>(5)? as u64,
        domain_count: row.get(6)?,
    })
}

pub fn create_customer(
    conn: &Connection,
    username: &str,
    display_name: Option<&str>,
    email: Option<&str>,
) -> Result<Customer> {
    crate::accounts::check_username(username)?;

    if conn
        .query_row(
            "SELECT 1 FROM customers WHERE username = ?1",
            params![username],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        bail!("a customer named {username:?} already exists");
    }

    conn.execute(
        "INSERT INTO customers (username, display_name, email, status, created_at)
         VALUES (?1, ?2, ?3, 'active', ?4)",
        params![username, display_name, email, now_secs() as i64],
    )?;

    find_customer(conn, conn.last_insert_rowid())?
        .context("the customer disappeared immediately after being written")
}

/// Remove a customer. Refuses while domains still point at it, so a delete
/// cannot silently orphan files on disk.
pub fn delete_customer(conn: &Connection, id: i64) -> Result<Customer> {
    let customer = find_customer(conn, id)?.context("no such customer")?;
    if customer.domain_count > 0 {
        bail!(
            "{} still has {} domain(s) — remove them first",
            customer.username,
            customer.domain_count
        );
    }
    conn.execute("DELETE FROM customers WHERE id = ?1", params![id])?;
    Ok(customer)
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

pub fn list_domains(conn: &Connection, customer_id: Option<i64>) -> Result<Vec<Domain>> {
    let sql = "SELECT d.id, d.customer_id, d.name, d.root, d.docroot, d.webserver,
                      d.php_version, d.status, d.created_at, c.username
                 FROM domains d
                 JOIN customers c ON c.id = d.customer_id
                WHERE (?1 IS NULL OR d.customer_id = ?1)
                ORDER BY d.name";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![customer_id], row_to_domain)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn find_domain(conn: &Connection, id: i64) -> Result<Option<Domain>> {
    let mut stmt = conn.prepare(
        "SELECT d.id, d.customer_id, d.name, d.root, d.docroot, d.webserver,
                d.php_version, d.status, d.created_at, c.username
           FROM domains d
           JOIN customers c ON c.id = d.customer_id
          WHERE d.id = ?1",
    )?;
    Ok(stmt.query_row(params![id], row_to_domain).optional()?)
}

fn row_to_domain(row: &rusqlite::Row<'_>) -> rusqlite::Result<Domain> {
    Ok(Domain {
        id: row.get(0)?,
        customer_id: row.get(1)?,
        name: row.get(2)?,
        root: row.get(3)?,
        docroot: row.get(4)?,
        webserver: row.get(5)?,
        php_version: row.get(6)?,
        status: row.get(7)?,
        created_at: row.get::<_, i64>(8)? as u64,
        customer_username: row.get(9)?,
    })
}

pub fn create_domain(
    conn: &Connection,
    customer_id: i64,
    name: &str,
    webserver: &str,
) -> Result<Domain> {
    check_domain_name(name)?;
    if !matches!(webserver, "nginx" | "apache") {
        bail!("webserver must be 'nginx' or 'apache'");
    }
    find_customer(conn, customer_id)?.context("no such customer")?;

    if conn
        .query_row(
            "SELECT 1 FROM domains WHERE name = ?1",
            params![name],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        bail!("{name} already exists on this server");
    }

    conn.execute(
        "INSERT INTO domains (customer_id, name, root, docroot, webserver, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
        params![
            customer_id,
            name,
            root_for(name),
            docroot_for(name),
            webserver,
            now_secs() as i64
        ],
    )?;

    find_domain(conn, conn.last_insert_rowid())?
        .context("the domain disappeared immediately after being written")
}

pub fn delete_domain(conn: &Connection, id: i64) -> Result<Domain> {
    let domain = find_domain(conn, id)?.context("no such domain")?;
    conn.execute("DELETE FROM domains WHERE id = ?1", params![id])?;
    Ok(domain)
}

/// Totals for the dashboard, in one round trip.
pub fn summary(conn: &Connection) -> Result<serde_json::Value> {
    let customers: i64 = conn.query_row("SELECT COUNT(*) FROM customers", [], |r| r.get(0))?;
    let domains: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;
    Ok(serde_json::json!({ "customers": customers, "domains": domains }))
}
