//! File management, confined to one domain's directory.
//!
//! Every operation here takes a path supplied by a browser, so containment is
//! the whole job. The rule is single and absolute: a resolved path must live
//! under the domain's root, or the operation is refused.
//!
//! Three ways out of a directory get closed:
//!
//! * `..` and absolute paths are rejected before anything touches the disk.
//! * The result is canonicalised, which resolves symlinks — so a link planted
//!   inside `httpdocs` pointing at `/etc` resolves outside the root and fails.
//! * For paths that do not exist yet the *parent* is canonicalised instead, so
//!   a new file cannot be created through a link either.
//!
//! Written files are handed to the customer's account, because a control panel
//! that leaves root-owned files in a customer's tree breaks their own site.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{config::Config, store::Domain};

/// Largest file the editor will load. Anything bigger is download-only —
/// reading it would mean holding it in memory twice to hand to the browser.
pub const MAX_EDIT_BYTES: u64 = 2 * 1024 * 1024;

/// Largest file that may be written through the API.
pub const MAX_WRITE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub name: String,
    /// Path relative to the domain root, always with a leading slash.
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified: u64,
    pub mode: String,
    pub owner: String,
    /// False for anything the editor should not open: too large, or binary.
    pub editable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<Entry>,
}

/// Turn a browser-supplied path into an absolute one inside the domain root.
///
/// `must_exist` distinguishes reading from creating: an existing path is
/// canonicalised itself, a new one has its parent canonicalised instead.
fn resolve(domain: &Domain, requested: &str, must_exist: bool) -> Result<PathBuf> {
    let root = PathBuf::from(&domain.root);
    let root_real =
        std::fs::canonicalize(&root).with_context(|| format!("{} is missing", root.display()))?;

    let relative = requested.trim().trim_start_matches('/');
    let candidate = root_real.join(relative);

    // Reject traversal and absolute segments before touching the filesystem.
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("path may not contain '..'"),
            Component::RootDir | Component::Prefix(_) => bail!("path must be relative"),
        }
    }

    let resolved = if must_exist {
        std::fs::canonicalize(&candidate).with_context(|| format!("no such file: /{relative}"))?
    } else {
        // The target may not exist; its parent must, and must be inside.
        let parent = candidate
            .parent()
            .context("path has no parent directory")?
            .to_path_buf();
        let parent_real = std::fs::canonicalize(&parent)
            .with_context(|| format!("no such directory: {}", parent.display()))?;
        if !parent_real.starts_with(&root_real) {
            bail!("path escapes the domain directory");
        }
        parent_real.join(candidate.file_name().context("path has no file name")?)
    };

    // The decisive check. Canonicalisation has already resolved any symlinks,
    // so a link pointing outside the root fails here.
    if !resolved.starts_with(&root_real) {
        bail!("path escapes the domain directory");
    }

    Ok(resolved)
}

/// The path as the UI shows it: relative to the root, leading slash.
fn display_path(domain: &Domain, absolute: &Path) -> String {
    let root = std::fs::canonicalize(&domain.root).unwrap_or_else(|_| PathBuf::from(&domain.root));
    match absolute.strip_prefix(&root) {
        Ok(rest) if rest.as_os_str().is_empty() => "/".to_string(),
        Ok(rest) => format!("/{}", rest.to_string_lossy()),
        Err(_) => "/".to_string(),
    }
}

fn owner_of(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    let uid = metadata.uid();
    // SAFETY: getpwuid returns a pointer we null-check and read immediately.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

fn mode_string(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:o}", metadata.permissions().mode() & 0o7777)
}

fn modified_secs(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Would the editor be able to open this?
fn looks_editable(path: &Path, size: u64) -> bool {
    if size > MAX_EDIT_BYTES {
        return false;
    }
    // Sniff the head rather than reading the whole file: a NUL byte means
    // binary, and so does anything that is not valid UTF-8.
    let Ok(bytes) = read_head(path, 4096) else {
        return false;
    };
    !bytes.contains(&0) && std::str::from_utf8(&bytes).is_ok()
}

fn read_head(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; limit];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(buffer)
}

/// List one directory.
pub fn list(domain: &Domain, requested: &str) -> Result<Listing> {
    let dir = resolve(domain, requested, true)?;
    if !dir.is_dir() {
        bail!("not a directory");
    }

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("cannot read {requested}"))? {
        let entry = entry?;
        let path = entry.path();
        // symlink_metadata: describe the link itself rather than its target,
        // so a dangling or escaping link still lists instead of erroring.
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let is_symlink = metadata.file_type().is_symlink();
        let is_dir = if is_symlink {
            path.is_dir()
        } else {
            metadata.is_dir()
        };
        let size = metadata.len();

        entries.push(Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            path: display_path(domain, &path),
            is_dir,
            is_symlink,
            size,
            modified: modified_secs(&metadata),
            mode: mode_string(&metadata),
            owner: owner_of(&metadata),
            editable: !is_dir && !is_symlink && looks_editable(&path, size),
        });
    }

    // Directories first, then by name — the ordering every file browser uses.
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));

    let shown = display_path(domain, &dir);
    let parent = if shown == "/" {
        None
    } else {
        Some(
            Path::new(&shown)
                .parent()
                .map(|p| {
                    let text = p.to_string_lossy().into_owned();
                    if text.is_empty() { "/".into() } else { text }
                })
                .unwrap_or_else(|| "/".into()),
        )
    };

    Ok(Listing {
        path: shown,
        parent,
        entries,
    })
}

/// Read a text file for the editor.
pub fn read(domain: &Domain, requested: &str) -> Result<String> {
    let path = resolve(domain, requested, true)?;
    let metadata = std::fs::metadata(&path)?;
    if metadata.is_dir() {
        bail!("that is a directory");
    }
    if metadata.len() > MAX_EDIT_BYTES {
        bail!(
            "file is {} KB; the editor opens files up to {} KB",
            metadata.len() / 1024,
            MAX_EDIT_BYTES / 1024
        );
    }
    std::fs::read_to_string(&path).context("file is not text")
}

/// Read raw bytes for download.
pub fn read_bytes(domain: &Domain, requested: &str) -> Result<(String, Vec<u8>)> {
    let path = resolve(domain, requested, true)?;
    if path.is_dir() {
        bail!("that is a directory");
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    Ok((name, std::fs::read(&path)?))
}

/// Hand a path to the domain's owner, so the customer keeps control of files
/// the panel creates on their behalf.
fn give_to_owner(path: &Path, owner: &str) -> Result<()> {
    let cname = std::ffi::CString::new(owner)?;
    // SAFETY: getpwnam returns a pointer we null-check before reading.
    let (uid, gid) = unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            // No such account is not fatal here: the file is written either
            // way, and reporting it would obscure a successful save.
            return Ok(());
        }
        ((*pw).pw_uid, (*pw).pw_gid)
    };

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: lchown on a path already proven to be inside the domain root.
    unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    Ok(())
}

pub fn write(cfg: &Config, domain: &Domain, requested: &str, content: &str) -> Result<String> {
    cfg.require_host_mode("write files")?;

    if content.len() > MAX_WRITE_BYTES {
        bail!("file is larger than {} MB", MAX_WRITE_BYTES / 1024 / 1024);
    }

    let path = resolve(domain, requested, false)?;
    if path.is_dir() {
        bail!("that is a directory");
    }

    std::fs::write(&path, content).with_context(|| format!("could not write {requested}"))?;
    if let Some(owner) = &domain.customer_username {
        give_to_owner(&path, owner)?;
    }

    Ok(display_path(domain, &path))
}

pub fn mkdir(cfg: &Config, domain: &Domain, requested: &str) -> Result<String> {
    cfg.require_host_mode("create directories")?;

    let path = resolve(domain, requested, false)?;
    if path.exists() {
        bail!("that already exists");
    }

    std::fs::create_dir(&path).with_context(|| format!("could not create {requested}"))?;
    if let Some(owner) = &domain.customer_username {
        give_to_owner(&path, owner)?;
    }

    Ok(display_path(domain, &path))
}

pub fn rename(cfg: &Config, domain: &Domain, from: &str, to: &str) -> Result<String> {
    cfg.require_host_mode("rename files")?;

    let source = resolve(domain, from, true)?;
    let target = resolve(domain, to, false)?;
    if target.exists() {
        bail!("something already exists at that name");
    }

    std::fs::rename(&source, &target).context("could not rename")?;
    Ok(display_path(domain, &target))
}

/// Delete a file, or a directory and everything under it.
pub fn delete(cfg: &Config, domain: &Domain, requested: &str) -> Result<String> {
    cfg.require_host_mode("delete files")?;

    let path = resolve(domain, requested, true)?;
    let root = std::fs::canonicalize(&domain.root)?;

    // Deleting the root would remove the site while leaving the record behind;
    // that is what removing the domain is for.
    if path == root {
        bail!("cannot delete the domain root — remove the domain instead");
    }

    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        std::fs::remove_file(&path)?;
    } else {
        std::fs::remove_dir_all(&path)?;
    }

    Ok(display_path(domain, &path))
}
