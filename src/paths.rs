//! Local-path confinement for the file-transfer tools.
//!
//! Tools that read or write files on *this* machine (`ssh_upload_file`,
//! `ssh_download_file`, `ubuntu_website_deployment`, `upload_config`,
//! `download_config`, `switch_backup_config.save_to`) only touch paths inside
//! one transfer directory. Without this, a prompt-injected agent could upload
//! `~/.ssh/id_ed25519` to any host it can reach, or drop a file into the
//! Windows Startup folder.
//!
//! The directory is `SSHCONNECT_TRANSFER_DIR`, else `[settings] transfer_dir`
//! in hosts.toml (editable in the web UI), else `~/ssh-connect-files`.
//! Relative paths are resolved inside it; absolute paths must already point
//! inside it. `..` and symlinks/junctions that lead outside are refused.

use std::path::{Component, Path, PathBuf};

use crate::config::Inventory;

/// What the caller is about to do with the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read an existing file (or, with `allow_dir`, a directory tree).
    Read,
    /// Create or overwrite a file; parent directories are created.
    Write,
}

/// The configured transfer directory (not yet created or canonicalised).
pub fn transfer_root() -> PathBuf {
    if let Ok(p) = std::env::var("SSHCONNECT_TRANSFER_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Some(p) = Inventory::load_raw()
        .ok()
        .and_then(|i| i.settings.transfer_dir)
    {
        return p;
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ssh-connect-files")
}

/// Resolve `user_path` for `access` inside the transfer directory.
pub fn resolve(user_path: &str, access: Access) -> Result<PathBuf, String> {
    resolve_in(&transfer_root(), user_path, access)
}

/// Remove `.` and `..` lexically. Fails if `..` would climb above the root of
/// the path.
fn normalize(p: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err("path climbs above its root".into());
                }
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Ok(out)
}

fn starts_with_ci(path: &Path, root: &Path) -> bool {
    if cfg!(windows) {
        let p = path.to_string_lossy().to_lowercase();
        let r = root.to_string_lossy().to_lowercase();
        Path::new(&p).starts_with(Path::new(&r))
    } else {
        path.starts_with(root)
    }
}

pub fn resolve_in(root: &Path, user_path: &str, access: Access) -> Result<PathBuf, String> {
    let outside = || {
        format!(
            "local path '{user_path}' is outside the transfer folder {}. Use a path relative to \
             that folder; the user can change the folder in `ssh-connect ui` → Настройки.",
            root.display()
        )
    };
    if user_path.trim().is_empty() {
        return Err("local path is empty".into());
    }
    std::fs::create_dir_all(root)
        .map_err(|e| format!("cannot create transfer folder {}: {e}", root.display()))?;
    let root_lex = normalize(&std::path::absolute(root).map_err(|e| e.to_string())?)?;
    let root_real = std::fs::canonicalize(root).map_err(|e| e.to_string())?;

    let p = Path::new(user_path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root_lex.join(p)
    };
    let candidate = normalize(&joined).map_err(|_| outside())?;
    if !starts_with_ci(&candidate, &root_lex) && !starts_with_ci(&candidate, &root_real) {
        return Err(outside());
    }

    match access {
        Access::Read => {
            // canonicalize follows every link, so the final target is checked.
            let real = std::fs::canonicalize(&candidate)
                .map_err(|e| format!("cannot read local '{}': {e}", candidate.display()))?;
            if !real.starts_with(&root_real) {
                return Err(outside());
            }
            Ok(real)
        }
        Access::Write => {
            let file_name = candidate
                .file_name()
                .ok_or_else(|| "local path must name a file".to_string())?;
            let parent = candidate.parent().ok_or_else(outside)?;
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create local folder '{}': {e}", parent.display()))?;
            let parent_real = std::fs::canonicalize(parent).map_err(|e| e.to_string())?;
            if !parent_real.starts_with(&root_real) {
                return Err(outside());
            }
            let target = parent_real.join(file_name);
            if let Ok(meta) = std::fs::symlink_metadata(&target) {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "refusing to write through a symlink: {}",
                        target.display()
                    ));
                }
                if meta.is_dir() {
                    return Err(format!("'{}' is a directory", target.display()));
                }
            }
            Ok(target)
        }
    }
}

/// True if `path` (already resolved) stays inside the transfer root once every
/// link is followed — used while walking a directory tree for upload.
pub fn still_inside(path: &Path) -> bool {
    let root = transfer_root();
    match (std::fs::canonicalize(&root), std::fs::canonicalize(path)) {
        (Ok(r), Ok(p)) => p.starts_with(r),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sshc-paths-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn relative_write_lands_inside_and_creates_parents() {
        let root = tmp_root();
        let p = resolve_in(&root, "backups/sw1.cfg", Access::Write).unwrap();
        assert!(p.starts_with(std::fs::canonicalize(&root).unwrap()));
        assert!(p.parent().unwrap().is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dotdot_and_absolute_escapes_are_refused() {
        let root = tmp_root();
        assert!(resolve_in(&root, "../evil.txt", Access::Write).is_err());
        assert!(resolve_in(&root, "a/../../evil.txt", Access::Write).is_err());
        assert!(resolve_in(&root, "/etc/passwd", Access::Read).is_err());
        let home_key = dirs::home_dir().unwrap().join(".ssh/id_ed25519");
        assert!(resolve_in(&root, home_key.to_str().unwrap(), Access::Read).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absolute_path_inside_root_is_allowed() {
        let root = tmp_root();
        std::fs::write(root.join("f.txt"), "x").unwrap();
        let abs = root.join("f.txt");
        let p = resolve_in(&root, abs.to_str().unwrap(), Access::Read).unwrap();
        assert_eq!(std::fs::read_to_string(p).unwrap(), "x");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escapes_are_refused() {
        let root = tmp_root();
        let outside = tmp_root();
        std::fs::write(outside.join("secret"), "s").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("link")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("dirlink")).unwrap();
        assert!(resolve_in(&root, "link", Access::Read).is_err());
        assert!(resolve_in(&root, "link", Access::Write).is_err());
        assert!(resolve_in(&root, "dirlink/new.txt", Access::Write).is_err());
        assert!(resolve_in(&root, "dirlink/secret", Access::Read).is_err());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn missing_file_for_read_is_an_error() {
        let root = tmp_root();
        assert!(resolve_in(&root, "nope.txt", Access::Read).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
