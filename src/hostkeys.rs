//! SSH host-key verification shared by both SSH paths (`ssh_connect` and the
//! interactive `connect`).
//!
//! Default policy is trust-on-first-use against `~/.ssh-connect/known_hosts`:
//! the first key seen for `host:port` is recorded and any later mismatch
//! refuses the connection (possible man-in-the-middle). A reinstalled device
//! legitimately changes its key — reset it from the web UI ("Забыть ключ") or
//! by deleting the line.
//!
//! Policy resolution: `SSHCONNECT_HOST_KEY_CHECK` (or legacy
//! `VPS_HOST_KEY_CHECK`) env var, then `[settings] host_key_check` in
//! hosts.toml, then the default (`tofu`). Values: `tofu`/`on`/`1`/`true`/`yes`
//! or `off`/`0`/`false`/`no`.

use std::path::{Path, PathBuf};

use crate::config::{data_dir, Inventory};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyPolicy {
    AcceptAny,
    Tofu(PathBuf),
}

fn parse_flag(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "tofu" | "1" | "true" | "on" | "yes" => Some(true),
        "off" | "0" | "false" | "no" | "none" => Some(false),
        _ => None,
    }
}

/// Resolve the policy once per connect.
pub fn host_key_policy() -> HostKeyPolicy {
    let from_env = ["SSHCONNECT_HOST_KEY_CHECK", "VPS_HOST_KEY_CHECK"]
        .iter()
        .find_map(|v| std::env::var(v).ok().and_then(|s| parse_flag(&s)));
    let enabled = from_env
        .or_else(|| {
            Inventory::load_raw()
                .ok()
                .and_then(|inv| inv.settings.host_key_check)
                .and_then(|s| parse_flag(&s))
        })
        .unwrap_or(true);
    if enabled {
        HostKeyPolicy::Tofu(known_hosts_path())
    } else {
        HostKeyPolicy::AcceptAny
    }
}

pub fn known_hosts_path() -> PathBuf {
    data_dir().join("known_hosts")
}

fn host_id(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// The key line recorded for `host:port`, if any.
fn recorded(path: &Path, id: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (stored_id, stored_key) = line.split_once(' ')?;
        (stored_id == id).then(|| stored_key.trim().to_string())
    })
}

/// Apply `policy` to the key a server presented. Returns whether to proceed.
pub fn verify(policy: &HostKeyPolicy, host: &str, port: u16, key: &russh::keys::PublicKey) -> bool {
    let path = match policy {
        HostKeyPolicy::AcceptAny => return true,
        HostKeyPolicy::Tofu(p) => p,
    };
    let key_line = match key.to_openssh() {
        Ok(k) => k.trim().to_string(),
        Err(_) => return false, // unencodable key — refuse rather than guess
    };
    let id = host_id(host, port);
    match recorded(path, &id) {
        Some(stored) if stored == key_line => true,
        Some(_) => {
            tracing::error!(
                host = %id,
                "host key MISMATCH — refusing connection (possible MITM). Reset it in `ssh-connect ui` \
                 or remove the line from {} if the device was reinstalled.",
                path.display()
            );
            false
        }
        None => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
                crate::config::restrict_dir(parent);
            }
            use std::io::Write;
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{id} {key_line}");
                    crate::config::restrict_file(path);
                }
                Err(e) => tracing::warn!(error = %e, "cannot record host key"),
            }
            let fp = key.fingerprint(Default::default());
            tracing::info!(host = %id, fingerprint = %fp, "learned new host key (TOFU)");
            true
        }
    }
}

/// SHA256 fingerprint of the recorded key for `host:port`, if any.
pub fn fingerprint(host: &str, port: u16) -> Option<String> {
    let line = recorded(&known_hosts_path(), &host_id(host, port))?;
    let key = russh::keys::PublicKey::from_openssh(&line).ok()?;
    Some(key.fingerprint(Default::default()).to_string())
}

/// Remove the recorded key for `host:port`. Returns whether one was removed.
pub fn forget(host: &str, port: u16) -> std::io::Result<bool> {
    forget_at(&known_hosts_path(), host, port)
}

fn forget_at(path: &Path, host: &str, port: u16) -> std::io::Result<bool> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let id = host_id(host, port);
    let mut removed = false;
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let hit = line
                .trim()
                .split_once(' ')
                .map(|(i, _)| i == id)
                .unwrap_or(false);
            removed |= hit;
            !hit
        })
        .collect();
    if removed {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        std::fs::write(path, out)?;
    }
    Ok(removed)
}

/// Turn a connect error into a message that says what to do on a key change.
pub fn explain_connect_error(e: &russh::Error, host: &str, port: u16) -> String {
    if matches!(e, russh::Error::UnknownKey) {
        format!(
            "host key for {host}:{port} does not match the one saved on first connect — refusing \
             (possible man-in-the-middle). If the device was reinstalled, ask the user to reset the \
             key in the SSH-Connect UI (`ssh-connect ui` → host → «Забыть ключ хоста»)."
        )
    } else {
        format!("ssh connect to {host}:{port}: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse() {
        assert_eq!(parse_flag("TOFU"), Some(true));
        assert_eq!(parse_flag("off"), Some(false));
        assert_eq!(parse_flag("maybe"), None);
    }

    #[test]
    fn forget_removes_only_that_host() {
        let dir = std::env::temp_dir().join(format!("sshc-kh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("known_hosts");
        std::fs::write(
            &p,
            "a:22 ssh-ed25519 AAAA1\nb:22 ssh-ed25519 AAAA2\na:2222 ssh-ed25519 AAAA3\n",
        )
        .unwrap();
        assert!(forget_at(&p, "a", 22).unwrap());
        assert!(!forget_at(&p, "a", 22).unwrap());
        let left = std::fs::read_to_string(&p).unwrap();
        assert_eq!(left, "b:22 ssh-ed25519 AAAA2\na:2222 ssh-ed25519 AAAA3\n");
        assert_eq!(recorded(&p, "a:2222").as_deref(), Some("ssh-ed25519 AAAA3"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
