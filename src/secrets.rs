//! Per-host secrets (login password, key passphrase, enable password).
//!
//! * **Windows:** the Windows Credential Manager (generic credentials named
//!   `ssh-connect:<kind>:<host>`), visible and removable under
//!   Control Panel → Credential Manager → Windows Credentials. Stored per user,
//!   encrypted by the OS, never roamed (`CRED_PERSIST_LOCAL_MACHINE`).
//! * **Elsewhere:** `~/.ssh-connect/secrets.json`, mode 0600 in a 0700
//!   directory. Weaker than an OS keyring; documented as such.
//!
//! Secrets are read by the MCP server process itself when it connects, so they
//! never pass through the model, the conversation, or the broker pipe.

/// Which secret of a host entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    Passphrase,
    Enable,
}

impl SecretKind {
    fn tag(self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::Passphrase => "passphrase",
            SecretKind::Enable => "enable",
        }
    }
}

fn target(host: &str, kind: SecretKind) -> String {
    format!("ssh-connect:{}:{host}", kind.tag())
}

/// Human-readable name of the backing store, for the UI.
pub fn backend_name() -> &'static str {
    if cfg!(windows) {
        "Диспетчер учётных данных Windows"
    } else {
        "~/.ssh-connect/secrets.json (0600)"
    }
}

/// Read a secret; `None` if absent or unreadable (the error is logged).
pub fn get(host: &str, kind: SecretKind) -> Option<String> {
    match backend::read(&target(host, kind)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(host, kind = kind.tag(), error = %e, "secret store read failed");
            None
        }
    }
}

pub fn has(host: &str, kind: SecretKind) -> bool {
    get(host, kind).is_some()
}

pub fn set(host: &str, kind: SecretKind, value: &str) -> Result<(), String> {
    backend::write(&target(host, kind), host, value).map_err(|e| format!("cannot save secret: {e}"))
}

/// Delete a secret; deleting a missing one is not an error.
pub fn delete(host: &str, kind: SecretKind) -> Result<(), String> {
    backend::delete(&target(host, kind)).map_err(|e| format!("cannot delete secret: {e}"))
}

/// Move every secret of `old` to `new` (host rename).
pub fn rename(old: &str, new: &str) -> Result<(), String> {
    if old == new {
        return Ok(());
    }
    for kind in [
        SecretKind::Password,
        SecretKind::Passphrase,
        SecretKind::Enable,
    ] {
        if let Some(v) = get(old, kind) {
            set(new, kind, &v)?;
            delete(old, kind)?;
        }
    }
    Ok(())
}

pub fn delete_all(host: &str) -> Result<(), String> {
    for kind in [
        SecretKind::Password,
        SecretKind::Passphrase,
        SecretKind::Enable,
    ] {
        delete(host, kind)?;
    }
    Ok(())
}

#[cfg(windows)]
use wincred as backend;

#[cfg(not(windows))]
use filestore as backend;

// ── Windows Credential Manager ───────────────────────────────────────────────
//
// Also compiled (not used) on other platforms with `--cfg ssh_connect_wincheck`
// so the FFI can be type-checked without a Windows toolchain.

#[cfg(any(windows, ssh_connect_wincheck))]
#[cfg_attr(not(windows), allow(dead_code))]
mod wincred {
    use std::io;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND, FILETIME};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn read(target: &str) -> io::Result<Option<String>> {
        let t = wide(target);
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `t` is NUL-terminated; on success `cred` points to a buffer
        // owned by the OS that we release with CredFree below.
        let ok = unsafe { CredReadW(t.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        // SAFETY: CredReadW succeeded, so `cred` is valid and its blob pointer
        // covers `CredentialBlobSize` bytes (or is null when the size is 0).
        let bytes = unsafe {
            let c = &*cred;
            let v = if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec()
            };
            CredFree(cred as *const core::ffi::c_void);
            v
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stored secret is not UTF-8"))
    }

    pub fn write(target: &str, user: &str, value: &str) -> io::Result<()> {
        let mut t = wide(target);
        let mut u = wide(user);
        let mut comment = wide("SSH-Connect");
        let mut blob = value.as_bytes().to_vec();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: t.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: u.as_mut_ptr(),
        };
        // SAFETY: every pointer in `cred` refers to a live, NUL-terminated
        // (strings) or correctly sized (blob) buffer for the duration of the call.
        let ok = unsafe { CredWriteW(&cred, 0) };
        blob.iter_mut().for_each(|b| *b = 0);
        if ok == 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ));
        }
        Ok(())
    }

    pub fn delete(target: &str) -> io::Result<()> {
        let t = wide(target);
        // SAFETY: `t` is NUL-terminated.
        let ok = unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(())
    }
}

// ── File fallback (non-Windows) ──────────────────────────────────────────────

#[cfg(not(windows))]
mod filestore {
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};

    fn path() -> PathBuf {
        crate::config::data_dir().join("secrets.json")
    }

    pub fn read(target: &str) -> io::Result<Option<String>> {
        read_at(&path(), target)
    }

    pub fn write(target: &str, _user: &str, value: &str) -> io::Result<()> {
        write_at(&path(), target, Some(value))
    }

    pub fn delete(target: &str) -> io::Result<()> {
        write_at(&path(), target, None)
    }

    fn load(p: &Path) -> io::Result<BTreeMap<String, String>> {
        match std::fs::read_to_string(p) {
            Ok(t) => {
                serde_json::from_str(&t).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }

    pub fn read_at(p: &Path, target: &str) -> io::Result<Option<String>> {
        Ok(load(p)?.remove(target))
    }

    pub fn write_at(p: &Path, target: &str, value: Option<&str>) -> io::Result<()> {
        let mut map = load(p)?;
        match value {
            Some(v) => {
                map.insert(target.to_string(), v.to_string());
            }
            None => {
                if map.remove(target).is_none() {
                    return Ok(());
                }
            }
        }
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
            crate::config::restrict_dir(dir);
        }
        let tmp = p.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(&map)?.as_bytes())?;
        }
        crate::config::restrict_file(&tmp);
        std::fs::rename(&tmp, p)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn write_read_delete() {
            let dir = std::env::temp_dir().join(format!("sshc-sec-{}", uuid::Uuid::new_v4()));
            let p = dir.join("secrets.json");
            assert_eq!(read_at(&p, "a").unwrap(), None);
            write_at(&p, "a", Some("pw1")).unwrap();
            write_at(&p, "b", Some("pw2")).unwrap();
            assert_eq!(read_at(&p, "a").unwrap().as_deref(), Some("pw1"));
            write_at(&p, "a", None).unwrap();
            assert_eq!(read_at(&p, "a").unwrap(), None);
            assert_eq!(read_at(&p, "b").unwrap().as_deref(), Some("pw2"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
