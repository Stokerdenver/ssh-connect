//! Host inventory (`hosts.toml`) and server settings, with environment-variable
//! overrides.
//!
//! A host entry names a device and the parameters needed to reach it. The file
//! lives in the per-user data directory (`~/.ssh-connect/hosts.toml`, i.e.
//! `%USERPROFILE%\.ssh-connect\hosts.toml` on Windows) — never the current
//! working directory, so a repository that ships its own `hosts.toml` cannot
//! redirect saved host names to other addresses. Point elsewhere with
//! `SSHCONNECT_HOSTS`.
//!
//! The file is re-read on every use, so hosts added or edited in the web UI
//! (`ssh-connect ui`) take effect on the next tool call without restarting the
//! MCP client.
//!
//! Secrets do not belong in this file. The web UI stores them in the OS
//! credential store (see [`crate::secrets`]); `SSHCONNECT_<STEM>_PASSWORD`
//! environment variables and a plaintext `password` key are still honoured for
//! compatibility. For a host named `core-sw-01` the stem is `CORE_SW_01`.

use crate::secrets::{self, SecretKind};
use crate::transport::Protocol;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One device in the inventory. Fields mirror the `connect` tool arguments so a
/// caller can `connect` by `name` alone and have the rest filled in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HostEntry {
    pub name: String,
    /// Free-text note shown to the agent in `list_hosts` (what the box is for).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Legacy plaintext password. Read for compatibility, never written by the
    /// UI (which moves it into the credential store on the next save).
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    /// Serial-only: COM port name (e.g. "COM3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_port: Option<String>,
    /// Serial-only: baud rate (default 9600 applied at connect time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baud: Option<u32>,
    /// Optional explicit prompt regex override for this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

impl HostEntry {
    /// The port the entry dials, with the protocol default applied.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.protocol {
            Protocol::Telnet => 23,
            _ => 22,
        })
    }

    /// Where this entry points (protocol, address, port, serial port, user).
    /// Sessions remember it so stored secrets are not used after an edit
    /// retargets the entry.
    pub fn signature(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol,
            self.host.as_deref().unwrap_or(""),
            self.effective_port(),
            self.serial_port.as_deref().unwrap_or(""),
            self.username.as_deref().unwrap_or("")
        )
    }

    /// The login password for this entry: env override, then the credential
    /// store, then a legacy plaintext `password` key.
    pub fn resolve_password(&self) -> Option<String> {
        env_override(&self.name, "PASSWORD")
            .or_else(|| secrets::get(&self.name, SecretKind::Password))
            .or_else(|| self.password.clone())
    }

    /// Passphrase for `key_path`, from the env or the credential store.
    pub fn resolve_passphrase(&self) -> Option<String> {
        env_override(&self.name, "PASSPHRASE")
            .or_else(|| secrets::get(&self.name, SecretKind::Passphrase))
    }

    /// Enable (privileged-mode) password for network devices.
    pub fn resolve_enable_password(&self) -> Option<String> {
        env_override(&self.name, "ENABLE_PASSWORD")
            .or_else(|| secrets::get(&self.name, SecretKind::Enable))
    }
}

/// Server-wide settings, editable in the web UI (`[settings]` in hosts.toml).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Settings {
    /// The only local directory file-transfer tools may read from or write to.
    /// Default: `~/ssh-connect-files`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_dir: Option<PathBuf>,
    /// Host-key verification: "tofu" (default) or "off".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_check: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct RawInventory {
    #[serde(default)]
    settings: Settings,
    #[serde(default, rename = "host")]
    hosts: Vec<HostEntry>,
}

/// The loaded inventory, in file order.
#[derive(Debug, Default, Clone)]
pub struct Inventory {
    pub settings: Settings,
    hosts: Vec<HostEntry>,
}

/// `~/.ssh-connect` — per-user data directory (inventory, known_hosts).
pub fn data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh-connect")
}

impl Inventory {
    /// Where the inventory lives: `$SSHCONNECT_HOSTS`, else
    /// `~/.ssh-connect/hosts.toml`.
    pub fn path() -> PathBuf {
        match std::env::var("SSHCONNECT_HOSTS") {
            Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
            _ => data_dir().join("hosts.toml"),
        }
    }

    /// Load the inventory for use by tools: env-var overrides applied. A
    /// missing or unreadable file yields an empty inventory (logged).
    pub fn load_default() -> Self {
        match Self::load_raw() {
            Ok(mut inv) => {
                for entry in &mut inv.hosts {
                    apply_env_overrides(entry);
                }
                inv
            }
            Err(e) => {
                tracing::warn!(path = %Self::path().display(), error = %e, "host inventory not loaded");
                Inventory::default()
            }
        }
    }

    /// Load the file exactly as written (no env overrides) — what the UI edits.
    pub fn load_raw() -> anyhow::Result<Self> {
        Self::load_from(&Self::path())
    }

    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let raw: RawInventory = toml::from_str(&text)?;
        Ok(Self {
            settings: raw.settings,
            hosts: raw.hosts,
        })
    }

    /// Write the inventory back atomically (temp file + rename).
    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::path())
    }

    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        let raw = RawInventory {
            settings: self.settings.clone(),
            hosts: self.hosts.clone(),
        };
        let body = toml::to_string_pretty(&raw)?;
        let text = format!(
            "# SSH-Connect host inventory. Managed by `ssh-connect ui`; hand edits are\n\
             # fine but comments are not preserved. Passwords live in the OS credential\n\
             # store, not in this file.\n\n{body}"
        );
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            restrict_dir(dir);
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        restrict_file(&tmp);
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&HostEntry> {
        self.hosts.iter().find(|h| h.name == name)
    }

    #[allow(dead_code)] // part of the inventory API
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    #[allow(dead_code)] // companion to len(); part of the inventory API
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Entries in file order, for `list_hosts` and the UI.
    pub fn summaries(&self) -> Vec<&HostEntry> {
        self.hosts.iter().collect()
    }

    /// Insert or replace an entry. `previous_name` is the entry being edited
    /// (for renames); the new name must not collide with a different entry.
    pub fn upsert(&mut self, entry: HostEntry, previous_name: Option<&str>) -> Result<(), String> {
        validate_name(&entry.name)?;
        let editing = previous_name.unwrap_or(&entry.name).to_string();
        if entry.name != editing && self.get(&entry.name).is_some() {
            return Err(format!("a host named '{}' already exists", entry.name));
        }
        match self.hosts.iter_mut().find(|h| h.name == editing) {
            Some(slot) => *slot = entry,
            None => self.hosts.push(entry),
        }
        Ok(())
    }

    /// Remove an entry; true if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|h| h.name != name);
        self.hosts.len() != before
    }
}

/// Host names are what the agent sees and what keys the credential store, so
/// keep them printable and bounded. Brackets, dots and dashes are fine
/// (`m300[152]`, `qa1.lab`).
pub fn validate_name(name: &str) -> Result<(), String> {
    let name_trimmed = name.trim();
    if name_trimmed.is_empty() {
        return Err("name must not be empty".into());
    }
    if name_trimmed != name {
        return Err("name must not start or end with spaces".into());
    }
    if name.chars().count() > 64 {
        return Err("name must be 64 characters or fewer".into());
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == ':' || c == '/' || c == '\\' || c == '"')
    {
        return Err("name must not contain control characters, ':', '/', '\\' or '\"'".into());
    }
    Ok(())
}

/// Normalise a host name into the env-var stem: upper-case, every run of
/// non-alphanumeric characters collapsed to a single underscore.
pub fn env_stem(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_us = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
            prev_us = false;
        } else if !prev_us {
            out.push('_');
            prev_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn env_override(name: &str, field: &str) -> Option<String> {
    std::env::var(format!("SSHCONNECT_{}_{field}", env_stem(name)))
        .ok()
        .filter(|v| !v.is_empty())
}

/// Apply `SSHCONNECT_<STEM>_<FIELD>` overrides (non-secret fields) to an entry.
/// Secrets are resolved lazily by the `resolve_*` methods instead.
fn apply_env_overrides(entry: &mut HostEntry) {
    let name = entry.name.clone();
    if let Some(v) = env_override(&name, "USERNAME") {
        entry.username = Some(v);
    }
    if let Some(v) = env_override(&name, "HOST") {
        entry.host = Some(v);
    }
    if let Some(v) = env_override(&name, "KEY_PATH") {
        entry.key_path = Some(PathBuf::from(v));
    }
    if let Some(v) = env_override(&name, "PORT").and_then(|s| s.parse().ok()) {
        entry.port = Some(v);
    }
}

/// Owner-only permissions on Unix; on Windows the user-profile ACL already
/// restricts the directory to the user, SYSTEM and Administrators.
pub fn restrict_dir(_dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(_dir, std::fs::Permissions::from_mode(0o700));
    }
}

pub fn restrict_file(_file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(_file, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_stem_normalises() {
        assert_eq!(env_stem("core-sw-01"), "CORE_SW_01");
        assert_eq!(env_stem("Console A"), "CONSOLE_A");
        assert_eq!(env_stem("a..b"), "A_B");
        assert_eq!(env_stem("_edge_"), "EDGE");
        assert_eq!(env_stem("m300[152]"), "M300_152");
    }

    #[test]
    fn parses_toml_inventory() {
        let toml = r#"
            [[host]]
            name = "core-sw-01"
            host = "10.0.0.2"
            protocol = "ssh"
            username = "admin"

            [[host]]
            name = "console-a"
            protocol = "serial"
            serial_port = "COM3"
            baud = 9600
        "#;
        let raw: RawInventory = toml::from_str(toml).unwrap();
        assert_eq!(raw.hosts.len(), 2);
        assert_eq!(raw.hosts[0].protocol, Protocol::Ssh);
        assert_eq!(raw.hosts[1].protocol, Protocol::Serial);
        assert_eq!(raw.hosts[1].serial_port.as_deref(), Some("COM3"));
        assert_eq!(raw.settings, Settings::default());
    }

    #[test]
    fn round_trips_without_writing_plaintext_passwords() {
        let dir = std::env::temp_dir().join(format!("sshc-inv-{}", uuid::Uuid::new_v4()));
        let path = dir.join("hosts.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            "[settings]\nhost_key_check = \"off\"\n\n[[host]]\nname = \"qa1\"\nhost = \"10.0.0.1\"\nprotocol = \"ssh\"\npassword = \"secret\"\n",
        )
        .unwrap();

        let mut inv = Inventory::load_from(&path).unwrap();
        assert_eq!(inv.get("qa1").unwrap().password.as_deref(), Some("secret"));
        assert_eq!(inv.settings.host_key_check.as_deref(), Some("off"));

        let mut e = inv.get("qa1").unwrap().clone();
        e.name = "m300[152]".into();
        e.description = Some("DUT".into());
        inv.upsert(e, Some("qa1")).unwrap();
        inv.save_to(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("secret"),
            "plaintext password must not be written: {text}"
        );
        let back = Inventory::load_from(&path).unwrap();
        assert!(back.get("qa1").is_none());
        let e = back.get("m300[152]").unwrap();
        assert_eq!(e.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(e.description.as_deref(), Some("DUT"));
        assert_eq!(back.settings.host_key_check.as_deref(), Some("off"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upsert_rejects_rename_onto_existing_name() {
        let mut inv = Inventory::default();
        let mk = |n: &str| HostEntry {
            name: n.into(),
            description: None,
            host: Some("h".into()),
            protocol: Protocol::Ssh,
            port: None,
            username: None,
            password: None,
            key_path: None,
            serial_port: None,
            baud: None,
            prompt: None,
        };
        inv.upsert(mk("a"), None).unwrap();
        inv.upsert(mk("b"), None).unwrap();
        assert!(inv.upsert(mk("b"), Some("a")).is_err());
        assert!(inv.upsert(mk("a"), Some("a")).is_ok());
        assert_eq!(inv.len(), 2);
        assert!(inv.remove("a"));
        assert!(!inv.remove("a"));
    }

    #[test]
    fn missing_file_is_an_empty_inventory() {
        let p = std::env::temp_dir().join(format!("sshc-none-{}.toml", uuid::Uuid::new_v4()));
        let inv = Inventory::load_from(&p).unwrap();
        assert!(inv.is_empty());
    }

    #[test]
    fn names_are_validated() {
        assert!(validate_name("m300[152]").is_ok());
        assert!(validate_name("windows[1.46]").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(" qa1").is_err());
        assert!(validate_name("a:b").is_err());
        assert!(validate_name("a\nb").is_err());
    }
}
