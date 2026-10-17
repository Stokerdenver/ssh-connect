//! `ssh-connect ui` — a small local web page for managing saved hosts.
//!
//! * Listens on 127.0.0.1 only, on a random port, and opens the browser.
//! * Every API call needs a per-run random token (carried in the URL fragment,
//!   which browsers never send to servers or in Referer) as a Bearer header.
//!   Cross-site pages cannot read it, cannot send the header without a CORS
//!   preflight we never answer, and DNS-rebinding is blocked by the Host check.
//! * Secrets go one way: the page can set or delete them, never read them back.
//!
//! The MCP server re-reads hosts.toml and the credential store on every call,
//! so changes here apply to the agent immediately.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::config::{HostEntry, Inventory, Settings};
use crate::hostkeys;
use crate::paths;
use crate::secrets::{self, SecretKind};
use crate::transport::Protocol;

const INDEX_HTML: &str = include_str!("index.html");
const MAX_BODY: usize = 64 * 1024;

pub struct UiOptions {
    pub port: u16,
    pub open_browser: bool,
}

/// Run the UI until the user stops it. Blocking; call from a blocking thread
/// with a handle to the async runtime (used for "test connection").
pub fn run(rt: tokio::runtime::Handle, opts: UiOptions) -> anyhow::Result<()> {
    let server = Server::http(("127.0.0.1", opts.port))
        .map_err(|e| anyhow::anyhow!("cannot listen on 127.0.0.1:{}: {e}", opts.port))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .ok_or_else(|| anyhow::anyhow!("no TCP listen address"))?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let url = format!("http://127.0.0.1:{port}/#token={token}");

    eprintln!();
    eprintln!("  SSH-Connect — управление хостами");
    eprintln!("  Откройте в браузере: {url}");
    eprintln!("  Хосты:  {}", Inventory::path().display());
    eprintln!("  Пароли: {}", secrets::backend_name());
    eprintln!("  Остановить: закройте это окно или нажмите Ctrl+C.");
    eprintln!();
    if opts.open_browser {
        open_browser(&url);
    }

    let ctx = Ctx { rt, token, port };
    for req in server.incoming_requests() {
        let stop = handle(&ctx, req);
        if stop {
            eprintln!("  Интерфейс остановлен.");
            break;
        }
    }
    Ok(())
}

struct Ctx {
    rt: tokio::runtime::Handle,
    token: String,
    port: u16,
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn with_security_headers<R: Read>(mut r: Response<R>) -> Response<R> {
    for (k, v) in [
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        (
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; \
             frame-ancestors 'none'",
        ),
    ] {
        r.add_header(header(k, v));
    }
    r
}

fn respond_json(req: Request, status: u16, body: Value) {
    let r = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json; charset=utf-8"));
    let _ = req.respond(with_security_headers(r));
}

fn err(req: Request, status: u16, msg: impl Into<String>) {
    respond_json(req, status, json!({ "error": msg.into() }));
}

fn header_value<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// Returns true when the server should stop.
fn handle(ctx: &Ctx, mut req: Request) -> bool {
    // DNS-rebinding guard: only our own origin names are acceptable.
    let allowed_hosts = [
        format!("127.0.0.1:{}", ctx.port),
        format!("localhost:{}", ctx.port),
    ];
    match header_value(&req, "Host") {
        Some(h) if allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)) => {}
        _ => {
            err(req, 421, "bad host");
            return false;
        }
    }
    if let Some(origin) = header_value(&req, "Origin") {
        let ok = allowed_hosts
            .iter()
            .any(|a| origin.eq_ignore_ascii_case(&format!("http://{a}")));
        if !ok {
            err(req, 403, "cross-origin request refused");
            return false;
        }
    }

    let url = req.url().split('?').next().unwrap_or("/").to_string();
    let method = req.method().clone();

    if method == Method::Get && (url == "/" || url == "/index.html") {
        let r = Response::from_string(INDEX_HTML)
            .with_header(header("Content-Type", "text/html; charset=utf-8"));
        let _ = req.respond(with_security_headers(r));
        return false;
    }

    if !url.starts_with("/api/") {
        err(req, 404, "not found");
        return false;
    }

    // Everything under /api needs the per-run token.
    let expected = format!("Bearer {}", ctx.token);
    let authorized = header_value(&req, "Authorization")
        .map(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);
    if !authorized {
        err(
            req,
            401,
            "missing or wrong token — open the link printed in the console",
        );
        return false;
    }

    let body: Value = if method == Method::Post {
        let is_json = header_value(&req, "Content-Type")
            .map(|v| v.to_ascii_lowercase().starts_with("application/json"))
            .unwrap_or(false);
        if !is_json {
            err(req, 415, "expected application/json");
            return false;
        }
        let mut buf = Vec::new();
        if req
            .as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut buf)
            .is_err()
            || buf.len() > MAX_BODY
        {
            err(req, 413, "request too large");
            return false;
        }
        match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(e) => {
                err(req, 400, format!("bad JSON: {e}"));
                return false;
            }
        }
    } else {
        Value::Null
    };

    let result = match (&method, url.as_str()) {
        (Method::Get, "/api/state") => api_state(),
        (Method::Post, "/api/hosts/save") => api_save(body),
        (Method::Post, "/api/hosts/delete") => api_delete(body),
        (Method::Post, "/api/hosts/forget-key") => api_forget_key(ctx, body),
        (Method::Post, "/api/hosts/test") => api_test(ctx, body),
        (Method::Post, "/api/settings") => api_settings(body),
        (Method::Post, "/api/shutdown") => {
            respond_json(req, 200, json!({ "ok": true }));
            return true;
        }
        _ => Err((404, "not found".to_string())),
    };
    match result {
        Ok(v) => respond_json(req, 200, v),
        Err((status, msg)) => err(req, status, msg),
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

type ApiResult = Result<Value, (u16, String)>;

fn bad(msg: impl Into<String>) -> (u16, String) {
    (400, msg.into())
}

fn internal(msg: impl ToString) -> (u16, String) {
    (500, msg.to_string())
}

fn load_inventory() -> Result<Inventory, (u16, String)> {
    Inventory::load_raw().map_err(|e| {
        internal(format!(
            "cannot read {}: {e}. Fix or move the file and reload.",
            Inventory::path().display()
        ))
    })
}

fn api_state() -> ApiResult {
    let inv = load_inventory()?;
    let hosts: Vec<Value> = inv
        .summaries()
        .into_iter()
        .map(|h| {
            json!({
                "name": h.name,
                "description": h.description,
                "protocol": h.protocol.to_string(),
                "host": h.host,
                "port": h.port,
                "username": h.username,
                "key_path": h.key_path.as_ref().map(|p| p.display().to_string()),
                "serial_port": h.serial_port,
                "baud": h.baud,
                "prompt": h.prompt,
                "has_password": secrets::has(&h.name, SecretKind::Password),
                "has_passphrase": secrets::has(&h.name, SecretKind::Passphrase),
                "has_enable": secrets::has(&h.name, SecretKind::Enable),
                "legacy_plaintext_password": h.password.is_some(),
                "host_key": host_key_target(h).and_then(|(host, port)| hostkeys::fingerprint(&host, port)),
            })
        })
        .collect();
    Ok(json!({
        "hosts": hosts,
        "settings": {
            "transfer_dir": inv.settings.transfer_dir.as_ref().map(|p| p.display().to_string()),
            "transfer_dir_effective": paths::transfer_root().display().to_string(),
            "transfer_dir_env": std::env::var("SSHCONNECT_TRANSFER_DIR").ok().filter(|v| !v.is_empty()),
            "host_key_check": inv.settings.host_key_check.clone().unwrap_or_else(|| "tofu".into()),
            "host_key_check_env": std::env::var("SSHCONNECT_HOST_KEY_CHECK").ok().filter(|v| !v.is_empty()),
        },
        "inventory_path": Inventory::path().display().to_string(),
        "secret_backend": secrets::backend_name(),
        "known_hosts": hostkeys::known_hosts_path().display().to_string(),
    }))
}

/// Where host-key records for an SSH entry are kept (address as dialled).
/// Uses the entry's address directly; a ~/.ssh/config alias that maps to a
/// different HostName is resolved by `resolve_ssh_target` when connecting.
fn host_key_target(h: &HostEntry) -> Option<(String, u16)> {
    if h.protocol != Protocol::Ssh {
        return None;
    }
    let host = h.host.clone().unwrap_or_else(|| h.name.clone());
    Some((host, h.effective_port()))
}

/// Secret field update from the page: absent → keep, "" → keep, text → set.
/// Deletion is explicit via the `clear_*` flags.
#[derive(Deserialize, Default)]
struct SaveRequest {
    previous_name: Option<String>,
    entry: EntryIn,
    #[serde(default)]
    auth: Option<String>, // "password" | "key"
    password: Option<String>,
    #[serde(default)]
    clear_password: bool,
    passphrase: Option<String>,
    #[serde(default)]
    clear_passphrase: bool,
    enable_password: Option<String>,
    #[serde(default)]
    clear_enable: bool,
}

#[derive(Deserialize, Default)]
struct EntryIn {
    name: String,
    description: Option<String>,
    protocol: String,
    host: Option<String>,
    port: Option<Value>,
    username: Option<String>,
    key_path: Option<String>,
    serial_port: Option<String>,
    baud: Option<Value>,
    prompt: Option<String>,
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn parse_num<T: std::str::FromStr>(
    v: Option<Value>,
    what: &str,
) -> Result<Option<T>, (u16, String)> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .to_string()
            .parse()
            .map(Some)
            .map_err(|_| bad(format!("invalid {what}"))),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| bad(format!("invalid {what}"))),
        _ => Err(bad(format!("invalid {what}"))),
    }
}

fn api_save(body: Value) -> ApiResult {
    let req: SaveRequest =
        serde_json::from_value(body).map_err(|e| bad(format!("bad request: {e}")))?;
    let e = req.entry;
    let protocol = match e.protocol.to_ascii_lowercase().as_str() {
        "ssh" => Protocol::Ssh,
        "telnet" => Protocol::Telnet,
        "serial" => Protocol::Serial,
        other => return Err(bad(format!("unknown protocol '{other}'"))),
    };
    let name = e.name.trim().to_string();
    crate::config::validate_name(&name).map_err(bad)?;
    let key_mode = protocol == Protocol::Ssh && req.auth.as_deref() == Some("key");

    let mut entry = HostEntry {
        name: name.clone(),
        description: non_empty(e.description),
        host: non_empty(e.host),
        protocol,
        port: parse_num(e.port, "port")?,
        username: non_empty(e.username),
        password: None,
        key_path: if key_mode {
            non_empty(e.key_path).map(PathBuf::from)
        } else {
            None
        },
        serial_port: non_empty(e.serial_port),
        baud: parse_num(e.baud, "baud rate")?,
        prompt: non_empty(e.prompt),
    };
    match protocol {
        Protocol::Ssh | Protocol::Telnet => {
            if entry.host.is_none() {
                return Err(bad("укажите хост (адрес или имя)"));
            }
            entry.serial_port = None;
            entry.baud = None;
        }
        Protocol::Serial => {
            if entry.serial_port.is_none() {
                return Err(bad("укажите COM-порт"));
            }
            entry.host = None;
            entry.port = None;
        }
    }
    if key_mode && entry.key_path.is_none() {
        return Err(bad("укажите путь к приватному ключу"));
    }
    if let Some(p) = &entry.prompt {
        regex::Regex::new(p).map_err(|e| bad(format!("prompt regex: {e}")))?;
    }

    let mut inv = load_inventory()?;
    let previous = non_empty(req.previous_name);
    let legacy_password = previous
        .as_deref()
        .and_then(|p| inv.get(p))
        .and_then(|old| old.password.clone());
    inv.upsert(entry, previous.as_deref()).map_err(bad)?;
    inv.save().map_err(internal)?;

    // Secrets follow a rename, then apply this request's changes.
    if let Some(prev) = previous.as_deref() {
        secrets::rename(prev, &name).map_err(internal)?;
    }
    let apply =
        |kind: SecretKind, value: Option<String>, clear: bool| -> Result<(), (u16, String)> {
            if clear {
                secrets::delete(&name, kind).map_err(internal)?;
            }
            if let Some(v) = value.filter(|v| !v.is_empty()) {
                secrets::set(&name, kind, &v).map_err(internal)?;
            }
            Ok(())
        };
    // Password mode drops a stored key passphrase; key mode drops the login
    // password — the tab the user picked is the one that is used.
    apply(
        SecretKind::Password,
        req.password,
        req.clear_password || key_mode,
    )?;
    apply(
        SecretKind::Passphrase,
        req.passphrase,
        req.clear_passphrase || !key_mode,
    )?;
    apply(SecretKind::Enable, req.enable_password, req.clear_enable)?;
    // Move a legacy plaintext password out of the file (it was just dropped
    // from hosts.toml by the save above).
    if let Some(pw) = legacy_password {
        if !key_mode && !secrets::has(&name, SecretKind::Password) && !req.clear_password {
            secrets::set(&name, SecretKind::Password, &pw).map_err(internal)?;
        }
    }
    Ok(json!({ "ok": true, "name": name }))
}

#[derive(Deserialize)]
struct NameRequest {
    name: String,
}

fn api_delete(body: Value) -> ApiResult {
    let r: NameRequest = serde_json::from_value(body).map_err(|e| bad(e.to_string()))?;
    let mut inv = load_inventory()?;
    if !inv.remove(&r.name) {
        return Err((404, format!("no host named '{}'", r.name)));
    }
    inv.save().map_err(internal)?;
    secrets::delete_all(&r.name).map_err(internal)?;
    Ok(json!({ "ok": true }))
}

/// Resolve an SSH entry to the address/port/user it is dialled with, the same
/// way `ssh_connect` does (inventory first, ~/.ssh/config for the rest).
async fn resolve_ssh_target(e: &HostEntry) -> (String, u16, Option<String>, Vec<PathBuf>) {
    let alias = e.host.clone().unwrap_or_else(|| e.name.clone());
    let defaults = crate::ssh_config::lookup(&alias).await;
    let host = defaults.hostname.clone().unwrap_or(alias);
    let port = e.port.or(defaults.port).unwrap_or(22);
    let user = e.username.clone().or(defaults.username);
    let mut keys = Vec::new();
    keys.extend(e.key_path.clone());
    keys.extend(defaults.identity_files);
    (host, port, user, keys)
}

fn find_entry(name: &str) -> Result<HostEntry, (u16, String)> {
    Inventory::load_default()
        .get(name)
        .cloned()
        .ok_or_else(|| (404, format!("no host named '{name}'")))
}

fn api_forget_key(ctx: &Ctx, body: Value) -> ApiResult {
    let r: NameRequest = serde_json::from_value(body).map_err(|e| bad(e.to_string()))?;
    let e = find_entry(&r.name)?;
    if e.protocol != Protocol::Ssh {
        return Err(bad("ключи хостов есть только у SSH"));
    }
    let (host, port, _, _) = ctx.rt.block_on(resolve_ssh_target(&e));
    let mut removed = hostkeys::forget(&host, port).map_err(internal)?;
    // Also clear a record under the literal address if the alias resolved
    // to something else.
    if let Some((h2, p2)) = host_key_target(&e) {
        if (h2.as_str(), p2) != (host.as_str(), port) {
            removed |= hostkeys::forget(&h2, p2).map_err(internal)?;
        }
    }
    Ok(json!({ "ok": true, "removed": removed, "target": format!("{host}:{port}") }))
}

fn api_test(ctx: &Ctx, body: Value) -> ApiResult {
    let r: NameRequest = serde_json::from_value(body).map_err(|e| bad(e.to_string()))?;
    let e = find_entry(&r.name)?;
    let outcome = ctx.rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(25), test_connection(&e))
            .await
            .unwrap_or_else(|_| Err("timed out after 25 s".to_string()))
    });
    Ok(match outcome {
        Ok((msg, fp)) => json!({ "ok": true, "message": msg, "fingerprint": fp }),
        Err(msg) => json!({ "ok": false, "message": msg }),
    })
}

async fn test_connection(e: &HostEntry) -> Result<(String, Option<String>), String> {
    match e.protocol {
        Protocol::Ssh => {
            let (host, port, user, keys) = resolve_ssh_target(e).await;
            let user = user.ok_or("не указан пользователь")?;
            let handler = crate::state::VpsClientHandler {
                host: host.clone(),
                port,
                policy: hostkeys::host_key_policy(),
            };
            let config = Arc::new(russh::client::Config::default());
            let mut session = russh::client::connect(config, (host.as_str(), port), handler)
                .await
                .map_err(|err| hostkeys::explain_connect_error(&err, &host, port))?;
            let used = crate::ssh_config::authenticate(
                &mut session,
                crate::ssh_config::Credentials {
                    username: user.clone(),
                    password: e.resolve_password(),
                    identity_files: keys,
                    passphrase: e.resolve_passphrase(),
                    use_agent: true,
                },
            )
            .await?;
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
            Ok((
                format!("{user}@{host}:{port} — вход выполнен ({used})"),
                hostkeys::fingerprint(&host, port),
            ))
        }
        Protocol::Telnet => {
            let host = e.host.clone().ok_or("не указан хост")?;
            let port = e.effective_port();
            tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|err| format!("{host}:{port}: {err}"))?;
            Ok((format!("{host}:{port} — TCP-порт доступен (вход по Telnet проверяется при подключении)"), None))
        }
        Protocol::Serial => {
            let sp = e.serial_port.clone().ok_or("не указан COM-порт")?;
            let baud = e.baud.unwrap_or(9600);
            crate::transport::serial::SerialTransport::open(&sp, baud)
                .map_err(|err| err.to_string())?;
            Ok((format!("{sp} @ {baud} — порт открывается"), None))
        }
    }
}

#[derive(Deserialize)]
struct SettingsRequest {
    transfer_dir: Option<String>,
    host_key_check: Option<String>,
}

fn api_settings(body: Value) -> ApiResult {
    let r: SettingsRequest = serde_json::from_value(body).map_err(|e| bad(e.to_string()))?;
    let mut inv = load_inventory()?;
    let transfer_dir = non_empty(r.transfer_dir).map(PathBuf::from);
    if let Some(dir) = &transfer_dir {
        if !dir.is_absolute() {
            return Err(bad("папка для файлов должна быть абсолютным путём"));
        }
        std::fs::create_dir_all(dir).map_err(|e| bad(format!("не удалось создать папку: {e}")))?;
    }
    let host_key_check = match r.host_key_check.as_deref().map(str::trim) {
        None | Some("") | Some("tofu") => None, // default
        Some("off") => Some("off".to_string()),
        Some(other) => return Err(bad(format!("unknown host_key_check '{other}'"))),
    };
    inv.settings = Settings {
        transfer_dir,
        host_key_check,
    };
    inv.save().map_err(internal)?;
    Ok(
        json!({ "ok": true, "transfer_dir_effective": paths::transfer_root().display().to_string() }),
    )
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    let r = {
        use std::os::windows::process::CommandExt;
        // rundll32 hands the URL to the default browser without cmd.exe
        // parsing it (no quoting issues with '#' or '&').
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x0800_0000)
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(not(any(windows, unix)))]
    let r: std::io::Result<()> = Ok(());
    if let Err(e) = r {
        eprintln!("  (не удалось открыть браузер автоматически: {e})");
    }
}
