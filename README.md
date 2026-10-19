# SSH-Connect

**English** | [Русский](README.ru.md)

> Fork of [mixelpixx/SSH-Connect](https://github.com/mixelpixx/SSH-Connect) (MIT).
> This fork adds a local web UI for saved hosts, keeps passwords out of the chat, and
> fixes the security problems listed below. Everything else — all 38 tools, the skills
> and the agents — works as in the original.

## What this fork changes

### Web UI for saved hosts

Run `ssh-connect ui` or double-click `ssh-connect.exe`. A page opens in your browser
where you add, edit and delete hosts — name, address, port, user, password **or** private
key (+ passphrase), enable password for network gear, a description for the agent — and
check each one with **Test connection**.

- The agent sees only host names. It calls `list_hosts`, then `ssh_connect {host: "qa1"}`
  or `connect {name: "switch"}`; `login` / `enable` use the stored passwords on their own.
- Passwords are stored in the **Windows Credential Manager** (on other systems in
  `~/.ssh-connect/secrets.json`, mode 0600) and are read by the server itself. They never
  pass through the model, the chat or the LLM provider.
- Changes apply immediately, without restarting the MCP client: the server re-reads the
  host list on every call.
- The page listens on `127.0.0.1` only, on a random port, and requires the per-run token
  from the link printed in the console. It checks `Host` / `Origin`, sends a strict
  Content-Security-Policy, and can set or delete secrets but never display them.

Details: [Saved hosts and the web UI](#saved-hosts-and-the-web-ui).

### Security fixes

| Problem in the original | Fix in this fork |
|---|---|
| File-transfer tools (`ssh_upload_file`, `ssh_download_file`, `ubuntu_website_deployment`, `upload_config`, `download_config`, `switch_backup_config.save_to`) read and wrote **any** local path. A prompt-injected agent could upload `~/.ssh` to an arbitrary host or drop a file into the Windows Startup folder. | Local paths are confined to one transfer folder (`~/ssh-connect-files` by default). `..` and symlinks/junctions leading outside it are refused. |
| Host keys: `ssh_connect` accepted any key by default and the interactive `connect` never checked them, so passwords could be intercepted by a man in the middle. | Trust-on-first-use is on by default for both paths. A changed key is refused and can be reset in the UI. |
| `connect {name, host}` took the stored password of `name` and sent it to an address chosen by the agent. | Saved hosts are pinned: address, port and protocol cannot be overridden, and stored secrets are used only for the saved user. |
| `hosts.toml` was read from the current directory, so a cloned repository could redirect saved host names to other addresses. | The host list lives only in `~/.ssh-connect/` (or wherever `SSHCONNECT_HOSTS` points). |
| Passwords could only be passed as tool arguments, i.e. through the model and the chat history. | Passwords are kept in the OS credential store; `list_hosts` reports only whether one is saved. |
| Shell injection through tool parameters: `chmod` mode, crontab user, `journalctl` unit, kill signal, nginx site name (path traversal under `sudo cp`), MySQL database name, health-check domains. | All of them are quoted or validated; the nginx temp file is created with `mktemp`. |
| The broker named pipe / socket accepted any local account, and whoever created it first received every forwarded tool call. | The peer must run as the same OS user; remote pipe clients are rejected; the Unix socket is `0600`. |

**Known limitations.** The `rsa` crate advisory RUSTSEC-2023-0071 has no upstream fix —
prefer ed25519 keys. ssh-agent identities are offered to whatever host you connect to.
Your MCP client's per-call approval is still the main safeguard: do not set this server
to "always allow".

## About the server

A Rust [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for
remote server administration and interactive network-device / console management over
**SSH, Telnet, and Serial**, with a set of bundled skills and agents. One binary covers
two kinds of work:

- **Server operations** — Linux/Ubuntu administration (nginx, SSL/certbot, UFW,
  packages, deployment, systemd, MySQL/MariaDB, Redis, Docker, logs, processes, files,
  cron). Each command runs on its own SSH channel and reports an exit code; file
  transfer uses SFTP; trust-on-first-use host-key checking is on by default.
- **Interactive console** — prompt-aware management of switches, routers, and consoles
  over SSH (PTY), Telnet, and Serial, with pagination handling, enable/login flows, and
  fleet commands. A broker (Windows named pipe / Unix domain socket) lets multiple MCP
  clients share one set of live sessions and serial ports.

Built on the `rmcp` MCP SDK. SSH is pure Rust via `russh` (no OpenSSL/C dependency).

**Download:** prebuilt binaries for Linux, macOS, and Windows are on the
[Releases page](https://github.com/Stokerdenver/ssh-connect/releases/latest) — no Rust
toolchain required to run them.

## Two interaction models, one server

| Goal | Tool family | Connect with | Run with |
|------|-------------|--------------|----------|
| Linux/VPS administration with exit codes | server-ops | `ssh_connect` | `ssh_exec`, `vps_*`, `ubuntu_*` |
| Switches, routers, consoles, serial | interactive console | `connect` | `run_command`, `enable`, `login`, etc. |

Both families run in one process and share the broker, so a session opened by one MCP
client is usable from another.

## Tools

- **Session / discovery (interactive):** `connect`, `disconnect`, `list_sessions`,
  `list_com_ports`, `list_hosts`
- **Interactive command:** `run_command`, `run_commands`, `enable`, `login`,
  `expect_send`, `run_on_fleet`, `upload_config`, `download_config`
- **Switch convenience:** `switch_backup_config`, `switch_network_diagnostics`
- **SSH server-ops:** `ssh_connect`, `ssh_exec`, `ssh_upload_file`, `ssh_download_file`,
  `ssh_list_files`, `ssh_disconnect`
- **VPS / Ubuntu:** `vps_system_stats`, `vps_logs`, `vps_process`, `vps_file_read`,
  `vps_file_ops`, `vps_cron`, `ubuntu_service_control`, `vps_nginx_config`,
  `ubuntu_nginx_control`, `ubuntu_update_packages`, `ubuntu_ssl_certificate`,
  `ubuntu_website_deployment`, `ubuntu_ufw_firewall`, `ubuntu_mysql`, `vps_redis`,
  `vps_docker`, `vps_health_check`

On timeout, `ssh_exec` (and the `vps_*`/`ubuntu_*` tools) return an error and make a
best-effort attempt to terminate the remote command. The attempt is not guaranteed —
OpenSSH may ignore a signal on a non-PTY exec channel. `ubuntu_update_packages`,
`ubuntu_ssl_certificate`, and `vps_docker` accept an optional `timeoutMs`. For
operations that can run for minutes, run them detached and poll a log file rather than
relying on a long timeout (see the `vps-management` skill).

## Skills (`skills/`)

- **switch-management** — operational guidance for switches/routers: vendor idioms,
  pagination, enable/config, saving, fleet operations, firmware upgrades, console-to-SSH
  setup.
- **vps-management** — safe-change discipline and standard workflows (patch + reboot,
  SSL/certbot troubleshooting, service recovery, long-running-operation polling).
- **vps-health-report** — a standardized HTML server health report (plus JSON sidecar
  and delta), driven by `vps_health_check`.
- **health-report** — a standardized HTML network-device health report (plus JSON
  sidecar).

## Agents (`.claude/agents/`)

`vps-troubleshooter`, `switch-config-auditor`, `deployment-runner`,
`fleet-health-reporter`, `vps-health-reporter`.

## Build

Requires a recent stable Rust toolchain. Rust dependencies (including `rmcp = "1.8"`
from crates.io) are fetched by Cargo.

```sh
cargo build --release
# Binary: target/release/ssh-connect  (ssh-connect.exe on Windows)
```

Windows and macOS need no system packages. On **Linux**, the `serialport` crate
(used for `list_com_ports` and serial console access) needs `libudev` at build time:

```sh
sudo apt-get install -y libudev-dev pkg-config   # Debian/Ubuntu
```

Prefer not to build from source? Prebuilt binaries for Linux, macOS, and Windows are
attached to every tagged release on the
[Releases page](https://github.com/Stokerdenver/ssh-connect/releases/latest) (produced by
the `release` GitHub Actions workflow).

## Register with an MCP client

Claude Code:

```sh
claude mcp add ssh-connect --scope user -- /path/to/ssh-connect/target/release/ssh-connect
```

Or in an MCP settings file:

```json
{
  "mcpServers": {
    "ssh-connect": {
      "command": "/path/to/ssh-connect/target/release/ssh-connect"
    }
  }
}
```

The server speaks MCP over stdio; all logging goes to stderr (set `RUST_LOG=info` to see
broker/role messages).

In the examples below, replace the path with the location of your binary. On Windows
point at `ssh-connect.exe` and escape backslashes in JSON
(`"C:\\Tools\\ssh-connect\\ssh-connect.exe"`) or use forward slashes. Thanks to the
broker, several clients (say, VS Code and OpenCode) can run at once and share the same
live sessions.

### VS Code

**GitHub Copilot (agent mode).** Add the server for the current workspace in
`.vscode/mcp.json` (note the top-level key is `servers`, not `mcpServers`):

```json
{
  "servers": {
    "ssh-connect": {
      "type": "stdio",
      "command": "/path/to/ssh-connect",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```

For all workspaces, run **MCP: Open User Configuration** from the Command Palette and add
the same entry, or register it from a terminal:

```sh
code --add-mcp "{\"name\":\"ssh-connect\",\"command\":\"/path/to/ssh-connect\"}"
```

Then open Copilot Chat, switch to **Agent** mode and enable the `ssh-connect` tools in the
tools picker. **MCP: List Servers** shows status and output logs.

**Claude Code extension.** The extension uses the same configuration as the CLI, so the
`claude mcp add ...` command above is enough. For a project-scoped server, commit a
`.mcp.json` at the repository root with the `mcpServers` block shown above.

**Cline.** Click the **MCP Servers** icon in the Cline panel → **Configure** →
**Configure MCP Servers**; this opens `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "ssh-connect": {
      "command": "/path/to/ssh-connect",
      "args": [],
      "env": {},
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

Keep `alwaysAllow` empty (or list read-only tools such as `list_hosts`,
`list_sessions`, `vps_system_stats` only) so that every state-changing command needs your
approval.

**Roo Code.** Same `mcpServers` format — globally via the MCP settings in the Roo panel
(**Edit Global MCP**), or per project in `.roo/mcp.json`.

**Continue.** Create `.continue/mcpServers/ssh-connect.yaml` in the workspace (MCP tools
are available in Agent mode):

```yaml
name: SSH-Connect
version: 0.0.1
schema: v1
mcpServers:
  - name: ssh-connect
    command: /path/to/ssh-connect
    args: []
```

### OpenCode

Add a `local` server under the `mcp` key in `opencode.json` — project-level at the
repository root, or global in `~/.config/opencode/opencode.json`. `command` is an
**array** (binary plus arguments):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ssh-connect": {
      "type": "local",
      "command": ["/path/to/ssh-connect"],
      "enabled": true,
      "timeout": 10000,
      "environment": { "RUST_LOG": "info" }
    }
  }
}
```

Run `opencode mcp list` to check that the server is connected. The tools appear as
`ssh-connect_<tool>`; you can restrict them per agent with the `tools` / `permission`
sections of the config (for example, set destructive tools to `"ask"`).

### OpenClaw

OpenClaw reads MCP servers from the `mcp.servers` block of `~/.openclaw/openclaw.json`
(JSON5):

```json5
{
  mcp: {
    servers: {
      "ssh-connect": {
        command: "/path/to/ssh-connect",
        args: [],
        env: { RUST_LOG: "info" },
      },
    },
  },
}
```

Restart the gateway after editing, then check with `openclaw mcp list` /
`openclaw mcp show ssh-connect`. The same block can be edited from the Control UI
(`/settings/mcp`). OpenClaw is often reachable from messengers, so think about who can
talk to the agent: SSH-Connect can change remote systems, and saved hosts give it
credentials without asking. Restrict the agent with `toolFilter` (include/exclude
lists), or register a separate read-only set of hosts.

### Using it

Once connected, ask the agent in plain language, e.g. *"List saved hosts and show disk
and memory usage on web-01"* or *"Back up the running config of core-sw-01"*. Add
servers in `ssh-connect ui` first (see below) so the agent never needs passwords in chat.
The bundled `skills/` are plain Markdown — clients without native skill support can
still use them as context or as custom instructions/rules.

## Saved hosts and the web UI

Run `ssh-connect ui` (or just double-click `ssh-connect.exe`) to open a local page for
managing saved hosts: name, address, port, user, password **or** private key (+ passphrase),
enable password for network gear, description for the agent, and a "test connection"
button. The page listens on `127.0.0.1` only and every request needs the per-run token in
the link printed to the console.

- Hosts live in `~/.ssh-connect/hosts.toml` (`%USERPROFILE%\.ssh-connect\hosts.toml`),
  never in the current directory. The server re-reads it on every call, so a host added
  in the UI is usable immediately — no MCP client restart.
- Passwords, passphrases and enable passwords go to the **Windows Credential Manager**
  (`ssh-connect:<kind>:<host>` generic credentials) — elsewhere to
  `~/.ssh-connect/secrets.json` (0600). The page can set or delete them, never read them.
- The agent calls `list_hosts`, then `ssh_connect {host: "<name>"}` or
  `connect {name: "<name>"}`; `login`/`enable` take the stored secrets when `password` is
  omitted. Secrets never pass through the model, the chat or the broker pipe.
- A saved host is **pinned**: its address, port and protocol cannot be overridden by tool
  arguments, and its stored secrets are only used for its own user — so a prompt-injected
  agent cannot send them elsewhere.

### Quick launch on Windows

The page gets a new port and access token on every start, so it cannot be bookmarked —
launch it from a shortcut instead and the browser opens with the right link.

**Start-menu shortcut with a hotkey.** Run once in PowerShell (adjust `$exe`):

```powershell
$exe = "C:\Tools\ssh-connect\ssh-connect.exe"
$lnk = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\SSH-Connect.lnk"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath       = $exe
$s.Arguments        = "ui"
$s.WorkingDirectory = Split-Path $exe
$s.Description      = "SSH-Connect — saved hosts"
$s.Hotkey           = "CTRL+ALT+S"
$s.WindowStyle      = 7          # start the console minimized; only the browser shows
$s.Save()
```

Then open the UI with **Ctrl+Alt+S**, from Start (type `SSH-Connect`), or pin the
shortcut to the taskbar (right-click it in Start → Pin to taskbar). Keep the minimized
console running while you use the page; stop it with the "Остановить интерфейс" link at
the bottom of the page or by closing the console. If the hotkey is taken, pick another
(e.g. `"CTRL+ALT+H"`) and run the script again.

**PowerShell command.** Add to your profile (`notepad $PROFILE`):

```powershell
function sshui { & "C:\Tools\ssh-connect\ssh-connect.exe" ui }
```

Every new PowerShell window then opens the UI with `sshui`.

## Configuration

- **Inventory:** managed by `ssh-connect ui`, or edit `~/.ssh-connect/hosts.toml` by hand
  (see `hosts.example.toml`). Override the path with `SSHCONNECT_HOSTS`.
- **Secrets via env (optional):** for host `core-sw-01`, `SSHCONNECT_CORE_SW_01_PASSWORD`
  (name upper-cased, non-alphanumerics collapsed to `_`) overrides the stored password;
  `_PASSPHRASE`, `_ENABLE_PASSWORD`, `_USERNAME`, `_HOST`, `_PORT`, `_KEY_PATH` work the same.
- **Host-key checking (both SSH paths):** trust-on-first-use against
  `~/.ssh-connect/known_hosts` **by default** — the first key seen is recorded, a later
  mismatch is refused. Reset a reinstalled device's key in the UI ("Забыть ключ хоста").
  Turn off in the UI settings or with `SSHCONNECT_HOST_KEY_CHECK=off`.
- **Transfer folder:** tools that read or write local files (`ssh_upload_file`,
  `ssh_download_file`, `ubuntu_website_deployment`, `upload_config`, `download_config`,
  `switch_backup_config.save_to`) only work inside one folder — `~/ssh-connect-files` by
  default, changeable in the UI or with `SSHCONNECT_TRANSFER_DIR`. Relative paths resolve
  inside it; `..` and links leading outside are refused.
- **SSH client config:** resolution is delegated to the local OpenSSH client — both
  connect tools run `ssh -G <host>` and use the HostName, User, Port and IdentityFile it
  reports, so `Host`/`Match` blocks, `Include`s, wildcards, percent tokens,
  canonicalization and OpenSSH's own defaults (User = the local account, Port 22) all
  behave exactly as they do for `ssh` itself. Explicit arguments and `hosts.toml` entries
  still win. With no `ssh` on PATH, only the local account name is inferred.
- **ssh-agent:** identities held by the agent are offered after any password and key file.
  On Unix the socket comes from `SSH_AUTH_SOCK`; on Windows the OpenSSH named pipe
  (`\\.\pipe\openssh-ssh-agent`) is used when that variable is unset. Pass
  `useAgent: false` (`use_agent` on `connect`) to force a specific credential instead.
  RSA identities are signed with the strongest hash the server advertises, so agent auth
  also works against OpenSSH 8.8+, which rejects SHA-1 `ssh-rsa`.

## Broker (multi-instance session sharing)

The first instance becomes the owner of a per-machine rendezvous endpoint — a named
pipe (`\\.\pipe\ssh-connect-broker-v1`) on Windows, or a Unix domain socket under
`$XDG_RUNTIME_DIR` (falling back to the temp dir) on Linux/macOS — and holds the live
connections and COM ports. Later instances act as proxies that forward `tools/call` to
the owner, so a session opened in one client is usable from another and two clients
cannot collide on the same serial port. Tool schemas are served locally by every
instance. On a platform with neither transport, each instance is a standalone owner.

Before attaching as a proxy, an instance checks that the endpoint is served by the same
OS user (Windows: the pipe server's token SID; Unix: `SO_PEERCRED`), so another account
cannot squat the well-known name and receive forwarded tool calls.

Limitation: if the owner process exits, existing proxies do not currently re-elect a new
owner mid-session — restart the affected client. A newly started instance always elects
correctly (and clears a stale socket).

## Tests

```sh
cargo test --bin ssh-connect
```

Unit tests cover the telnet IAC parser, prompt/ANSI output handling, the host inventory,
`ssh -G` alias resolution, serial-port probing, and the legacy SSH algorithm set.
Protocol and broker behavior are checked by sending an `initialize` + `tools/list`
sequence to the binary and by running two instances to confirm owner/proxy election.

## License

MIT — see [LICENSE](LICENSE).
