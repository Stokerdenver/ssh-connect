//! Interactive-console command tools: `run_command`, `run_commands`, `enable`,
//! `login`, `expect_send`, `run_on_fleet`, plus SFTP `upload_config` /
//! `download_config`. These drive prompt-aware sessions in the
//! [`SessionManager`](crate::transport::SessionManager) registry.

use rmcp::{
    ErrorData,
    handler::server::wrapper::Parameters,
    model::CallToolResult,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::config::{HostEntry, Inventory};
use crate::error::ToolError;
use crate::paths::{self, Access};
use crate::server::SshConnectServer;
use crate::transport::Session;
use crate::tools::util::{json_result, timeout_or_default};
use regex::Regex;

// ── parameter structs ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunCommandParams {
    /// Target session name.
    pub session: String,
    /// Command to send.
    pub command: String,
    /// Per-command timeout in seconds (default 30).
    pub timeout_secs: Option<u64>,
    /// Send bytes verbatim with no line ending appended (for control chars).
    pub raw: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunCommandsParams {
    pub session: String,
    /// Commands to send sequentially.
    pub commands: Vec<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnableParams {
    pub session: String,
    /// Enable password (never echoed back). Omit for saved hosts — the stored
    /// enable password is used.
    pub password: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoginParams {
    pub session: String,
    /// Login username (omit for password-only lines; saved hosts use their user).
    pub username: Option<String>,
    /// Login password (never echoed back). Omit for saved hosts — the stored
    /// password is used.
    pub password: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpectSendParams {
    pub session: String,
    /// Regex to wait for in the output.
    pub expect: String,
    /// Text to send verbatim once matched (no newline added — include \n yourself).
    pub send: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunOnFleetParams {
    /// Session names to run the command against, in parallel.
    pub sessions: Vec<String>,
    pub command: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadConfigParams {
    pub session: String,
    /// Local file to upload, relative to the user's transfer folder.
    pub local_path: String,
    /// Destination path on the device.
    pub remote_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadConfigParams {
    pub session: String,
    /// Source path on the device.
    pub remote_path: String,
    /// Local destination, relative to the user's transfer folder.
    pub local_path: String,
}

// ── tool implementations ──────────────────────────────────────────────────────

#[tool_router(router = interactive_tool_router, vis = "pub(crate)")]
impl SshConnectServer {
    #[tool(description = "Send one command to an interactive session and return device output up to the next prompt: { output, matched_prompt, sub_prompt, timed_out, truncated, duration_ms }. A --More-- pager is auto-advanced. If the device stops at a sub-prompt (Password:, [confirm]) it returns immediately with sub_prompt set. Do NOT send passwords here (they would be echoed) — use enable/login.")]
    async fn run_command(
        &self,
        Parameters(params): Parameters<RunCommandParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let start = std::time::Instant::now();
        let outcome = guard
            .run_command_raw(
                &params.command,
                timeout_or_default(params.timeout_secs),
                params.raw.unwrap_or(false),
            )
            .await?;
        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(json_result(json!({
            "session": params.session,
            "command": params.command,
            "output": outcome.output,
            "matched_prompt": outcome.matched_prompt,
            "sub_prompt": outcome.sub_prompt,
            "timed_out": outcome.timed_out,
            "truncated": outcome.truncated,
            "duration_ms": duration_ms,
        })))
    }

    #[tool(description = "Send a list of commands sequentially to one session and return each command's output. A per-command timeout does NOT abort the sequence; only a transport/connection error stops it early.")]
    async fn run_commands(
        &self,
        Parameters(params): Parameters<RunCommandsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let timeout = timeout_or_default(params.timeout_secs);
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let mut results = Vec::with_capacity(params.commands.len());
        for command in &params.commands {
            let start = std::time::Instant::now();
            let outcome = guard.run_command(command, timeout).await?;
            results.push(json!({
                "command": command,
                "output": outcome.output,
                "matched_prompt": outcome.matched_prompt,
                "timed_out": outcome.timed_out,
                "duration_ms": start.elapsed().as_millis() as u64,
            }));
        }
        Ok(json_result(json!({ "session": params.session, "results": results })))
    }

    #[tool(description = "Enter privileged (enable) mode, supplying the enable password if the device challenges. Omit `password` for saved hosts — the stored enable password is used. The password is NEVER echoed back. Drives the 'enable' → Password: handshake in one step.")]
    async fn enable(
        &self,
        Parameters(params): Parameters<EnableParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let password = match params.password {
            Some(p) => p,
            None => saved_entry(&guard)?
                .and_then(|e| e.resolve_enable_password())
                .ok_or_else(|| {
                    ToolError::bad_request(
                        "no enable password given and none is saved for this session's host. Ask the \
                         user to add it in `ssh-connect ui` (preferred) or to provide it.",
                    )
                })?,
        };
        let outcome = guard
            .enable(&password, timeout_or_default(params.timeout_secs))
            .await?;
        Ok(json_result(json!({
            "session": params.session,
            "privileged": outcome.matched_prompt.as_deref().map(|p| p.ends_with('#')).unwrap_or(false),
            "matched_prompt": outcome.matched_prompt,
            "output": outcome.output,
            "timed_out": outcome.timed_out,
        })))
    }

    #[tool(description = "Log in over a console/vty that prompts for username and/or password (e.g. after connecting telnet/serial). Omit `password` (and `username`) for saved hosts — the stored credentials are used. Secrets are NEVER echoed back.")]
    async fn login(
        &self,
        Parameters(params): Parameters<LoginParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let (username, password) = match params.password {
            Some(p) => (params.username, p),
            None => {
                let entry = saved_entry(&guard)?.ok_or_else(|| {
                    ToolError::bad_request(
                        "no password given and this session was not opened from a saved host. Ask \
                         the user to save the device in `ssh-connect ui` (preferred) or to provide it.",
                    )
                })?;
                let pw = entry.resolve_password().ok_or_else(|| {
                    ToolError::bad_request(format!(
                        "no password is saved for '{}'. Ask the user to add it in `ssh-connect ui`.",
                        entry.name
                    ))
                })?;
                (params.username.or(entry.username.clone()), pw)
            }
        };
        let outcome = guard
            .login(
                username.as_deref(),
                &password,
                timeout_or_default(params.timeout_secs),
            )
            .await?;
        Ok(json_result(json!({
            "session": params.session,
            "logged_in": outcome.matched_prompt.is_some(),
            "matched_prompt": outcome.matched_prompt,
            "output": outcome.output,
            "timed_out": outcome.timed_out,
        })))
    }

    #[tool(description = "Wait until `expect` (a regex) appears in the output, then send `send` verbatim (no newline added). Use for enable passwords, [confirm] prompts, and pagination.")]
    async fn expect_send(
        &self,
        Parameters(params): Parameters<ExpectSendParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let expect = Regex::new(&params.expect)
            .map_err(|e| ToolError::bad_request(format!("invalid 'expect' regex: {e}")))?;
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let outcome = guard
            .expect_send(&expect, &params.send, timeout_or_default(params.timeout_secs))
            .await?;
        Ok(json_result(json!({
            "session": params.session,
            "matched": !outcome.timed_out,
            "output": outcome.output,
            "timed_out": outcome.timed_out,
        })))
    }

    #[tool(description = "Run the same command across multiple named sessions in parallel. Returns a per-session result with output or an error — one failing device does not abort the others.")]
    async fn run_on_fleet(
        &self,
        Parameters(params): Parameters<RunOnFleetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let timeout = timeout_or_default(params.timeout_secs);
        let command = params.command.clone();
        let mut set = tokio::task::JoinSet::new();
        for name in params.sessions {
            let sessions = self.sessions.clone();
            let command = command.clone();
            set.spawn(async move {
                let outcome = async {
                    let handle = sessions.get(&name).await?;
                    let mut guard = handle.lock().await;
                    guard.run_command(&command, timeout).await
                }
                .await;
                match outcome {
                    Ok(o) => json!({
                        "session": name,
                        "ok": true,
                        "output": o.output,
                        "timed_out": o.timed_out,
                    }),
                    Err(e) => json!({
                        "session": name,
                        "ok": false,
                        "error": e.message,
                        "error_kind": e.kind,
                    }),
                }
            });
        }

        let mut results = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(v) => results.push(v),
                Err(e) => results.push(json!({ "ok": false, "error": format!("task panicked: {e}") })),
            }
        }
        results.sort_by(|a, b| {
            a.get("session")
                .and_then(|v| v.as_str())
                .cmp(&b.get("session").and_then(|v| v.as_str()))
        });
        Ok(json_result(json!({ "command": command, "results": results })))
    }

    #[tool(description = "Upload a local file to an interactive SSH session over SFTP (firmware, configs). SSH sessions only. local_path is relative to the user's transfer folder (default ~/ssh-connect-files); paths outside it are refused. Returns bytes transferred.")]
    async fn upload_config(
        &self,
        Parameters(params): Parameters<UploadConfigParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let local = paths::resolve(&params.local_path, Access::Read).map_err(ToolError::bad_request)?;
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let bytes = guard.upload(&local, &params.remote_path).await?;
        Ok(json_result(json!({
            "uploaded": true,
            "session": params.session,
            "local_path": local.display().to_string(),
            "remote_path": params.remote_path,
            "bytes": bytes,
        })))
    }

    #[tool(description = "Download a remote file (e.g. a saved config) from an interactive SSH session over SFTP into the user's transfer folder (default ~/ssh-connect-files). local_path is relative to that folder. SSH sessions only. Returns bytes transferred.")]
    async fn download_config(
        &self,
        Parameters(params): Parameters<DownloadConfigParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let local = paths::resolve(&params.local_path, Access::Write).map_err(ToolError::bad_request)?;
        let handle = self.sessions.get(&params.session).await?;
        let mut guard = handle.lock().await;
        let bytes = guard.download(&params.remote_path, &local).await?;
        Ok(json_result(json!({
            "downloaded": true,
            "session": params.session,
            "remote_path": params.remote_path,
            "local_path": local.display().to_string(),
            "bytes": bytes,
        })))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// The saved host behind `session`, if it was opened from one and the entry
/// still points where it did at connect time.
fn saved_entry(session: &Session) -> Result<Option<HostEntry>, ToolError> {
    let Some(r) = &session.saved_host else {
        return Ok(None);
    };
    match Inventory::load_default().get(&r.name) {
        Some(e) if e.signature() == r.signature => Ok(Some(e.clone())),
        Some(_) => Err(ToolError::bad_request(format!(
            "saved host '{}' was edited after this session was opened; disconnect and connect again",
            r.name
        ))),
        None => Ok(None),
    }
}
