use std::{collections::HashMap, sync::Arc};

use russh::client::Handle;
use tokio::sync::Mutex;

pub use crate::hostkeys::{host_key_policy, HostKeyPolicy};

/// SSH client handler. Carries the target identity and host-key policy so
/// `check_server_key` can do trust-on-first-use (the default; see
/// [`crate::hostkeys`]). Used by both the server-ops and interactive SSH paths.
pub struct VpsClientHandler {
    pub host: String,
    pub port: u16,
    pub policy: HostKeyPolicy,
}

impl russh::client::Handler for VpsClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(crate::hostkeys::verify(&self.policy, &self.host, self.port, server_public_key))
    }
}

/// A single live SSH session.
#[allow(dead_code)]
pub struct SshConnection {
    pub handle: Handle<VpsClientHandler>,
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Thread-safe pool of active SSH connections.
///
/// Outer Mutex guards the map (insert/remove).
/// Inner Mutex guards one connection during SSH operations.
/// This allows concurrent tool calls on different connections
/// without blocking each other.
#[derive(Clone, Default)]
pub struct ConnectionPool {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<SshConnection>>>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, id: String, conn: SshConnection) {
        self.inner
            .lock()
            .await
            .insert(id, Arc::new(Mutex::new(conn)));
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Mutex<SshConnection>>> {
        self.inner.lock().await.get(id).cloned()
    }

    pub async fn remove(&self, id: &str) -> bool {
        self.inner.lock().await.remove(id).is_some()
    }
}

/// Execute a command on a live SSH handle and return (exit_code, stdout, stderr).
/// Each call opens a fresh session channel, runs the command, and closes the channel.
///
/// On timeout this **terminates the remote command** (best-effort `SIGTERM` then
/// channel EOF/close) and returns an `Err` — it does NOT silently return an empty
/// `Ok`. That distinction matters: a silent timeout previously let long commands
/// (e.g. `certbot renew`, `apt upgrade`) keep running server-side and hold locks
/// while the caller saw an empty success. Note that OpenSSH commonly ignores
/// `signal` requests on a non-PTY exec channel, so termination is best-effort;
/// for genuinely long operations prefer the run-detached-and-poll pattern
/// (see the vps-management skill) over a large timeout.
pub async fn exec_command(
    handle: &mut Handle<VpsClientHandler>,
    command: &str,
    timeout_ms: u64,
) -> anyhow::Result<(i32, String, String)> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0i32;
    let mut timed_out = false;

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    loop {
        match tokio::time::timeout_at(deadline, channel.wait()).await {
            Err(_elapsed) => {
                timed_out = true;
                break;
            }
            Ok(None) => break,
            Ok(Some(russh::ChannelMsg::Data { ref data })) => {
                stdout.push_str(&String::from_utf8_lossy(data));
            }
            Ok(Some(russh::ChannelMsg::ExtendedData { ref data, ext })) if ext == 1 => {
                stderr.push_str(&String::from_utf8_lossy(data));
            }
            Ok(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = exit_status as i32;
            }
            Ok(Some(russh::ChannelMsg::Eof)) => {}
            Ok(Some(_)) => {}
        }
    }

    if timed_out {
        // Best-effort terminate the remote command so it can't linger and hold
        // locks, then tear the channel down.
        let _ = channel.signal(russh::Sig::TERM).await;
        let _ = channel.eof().await;
        let _ = channel.close().await;
        anyhow::bail!(
            "command timed out after {timeout_ms} ms (remote command signaled to terminate; \
             for long-running operations run them detached and poll a log file)"
        );
    }

    Ok((
        exit_code,
        stdout.trim().to_string(),
        stderr.trim().to_string(),
    ))
}
