//! Windows-only: verify that the process serving the broker named pipe runs as
//! the same user as we do.
//!
//! The pipe name is fixed and global, so another account on the machine could
//! create `\\.\pipe\ssh-connect-broker-v1` first (with a permissive DACL) and
//! receive every forwarded tool call. Before attaching as a proxy we check the
//! server process's token user SID against our own and refuse otherwise.
//!
//! Compiled on other platforms only with `--cfg ssh_connect_wincheck`, for
//! type-checking without a Windows toolchain.

#![cfg_attr(not(windows), allow(dead_code))]

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Owned token-user buffer; `sid()` points into it.
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn sid(&self) -> *mut core::ffi::c_void {
        // SAFETY: the buffer was filled by GetTokenInformation(TokenUser) and is
        // 8-byte aligned (Vec<u64>), so it holds a valid TOKEN_USER.
        unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
    }
}

fn token_user(process: HANDLE) -> Option<TokenUserBuf> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: plain Win32 calls with out-pointers to locals; the token handle
    // is closed before returning.
    unsafe {
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut len: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            (buf.len() * 8) as u32,
            &mut len,
        );
        CloseHandle(token);
        (ok != 0).then_some(TokenUserBuf(buf))
    }
}

/// True only if the server end of `pipe` belongs to a process running as the
/// current user. Any failure to establish that counts as "no".
pub fn pipe_server_is_current_user(pipe: HANDLE) -> bool {
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is a live client handle owned by the caller.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return false;
    }
    // SAFETY: OpenProcess returns null on failure; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return false;
    }
    let theirs = token_user(process);
    unsafe { CloseHandle(process) };
    // GetCurrentProcess is a pseudo-handle and needs no close.
    let mine = token_user(unsafe { GetCurrentProcess() });
    match (theirs, mine) {
        // SAFETY: both SIDs point into live buffers held for this call.
        (Some(a), Some(b)) => unsafe { EqualSid(a.sid(), b.sid()) != 0 },
        _ => false,
    }
}
