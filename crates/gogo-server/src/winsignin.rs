//! Same-PC Windows sign-in (spec section 3.4).
//!
//! The service listens on a local named pipe that refuses remote clients and
//! only accepts interactive users. `gogo signin` connects, the service reads
//! the caller's Windows identity by impersonating it (identification level
//! only), and returns a 60-second single-use sign-in link for the browser.

use crate::config::Config;
use crate::state::Shared;
use anyhow::{anyhow, bail, Result};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

pub const PIPE_NAME: &str = r"\\.\pipe\gogo-desktop-signin";

/// SYSTEM and Administrators: full access. Interactive users: read/write. Nobody else.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn spawn_server(state: Shared) {
    std::thread::Builder::new()
        .name("gogo-signin-pipe".into())
        .spawn(move || loop {
            if let Err(e) = serve_one(&state) {
                tracing::warn!("same-PC sign-in: {e:#}");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        })
        .expect("spawn sign-in pipe thread");
    tracing::info!("same-PC Windows sign-in is available: run 'gogo signin'");
}

fn last_error() -> anyhow::Error {
    anyhow!("Windows error {}", unsafe { GetLastError() })
}

/// Reads the impersonated caller's SID and DOMAIN\name.
unsafe fn caller_identity() -> Result<(String, String)> {
    let mut token: HANDLE = null_mut();
    if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
        return Err(last_error());
    }
    let token = Handle(token);
    let mut buf = vec![0u8; 512];
    let mut len = 0u32;
    if GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len) == 0 {
        return Err(last_error());
    }
    let tu = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid = tu.User.Sid;
    let mut sid_str: *mut u16 = null_mut();
    if ConvertSidToStringSidW(sid, &mut sid_str) == 0 {
        return Err(last_error());
    }
    let mut n = 0;
    while *sid_str.add(n) != 0 {
        n += 1;
    }
    let sid_text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, n));
    LocalFree(sid_str.cast());
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let (mut nl, mut dl) = (name.len() as u32, domain.len() as u32);
    let mut use_: SID_NAME_USE = 0;
    let display =
        if LookupAccountSidW(null(), sid, name.as_mut_ptr(), &mut nl, domain.as_mut_ptr(), &mut dl, &mut use_) != 0 {
            format!(
                "{}\\{}",
                String::from_utf16_lossy(&domain[..dl as usize]),
                String::from_utf16_lossy(&name[..nl as usize])
            )
        } else {
            sid_text.clone()
        };
    Ok((sid_text, display))
}

fn serve_one(state: &Shared) -> Result<()> {
    unsafe {
        let sddl = wide(PIPE_SDDL);
        let mut psd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut psd, null_mut())
            == 0
        {
            return Err(last_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        let name = wide(PIPE_NAME);
        let h = CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            512,
            512,
            0,
            &sa,
        );
        LocalFree(psd);
        if h == INVALID_HANDLE_VALUE {
            bail!("can't create the sign-in pipe (is another copy running?): {}", last_error());
        }
        let pipe = Handle(h);
        if ConnectNamedPipe(pipe.0, null_mut()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
            return Err(last_error());
        }
        // Impersonation needs the client to have written first.
        let mut req = [0u8; 64];
        let mut read = 0u32;
        if ReadFile(pipe.0, req.as_mut_ptr(), req.len() as u32, &mut read, null_mut()) == 0 || read == 0 {
            DisconnectNamedPipe(pipe.0);
            return Ok(());
        }
        let reply = if &req[..read as usize] != b"SIGNIN\n" {
            "ERR unknown request\n".to_string()
        } else {
            if ImpersonateNamedPipeClient(pipe.0) == 0 {
                DisconnectNamedPipe(pipe.0);
                return Err(last_error());
            }
            let ident = caller_identity();
            if RevertToSelf() == 0 {
                // Never keep running as someone else.
                std::process::abort();
            }
            match ident {
                Ok((sid, display)) => match state.store.windows_user(&sid, &display) {
                    Ok(u) if !u.disabled => {
                        let token = state.issue_onetime(u.id);
                        state.audit.record(
                            "auth.onetime_issued",
                            Some(&u.username),
                            Some("pipe"),
                            serde_json::json!({ "sid": sid }),
                        );
                        format!("OK {token}\n")
                    }
                    Ok(_) => "ERR this account is disabled in Gogo Desktop\n".into(),
                    Err(e) => format!("ERR {e}\n"),
                },
                Err(e) => format!("ERR can't read your Windows identity: {e}\n"),
            }
        };
        let mut written = 0u32;
        WriteFile(pipe.0, reply.as_ptr(), reply.len() as u32, &mut written, null_mut());
        FlushFileBuffers(pipe.0);
        DisconnectNamedPipe(pipe.0);
        Ok(())
    }
}

/// `gogo signin`: asks the service for a sign-in link and opens the browser.
pub fn client(cfg: &Config) -> Result<()> {
    let port =
        cfg.http_bind.map(|a| a.port()).ok_or_else(|| anyhow!("same-PC sign-in needs GOGO_HTTP_BIND on 127.0.0.1"))?;
    let reply = unsafe {
        let name = wide(PIPE_NAME);
        let h = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            // Let the service identify us, but not act as us.
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            bail!("Gogo Desktop isn't running on this PC ({}). Start the service and try again.", last_error());
        }
        let pipe = Handle(h);
        let msg = b"SIGNIN\n";
        let mut n = 0u32;
        if WriteFile(pipe.0, msg.as_ptr(), msg.len() as u32, &mut n, null_mut()) == 0 {
            return Err(last_error());
        }
        let mut buf = [0u8; 256];
        if ReadFile(pipe.0, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) == 0 {
            return Err(last_error());
        }
        String::from_utf8_lossy(&buf[..n as usize]).trim().to_string()
    };
    let token = match reply.strip_prefix("OK ") {
        Some(t) if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => t.to_string(),
        _ => bail!("{}", reply.strip_prefix("ERR ").unwrap_or(&reply)),
    };
    // The token travels in the URL fragment, so it never reaches server logs.
    let url = format!("http://127.0.0.1:{port}/signin#{token}");
    std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", &url]).spawn()?;
    println!("Opening Gogo Desktop in your browser. The link works once, within 60 seconds.");
    Ok(())
}
