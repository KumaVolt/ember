//! PAM password authentication for system accounts.
//!
//! Written against the C API directly rather than a crate: `pam-client2` and
//! `pam` both hardcode Linux-PAM internals that OpenPAM (macOS, BSD) does not
//! have, and neither builds here. The subset used below — `pam_start`,
//! `pam_authenticate`, `pam_acct_mgmt`, `pam_end` — is identical on both
//! implementations, so this works on the developer's Mac and in the container.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use anyhow::{Context, Result, bail};

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(handle: *mut c_void, code: c_int) -> *const c_char;
}

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

// The only constant that genuinely differs between the two implementations.
#[cfg(target_os = "linux")]
const PAM_CONV_ERR: c_int = 19;
#[cfg(not(target_os = "linux"))]
const PAM_CONV_ERR: c_int = 6;

/// Which PAM stack to authenticate against.
///
/// macOS ships `chkpasswd` (pam_opendirectory), which exists precisely to check
/// a password and works without root for one's own account. Linux has no
/// universal equivalent, so the container ships `/etc/pam.d/ember`.
pub fn default_service() -> String {
    if let Ok(service) = std::env::var("EMBER_PAM_SERVICE") {
        return service;
    }
    if cfg!(target_os = "macos") {
        "chkpasswd".to_string()
    } else {
        "ember".to_string()
    }
}

/// Hands the password to every "prompt without echo" request PAM makes.
///
/// # Safety
/// Called by libpam. `appdata` is the `CString` password passed to `pam_start`,
/// which outlives the exchange. Responses are allocated with `malloc`/`strdup`
/// because libpam takes ownership and frees them itself.
unsafe extern "C" fn converse(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    unsafe {
        if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
            return PAM_CONV_ERR;
        }
        let password = &*(appdata as *const CString);
        let count = num_msg as usize;

        let responses = libc::calloc(count, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if responses.is_null() {
            return PAM_CONV_ERR;
        }

        for i in 0..count {
            let message = *msg.add(i);
            let slot = responses.add(i);
            (*slot).resp_retcode = 0;
            // Only answer password prompts. An echoing prompt is asking for
            // something else (usually the username, which pam_start already
            // supplied), and echoing the password back would be a leak.
            (*slot).resp = if !message.is_null() && (*message).msg_style == PAM_PROMPT_ECHO_OFF {
                libc::strdup(password.as_ptr())
            } else {
                std::ptr::null_mut()
            };
        }

        *resp = responses;
        PAM_SUCCESS
    }
}

/// Verify a system account's password.
///
/// Returns `Ok(false)` for a genuine authentication failure and `Err` only when
/// PAM itself could not run — the caller must not report a misconfigured stack
/// as "wrong password".
pub fn authenticate(service: &str, user: &str, password: &str) -> Result<bool> {
    let c_service = CString::new(service).context("invalid PAM service name")?;
    let c_user = CString::new(user).context("invalid username")?;
    let c_password = CString::new(password).context("password contains a NUL byte")?;

    let conv = PamConv {
        conv: Some(converse),
        appdata_ptr: &c_password as *const CString as *mut c_void,
    };

    let mut handle: *mut c_void = std::ptr::null_mut();

    // SAFETY: all pointers are valid for the duration of the call, and the
    // handle is closed with pam_end on every path below.
    unsafe {
        let rc = pam_start(c_service.as_ptr(), c_user.as_ptr(), &conv, &mut handle);
        if rc != PAM_SUCCESS || handle.is_null() {
            bail!("pam_start failed for service {service:?} (code {rc})");
        }

        let auth_rc = pam_authenticate(handle, 0);
        if auth_rc != PAM_SUCCESS {
            let reason = strerror(handle, auth_rc);
            pam_end(handle, auth_rc);
            // A missing or deny-all stack is a configuration fault, not a bad
            // password, and must be distinguishable in the logs.
            if is_stack_failure(auth_rc) {
                bail!("PAM service {service:?} could not authenticate: {reason}");
            }
            return Ok(false);
        }

        // Catches expired, locked, and disabled accounts — a panel must honour
        // those, not just the password check.
        let acct_rc = pam_acct_mgmt(handle, 0);
        if acct_rc != PAM_SUCCESS {
            let reason = strerror(handle, acct_rc);
            pam_end(handle, acct_rc);
            // The password was right but the account is not usable. Denied, not
            // an error — but say why in the log rather than swallowing it.
            crate::esw::log_line(&format!("pam: {user} passed auth but was denied: {reason}"));
            return Ok(false);
        }

        pam_end(handle, PAM_SUCCESS);
    }

    Ok(true)
}

/// Distinguish "the stack is broken" from "the credentials were wrong".
fn is_stack_failure(code: c_int) -> bool {
    // PAM_ABORT and PAM_SYSTEM_ERR (and PAM_SERVICE_ERR) mean the stack itself
    // failed. Their numeric values differ between implementations, so match the
    // ones each actually uses.
    #[cfg(target_os = "linux")]
    {
        matches!(code, 3 | 4 | 26) // SERVICE_ERR, SYSTEM_ERR, ABORT
    }
    #[cfg(not(target_os = "linux"))]
    {
        matches!(code, 1 | 4 | 5) // SERVICE_ERR, SYSTEM_ERR, ABORT
    }
}

/// # Safety
/// `handle` must be a live PAM handle.
unsafe fn strerror(handle: *mut c_void, code: c_int) -> String {
    unsafe {
        let text = pam_strerror(handle, code);
        if text.is_null() {
            return format!("PAM error {code}");
        }
        CStr::from_ptr(text).to_string_lossy().into_owned()
    }
}
