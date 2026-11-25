//! The crate's only `unsafe` boundary (WLS-03; safety review in
//! docs/modules/windows-local-service.md). It contains exactly four kinds of
//! foreign call, each with a stated precondition:
//!
//! 1. `ConvertStringSecurityDescriptorToSecurityDescriptorW` turns the fixed
//!    [`LOCAL_API_PIPE_SDDL`] into a `LocalAlloc`ated descriptor owned by
//!    [`LocalDescriptor`], which frees it exactly once.
//! 2. Tokio's `create_with_security_attributes_raw` receives a pointer to a
//!    stack `SECURITY_ATTRIBUTES` whose descriptor outlives the call.
//!    `CreateNamedPipeW` copies the descriptor into the kernel object.
//! 3. `GetSecurityInfo` and `IsWellKnownSid` read the owner of a handle that
//!    is borrowed for the duration of the calls; the owner SID points into
//!    the returned descriptor, which outlives its last use.
//! 4. Tokio's `NamedPipeClient::from_raw_handle` takes sole ownership of a
//!    freshly opened overlapped pipe handle released by `File::into_raw_handle`.
//!
//! No pointer escapes these functions, and nothing here is `Send`/`Sync` by
//! assertion.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::{CLIENT_ACCESS, LOCAL_API_PIPE_SDDL, validate_pipe_name};
use std::ffi::{OsStr, c_void};
use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, AsRawHandle, IntoRawHandle};
use std::ptr::null_mut;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION};

/// Maximum simultaneous instances a caller may request (the Windows limit is 255).
const MAX_INSTANCES: usize = 254;

/// A descriptor allocated by the system with `LocalAlloc`; freed once on drop.
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by a Windows API documented to
            // allocate it with LocalAlloc, is owned only by this value, and is
            // freed only here. A failure result leaks nothing further.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn proposed_descriptor() -> io::Result<LocalDescriptor> {
    let sddl: Vec<u16> = OsStr::new(LOCAL_API_PIPE_SDDL)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `sddl` is a NUL-terminated UTF-16 buffer that lives across the
    // call; `descriptor` is a valid out pointer; the optional size out
    // parameter is documented to accept null.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalDescriptor(descriptor))
}

/// Create one server instance of the local API pipe `name` with the proposed
/// [`LOCAL_API_PIPE_SDDL`], byte mode and `PIPE_REJECT_REMOTE_CLIENTS`.
///
/// `first` sets `FILE_FLAG_FIRST_PIPE_INSTANCE`: creation then fails if any
/// other process already created the name, instead of joining its pipe. The
/// first instance's owner must be LocalSystem or Administrators (see
/// [`open_local_api_pipe`]), so a nonelevated foreground host is refused
/// before it serves anything. Must be called inside a Tokio runtime.
pub fn create_local_api_pipe(
    name: &str,
    first: bool,
    max_instances: usize,
) -> io::Result<NamedPipeServer> {
    validate_pipe_name(name)?;
    if !(1..=MAX_INSTANCES).contains(&max_instances) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe instance limit must be 1..=254",
        ));
    }
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .access_inbound(true)
        .access_outbound(true)
        .max_instances(max_instances);
    let descriptor = proposed_descriptor()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` is a valid, initialized SECURITY_ATTRIBUTES whose
    // descriptor (owned by `descriptor`) is alive until after this call;
    // CreateNamedPipeW copies it and retains no pointer.
    let server = unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }?;
    drop(descriptor);
    if first {
        verify_privileged_owner(&server).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the local API pipe must be created by LocalSystem or an elevated administrator",
            )
        })?;
    }
    Ok(server)
}

/// Open the local API pipe `name` as a client with [`CLIENT_ACCESS`] and
/// identification-only impersonation, then require that the pipe is owned by
/// LocalSystem or BUILTIN\Administrators.
///
/// The owner check refuses a pipe a nonprivileged user created before the
/// service (name squatting). It does not prove which executable serves the
/// pipe: any LocalSystem or administrator process passes. Busy pipes return
/// the raw `ERROR_PIPE_BUSY` error. Must be called inside a Tokio runtime.
pub fn open_local_api_pipe(name: &str) -> io::Result<NamedPipeClient> {
    validate_pipe_name(name)
        .map_err(|error| io::Error::new(io::ErrorKind::NotFound, error.to_string()))?;
    let file = OpenOptions::new()
        .access_mode(CLIENT_ACCESS)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)?;
    verify_privileged_owner(&file)?;
    let handle = file.into_raw_handle();
    // SAFETY: `handle` was just opened with FILE_FLAG_OVERLAPPED on a named
    // pipe and released by `into_raw_handle`, so Tokio becomes its sole owner
    // (and closes it if registration fails).
    unsafe { NamedPipeClient::from_raw_handle(handle) }
}

/// Require the pipe object's owner to be LocalSystem or BUILTIN\Administrators.
fn verify_privileged_owner(pipe: &impl AsHandle) -> io::Result<()> {
    let handle = pipe.as_handle();
    let mut owner: PSID = null_mut();
    let mut raw: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is a live handle borrowed for this call; the owner and
    // descriptor out pointers are valid; unrequested outputs are null as
    // documented for GetSecurityInfo.
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut raw,
        )
    };
    let descriptor = LocalDescriptor(raw);
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let privileged = !owner.is_null()
        // SAFETY: `owner` points into `descriptor`, which is alive here.
        && unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        };
    drop(descriptor);
    if privileged {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local API pipe is not owned by LocalSystem or Administrators",
        ))
    }
}
