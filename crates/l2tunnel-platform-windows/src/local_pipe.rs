//! Local API named-pipe naming, access policy and the narrow Windows security
//! boundary (docs/modules/windows-local-service.md, WLS-02/WLS-03).
//!
//! Name validation and the access constants are portable so that their
//! structure is unit-tested on every host. Only `create_local_api_pipe` and
//! `open_local_api_pipe` (Windows targets) touch Windows, and they live in the one module of
//! this crate that may contain `unsafe` (`ffi`).
use std::io;

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;
#[cfg(windows)]
pub use ffi::{create_local_api_pipe, open_local_api_pipe};

/// Default pipe of the installed l2tunnel Windows service.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\l2tunnel";
/// Only the local pipe namespace is accepted; `\\SERVER\pipe\...` is refused.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";
/// Maximum characters after [`PIPE_PREFIX`] (the whole name stays below 256).
pub const MAX_PIPE_COMPONENT: usize = 200;

/// Proposed DACL of the local API pipe, in SDDL. **Proposal awaiting owner
/// confirmation**, not an owner decision.
///
/// - `D:P`: a protected DACL, so nothing is inherited.
/// - `(A;;GA;;;SY)`: LocalSystem, full access (the installed service).
/// - `(A;;GA;;;BA)`: BUILTIN\Administrators, full access (elevated foreground
///   testing and administration).
/// - `(A;;0x12019b;;;IU)`: NT AUTHORITY\INTERACTIVE, [`INTERACTIVE_ACCESS`]:
///   read and write data but *not* `FILE_CREATE_PIPE_INSTANCE`, so a
///   nonprivileged user cannot add a competing server instance.
///
/// Network logons, services and anonymous callers receive no entry; remote
/// clients are additionally refused by `PIPE_REJECT_REMOTE_CLIENTS`.
pub const LOCAL_API_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
/// For a named pipe this bit is `FILE_CREATE_PIPE_INSTANCE`.
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_EA: u32 = 0x0008;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_GENERIC_READ: u32 =
    READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES;
const FILE_GENERIC_WRITE: u32 = READ_CONTROL
    | SYNCHRONIZE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES;

/// Access granted to interactive users: generic read and write except
/// `FILE_CREATE_PIPE_INSTANCE`.
pub const INTERACTIVE_ACCESS: u32 = (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_APPEND_DATA;
/// Access a client requests. `GENERIC_WRITE` would map to
/// `FILE_CREATE_PIPE_INSTANCE`, which interactive users are not granted, so
/// clients request exactly read, data write and `READ_CONTROL` (needed to read
/// the pipe owner).
pub const CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;
/// `ERROR_PIPE_BUSY`: every server instance is connected.
pub const ERROR_PIPE_BUSY: i32 = 231;

/// Whether opening failed only because every instance is busy (retryable).
pub fn is_pipe_busy(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_PIPE_BUSY)
}

/// Validate a local pipe name: exactly `\\.\pipe\` followed by 1..=200 ASCII
/// letters, digits, `.`, `_` or `-` (not only dots). Remote, device-namespace
/// and nested names are refused before any I/O.
pub fn validate_pipe_name(name: &str) -> io::Result<()> {
    let refuse = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            r"local API pipe must be \\.\pipe\NAME with NAME of 1..=200 ASCII letters, digits, '.', '_' or '-'",
        )
    };
    let prefix = name.get(..PIPE_PREFIX.len()).ok_or_else(refuse)?;
    if !prefix.eq_ignore_ascii_case(PIPE_PREFIX) {
        return Err(refuse());
    }
    let component = &name[PIPE_PREFIX.len()..];
    if component.is_empty()
        || component.len() > MAX_PIPE_COMPONENT
        || component.bytes().all(|byte| byte == b'.')
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names_are_local_and_bounded() {
        for name in [
            DEFAULT_PIPE_NAME,
            r"\\.\PIPE\l2tunnel-test_1.0",
            &format!(r"\\.\pipe\{}", "a".repeat(MAX_PIPE_COMPONENT)),
        ] {
            assert!(validate_pipe_name(name).is_ok(), "{name}");
        }
        for name in [
            "",
            "l2tunnel",
            r"\\.\pipe\",
            r"\\.\pipe\..",
            r"\\server\pipe\l2tunnel",
            r"\\?\pipe\l2tunnel",
            r"\\.\C:\l2tunnel",
            r"\\.\pipe\nested\name",
            r"\\.\pipe\space name",
            r"\\.\pipe\l2tunnel/x",
            "\\\\.\\pipe\\nul\0",
            r"\\.\pipe\é",
            &format!(r"\\.\pipe\{}", "a".repeat(MAX_PIPE_COMPONENT + 1)),
        ] {
            let error = validate_pipe_name(name).err().map(|error| error.kind());
            assert_eq!(error, Some(io::ErrorKind::InvalidInput), "{name:?}");
        }
    }

    #[test]
    fn proposed_dacl_is_explicit_and_withholds_instance_creation() {
        assert_eq!(INTERACTIVE_ACCESS, 0x0012_019b);
        assert_eq!(
            LOCAL_API_PIPE_SDDL,
            format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{INTERACTIVE_ACCESS:#x};;;IU)")
        );
        // Protected, allow-only, and no broad principals.
        assert!(LOCAL_API_PIPE_SDDL.starts_with("D:P("));
        assert!(!LOCAL_API_PIPE_SDDL.contains("(D;"));
        for broad in [";WD)", ";AU)", ";AN)", ";NU)", ";BU)", ";NS)", ";LS)"] {
            assert!(!LOCAL_API_PIPE_SDDL.contains(broad), "{broad}");
        }
        assert_eq!(LOCAL_API_PIPE_SDDL.matches("(A;").count(), 3);
        // Interactive users cannot create pipe instances.
        assert_eq!(INTERACTIVE_ACCESS & FILE_APPEND_DATA, 0);
        // The client request is a subset of the interactive grant and can
        // read the owner.
        assert_eq!(CLIENT_ACCESS & !INTERACTIVE_ACCESS, 0);
        assert_eq!(CLIENT_ACCESS & FILE_APPEND_DATA, 0);
        for required in [READ_CONTROL, FILE_READ_DATA, FILE_WRITE_DATA] {
            assert_eq!(CLIENT_ACCESS & required, required);
        }
    }

    #[test]
    fn only_pipe_busy_is_retryable() {
        assert!(is_pipe_busy(&io::Error::from_raw_os_error(ERROR_PIPE_BUSY)));
        assert!(!is_pipe_busy(&io::Error::from_raw_os_error(2)));
        assert!(!is_pipe_busy(&io::Error::other("busy")));
    }

    #[cfg(windows)]
    #[test]
    fn portable_masks_match_the_windows_definitions() {
        use windows_sys::Win32::Storage::FileSystem as fs;
        assert_eq!(FILE_GENERIC_READ, fs::FILE_GENERIC_READ);
        assert_eq!(FILE_GENERIC_WRITE, fs::FILE_GENERIC_WRITE);
        assert_eq!(FILE_APPEND_DATA, fs::FILE_APPEND_DATA);
        assert_eq!(
            ERROR_PIPE_BUSY,
            windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32
        );
    }
}
