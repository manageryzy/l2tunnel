//! Windows directory ACL verification (`WLS-08`).
//!
//! Ensures that directories holding the service binary, state/profiles, or
//! Wintun DLL are owned by `LocalSystem` or `BUILTIN\Administrators` and do not
//! grant write/modify/full-control rights to non-administrator principals.
use std::io;
use std::path::Path;

/// Bits that allow modifying directory contents, permissions, or ownership.
pub const WRITE_DANGEROUS_MASK: u32 = 0x0000_0002 // FILE_ADD_FILE / WRITE_DATA
    | 0x0000_0004 // FILE_ADD_SUBDIRECTORY / APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Result of checking a directory's ownership and DACL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AclAudit {
    /// Whether the directory is owned by LocalSystem or BUILTIN\Administrators.
    pub privileged_owner: bool,
    /// Whether any non-admin allow ACE grants write/modify permissions.
    pub non_admin_writable: bool,
}

impl AclAudit {
    /// True when the directory satisfies `WLS-08` (admin-owned, not writable by non-admins).
    pub fn is_safe(&self) -> bool {
        self.privileged_owner && !self.non_admin_writable
    }
}

/// Inspect `directory` and return an [`AclAudit`] without modifying anything.
pub fn audit_admin_only_directory(directory: &Path) -> io::Result<AclAudit> {
    if !directory.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path for ACL audit must be absolute",
        ));
    }
    let meta = std::fs::symlink_metadata(directory)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACL audit target must be a real directory (not a symlink)",
        ));
    }
    #[cfg(windows)]
    {
        ffi::audit_directory(directory)
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows ACL auditing requires Windows",
        ))
    }
}

/// Require `directory` to be owned by LocalSystem/Administrators and not writable
/// by non-administrators (`WLS-08`).
pub fn require_admin_only_directory(directory: &Path) -> io::Result<()> {
    let audit = audit_admin_only_directory(directory)?;
    if !audit.privileged_owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} is not owned by LocalSystem or BUILTIN\\Administrators",
                directory.display()
            ),
        ));
    }
    if audit.non_admin_writable {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} grants write permissions to non-administrators; tighten ACLs with icacls",
                directory.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use super::{AclAudit, WRITE_DANGEROUS_MASK};
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinCreatorOwnerSid, WinLocalSystemSid,
    };

    /// `ACCESS_ALLOWED_ACE_TYPE` from Windows SDK `winnt.h`.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    struct SdGuard(PSECURITY_DESCRIPTOR);

    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by `GetNamedSecurityInfoW` via `LocalAlloc`.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn is_admin_sid(sid: PSID) -> bool {
        if sid.is_null() {
            return false;
        }
        // SAFETY: `sid` points into an active security descriptor owned by `SdGuard`.
        unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
    }

    pub(super) fn audit_directory(directory: &Path) -> io::Result<AclAudit> {
        let wide: Vec<u16> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut raw_sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16; all out pointers are valid stack locals.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut raw_sd,
            )
        };
        let _sd = SdGuard(raw_sd);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let privileged_owner = is_admin_sid(owner);
        // A NULL DACL grants Everyone full access.
        if dacl.is_null() {
            return Ok(AclAudit {
                privileged_owner,
                non_admin_writable: true,
            });
        }
        let mut size_info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` points into `_sd` and `size_info` matches `AclSizeInformation`.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size_info).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut non_admin_writable = false;
        for index in 0..size_info.AceCount {
            let mut ace_ptr: *mut c_void = null_mut();
            // SAFETY: `index < size_info.AceCount` and `dacl` is alive.
            if unsafe { GetAce(dacl, index, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
                continue;
            }
            // SAFETY: every ACE begins with `ACE_HEADER`; when `AceType == ACCESS_ALLOWED_ACE_TYPE`
            // it has the `ACCESS_ALLOWED_ACE` layout with the SID starting at `SidStart`.
            let (ace_type, mask, sid) = unsafe {
                let ace = &*(ace_ptr.cast::<ACCESS_ALLOWED_ACE>());
                let sid = (&raw const ace.SidStart).cast::<c_void>().cast_mut();
                (ace.Header.AceType, ace.Mask, sid)
            };
            if ace_type == ACCESS_ALLOWED_ACE_TYPE && (mask & WRITE_DANGEROUS_MASK) != 0 {
                // SAFETY: `sid` points into `_sd`.
                let creator_owner = unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid) != 0 };
                if !is_admin_sid(sid) && !creator_owner {
                    non_admin_writable = true;
                    break;
                }
            }
        }
        Ok(AclAudit {
            privileged_owner,
            non_admin_writable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_audit_logic_and_relative_rejection() {
        assert!(
            AclAudit {
                privileged_owner: true,
                non_admin_writable: false
            }
            .is_safe()
        );
        assert!(
            !AclAudit {
                privileged_owner: true,
                non_admin_writable: true
            }
            .is_safe()
        );
        assert!(
            !AclAudit {
                privileged_owner: false,
                non_admin_writable: false
            }
            .is_safe()
        );
        assert!(audit_admin_only_directory(Path::new("relative/dir")).is_err());
    }
}
