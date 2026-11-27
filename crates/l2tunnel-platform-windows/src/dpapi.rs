//! Windows DPAPI secret envelope sealing (`L2DP` format, CL-27).
//!
//! Portable envelope framing and validation run on every host; native
//! `CryptProtectData` / `CryptUnprotectData` calls live in the narrow
//! documented `ffi` submodule on Windows targets. Plaintext buffers are
//! zeroized via `zeroize::Zeroizing`.
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

/// 4-byte magic prefix marking a DPAPI-sealed l2tunnel secret blob.
pub const DPAPI_MAGIC: &[u8; 4] = b"L2DP";
/// Envelope version byte.
pub const DPAPI_VERSION: u8 = 1;
/// Maximum secret size accepted for sealing or unsealing (64 KiB).
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Fixed header length: `L2DP` (4) + version (1) + scope (1) + reserved (2).
const HEADER_LEN: usize = 8;

/// DPAPI protection scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Bound to the current Windows user logon (for unprivileged user key stores).
    CurrentUser = 1,
    /// Bound to the local machine (readable by the LocalSystem Windows service).
    LocalMachine = 2,
}

impl Scope {
    fn from_byte(byte: u8) -> io::Result<Self> {
        match byte {
            1 => Ok(Self::CurrentUser),
            2 => Ok(Self::LocalMachine),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown DPAPI scope byte in L2DP envelope",
            )),
        }
    }
}

/// Returns true when `bytes` starts with the [`DPAPI_MAGIC`] header.
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN && &bytes[..4] == DPAPI_MAGIC
}

/// Wrap raw ciphertext into an `L2DP` envelope.
pub fn encode_envelope(scope: Scope, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_SECRET_BYTES * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DPAPI ciphertext length out of bounds",
        ));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(DPAPI_MAGIC);
    out.push(DPAPI_VERSION);
    out.push(scope as u8);
    out.extend_from_slice(&[0u8, 0u8]);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Parse and validate an `L2DP` envelope without calling Windows APIs.
pub fn decode_envelope(blob: &[u8]) -> io::Result<(Scope, &[u8])> {
    if blob.len() <= HEADER_LEN || blob.len() > HEADER_LEN + MAX_SECRET_BYTES * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI envelope length out of bounds",
        ));
    }
    if &blob[..4] != DPAPI_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing L2DP DPAPI magic header",
        ));
    }
    if blob[4] != DPAPI_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported L2DP DPAPI envelope version",
        ));
    }
    let scope = Scope::from_byte(blob[5])?;
    Ok((scope, &blob[HEADER_LEN..]))
}

/// Seal `plaintext` using Windows DPAPI and wrap it in an `L2DP` envelope.
pub fn protect_secret(plaintext: &[u8], scope: Scope) -> io::Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret length must be 1..=65536 bytes",
        ));
    }
    #[cfg(windows)]
    {
        let ciphertext = ffi::protect(plaintext, scope)?;
        encode_envelope(scope, &ciphertext)
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows DPAPI sealing requires Windows",
        ))
    }
}

/// Unseal an `L2DP` DPAPI envelope into a zeroizing buffer.
pub fn unprotect_secret(blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let (_scope, ciphertext) = decode_envelope(blob)?;
    #[cfg(windows)]
    {
        ffi::unprotect(ciphertext)
    }
    #[cfg(not(windows))]
    {
        let _ = ciphertext;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows DPAPI unsealing requires Windows",
        ))
    }
}

/// Read a key file transparently: if it starts with `L2DP`, unseal via DPAPI;
/// otherwise return the bounded raw bytes in a zeroizing buffer.
pub fn read_maybe_sealed_file(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() == 0 || meta.len() > (HEADER_LEN + MAX_SECRET_BYTES * 2) as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret file size out of bounds",
        ));
    }
    let raw = Zeroizing::new(std::fs::read(path)?);
    if is_sealed(&raw) {
        unprotect_secret(&raw)
    } else {
        Ok(raw)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use super::{MAX_SECRET_BYTES, Scope};
    use std::io;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CryptProtectData, CryptUnprotectData,
    };
    use zeroize::Zeroizing;

    /// Domain-separation entropy bound to l2tunnel DPAPI blobs.
    const ENTROPY: &[u8] = b"l2tunnel-win-dpapi-v1";

    struct CryptoBlobGuard(CRYPT_INTEGER_BLOB);

    impl Drop for CryptoBlobGuard {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: `pbData` was allocated by `CryptProtectData` /
                // `CryptUnprotectData` with `LocalAlloc` and has length `cbData`.
                // Zeroize sensitive bytes before releasing with `LocalFree`.
                unsafe {
                    if self.0.cbData > 0 {
                        std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
                    }
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }

    pub(super) fn protect(plaintext: &[u8], scope: Scope) -> io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(plaintext.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "secret too large"))?,
            pbData: plaintext.as_ptr().cast_mut(),
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr().cast_mut(),
        };
        let mut output = CryptoBlobGuard(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        });
        let flags = match scope {
            Scope::CurrentUser => CRYPTPROTECT_UI_FORBIDDEN,
            Scope::LocalMachine => CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
        };
        // SAFETY: `input` and `entropy` point to valid read-only slices for the
        // duration of the call; `output.0` is initialized and freed by `Drop`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                null(),
                &entropy,
                null_mut(),
                null_mut(),
                flags,
                &mut output.0,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if output.0.pbData.is_null() || output.0.cbData == 0 {
            return Err(io::Error::other("CryptProtectData returned an empty blob"));
        }
        // SAFETY: `pbData` is valid for `cbData` bytes until `output` drops.
        let slice =
            unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
        Ok(slice.to_vec())
    }

    pub(super) fn unprotect(ciphertext: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(ciphertext.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ciphertext too large"))?,
            pbData: ciphertext.as_ptr().cast_mut(),
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr().cast_mut(),
        };
        let mut output = CryptoBlobGuard(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        });
        // SAFETY: `input` and `entropy` point to valid slices for the duration of
        // the call; `output.0` is initialized and zeroized+freed on drop.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                &entropy,
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = output.0.cbData as usize;
        if output.0.pbData.is_null() || len == 0 || len > MAX_SECRET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DPAPI unsealed secret length out of bounds",
            ));
        }
        // SAFETY: `pbData` is valid for `len` bytes until `output` drops.
        let slice = unsafe { std::slice::from_raw_parts(output.0.pbData, len) };
        Ok(Zeroizing::new(slice.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_and_bounds() -> io::Result<()> {
        let blob = encode_envelope(Scope::LocalMachine, b"ciphertext-bytes")?;
        assert!(is_sealed(&blob));
        let (scope, ct) = decode_envelope(&blob)?;
        assert_eq!(scope, Scope::LocalMachine);
        assert_eq!(ct, b"ciphertext-bytes");
        assert!(!is_sealed(b"plain-key-bytes"));
        assert!(decode_envelope(b"short").is_err());
        assert!(decode_envelope(b"XXXX\x01\x02\x00\x00abc").is_err());
        assert!(decode_envelope(b"L2DP\x09\x02\x00\x00abc").is_err());
        assert!(decode_envelope(b"L2DP\x01\x09\x00\x00abc").is_err());
        assert!(encode_envelope(Scope::CurrentUser, &[]).is_err());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn native_dpapi_round_trip_current_user() -> io::Result<()> {
        let secret = b"0123456789abcdef0123456789abcdef";
        let sealed = protect_secret(secret, Scope::CurrentUser)?;
        assert!(is_sealed(&sealed));
        assert_ne!(&sealed[HEADER_LEN..], secret);
        let opened = unprotect_secret(&sealed)?;
        assert_eq!(opened.as_slice(), secret);
        Ok(())
    }
}
