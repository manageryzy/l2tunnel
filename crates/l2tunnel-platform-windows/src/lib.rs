//! Safe Windows Wintun L3 boundary; no protocol, authentication or service engine.
//!
//! Construction is privileged, blocking platform work. Packet operations are
//! nonblocking. The maintained `tun-rs` dependency owns its reviewed native FFI;
//! this crate inherits the workspace's `unsafe_code = "forbid"` policy.

#[cfg(any(windows, test))]
use l2tunnel_device::MAX_PACKET_BYTES;
#[cfg(any(windows, test))]
use ring::digest::{Context, SHA256};
use std::io;
#[cfg(any(windows, test))]
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::Device;

/// Maximum DLL size accepted before any native library is loaded.
pub const MAX_DLL_BYTES: u64 = 16 * 1024 * 1024;
/// Fixed, bounded Wintun receive/send ring capacity (one MiB).
pub const RING_CAPACITY: u32 = 1024 * 1024;

/// Local, administrator-supplied configuration for a newly owned L3 adapter.
///
/// The DLL digest is an operator trust decision, never peer-controlled input.
/// Existing adapter names, default routes, DNS and driver deletion are excluded.
#[derive(Clone)]
pub struct Config {
    dll: PathBuf,
    dll_sha256: [u8; 32],
    address: Ipv4Addr,
    prefix: u8,
    mtu: u16,
}

impl Config {
    /// Validate configuration without opening files or changing the host.
    ///
    /// Windows accepts only absolute paths on local drive letters. Opening the
    /// device resolves that path, locks the DLL against file writes/deletion,
    /// and verifies its SHA-256 pin before loading it.
    pub fn new(
        dll: PathBuf,
        dll_sha256: [u8; 32],
        address: Ipv4Addr,
        prefix: u8,
        mtu: u16,
    ) -> io::Result<Self> {
        validate_dll_path(&dll)?;
        if address.is_unspecified()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_loopback()
        {
            return Err(invalid(
                "Wintun address must be a non-loopback unicast IPv4 address",
            ));
        }
        if prefix == 0 || prefix > 32 {
            return Err(invalid("Wintun IPv4 prefix must be in 1..=32"));
        }
        if mtu < 1280 {
            return Err(invalid("Wintun MTU must be in 1280..=65535"));
        }
        Ok(Self {
            dll,
            dll_sha256,
            address,
            prefix,
            mtu,
        })
    }

    /// Explicit local DLL path; no search-path fallback is supported.
    pub fn dll_path(&self) -> &Path {
        &self.dll
    }

    /// Operator-supplied SHA-256 digest of the selected DLL.
    pub fn dll_sha256(&self) -> &[u8; 32] {
        &self.dll_sha256
    }

    /// Address assigned only to the newly owned interface.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// IPv4 prefix length assigned only to the newly owned interface.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// IPv4 and IPv6 MTU assigned only to the newly owned interface.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_dll_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("dll"))
    {
        return Err(invalid(
            "Wintun path must be an absolute file with an explicit .dll extension",
        ));
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if !matches!(
            path.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            return Err(invalid(
                "Wintun DLL must use a local drive path, not UNC or device paths",
            ));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn verify_dll(reader: &mut impl Read, expected: &[u8; 32]) -> io::Result<()> {
    let mut digest = Context::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|total| *total <= MAX_DLL_BYTES)
            .ok_or_else(|| invalid("Wintun DLL exceeds the permitted size"))?;
        digest.update(&buffer[..read]);
    }
    if total == 0 || digest.finish().as_ref() != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Wintun DLL SHA-256 pin mismatch or empty DLL",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn validate_packet(packet: &[u8]) -> io::Result<()> {
    if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
        return Err(invalid("Wintun IP packet length is outside 1..=65535"));
    }
    let valid = match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            header >= 20 && header <= packet.len() && total == packet.len()
        }
        6 if packet.len() >= 40 => {
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            payload + 40 == packet.len()
        }
        _ => false,
    };
    if !valid {
        return Err(invalid("Wintun requires one complete IPv4 or IPv6 packet"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::digest;
    use std::io::Cursor;

    fn absolute_dll() -> PathBuf {
        #[cfg(windows)]
        return PathBuf::from(r"C:\trusted\wintun.dll");
        #[cfg(not(windows))]
        PathBuf::from("/trusted/wintun.dll")
    }

    #[test]
    fn config_rejects_implicit_paths_and_invalid_network_parameters() -> io::Result<()> {
        let address = Ipv4Addr::new(10, 77, 0, 1);
        let mut extensionless = absolute_dll();
        extensionless.set_extension("");
        assert!(Config::new(extensionless, [0; 32], address, 24, 1400).is_err());
        let mut wrong_extension = absolute_dll();
        wrong_extension.set_extension("bin");
        assert!(Config::new(wrong_extension, [0; 32], address, 24, 1400).is_err());
        assert!(Config::new("wintun.dll".into(), [0; 32], address, 24, 1400).is_err());
        for prefix in [0, 33, u8::MAX] {
            assert!(Config::new(absolute_dll(), [0; 32], address, prefix, 1400).is_err());
        }
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(Config::new(absolute_dll(), [0; 32], address, 24, 1400).is_err());
        }
        assert!(Config::new(absolute_dll(), [0; 32], address, 24, 1279).is_err());
        let config = Config::new(absolute_dll(), [7; 32], address, 32, 1280)?;
        assert_eq!(config.address(), address);
        assert_eq!(config.prefix(), 32);
        assert_eq!(config.mtu(), 1280);
        assert_eq!(config.dll_sha256(), &[7; 32]);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn config_rejects_unc_and_device_namespace_paths() {
        for path in [
            r"\\server\share\wintun.dll",
            r"\\?\UNC\server\share\wintun.dll",
            r"\\.\C:\wintun.dll",
        ] {
            assert!(
                Config::new(path.into(), [0; 32], Ipv4Addr::new(10, 77, 0, 1), 24, 1400).is_err()
            );
        }
    }

    #[test]
    fn dll_pin_is_checked_before_native_loading() -> io::Result<()> {
        let bytes = b"bounded DLL test fixture";
        let pin: [u8; 32] = digest(&SHA256, bytes)
            .as_ref()
            .try_into()
            .map_err(io::Error::other)?;
        verify_dll(&mut Cursor::new(bytes), &pin)?;
        assert_eq!(
            verify_dll(&mut Cursor::new(bytes), &[0; 32])
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(verify_dll(&mut Cursor::new([]), &pin).is_err());
        let mut oversized = io::repeat(0).take(MAX_DLL_BYTES + 1);
        assert_eq!(
            verify_dll(&mut oversized, &pin).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        Ok(())
    }

    #[test]
    fn ip_shapes_reject_truncation_overflow_and_non_ip_frames() -> io::Result<()> {
        let mut ipv4 = [0; 20];
        ipv4[0] = 0x45;
        ipv4[3] = 20;
        validate_packet(&ipv4)?;
        ipv4[0] = 0x46;
        assert!(validate_packet(&ipv4).is_err());
        ipv4[0] = 0x45;
        ipv4[3] = 21;
        assert!(validate_packet(&ipv4).is_err());
        let mut ipv6 = [0; 41];
        ipv6[0] = 0x60;
        ipv6[5] = 1;
        validate_packet(&ipv6)?;
        assert!(validate_packet(&ipv6[..40]).is_err());
        assert!(validate_packet(&[]).is_err());
        assert!(validate_packet(&[0; 14]).is_err());
        assert!(validate_packet(&vec![0; MAX_PACKET_BYTES + 1]).is_err());
        Ok(())
    }
}
