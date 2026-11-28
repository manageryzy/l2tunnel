//! Safe Windows Wintun L3 boundary and local API pipe security; no protocol,
//! authentication or service engine.
//!
//! Construction is privileged, blocking platform work. Packet operations are
//! nonblocking. The maintained `tun-rs` dependency owns its reviewed native FFI
//! for the device. The crate denies `unsafe` everywhere except the single
//! documented named-pipe security module `local_pipe::ffi`
//! (docs/modules/windows-local-service.md, WLS-03), which is the narrow
//! exception this crate's `[lints]` table exists for.

#[cfg(any(windows, test))]
use l2tunnel_device::MAX_PACKET_BYTES;
#[cfg(any(windows, test))]
use ring::digest::{Context, SHA256};
use std::io;
#[cfg(any(windows, test))]
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Windows DPAPI secret envelope sealing (`L2DP`, CL-27).
pub mod dpapi;
/// Bounded rotating file diagnostics and Windows Event Log reporter (CL-27).
pub mod event_log;
/// Local API named-pipe names, proposed access policy and security boundary.
pub mod local_pipe;
#[cfg(windows)]
mod native;
/// Debounced Windows IP interface change and sleep/resume coordinator (CL-27).
pub mod net_watch;
/// Windows IPv4/IPv6 routing table access via IP Helper API (`iphlpapi.dll`).
pub mod routes;
/// Administrator-only directory ACL auditing (`WLS-08`).
pub mod security;
#[cfg(windows)]
pub use native::{Device, MtuController, TapDevice};

/// Minimum Ethernet II frame length in bytes (6 dst + 6 src + 2 EtherType).
pub const MIN_ETHERNET_FRAME_BYTES: usize = 14;
/// Maximum Windows TAP adapter display name length.
pub const MAX_ADAPTER_NAME_BYTES: usize = 64;
/// Maximum DLL size accepted before any native library is loaded.
pub const MAX_DLL_BYTES: u64 = 16 * 1024 * 1024;
/// Fixed, bounded Wintun receive/send ring capacity (one MiB).
pub const RING_CAPACITY: u32 = 1024 * 1024;

/// Local, administrator-supplied configuration for a Windows TAP L2 adapter
/// backed by the OpenVPN TAP-Windows6 (`tap0901`) driver (`CL-26`).
///
/// No custom FFI is added: [`tun_rs`] owns the reviewed NDIS 6 TAP driver FFI.
/// An explicit IPv4 address is optional because L2 TAP adapters are frequently
/// attached unnumbered to a Windows network bridge or hypervisor switch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TapConfig {
    adapter_name: Option<String>,
    address: Option<(Ipv4Addr, u8)>,
    mac: Option<[u8; 6]>,
    mtu: u16,
    persist: bool,
}

impl TapConfig {
    /// Validate Windows TAP L2 settings without opening any OS adapter.
    pub fn new(
        adapter_name: Option<String>,
        address: Option<(Ipv4Addr, u8)>,
        mac: Option<[u8; 6]>,
        mtu: u16,
        persist: bool,
    ) -> io::Result<Self> {
        if let Some(name) = &adapter_name {
            validate_adapter_name(name)?;
        }
        if let Some((ip, prefix)) = address {
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
                return Err(invalid(
                    "TAP IPv4 address must be a non-loopback unicast address",
                ));
            }
            if prefix == 0 || prefix > 32 {
                return Err(invalid("TAP IPv4 prefix must be in 1..=32"));
            }
        }
        if let Some(bytes) = mac {
            validate_unicast_mac(bytes)?;
        }
        if mtu < 1280 {
            return Err(invalid("TAP MTU must be in 1280..=65535"));
        }
        Ok(Self {
            adapter_name,
            address,
            mac,
            mtu,
            persist,
        })
    }

    /// Optional explicit adapter alias; when `None`, a unique random `l2tap-*`
    /// adapter name is generated at open time.
    pub fn adapter_name(&self) -> Option<&str> {
        self.adapter_name.as_deref()
    }

    /// Optional IPv4 address and prefix length configured on the TAP adapter.
    pub fn address(&self) -> Option<(Ipv4Addr, u8)> {
        self.address
    }

    /// Optional unicast MAC address configured on the TAP adapter.
    pub fn mac(&self) -> Option<[u8; 6]> {
        self.mac
    }

    /// Interface MTU (`1280..=65535`).
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Whether the TAP adapter should persist after the handle closes.
    pub fn persist(&self) -> bool {
        self.persist
    }
}

/// Parse a unicast Ethernet MAC address (`AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF`).
pub fn parse_mac(text: &str) -> io::Result<[u8; 6]> {
    let trimmed = text.trim();
    let sep = if trimmed.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = trimmed.split(sep).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return Err(invalid(
            "MAC address must be 6 hex octets (AA:BB:CC:DD:EE:FF)",
        ));
    }
    let mut mac = [0_u8; 6];
    for (dst, part) in mac.iter_mut().zip(parts) {
        *dst = u8::from_str_radix(part, 16)
            .map_err(|_| invalid("MAC address must contain only ASCII hex digits"))?;
    }
    validate_unicast_mac(mac)?;
    Ok(mac)
}

/// Format a 6-byte MAC address as lowercase colon-separated hex.
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn validate_unicast_mac(mac: [u8; 6]) -> io::Result<()> {
    if mac == [0; 6] || (mac[0] & 0x01) != 0 {
        return Err(invalid(
            "TAP MAC address must be a non-zero unicast Ethernet address",
        ));
    }
    Ok(())
}

fn validate_adapter_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > MAX_ADAPTER_NAME_BYTES
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b' '))
        || name.trim().is_empty()
    {
        return Err(invalid(
            "TAP adapter name must be 1..=64 ASCII alphanumeric/[-_. ] characters",
        ));
    }
    Ok(())
}

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

#[cfg(any(windows, test))]
fn validate_ethernet_frame(frame: &[u8]) -> io::Result<()> {
    if frame.len() < MIN_ETHERNET_FRAME_BYTES || frame.len() > MAX_PACKET_BYTES {
        return Err(invalid(
            "TAP Ethernet frame length must be within 14..=65535 bytes",
        ));
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

    #[test]
    fn tap_config_mac_and_ethernet_frame_validation() -> io::Result<()> {
        let mac = parse_mac("02:aa:bb:cc:dd:ee")?;
        assert_eq!(format_mac(mac), "02:aa:bb:cc:dd:ee");
        assert_eq!(parse_mac("02-AA-BB-CC-DD-EE")?, mac);
        // Multicast / broadcast / all-zero MACs rejected.
        assert!(parse_mac("01:00:5e:00:00:01").is_err());
        assert!(parse_mac("ff:ff:ff:ff:ff:ff").is_err());
        assert!(parse_mac("00:00:00:00:00:00").is_err());
        assert!(parse_mac("02:aa:bb").is_err());

        let cfg = TapConfig::new(
            Some("l2tap0".into()),
            Some((Ipv4Addr::new(10, 99, 0, 2), 24)),
            Some(mac),
            1500,
            false,
        )?;
        assert_eq!(cfg.adapter_name(), Some("l2tap0"));
        assert_eq!(cfg.address(), Some((Ipv4Addr::new(10, 99, 0, 2), 24)));
        assert_eq!(cfg.mac(), Some(mac));
        assert_eq!(cfg.mtu(), 1500);
        assert!(!cfg.persist());

        // Unnumbered TAP L2 (for Windows bridge/VXLAN) is valid.
        let unnumbered = TapConfig::new(None, None, None, 1500, false)?;
        assert_eq!(unnumbered.address(), None);

        // Invalid MTU, loopback IP, invalid adapter name rejected.
        assert!(TapConfig::new(None, None, None, 1279, false).is_err());
        assert!(TapConfig::new(Some("".into()), None, None, 1500, false).is_err());
        assert!(TapConfig::new(Some("bad/name".into()), None, None, 1500, false).is_err());
        assert!(TapConfig::new(None, Some((Ipv4Addr::LOCALHOST, 24)), None, 1500, false).is_err());

        // Ethernet frame validation.
        assert!(validate_ethernet_frame(&[0; 13]).is_err());
        validate_ethernet_frame(&[0; 14])?;
        validate_ethernet_frame(&[0; 1518])?;
        assert!(validate_ethernet_frame(&vec![0; MAX_PACKET_BYTES + 1]).is_err());
        Ok(())
    }
}
