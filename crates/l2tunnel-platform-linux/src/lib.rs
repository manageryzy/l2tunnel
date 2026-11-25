//! Linux-only nonblocking TAP/TUN adapter with one isolated ioctl boundary.
//! `TunTap::attach` changes no routes, bridges, sysctls or persistence flags.
//! The service-owned device and route operations (CL-22/CL-23) are separate:
//! `TunTap::create_persistent` and the netlink [`netconf`] module.
#![cfg(target_os = "linux")]

/// Service-side netlink configuration of links, addresses and routes.
pub mod netconf;

use l2tunnel_device::{PacketDevice, PacketLayer};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

/// Largest packet supported by the protocol record contract.
pub const MAX_PACKET_BYTES: usize = 65_535;
/// Receive storage includes one sentinel byte to reject over-limit packets.
pub const READ_BUFFER_BYTES: usize = MAX_PACKET_BYTES + 1;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid(
            "device name must contain 1..15 ASCII letters, digits, '_' or '-'",
        ));
    }
    Ok(())
}

fn validate_packet(layer: PacketLayer, packet: &[u8]) -> io::Result<()> {
    if packet.len() > MAX_PACKET_BYTES {
        return Err(invalid("packet exceeds protocol limit"));
    }
    let valid = match layer {
        PacketLayer::Ethernet => packet.len() >= 14,
        PacketLayer::Ip => packet.first().is_some_and(|first| {
            (first >> 4 == 4 && packet.len() >= 20) || (first >> 4 == 6 && packet.len() >= 40)
        }),
    };
    if !valid {
        return Err(invalid("packet does not match device layer"));
    }
    Ok(())
}

// SAFETY REVIEW: all unsafe operations are contained in this synchronous ABI call.
// libc supplies the target-specific ifreq layout. Its storage is fully initialized,
// the FD remains owned by the caller, and the kernel does not retain the pointer.
#[allow(unsafe_code)]
fn attach_ioctl(fd: RawFd, name: &str, layer: PacketLayer) -> io::Result<String> {
    // SAFETY: ifreq consists of integer/byte fields and unions with valid zero storage.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = source as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = ((match layer {
        PacketLayer::Ethernet => libc::IFF_TAP,
        PacketLayer::Ip => libc::IFF_TUN,
    }) | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: request is a valid mutable ifreq throughout ioctl; fd is live and open.
    let result = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut request) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let name: Vec<u8> = request
        .ifr_name
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned non-UTF8 interface name",
        )
    })
}

/// Owned device descriptor in the current network namespace.
pub struct TunTap {
    file: File,
    name: String,
    layer: PacketLayer,
}
impl TunTap {
    /// Attach/create an explicitly named device; requires kernel permission.
    pub fn attach(name: &str, layer: PacketLayer) -> io::Result<Self> {
        validate_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        let name = attach_ioctl(file.as_raw_fd(), name, layer)?;
        Ok(Self { file, name, layer })
    }
    /// Effective kernel device name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Create (or adopt) a persistent named device owned by `owner` (a uid),
    /// as `ip tuntap add` does; it survives this process. Returns the
    /// effective name. Requires CAP_NET_ADMIN.
    pub fn create_persistent(
        name: &str,
        layer: PacketLayer,
        owner: Option<u32>,
    ) -> io::Result<String> {
        let device = Self::attach(name, layer)?;
        let fd = device.file.as_raw_fd();
        if let Some(owner) = owner {
            value_ioctl(fd, libc::TUNSETOWNER, libc::c_ulong::from(owner))?;
        }
        value_ioctl(fd, libc::TUNSETPERSIST, 1)?;
        Ok(device.name)
    }
}

// SAFETY REVIEW: TUNSETOWNER and TUNSETPERSIST take their argument by value;
// no pointer crosses the boundary and the FD stays owned by the caller.
#[allow(unsafe_code)]
fn value_ioctl(fd: RawFd, request: libc::c_ulong, value: libc::c_ulong) -> io::Result<()> {
    // SAFETY: fd is a live /dev/net/tun descriptor attached by TUNSETIFF; both
    // requests read only the integer argument.
    let result = unsafe { libc::ioctl(fd, request as _, value) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
impl AsRawFd for TunTap {
    /// Borrowed descriptor for readiness registration; the device keeps ownership.
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
impl AsFd for TunTap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
impl PacketDevice for TunTap {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        if buffer.len() < READ_BUFFER_BYTES {
            return Err(invalid(
                "receive buffer too small to detect oversized packets",
            ));
        }
        match self.file.read(buffer) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN/TAP descriptor closed",
            )),
            Ok(size) => {
                validate_packet(self.layer, &buffer[..size])?;
                Ok(Some(size))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        validate_packet(self.layer, packet)?;
        let written = self.file.write(packet)?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial TUN/TAP packet write",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_reject_implicit_templates_and_invalid_inputs() {
        for name in ["", "tun%d", "../tun", "bad name", "abcdefghijklmnop", "tün"] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name("tun0").is_ok());
        assert!(validate_name("l2t-tap_1").is_ok());
    }
    #[test]
    fn native_packet_layer_and_limits_are_checked() {
        assert!(validate_packet(PacketLayer::Ethernet, &[0; 14]).is_ok());
        assert!(validate_packet(PacketLayer::Ethernet, &[0; 13]).is_err());
        assert!(validate_packet(PacketLayer::Ip, &[0x45; 20]).is_ok());
        assert!(validate_packet(PacketLayer::Ip, &[0x60; 40]).is_ok());
        assert!(validate_packet(PacketLayer::Ip, &[0; 40]).is_err());
        assert!(validate_packet(PacketLayer::Ethernet, &vec![0; MAX_PACKET_BYTES + 1]).is_err());
    }
}
