//! Device contracts; OS handles, drivers and privileges belong to wrappers.

/// Supported complete native packet ceiling for the current device adapters.
pub const MAX_PACKET_BYTES: usize = 65_535;
/// Whole-packet receive storage including one byte to detect oversize/truncation.
/// This allocation bound is distinct from the configured admitted packet MTU.
pub const READ_BUFFER_BYTES: usize = MAX_PACKET_BYTES + 1;

/// Native packet layer supplied by a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketLayer {
    /// Complete Ethernet frame, including VLAN tags when present.
    Ethernet,
    /// IPv4 or IPv6 packet, without an Ethernet header.
    Ip,
}
/// Planned device adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Adapter {
    /// Linux TAP.
    LinuxTap,
    /// Linux TUN.
    LinuxTun,
    /// Windows TAP driver.
    WindowsTap,
    /// Windows Wintun L3 driver.
    WindowsTun,
    /// Android VpnService L3 interface.
    AndroidVpnService,
}
impl Adapter {
    /// Native packet layer; no implicit synthetic Ethernet bridge is provided.
    pub fn layer(self) -> PacketLayer {
        match self {
            Self::LinuxTap | Self::WindowsTap => PacketLayer::Ethernet,
            Self::LinuxTun | Self::WindowsTun | Self::AndroidVpnService => PacketLayer::Ip,
        }
    }
    /// Reject mismatched L2/L3 use before attempting device creation.
    pub fn validate(self, requested: PacketLayer) -> Result<(), &'static str> {
        if self.layer() == requested {
            Ok(())
        } else {
            Err("adapter packet layer mismatch")
        }
    }
}
/// Host supplies bounded packet I/O; protocol crates never create devices.
pub trait PacketDevice {
    /// Platform-specific error type.
    type Error;
    /// Native layer of this device.
    fn layer(&self) -> PacketLayer;
    /// Nonblocking receive; None indicates no complete packet is available.
    /// Supply [`READ_BUFFER_BYTES`] so native adapters can detect oversized input;
    /// the runtime enforces its smaller negotiated MTU after a complete read.
    /// Adapters must never return a silently truncated packet as valid input.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    /// Transmit one complete native-layer packet.
    fn transmit(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}
/// Delegate an owned dynamic or concrete device without changing packet semantics.
impl<T: PacketDevice + ?Sized> PacketDevice for Box<T> {
    type Error = T::Error;
    fn layer(&self) -> PacketLayer {
        (**self).layer()
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        (**self).receive(buffer)
    }
    fn transmit(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        (**self).transmit(packet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn android_and_wintun_are_not_tap() {
        assert!(
            Adapter::AndroidVpnService
                .validate(PacketLayer::Ethernet)
                .is_err()
        );
        assert!(Adapter::WindowsTun.validate(PacketLayer::Ethernet).is_err());
        assert!(Adapter::LinuxTap.validate(PacketLayer::Ethernet).is_ok());
    }
}
