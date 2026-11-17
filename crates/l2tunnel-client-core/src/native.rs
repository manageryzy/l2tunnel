//! Native device ownership shared by the client/service API on every platform.
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::io;

/// Unix native devices expose a readiness descriptor to the runtime.
#[cfg(unix)]
pub trait Device: PacketDevice<Error = io::Error> + std::os::fd::AsRawFd + Send + Sync {}
#[cfg(unix)]
impl<T> Device for T where T: PacketDevice<Error = io::Error> + std::os::fd::AsRawFd + Send + Sync {}
/// Other platforms provide bounded nonblocking packet operations to the runtime.
#[cfg(not(unix))]
pub trait Device: PacketDevice<Error = io::Error> + Send {}
#[cfg(not(unix))]
impl<T> Device for T where T: PacketDevice<Error = io::Error> + Send {}

/// One owned dynamic native device; construction performs no I/O.
pub struct Native(Box<dyn Device>);
impl Native {
    /// Retain the concrete device until its runtime releases it.
    pub fn new(device: impl Device + 'static) -> Self {
        Self(Box::new(device))
    }
}
impl PacketDevice for Native {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.0.layer()
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.0.receive(output)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0.transmit(packet)
    }
}
#[cfg(unix)]
impl std::os::fd::AsRawFd for Native {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}
