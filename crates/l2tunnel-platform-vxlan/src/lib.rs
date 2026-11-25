//! Safe nonblocking UDP VXLAN Ethernet device adapters.
//!
//! Provides both the fixed point-to-point [`VxlanDevice`] and the multi-peer
//! [`vtep::VxlanVtepDevice`] backed by the pure [`l2tunnel_vxlan::vtep`] policy
//! engine (FDB learning/aging, BUM rate/byte accounting, VLAN isolation, and
//! path-MTU bounds). Source-IP/VNI checks are not authentication; authentic
//! transport remains the responsibility of the enclosing authenticated tunnel.
//! This native boundary performs explicit socket I/O; public protocol/codec
//! crates remain pure.
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_vxlan::{HEADER_LEN, Vni};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/// Multi-peer UDP VTEP adapter backed by the pure [`l2tunnel_vxlan::vtep`] engine.
pub mod vtep;

pub use vtep::{MAX_VTEP_PEERS, VtepDeviceConfig, VtepDeviceStats, VxlanVtepDevice};

/// Portable non-jumbo IPv4 UDP payload ceiling, used for both address families.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;
/// Maximum configured inner Ethernet frame after the VXLAN base header.
pub const MAX_FRAME_BYTES: usize = MAX_UDP_PAYLOAD_BYTES - HEADER_LEN;
/// Hard bound on receive attempts made by one `PacketDevice::receive` call.
pub const MAX_RECEIVE_BUDGET: usize = 4096;

/// Immutable peer/VNI and resource policy for one UDP attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VxlanConfig {
    /// Egress destination; ingress checks this IP but permits varying source ports.
    pub peer: SocketAddr,
    /// The only admitted VXLAN network identifier.
    pub vni: Vni,
    /// Maximum inner Ethernet bytes, 14..=MAX_FRAME_BYTES.
    pub max_frame_bytes: usize,
    /// Maximum datagrams examined per nonblocking receive call, 1..=4096.
    pub receive_budget: usize,
}

/// Saturating counters for accepted traffic and explicit discard/error reasons.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VxlanStats {
    /// UDP datagrams returned by the socket, including subsequently discarded ones.
    pub received_datagrams: u64,
    /// Ethernet packets successfully copied to caller storage.
    pub received_frames: u64,
    /// Exact Ethernet bytes successfully copied to caller storage.
    pub received_frame_bytes: u64,
    /// UDP datagrams discarded because their source IP was not configured.
    pub dropped_foreign_source: u64,
    /// Well-formed VXLAN datagrams discarded because their VNI was not configured.
    pub dropped_wrong_vni: u64,
    /// Datagrams discarded for malformed/unsupported VXLAN or short Ethernet.
    pub dropped_malformed: u64,
    /// Datagrams exceeding the configured packet limit, including sentinel truncation.
    pub dropped_oversized: u64,
    /// Valid received frames consumed because the caller's destination was too small.
    pub dropped_output_too_small: u64,
    /// Receive calls that consumed their entire work budget without delivering a frame.
    pub receive_budget_exhaustions: u64,
    /// Socket receive failures other than ordinary WouldBlock.
    pub receive_errors: u64,
    /// Frames sent as one complete UDP datagram.
    pub transmitted_frames: u64,
    /// Exact Ethernet bytes sent successfully, excluding encapsulation overhead.
    pub transmitted_frame_bytes: u64,
    /// Locally rejected transmit packets, socket failures and short UDP writes.
    pub transmit_errors: u64,
}

/// One nonblocking UDP socket with a fixed peer-IP/VNI admission rule.
///
/// All decoded frames are user Ethernet; no payload receives session-management
/// privileges. Kernel IP fragmentation/PMTU options are not configured here.
pub struct VxlanDevice {
    socket: UdpSocket,
    config: VxlanConfig,
    receive_buffer: Vec<u8>,
    transmit_buffer: Vec<u8>,
    stats: VxlanStats,
}

impl VxlanDevice {
    /// Explicitly bind a UDP socket and configure this Ethernet attachment.
    ///
    /// Local port zero is allowed. The remote destination port must be nonzero.
    pub fn bind(bind_addr: SocketAddr, config: VxlanConfig) -> io::Result<Self> {
        validate_config(bind_addr, config)?;
        Self::from_socket(UdpSocket::bind(bind_addr)?, config)
    }

    /// Take exclusive ownership of a prebound, unconnected socket and make it nonblocking.
    ///
    /// The caller must not retain another active clone of the socket. A connected
    /// UDP socket is rejected because it would filter changing VXLAN source ports.
    pub fn from_socket(socket: UdpSocket, config: VxlanConfig) -> io::Result<Self> {
        validate_config(socket.local_addr()?, config)?;
        if socket.peer_addr().is_ok() {
            return Err(invalid("VXLAN requires an unconnected UDP socket"));
        }
        socket.set_nonblocking(true)?;
        let datagram_bytes = config
            .max_frame_bytes
            .checked_add(HEADER_LEN)
            .ok_or_else(|| invalid("VXLAN datagram size overflow"))?;
        let receive_bytes = datagram_bytes
            .checked_add(1)
            .ok_or_else(|| invalid("VXLAN receive sentinel size overflow"))?;
        Ok(Self {
            socket,
            config,
            receive_buffer: vec![0; receive_bytes],
            transmit_buffer: vec![0; datagram_bytes],
            stats: VxlanStats::default(),
        })
    }

    /// Actual bound address, including an OS-selected ephemeral port if requested.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Fixed remote UDP destination used for all transmitted frames.
    pub fn peer_addr(&self) -> SocketAddr {
        self.config.peer
    }

    /// Required caller receive-buffer capacity to avoid dropping valid frames.
    pub fn max_frame_bytes(&self) -> usize {
        self.config.max_frame_bytes
    }

    /// Copy the current saturating traffic/drop/error counters.
    pub fn stats(&self) -> VxlanStats {
        self.stats
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for VxlanDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

impl PacketDevice for VxlanDevice {
    type Error = io::Error;

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    /// Receive one whole Ethernet frame after bounded IP/VNI/header filtering.
    ///
    /// Invalid datagrams are counted and consumed. A valid frame with insufficient
    /// destination capacity is counted, consumed and returned as InvalidInput.
    /// None/errors never modify the caller buffer. A zero return length is unused.
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        for _ in 0..self.config.receive_budget {
            let (length, source) = match self.socket.recv_from(&mut self.receive_buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => {
                    self.stats.receive_errors = self.stats.receive_errors.saturating_add(1);
                    return Err(error);
                }
            };
            self.stats.received_datagrams = self.stats.received_datagrams.saturating_add(1);
            if source.ip() != self.config.peer.ip() {
                self.stats.dropped_foreign_source =
                    self.stats.dropped_foreign_source.saturating_add(1);
                continue;
            }
            if length > self.transmit_buffer.len() {
                self.stats.dropped_oversized = self.stats.dropped_oversized.saturating_add(1);
                continue;
            }
            let datagram = self
                .receive_buffer
                .get(..length)
                .ok_or_else(|| io::Error::other("UDP receive length exceeded its buffer"))?;
            let packet = match l2tunnel_vxlan::decode(datagram, self.config.max_frame_bytes) {
                Ok(packet) => packet,
                Err(l2tunnel_vxlan::Error::FrameTooLarge) => {
                    self.stats.dropped_oversized = self.stats.dropped_oversized.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    self.stats.dropped_malformed = self.stats.dropped_malformed.saturating_add(1);
                    continue;
                }
            };
            if packet.vni != self.config.vni {
                self.stats.dropped_wrong_vni = self.stats.dropped_wrong_vni.saturating_add(1);
                continue;
            }
            let Some(destination) = buffer.get_mut(..packet.ethernet.len()) else {
                self.stats.dropped_output_too_small =
                    self.stats.dropped_output_too_small.saturating_add(1);
                return Err(invalid(
                    "VXLAN Ethernet frame exceeds caller receive capacity",
                ));
            };
            destination.copy_from_slice(packet.ethernet);
            self.stats.received_frames = self.stats.received_frames.saturating_add(1);
            self.stats.received_frame_bytes = self
                .stats
                .received_frame_bytes
                .saturating_add(packet.ethernet.len() as u64);
            return Ok(Some(packet.ethernet.len()));
        }
        self.stats.receive_budget_exhaustions =
            self.stats.receive_budget_exhaustions.saturating_add(1);
        Ok(None)
    }

    /// Send one bounded Ethernet frame as exactly one VXLAN UDP datagram.
    ///
    /// No automatic retries, peer discovery or PMTU/fragmentation policy is applied.
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if !(14..=self.config.max_frame_bytes).contains(&packet.len()) {
            self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
            return Err(invalid(
                "VXLAN Ethernet frame length is outside configured bounds",
            ));
        }
        let length =
            match l2tunnel_vxlan::encode(self.config.vni, packet, &mut self.transmit_buffer) {
                Ok(length) => length,
                Err(error) => {
                    self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("VXLAN encode failed: {error:?}"),
                    ));
                }
            };
        let datagram = self
            .transmit_buffer
            .get(..length)
            .ok_or_else(|| io::Error::other("VXLAN encoder exceeded its output buffer"))?;
        match self.socket.send_to(datagram, self.config.peer) {
            Ok(written) if written == length => {
                self.stats.transmitted_frames = self.stats.transmitted_frames.saturating_add(1);
                self.stats.transmitted_frame_bytes = self
                    .stats
                    .transmitted_frame_bytes
                    .saturating_add(packet.len() as u64);
                Ok(())
            }
            Ok(_) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial VXLAN UDP datagram send",
                ))
            }
            Err(error) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                Err(error)
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_config(local: SocketAddr, config: VxlanConfig) -> io::Result<()> {
    if !(14..=MAX_FRAME_BYTES).contains(&config.max_frame_bytes) {
        return Err(invalid("VXLAN frame bound must be 14..=65499 bytes"));
    }
    if !(1..=MAX_RECEIVE_BUDGET).contains(&config.receive_budget) {
        return Err(invalid("VXLAN receive budget must be 1..=4096 datagrams"));
    }
    if local.is_ipv4() != config.peer.is_ipv4() {
        return Err(invalid("VXLAN bind and peer address families must match"));
    }
    if local == config.peer {
        return Err(invalid("VXLAN bind and peer endpoints must be distinct"));
    }
    if config.peer.port() == 0
        || config.peer.ip().is_unspecified()
        || config.peer.ip().is_multicast()
        || matches!(config.peer.ip(), IpAddr::V4(address) if address.is_broadcast())
    {
        return Err(invalid(
            "VXLAN requires a unicast peer IP and nonzero destination port",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
