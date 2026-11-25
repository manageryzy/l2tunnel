//! Safe nonblocking multi-peer UDP VXLAN VTEP adapter (`MOD-VX-06`, `VX-03..VX-07`).
//!
//! Wraps one unconnected nonblocking IPv4 or IPv6 [`UdpSocket`] around the pure
//! [`l2tunnel_vxlan::vtep::Vtep`] forwarding engine:
//! - enforces explicit peer allowlist matching before any FDB learning occurs,
//! - supports varying RFC 7348 UDP source ports per authorized remote IP (with
//!   exact socket-address disambiguation when multiple test peers share one
//!   loopback IP such as `[::1]`),
//! - enforces VNI, VLAN policy, path-MTU non-fragmenting bounds, optional
//!   recursive-VXLAN rejection, FDB capacity/aging/move-rate/static precedence,
//!   split-horizon, and aggregate BUM byte/packet/replica rate limits,
//! - implements [`PacketDevice`] (`PacketLayer::Ethernet`) and Unix `AsRawFd`
//!   so it attaches directly to the Common authenticated session runtime.

use crate::{MAX_FRAME_BYTES, MAX_RECEIVE_BUDGET, invalid};
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_vxlan::HEADER_LEN;
use l2tunnel_vxlan::vtep::{
    DomainConfig, DomainId, EgressSource, FdbEntry, FdbKey, Mac, OverheadBudget, PeerId, Vtep,
    VtepError, VtepStats,
};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Hard bound on concurrent remote VTEP peers registered on one adapter.
pub const MAX_VTEP_PEERS: usize = 256;

/// Configuration for one multi-peer UDP VTEP device adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VtepDeviceConfig {
    /// Bridge domain policy (domain ID, VNI, MTU budget, VLAN policy, FDB and BUM bounds).
    pub domain: DomainConfig,
    /// Maximum UDP datagrams examined per nonblocking [`PacketDevice::receive`] call (`1..=4096`).
    pub receive_budget: usize,
    /// Hard limit on registered remote peers (`1..=MAX_VTEP_PEERS`).
    pub max_peers: usize,
}

/// Saturating I/O and policy counters for [`VxlanVtepDevice`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VtepDeviceStats {
    /// UDP datagrams returned by the socket, including subsequently discarded ones.
    pub received_datagrams: u64,
    /// Valid Ethernet frames delivered to the caller.
    pub received_frames: u64,
    /// Exact inner Ethernet bytes delivered to the caller.
    pub received_frame_bytes: u64,
    /// Datagrams discarded because their source was not an authorized peer.
    pub dropped_foreign_source: u64,
    /// Datagrams rejected by VTEP policy (VNI, malformed header, VLAN, recursion).
    pub dropped_vtep_policy: u64,
    /// Datagrams exceeding the configured MTU / truncation sentinel.
    pub dropped_oversized: u64,
    /// Valid frames dropped because the caller receive buffer was too small.
    pub dropped_output_too_small: u64,
    /// Receive calls that consumed the full work budget without yielding a frame.
    pub receive_budget_exhaustions: u64,
    /// Socket receive errors other than `WouldBlock`.
    pub receive_errors: u64,
    /// Inner Ethernet frames transmitted to at least one remote peer.
    pub transmitted_frames: u64,
    /// Total VXLAN UDP datagrams sent across unicast and replicated BUM traffic.
    pub transmitted_datagrams: u64,
    /// Exact inner Ethernet bytes transmitted (counted once per frame).
    pub transmitted_frame_bytes: u64,
    /// Total VXLAN UDP payload bytes sent across all replicas.
    pub transmitted_wire_bytes: u64,
    /// Outbound frames dropped by VTEP policy (BUM budget, unknown-unicast drop, VLAN, no peers).
    pub transmit_dropped_policy: u64,
    /// Locally rejected invalid frames or socket send failures.
    pub transmit_errors: u64,
}

/// Nonblocking multi-peer UDP VXLAN VTEP implementing [`PacketDevice`].
pub struct VxlanVtepDevice {
    socket: UdpSocket,
    local_addr: SocketAddr,
    domain_id: DomainId,
    vtep: Vtep,
    max_frame_bytes: usize,
    receive_budget: usize,
    max_peers: usize,
    peers_by_id: BTreeMap<PeerId, SocketAddr>,
    peers_by_addr: BTreeMap<SocketAddr, PeerId>,
    ip_peer_counts: BTreeMap<IpAddr, usize>,
    unique_peer_by_ip: BTreeMap<IpAddr, PeerId>,
    clock_origin: Instant,
    clock_offset_micros: u64,
    receive_buffer: Vec<u8>,
    transmit_buffer: Vec<u8>,
    stats: VtepDeviceStats,
}

impl VxlanVtepDevice {
    /// Bind an unconnected UDP socket and initialize a multi-peer VTEP domain.
    pub fn bind(bind_addr: SocketAddr, config: VtepDeviceConfig) -> io::Result<Self> {
        validate_device_config(&config)?;
        Self::from_socket(UdpSocket::bind(bind_addr)?, config)
    }

    /// Take exclusive ownership of a prebound, unconnected UDP socket and make it nonblocking.
    pub fn from_socket(socket: UdpSocket, config: VtepDeviceConfig) -> io::Result<Self> {
        validate_device_config(&config)?;
        let local_addr = socket.local_addr()?;
        if socket.peer_addr().is_ok() {
            return Err(invalid("VXLAN VTEP requires an unconnected UDP socket"));
        }
        if local_addr.is_ipv6() != config.domain.mtu.outer_ipv6 {
            return Err(invalid(
                "VXLAN VTEP socket address family must match OverheadBudget.outer_ipv6",
            ));
        }
        socket.set_nonblocking(true)?;
        let domain_id = config.domain.domain;
        let max_frame_bytes = config.domain.mtu.max_inner_frame_bytes;
        let max_total_fdb = config.domain.fdb.max_entries;
        let mut vtep = Vtep::new(max_total_fdb).map_err(vtep_to_io)?;
        vtep.add_domain(config.domain).map_err(vtep_to_io)?;
        let datagram_bytes = MAX_FRAME_BYTES
            .checked_add(HEADER_LEN)
            .ok_or_else(|| invalid("VXLAN VTEP datagram size overflow"))?;
        let receive_bytes = datagram_bytes
            .checked_add(1)
            .ok_or_else(|| invalid("VXLAN VTEP receive sentinel size overflow"))?;
        Ok(Self {
            socket,
            local_addr,
            domain_id,
            vtep,
            max_frame_bytes,
            receive_budget: config.receive_budget,
            max_peers: config.max_peers,
            peers_by_id: BTreeMap::new(),
            peers_by_addr: BTreeMap::new(),
            ip_peer_counts: BTreeMap::new(),
            unique_peer_by_ip: BTreeMap::new(),
            clock_origin: Instant::now(),
            clock_offset_micros: 0,
            receive_buffer: vec![0; receive_bytes],
            transmit_buffer: vec![0; datagram_bytes],
            stats: VtepDeviceStats::default(),
        })
    }

    /// Actual bound local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Current maximum inner Ethernet frame bytes permitted by the domain MTU budget.
    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Register an authorized remote VTEP peer endpoint.
    ///
    /// Rejects unspecified, multicast, broadcast, zero-port, cross-family,
    /// self-loop, or duplicate peer endpoints (`VX-05`).
    pub fn add_peer(&mut self, peer: PeerId, endpoint: SocketAddr) -> io::Result<()> {
        if self.peers_by_id.contains_key(&peer) {
            return Err(invalid("duplicate VXLAN VTEP peer identifier"));
        }
        if self.peers_by_id.len() >= self.max_peers {
            return Err(invalid("VXLAN VTEP peer capacity exceeded"));
        }
        validate_peer_endpoint(self.local_addr, endpoint)?;
        let mut all_endpoints: Vec<(PeerId, SocketAddr)> = self
            .peers_by_id
            .iter()
            .map(|(&id, &addr)| (id, addr))
            .collect();
        all_endpoints.push((peer, endpoint));
        Vtep::validate_no_endpoint_loop(self.local_addr, &all_endpoints).map_err(vtep_to_io)?;
        self.vtep
            .authorize_peer(self.domain_id, peer)
            .map_err(vtep_to_io)?;
        self.peers_by_id.insert(peer, endpoint);
        self.peers_by_addr.insert(endpoint, peer);
        let count = self.ip_peer_counts.entry(endpoint.ip()).or_insert(0);
        *count = count.saturating_add(1);
        if *count == 1 {
            self.unique_peer_by_ip.insert(endpoint.ip(), peer);
        } else {
            self.unique_peer_by_ip.remove(&endpoint.ip());
        }
        Ok(())
    }

    /// Remove a remote peer and immediately purge its dynamic FDB entries (`VX-04`).
    ///
    /// Returns the number of dynamic FDB entries purged for that peer.
    pub fn remove_peer(&mut self, peer: PeerId) -> io::Result<usize> {
        let Some(endpoint) = self.peers_by_id.remove(&peer) else {
            return Err(invalid("unknown VXLAN VTEP peer identifier"));
        };
        self.peers_by_addr.remove(&endpoint);
        if let Some(count) = self.ip_peer_counts.get_mut(&endpoint.ip()) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.ip_peer_counts.remove(&endpoint.ip());
                self.unique_peer_by_ip.remove(&endpoint.ip());
            } else if *count == 1
                && let Some((&remaining_id, _)) = self
                    .peers_by_id
                    .iter()
                    .find(|(_, addr)| addr.ip() == endpoint.ip())
            {
                self.unique_peer_by_ip.insert(endpoint.ip(), remaining_id);
            }
        }
        self.vtep
            .remove_peer(self.domain_id, peer)
            .map_err(vtep_to_io)
    }

    /// Install a static FDB entry that takes precedence over dynamic learning (`VX-04`).
    pub fn insert_static_fdb(
        &mut self,
        vlan: Option<u16>,
        mac: Mac,
        peer: PeerId,
    ) -> io::Result<()> {
        self.vtep
            .insert_static_fdb(self.domain_id, vlan, mac, peer)
            .map_err(vtep_to_io)
    }

    /// Remove a static or dynamic FDB entry explicitly.
    pub fn remove_fdb(&mut self, vlan: Option<u16>, mac: Mac) -> Option<FdbEntry> {
        self.vtep.remove_fdb(FdbKey {
            domain: self.domain_id,
            vlan,
            mac,
        })
    }

    /// Update the active path-MTU overhead budget without fragmenting frames (`VX-07`).
    pub fn update_mtu(&mut self, mtu: OverheadBudget) -> io::Result<()> {
        if self.local_addr.is_ipv6() != mtu.outer_ipv6 {
            return Err(invalid(
                "VXLAN VTEP MTU update address family must match bound socket",
            ));
        }
        let max_frame = mtu.max_inner_frame_bytes;
        if !(14..=MAX_FRAME_BYTES).contains(&max_frame) {
            return Err(invalid("VXLAN VTEP frame bound must be 14..=65499 bytes"));
        }
        self.vtep
            .update_domain_mtu(self.domain_id, mtu)
            .map_err(vtep_to_io)?;
        self.max_frame_bytes = max_frame;
        Ok(())
    }

    /// Age out expired dynamic FDB entries against the current monotonic clock.
    pub fn age_fdb(&mut self) -> usize {
        let now = self.now_micros();
        self.vtep.age_fdb(now)
    }

    /// Advance the logical clock offset (useful for deterministic aging/refill tests).
    pub fn advance_clock(&mut self, delta: Duration) {
        let micros = u64::try_from(delta.as_micros()).unwrap_or(u64::MAX);
        self.clock_offset_micros = self.clock_offset_micros.saturating_add(micros);
    }

    /// Current saturating socket/adapter counters.
    pub fn stats(&self) -> VtepDeviceStats {
        self.stats
    }

    /// Current saturating pure VTEP policy counters.
    pub fn vtep_stats(&self) -> VtepStats {
        self.vtep.stats()
    }

    /// Transmit one inner Ethernet frame with an explicit [`EgressSource`] (local or
    /// remote peer for split-horizon testing), returning the number of UDP datagrams
    /// actually sent (`0` if dropped by BUM/VLAN/unknown-unicast policy or if no peer
    /// is reachable).
    pub fn transmit_with_source(
        &mut self,
        source: EgressSource,
        packet: &[u8],
    ) -> io::Result<usize> {
        let now = self.now_micros();
        let plan = match self.vtep.egress(self.domain_id, source, packet, now) {
            Ok(plan) => plan,
            Err(VtepError::Codec(_)) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                return Err(invalid("VXLAN VTEP Ethernet frame shorter than 14 bytes"));
            }
            Err(VtepError::PathMtuExceeded { .. }) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                return Err(invalid(
                    "VXLAN VTEP Ethernet frame exceeds active path MTU budget",
                ));
            }
            Err(
                VtepError::VlanNotAllowed
                | VtepError::InvalidVlan
                | VtepError::RecursiveEncapsulation,
            ) => {
                self.stats.transmit_dropped_policy =
                    self.stats.transmit_dropped_policy.saturating_add(1);
                return Ok(0);
            }
            Err(error) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                return Err(vtep_to_io(error));
            }
        };
        if plan.targets.is_empty() {
            self.stats.transmit_dropped_policy =
                self.stats.transmit_dropped_policy.saturating_add(1);
            return Ok(0);
        }
        let length = match l2tunnel_vxlan::encode(plan.vni, packet, &mut self.transmit_buffer) {
            Ok(length) => length,
            Err(error) => {
                self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("VXLAN VTEP encode failed: {error:?}"),
                ));
            }
        };
        let datagram = self
            .transmit_buffer
            .get(..length)
            .ok_or_else(|| io::Error::other("VXLAN VTEP encoder exceeded output buffer"))?;
        let mut sent = 0usize;
        for target_peer in plan.targets {
            let Some(&endpoint) = self.peers_by_id.get(&target_peer) else {
                continue;
            };
            match self.socket.send_to(datagram, endpoint) {
                Ok(written) if written == length => {
                    sent = sent.saturating_add(1);
                }
                Ok(_) => {
                    self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial VXLAN VTEP UDP datagram send",
                    ));
                }
                Err(error) => {
                    self.stats.transmit_errors = self.stats.transmit_errors.saturating_add(1);
                    return Err(error);
                }
            }
        }
        if sent > 0 {
            self.stats.transmitted_frames = self.stats.transmitted_frames.saturating_add(1);
            self.stats.transmitted_datagrams =
                self.stats.transmitted_datagrams.saturating_add(sent as u64);
            self.stats.transmitted_frame_bytes = self
                .stats
                .transmitted_frame_bytes
                .saturating_add(packet.len() as u64);
            self.stats.transmitted_wire_bytes = self
                .stats
                .transmitted_wire_bytes
                .saturating_add((sent as u64).saturating_mul(length as u64));
        }
        Ok(sent)
    }

    fn resolve_ingress_peer(&self, source: SocketAddr) -> Option<PeerId> {
        if let Some(&peer) = self.peers_by_addr.get(&source) {
            return Some(peer);
        }
        // RFC 7348 allows varying UDP source ports per remote VTEP IP when that IP
        // uniquely identifies one configured peer.
        self.unique_peer_by_ip.get(&source.ip()).copied()
    }

    fn now_micros(&self) -> u64 {
        let elapsed = u64::try_from(self.clock_origin.elapsed().as_micros()).unwrap_or(u64::MAX);
        elapsed.saturating_add(self.clock_offset_micros)
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for VxlanVtepDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

impl PacketDevice for VxlanVtepDevice {
    type Error = io::Error;

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let max_datagram = self.max_frame_bytes.saturating_add(HEADER_LEN);
        for _ in 0..self.receive_budget {
            let (length, source) = match self.socket.recv_from(&mut self.receive_buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => {
                    self.stats.receive_errors = self.stats.receive_errors.saturating_add(1);
                    return Err(error);
                }
            };
            self.stats.received_datagrams = self.stats.received_datagrams.saturating_add(1);
            let Some(peer) = self.resolve_ingress_peer(source) else {
                self.stats.dropped_foreign_source =
                    self.stats.dropped_foreign_source.saturating_add(1);
                continue;
            };
            if length > max_datagram {
                self.stats.dropped_oversized = self.stats.dropped_oversized.saturating_add(1);
                continue;
            }
            let datagram = self
                .receive_buffer
                .get(..length)
                .ok_or_else(|| io::Error::other("UDP receive length exceeded its buffer"))?;
            let now = self.now_micros();
            let frame_len = match self.vtep.ingress(peer, datagram, now) {
                Ok(ingress) => {
                    let Some(destination) = buffer.get_mut(..ingress.ethernet.len()) else {
                        self.stats.dropped_output_too_small =
                            self.stats.dropped_output_too_small.saturating_add(1);
                        return Err(invalid(
                            "VXLAN VTEP Ethernet frame exceeds caller receive capacity",
                        ));
                    };
                    destination.copy_from_slice(ingress.ethernet);
                    ingress.ethernet.len()
                }
                Err(VtepError::PathMtuExceeded { .. }) => {
                    self.stats.dropped_oversized = self.stats.dropped_oversized.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    self.stats.dropped_vtep_policy =
                        self.stats.dropped_vtep_policy.saturating_add(1);
                    continue;
                }
            };
            self.stats.received_frames = self.stats.received_frames.saturating_add(1);
            self.stats.received_frame_bytes = self
                .stats
                .received_frame_bytes
                .saturating_add(frame_len as u64);
            return Ok(Some(frame_len));
        }
        self.stats.receive_budget_exhaustions =
            self.stats.receive_budget_exhaustions.saturating_add(1);
        Ok(None)
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        let _ = self.transmit_with_source(EgressSource::Local, packet)?;
        Ok(())
    }
}

fn validate_device_config(config: &VtepDeviceConfig) -> io::Result<()> {
    let max_frame = config.domain.mtu.max_inner_frame_bytes;
    if !(14..=MAX_FRAME_BYTES).contains(&max_frame) {
        return Err(invalid("VXLAN VTEP frame bound must be 14..=65499 bytes"));
    }
    if !(1..=MAX_RECEIVE_BUDGET).contains(&config.receive_budget) {
        return Err(invalid(
            "VXLAN VTEP receive budget must be 1..=4096 datagrams",
        ));
    }
    if !(1..=MAX_VTEP_PEERS).contains(&config.max_peers) {
        return Err(invalid("VXLAN VTEP peer bound must be 1..=256 peers"));
    }
    Ok(())
}

fn validate_peer_endpoint(local: SocketAddr, endpoint: SocketAddr) -> io::Result<()> {
    if local.is_ipv4() != endpoint.is_ipv4() {
        return Err(invalid(
            "VXLAN VTEP bind and peer address families must match",
        ));
    }
    if endpoint.port() == 0
        || endpoint.ip().is_unspecified()
        || endpoint.ip().is_multicast()
        || matches!(endpoint.ip(), IpAddr::V4(address) if address.is_broadcast())
    {
        return Err(invalid(
            "VXLAN VTEP requires a unicast peer IP and nonzero destination port",
        ));
    }
    Ok(())
}

fn vtep_to_io(error: VtepError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("VTEP error: {error:?}"),
    )
}
