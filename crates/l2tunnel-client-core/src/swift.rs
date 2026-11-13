//! Explicit lean `swift` profile: authenticated TCP/TLS bootstrap, then one
//! paced protected UDP flow per direction carrying packed, ordered channels
//! recovered by requested retransmission and optional coded repairs.
//!
//! The complete profile policy is bound into the authenticated session digest,
//! so peers with different geometry, budgets or repair proportion never reach
//! forwarding. The retained TLS stream carries no data; its closure ends the
//! session. This profile has no hot switching, lanes or local reload.
use super::*;
use l2tunnel_auth::{Direction, KeyPurpose, Secret, SessionInfo};
use l2tunnel_runtime::swift as runtime;
pub use l2tunnel_runtime::swift::Snapshot;
use std::pin::Pin;
use tokio::net::UdpSocket;

/// Sources that may be outstanding per direction.
const FLOW_SOURCES: usize = 4096;

/// Complete explicit profile selection shared by CLI and future GUI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Local UDP address.
    pub local: SocketAddr,
    /// The single fixed UDP peer.
    pub peer: SocketAddr,
    /// IP path MTU available to tunnel datagrams.
    pub path_mtu: usize,
    /// Client-to-server budget in kilobits of IP bytes per second.
    pub forward_kbit: u64,
    /// Server-to-client budget in kilobits of IP bytes per second.
    pub reverse_kbit: u64,
    /// Independent ordering channels connections are spread over.
    pub channels: usize,
    /// Sources covered by one repair.
    pub window: usize,
    /// Proportional repairs per thousand sources; zero recovers by
    /// retransmission only, the cheapest in bytes.
    pub repair_permille: u32,
    /// Local reporting interval; not part of the authenticated policy.
    pub report: Option<Duration>,
}

impl Settings {
    fn overhead(self) -> usize {
        if self.peer.is_ipv4() { 28 } else { 48 }
    }
    /// Runtime policy of one endpoint. Only the sender's packing queue and
    /// budget depend on the role.
    pub fn runtime(self, config: ConnectionConfig, client: bool) -> io::Result<runtime::Config> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        if config.duplex != Duplex::Full || config.compression != Compression::None {
            return Err(invalid(
                "swift requires full duplex and no record compression",
            ));
        }
        if self.local.is_ipv4() != self.peer.is_ipv4() || self.peer.port() == 0 {
            return Err(invalid(
                "swift UDP addresses must share a family and name a peer port",
            ));
        }
        if !(576..=9000).contains(&self.path_mtu)
            || !(64..=10_000_000).contains(&self.forward_kbit)
            || !(64..=10_000_000).contains(&self.reverse_kbit)
        {
            return Err(invalid(
                "swift path MTU or budget outside the supported range",
            ));
        }
        let kbit = if client {
            self.forward_kbit
        } else {
            self.reverse_kbit
        };
        let rate = kbit * 125;
        let result = runtime::Config {
            codec: l2tunnel_swift::Config {
                datagram_bytes: self.path_mtu - self.overhead() - runtime::PROTECTION_BYTES,
                window: self.window,
                repair_numerator: self.repair_permille,
                repair_denominator: 1000,
                flow_sources: FLOW_SOURCES,
                // About twenty milliseconds of budget: enough to keep the pacer
                // busy, small enough that the native queue signals congestion.
                queue_bytes: usize::try_from(rate / 50)
                    .unwrap_or(usize::MAX)
                    .clamp(2 * (config.max_packet + 3), 1 << 20),
                max_packet: config.max_packet + l2tunnel_swift::header::MAX_EXPANSION,
                flush_micros: 1_000,
                feedback_micros: 5_000,
                tail_micros: 10_000,
                min_rto_micros: 20_000,
                max_rto_micros: 1_000_000,
            },
            channels: self.channels,
            layer: config.layer,
            max_native: config.max_packet,
            send_bytes_per_second: rate,
            network_overhead: self.overhead(),
            report_interval: self.report,
        };
        result.validate()?;
        Ok(result)
    }
    /// Canonical digest of the base configuration and every protocol-visible
    /// profile value. Addresses and reporting are local.
    pub fn session(self, config: ConnectionConfig) -> io::Result<SessionConfig> {
        let base = config.session()?;
        let policy = self.runtime(config, true)?.codec;
        self.runtime(config, false)?;
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        context.update(b"l2tunnel swift profile v1: packed channels, exact header records\0");
        context.update(&base.digest.0);
        for value in [
            policy.datagram_bytes as u64,
            policy.window as u64,
            u64::from(policy.repair_numerator),
            u64::from(policy.repair_denominator),
            policy.flow_sources as u64,
            policy.max_packet as u64,
            self.channels as u64,
            policy.flush_micros,
            policy.feedback_micros,
            policy.tail_micros,
            policy.min_rto_micros,
            policy.max_rto_micros,
            self.forward_kbit,
            self.reverse_kbit,
        ] {
            context.update(&value.to_be_bytes());
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(context.finish().as_ref());
        Ok(SessionConfig {
            layer: base.layer,
            digest: l2tunnel_core::ConfigDigest(digest),
        })
    }
}

/// Non-secret state of a running swift session for the local status API.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Ordering channels in use.
    pub channels: u64,
    /// Outbound budget in IP bytes per second.
    pub send_bytes_per_second: u64,
    /// Microseconds since forwarding started, at the latest observation.
    pub elapsed_micros: u64,
    /// Source symbols sent.
    pub sources: u64,
    /// Requested retransmissions sent.
    pub retransmits: u64,
    /// Proportional and idle repairs sent.
    pub repairs: u64,
    /// Protected datagrams sent.
    pub datagrams_sent: u64,
    /// IP bytes charged for them.
    pub ip_bytes_sent: u64,
    /// Authenticated datagrams received.
    pub datagrams_received: u64,
    /// Datagrams rejected by authentication, replay or length checks.
    pub datagrams_rejected: u64,
    /// Datagrams the socket or local firewall refused.
    pub socket_drops: u64,
    /// Native packets accepted from the device.
    pub native_read: u64,
    /// Native packets refused for size or a full queue.
    pub native_dropped: u64,
    /// Native packets written to the device.
    pub native_written: u64,
    /// Recovered packets the device refused.
    pub native_write_drops: u64,
    /// Native bytes removed by header compression.
    pub header_bytes_saved: u64,
    /// Largest per-channel round-trip estimate in microseconds.
    pub round_trip_micros: u64,
}

impl Status {
    /// Combine the fixed policy with the latest counters.
    pub fn new(config: runtime::Config, snapshot: &Snapshot) -> Self {
        Self {
            channels: config.channels as u64,
            send_bytes_per_second: config.send_bytes_per_second,
            elapsed_micros: snapshot.elapsed_micros,
            sources: snapshot.sender.sources,
            retransmits: snapshot.sender.retransmits,
            repairs: snapshot.sender.repairs + snapshot.sender.tail_repairs,
            datagrams_sent: snapshot.datagrams_sent,
            ip_bytes_sent: snapshot.ip_bytes_sent,
            datagrams_received: snapshot.datagrams_received,
            datagrams_rejected: snapshot.datagrams_rejected,
            socket_drops: snapshot.socket_drops,
            native_read: snapshot.native_read,
            native_dropped: snapshot.native_dropped,
            native_written: snapshot.native_written,
            native_write_drops: snapshot.native_write_drops,
            header_bytes_saved: snapshot.header_bytes_saved,
            round_trip_micros: snapshot.sender.smoothed_rtt_micros,
        }
    }
}

/// A native device the swift runtime can wait on for readiness.
pub trait Device:
    l2tunnel_device::PacketDevice<Error = io::Error> + std::os::fd::AsRawFd + Send + Sync
{
}
impl<T> Device for T where
    T: l2tunnel_device::PacketDevice<Error = io::Error> + std::os::fd::AsRawFd + Send + Sync
{
}
/// Owned dynamic readiness-capable device, as a service attachment returns it.
pub struct Native(Box<dyn Device>);
impl Native {
    /// Take ownership of a concrete device.
    pub fn new(device: impl Device + 'static) -> Self {
        Self(Box::new(device))
    }
}
impl l2tunnel_device::PacketDevice for Native {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.0.layer()
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        self.0.receive(buffer)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0.transmit(packet)
    }
}
impl std::os::fd::AsRawFd for Native {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

/// One authenticated endpoint ready to forward.
pub struct Session {
    control: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
    socket: UdpSocket,
    send: Secret,
    receive: Secret,
    config: runtime::Config,
    info: SessionInfo,
}

impl Session {
    fn new(
        connection: auth::AuthenticatedConnection,
        socket: UdpSocket,
        config: runtime::Config,
        client: bool,
    ) -> io::Result<Self> {
        let export = |direction| {
            connection
                .export_key(KeyPurpose::Data, direction, 0)
                .map_err(auth_error)
        };
        let forward = export(Direction::ClientToServer)?;
        let reverse = export(Direction::ServerToClient)?;
        let (send, receive) = if client {
            (forward, reverse)
        } else {
            (reverse, forward)
        };
        let (stream, info) = connection.into_parts();
        Ok(Self {
            control: Box::pin(runtime::closed(stream)),
            socket,
            send,
            receive,
            config,
            info,
        })
    }
    /// Authenticated identities and the bound configuration.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }
    /// Effective kernel receive buffer of the data socket in bytes.
    pub fn receive_buffer(&self) -> io::Result<usize> {
        rustix::net::sockopt::socket_recv_buffer_size(&self.socket).map_err(io::Error::from)
    }
    /// Observe counters at least this often, for a frontend that serves
    /// status; does not change the authenticated policy.
    pub fn observe_every(mut self, interval: Duration) -> Self {
        let current = self.config.report_interval;
        self.config.report_interval = Some(current.map_or(interval, |value| value.min(interval)));
        self
    }
    /// Effective runtime policy of this endpoint.
    pub fn config(&self) -> runtime::Config {
        self.config
    }
    /// Forward until the peer closes the retained control stream or an error
    /// occurs. `report` receives periodic and terminal counters.
    pub async fn run<D>(self, device: D, report: impl FnMut(&Snapshot)) -> io::Result<()>
    where
        D: l2tunnel_device::PacketDevice<Error = io::Error> + std::os::fd::AsRawFd,
    {
        runtime::run(
            device,
            self.socket,
            runtime::Keys {
                send: self.send.expose_bytes(),
                receive: self.receive.expose_bytes(),
            },
            self.config,
            self.control,
            report,
        )
        .await
    }
}

/// Receive buffer requested for the data socket. In-order delivery releases
/// long runs of packets at once; the socket must hold what arrives meanwhile.
const RECEIVE_BUFFER_BYTES: usize = 8 << 20;

async fn bind(settings: Settings) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(settings.local).await?;
    socket.connect(settings.peer).await?;
    // Best effort: the privileged form may exceed the system-wide maximum,
    // the plain form is clamped to it. Neither failing is an error; the
    // effective size is reported by `Session::receive_buffer`.
    if rustix::net::sockopt::set_socket_recv_buffer_size_force(&socket, RECEIVE_BUFFER_BYTES)
        .is_err()
    {
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(&socket, RECEIVE_BUFFER_BYTES);
    }
    Ok(socket)
}

/// Connect, authenticate and derive the directional data keys. One deadline
/// covers the TCP connect and the TLS/member exchange.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<Session> {
    let session = settings.session(config)?;
    let runtime = settings.runtime(config, true)?;
    let deadline = HandshakeDeadline::start(config.handshake_timeout)?;
    let socket = bind(settings).await?;
    let tcp = deadline.within(base_socket(address, deadline)).await?;
    let connection = auth::client_connect(
        tcp,
        tls,
        server_name,
        identity,
        session,
        deadline.remaining()?,
    )
    .await
    .map_err(base_auth_error)?;
    Session::new(connection, socket, runtime, true)
}

/// Accept one member on `listener` and derive the directional data keys.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<Session> {
    let session = settings.session(config)?;
    let runtime = settings.runtime(config, false)?;
    let socket = bind(settings).await?;
    let (tcp, _) = listener.accept().await?;
    tcp.set_nodelay(true)?;
    let deadline = HandshakeDeadline::start(config.handshake_timeout)?;
    let connection = auth::server_accept(tcp, tls, members, session, deadline.remaining()?)
        .await
        .map_err(base_auth_error)?;
    Session::new(connection, socket, runtime, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> io::Result<Settings> {
        let parse = |text: &str| {
            text.parse::<SocketAddr>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        };
        Ok(Settings {
            local: parse("127.0.0.1:24000")?,
            peer: parse("127.0.0.1:24001")?,
            path_mtu: 1500,
            forward_kbit: 100_000,
            reverse_kbit: 10_000,
            channels: 16,
            window: 64,
            repair_permille: 0,
            report: None,
        })
    }
    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            layer: PacketLayer::Ethernet,
            duplex: Duplex::Full,
            max_packet: 1600,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn geometry_and_budgets_follow_the_role_and_the_path() -> io::Result<()> {
        let settings = settings()?;
        let client = settings.runtime(connection(), true)?;
        let server = settings.runtime(connection(), false)?;
        // 1500 - IPv4/UDP 28 - packet number and tag 24.
        assert_eq!(client.codec.datagram_bytes, 1448);
        assert_eq!(client.codec.symbol_bytes(), 1440);
        assert_eq!(client.send_bytes_per_second, 12_500_000);
        assert_eq!(server.send_bytes_per_second, 1_250_000);
        assert_eq!(client.codec.queue_bytes, 250_000);
        assert_eq!(server.codec.queue_bytes, 25_000);
        let mut v6 = settings;
        v6.local = "[::1]:1".parse().map_err(io::Error::other)?;
        v6.peer = "[::1]:2".parse().map_err(io::Error::other)?;
        assert_eq!(v6.runtime(connection(), true)?.codec.datagram_bytes, 1428);
        Ok(())
    }

    #[test]
    fn every_protocol_value_changes_the_digest_and_local_values_do_not() -> io::Result<()> {
        let base = settings()?;
        let digest = base.session(connection())?;
        let mut local = base;
        local.report = Some(Duration::from_secs(1));
        local.local = "127.0.0.9:9".parse().map_err(io::Error::other)?;
        local.peer = "127.0.0.8:8".parse().map_err(io::Error::other)?;
        assert_eq!(local.session(connection())?, digest);
        let changes: [fn(&mut Settings); 6] = [
            |value| value.channels = 8,
            |value| value.path_mtu = 1400,
            |value| value.forward_kbit += 1,
            |value| value.reverse_kbit += 1,
            |value| value.window = 32,
            |value| value.repair_permille = 1,
        ];
        for change in changes {
            let mut other = base;
            change(&mut other);
            assert_ne!(other.session(connection())?.digest, digest.digest);
        }
        let mut tun = connection();
        tun.layer = PacketLayer::Ip;
        assert_ne!(base.session(tun)?, digest);
        let mut larger = connection();
        larger.max_packet = 1700;
        assert_ne!(base.session(larger)?.digest, digest.digest);
        Ok(())
    }

    #[test]
    fn unsupported_selections_are_rejected_before_any_socket() -> io::Result<()> {
        let base = settings()?;
        let mut half = connection();
        half.duplex = Duplex::Half;
        assert!(base.session(half).is_err());
        let mut compressed = connection();
        compressed.compression = Compression::Lz4IfSmaller;
        assert!(base.session(compressed).is_err());
        let changes: [fn(&mut Settings); 9] = [
            |value| value.channels = 0,
            |value| value.channels = 65,
            |value| value.path_mtu = 500,
            |value| value.path_mtu = 9001,
            |value| value.forward_kbit = 10,
            |value| value.reverse_kbit = 20_000_000,
            |value| value.window = 0,
            |value| value.window = 256,
            |value| value.repair_permille = 1001,
        ];
        for change in changes {
            let mut other = base;
            change(&mut other);
            assert!(other.session(connection()).is_err(), "{other:?}");
        }
        let mut mixed = base;
        mixed.peer = "[::1]:2".parse().map_err(io::Error::other)?;
        assert!(mixed.session(connection()).is_err());
        Ok(())
    }
}
