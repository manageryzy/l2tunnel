use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{net::SocketAddr, time::Duration};
pub(super) type Device = Box<dyn PacketDevice<Error = io::Error> + Send>;
/// Fresh attachment provider. The service calls it only after authentication.
/// It must do finite nonblocking work, retain all owners in the returned device,
/// and bound its trusted captures. No hidden tasks or asynchronous cancellation
/// are implied by this synchronous provider.
#[derive(Clone)]
pub struct Attachment {
    layer: PacketLayer,
    open: Open,
}
#[derive(Clone)]
enum Open {
    Packet(Arc<dyn Fn() -> io::Result<Device> + Send + Sync>),
    #[cfg(unix)]
    Readable(Arc<dyn Fn() -> io::Result<crate::swift::Native> + Send + Sync>),
}
impl Attachment {
    pub(super) fn open(&self) -> io::Result<Device> {
        match &self.open {
            Open::Packet(open) => open(),
            #[cfg(unix)]
            Open::Readable(open) => Ok(Box::new(open()?)),
        }
    }
    /// Fresh readiness-capable owner; absent for a plain packet provider.
    #[cfg(unix)]
    pub(super) fn open_readable(&self) -> io::Result<crate::swift::Native> {
        match &self.open {
            Open::Readable(open) => open(),
            Open::Packet(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment has no readiness descriptor",
            )),
        }
    }
    #[cfg(unix)]
    fn readable_kind(&self) -> bool {
        matches!(self.open, Open::Readable(_))
    }
    /// Bind a layer and a factory of devices that expose a readiness
    /// descriptor. Every backend accepts it; the swift backend requires it.
    #[cfg(unix)]
    pub fn readable(
        layer: PacketLayer,
        open: impl Fn() -> io::Result<crate::swift::Native> + Send + Sync + 'static,
    ) -> Self {
        Self {
            layer,
            open: Open::Readable(Arc::new(open)),
        }
    }
    /// Bind an advertised layer and a fresh-owner factory; does not invoke it.
    pub fn new(
        layer: PacketLayer,
        open: impl Fn() -> io::Result<Device> + Send + Sync + 'static,
    ) -> Self {
        Self {
            layer,
            open: Open::Packet(Arc::new(open)),
        }
    }
}
/// Existing managed TCP options; no parallel mode or recovery selector.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Existing explicit canonical delivery binding, or supported legacy TCP default.
    pub delivery: Option<managed::DeliveryConfig>,
    /// Existing optional profiler cadence, constrained to 100..60000 ms.
    pub profile_interval: Option<Duration>,
}
/// Already parsed client credentials and fixed original endpoint.
pub struct Client {
    /// Fixed remote socket address.
    pub remote: SocketAddr,
    /// Maintained TLS verifier configuration.
    pub tls: ClientTls,
    /// Certificate verification name; public SNI is configured separately in tls.
    pub server_name: String,
    /// Existing authenticated member key, retained without serialization or Debug.
    pub member: Arc<MemberKey>,
}
/// Already parsed server credentials and fixed listen address.
pub struct Server {
    /// Original listener address; port zero is permitted for an owned test listener.
    pub listen: SocketAddr,
    /// Maintained TLS server configuration.
    pub tls: ServerTls,
    /// Existing bounded member allowlist.
    pub members: MemberAllowlist,
}
pub(super) enum Endpoint {
    Client(Client),
    Server(Server),
    #[cfg(unix)]
    SecureClient(crate::secure_udp::credentials::Client),
    #[cfg(unix)]
    SecureServer(Box<SecureServer>),
    #[cfg(unix)]
    CommonCarrierClient {
        outer: Client,
        inner: crate::secure_udp::credentials::Client,
    },
    #[cfg(unix)]
    CommonCarrierServer(Box<CommonCarrierServer>),
    #[cfg(unix)]
    CommonRawClient {
        outer: Client,
        inner: crate::secure_udp::credentials::Client,
    },
    #[cfg(unix)]
    CommonRawServer(Box<CommonRawServer>),
    #[cfg(unix)]
    CommonMaintainedClient {
        outer: crate::secure_udp::maintained::Client,
        inner: crate::secure_udp::credentials::Client,
    },
    #[cfg(unix)]
    CommonMaintainedServer(Box<CommonMaintainedServer>),
}
#[cfg(unix)]
pub(super) struct SecureServer {
    pub credentials: crate::secure_udp::credentials::Server,
    pub admission: tokio::sync::Mutex<Option<crate::secure_udp::Server>>,
}
#[cfg(unix)]
pub(super) struct CommonCarrierServer {
    pub outer: Server,
    pub inner: crate::secure_udp::credentials::Server,
    // A quarantine is bound to one actual TLS proof. A new outer connection
    // replaces it; this is not retained-session recovery across fresh TLS.
    pub admission: tokio::sync::Mutex<
        Option<l2tunnel_runtime::secure_udp::establish::carrier::InitialServerAdmission>,
    >,
}
#[cfg(unix)]
pub(super) struct CommonRawServer {
    pub outer: Server,
    pub inner: crate::secure_udp::credentials::Server,
    pub admission: tokio::sync::Mutex<
        Option<l2tunnel_runtime::secure_udp::establish::raw_carrier::RawInitialServerAdmission>,
    >,
}
#[cfg(unix)]
pub(super) struct CommonMaintainedServer {
    pub outer: crate::secure_udp::maintained::Server,
    pub inner: crate::secure_udp::credentials::Server,
    pub admission: tokio::sync::Mutex<
        Option<l2tunnel_runtime::secure_udp::establish::maintained::InitialServerAdmission>,
    >,
}
/// Selected setup backend. Each variant names one existing authenticated factory;
/// this is not a carrier preference list and never falls back to another variant.
#[derive(Clone)]
pub(super) enum Transport {
    Managed(Options),
    Proxy(Arc<crate::proxy::Settings>),
    ProxyMeasured(Arc<crate::proxy_measured::Settings>),
    #[cfg(unix)]
    ProxyCommon(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    ProxyCommonRaw {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        raw: Arc<crate::raw_packet::common::Settings>,
        opener: crate::raw_packet::common::PacketOpener,
    },
    UdpFrame {
        settings: crate::udp::Settings,
        delivery: managed::DeliveryConfig,
    },
    #[cfg(unix)]
    Swift(crate::swift::Settings),
    #[cfg(unix)]
    SecureUdpSwift(Arc<crate::secure_udp::profile::Profile>),
    #[cfg(unix)]
    SecureUdpTransaction(Arc<crate::secure_udp::transaction_profile::Profile>),
    #[cfg(unix)]
    SecureUdpCommon(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    SecureUdpCommonMaintained(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    SecureUdpCommonCarrier {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        outer: l2tunnel_openvpn::wire_carrier::common::Config,
    },
    #[cfg(unix)]
    SecureUdpCommonRaw {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        raw: Arc<crate::raw_packet::common::Settings>,
        opener: crate::raw_packet::common::PacketOpener,
    },
}
/// Longest time a swift acceptor keeps its listener open for a peer. Each
/// accepted TCP connection is still bound by the original handshake timeout.
#[cfg(unix)]
pub const SWIFT_LISTEN: Duration = Duration::from_secs(24 * 60 * 60);
pub(super) struct Data {
    pub connection: ConnectionConfig,
    pub endpoint: Endpoint,
    pub attachment: Attachment,
    pub transport: Transport,
}
/// Immutable validated plan for one explicit backend. Clone retains exact identity. A newly
/// prepared plan is a different operation even with equivalent visible settings.
#[derive(Clone)]
pub struct Prepared {
    pub(super) identity: Arc<()>,
    pub(super) data: Arc<Data>,
}
impl Prepared {
    /// Explicit fixed-credit maintained-TCP proxy; all attachment work is deferred.
    pub fn proxy_client(
        connection: ConnectionConfig,
        credentials: Client,
        settings: crate::proxy::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&credentials)?;
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            Transport::Proxy(Arc::new(settings)),
        )
    }
    /// Fixed proxy acceptor retaining the existing full/paired TLS factory.
    pub fn proxy_server(
        connection: ConnectionConfig,
        credentials: Server,
        settings: crate::proxy::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            connection,
            Endpoint::Server(credentials),
            attachment,
            Transport::Proxy(Arc::new(settings)),
        )
    }
    /// Explicit measured relay targets; this does not select exact native rwnd control.
    pub fn proxy_measured_client(
        connection: ConnectionConfig,
        credentials: Client,
        settings: crate::proxy_measured::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&credentials)?;
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            Transport::ProxyMeasured(Arc::new(settings)),
        )
    }
    /// Measured proxy acceptor with the same deferred attachment and TLS ownership.
    pub fn proxy_measured_server(
        connection: ConnectionConfig,
        credentials: Server,
        settings: crate::proxy_measured::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            connection,
            Endpoint::Server(credentials),
            attachment,
            Transport::ProxyMeasured(Arc::new(settings)),
        )
    }
    /// Explicit fixed proxy over the original Common authenticated UDP owner.
    #[cfg(unix)]
    pub fn proxy_common_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureClient(credentials),
            attachment,
            Transport::ProxyCommon(Arc::new(profile)),
        )
    }
    /// Same fixed Common proxy selection with the existing server admission owner.
    #[cfg(unix)]
    pub fn proxy_common_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureServer(Box::new(SecureServer {
                credentials,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::ProxyCommon(Arc::new(profile)),
        )
    }
    /// Explicit fixed/full proxy over genuine original raw TLS/packet owners.
    /// All original I/O and native attachment remain deferred to the sole Run.
    #[cfg(unix)]
    pub fn proxy_common_raw_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        raw: crate::raw_packet::common::Settings,
        outer: Client,
        inner: crate::secure_udp::credentials::Client,
        opener: crate::raw_packet::common::PacketOpener,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&outer)?;
        Self::new(
            profile.connection(),
            Endpoint::CommonRawClient { outer, inner },
            attachment,
            Transport::ProxyCommonRaw {
                profile: Arc::new(profile),
                raw: Arc::new(raw),
                opener,
            },
        )
    }
    /// Matching fixed raw proxy acceptor with real independent TLS/Noise trust.
    #[cfg(unix)]
    pub fn proxy_common_raw_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        raw: crate::raw_packet::common::Settings,
        outer: Server,
        inner: crate::secure_udp::credentials::Server,
        opener: crate::raw_packet::common::PacketOpener,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonRawServer(Box::new(CommonRawServer {
                outer,
                inner,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::ProxyCommonRaw {
                profile: Arc::new(profile),
                raw: Arc::new(raw),
                opener,
            },
        )
    }
    /// Explicit same-socket Noise/member/Swift client, with deferred device work.
    #[cfg(unix)]
    pub fn secure_udp_client(
        profile: crate::secure_udp::profile::Profile,
        credentials: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureClient(credentials),
            attachment,
            Transport::SecureUdpSwift(Arc::new(profile)),
        )
    }
    /// Fixed-peer acceptor retaining one admission quarantine across attempts.
    #[cfg(unix)]
    pub fn secure_udp_server(
        profile: crate::secure_udp::profile::Profile,
        credentials: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureServer(Box::new(SecureServer {
                credentials,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpSwift(Arc::new(profile)),
        )
    }
    /// Explicit complete-configuration transaction client, with deferred device work.
    #[cfg(unix)]
    pub fn secure_udp_transaction_client(
        profile: crate::secure_udp::transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureClient(credentials),
            attachment,
            Transport::SecureUdpTransaction(Arc::new(profile)),
        )
    }
    /// Explicit transaction acceptor retaining one admission owner across attempts.
    #[cfg(unix)]
    pub fn secure_udp_transaction_server(
        profile: crate::secure_udp::transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureServer(Box::new(SecureServer {
                credentials,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpTransaction(Arc::new(profile)),
        )
    }
    /// Explicit mixed-profile client using the existing authenticated UDP factory.
    #[cfg(unix)]
    pub fn secure_udp_common_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureClient(credentials),
            attachment,
            Transport::SecureUdpCommon(Arc::new(profile)),
        )
    }
    /// Explicit mixed-profile acceptor retaining the same admission quarantine.
    #[cfg(unix)]
    pub fn secure_udp_common_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        credentials: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::SecureServer(Box::new(SecureServer {
                credentials,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpCommon(Arc::new(profile)),
        )
    }
    /// Explicit initial-only OpenVPN outer TLS and common Noise/member client.
    /// Validation defers all socket, handshake and attachment work to the service.
    #[cfg(unix)]
    pub fn secure_udp_common_carrier_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        outer: l2tunnel_openvpn::wire_carrier::common::Config,
        tls: Client,
        inner: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&tls)?;
        Self::new(
            profile.connection(),
            Endpoint::CommonCarrierClient { outer: tls, inner },
            attachment,
            Transport::SecureUdpCommonCarrier {
                profile: Arc::new(profile),
                outer,
            },
        )
    }
    /// Explicit compact Common over original maintained TLS or genuine QUIC.
    #[cfg(unix)]
    pub fn secure_udp_common_maintained_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        outer: crate::secure_udp::maintained::Client,
        inner: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonMaintainedClient { outer, inner },
            attachment,
            Transport::SecureUdpCommonMaintained(Arc::new(profile)),
        )
    }
    /// Matching retained Full/Half acceptor, with no listener opened at preparation.
    #[cfg(unix)]
    pub fn secure_udp_common_maintained_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        outer: crate::secure_udp::maintained::Server,
        inner: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonMaintainedServer(Box::new(CommonMaintainedServer {
                outer,
                inner,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpCommonMaintained(Arc::new(profile)),
        )
    }
    /// Explicit fixed-peer OpenVPN acceptor with independent TLS and Noise trust.
    #[cfg(unix)]
    pub fn secure_udp_common_carrier_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        outer: l2tunnel_openvpn::wire_carrier::common::Config,
        tls: Server,
        inner: crate::secure_udp::credentials::Server,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonCarrierServer(Box::new(CommonCarrierServer {
                outer: tls,
                inner,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpCommonCarrier {
                profile: Arc::new(profile),
                outer,
            },
        )
    }
    /// Explicit original raw Full/Half Common client; all original I/O is deferred.
    #[cfg(unix)]
    pub fn secure_udp_common_raw_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        raw: crate::raw_packet::common::Settings,
        outer: Client,
        inner: crate::secure_udp::credentials::Client,
        opener: crate::raw_packet::common::PacketOpener,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&outer)?;
        Self::new(
            profile.connection(),
            Endpoint::CommonRawClient { outer, inner },
            attachment,
            Transport::SecureUdpCommonRaw {
                profile: Arc::new(profile),
                raw: Arc::new(raw),
                opener,
            },
        )
    }
    /// Same original paired raw factory and actual fixed-member acceptance path.
    #[cfg(unix)]
    pub fn secure_udp_common_raw_server(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        raw: crate::raw_packet::common::Settings,
        outer: Server,
        inner: crate::secure_udp::credentials::Server,
        opener: crate::raw_packet::common::PacketOpener,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonRawServer(Box::new(CommonRawServer {
                outer,
                inner,
                admission: tokio::sync::Mutex::new(None),
            })),
            attachment,
            Transport::SecureUdpCommonRaw {
                profile: Arc::new(profile),
                raw: Arc::new(raw),
                opener,
            },
        )
    }
    #[cfg(unix)]
    pub(super) fn secure_udp(&self) -> bool {
        matches!(
            &self.data.transport,
            Transport::SecureUdpSwift(_)
                | Transport::ProxyCommon(_)
                | Transport::ProxyCommonRaw { .. }
                | Transport::SecureUdpTransaction(_)
                | Transport::SecureUdpCommon(_)
                | Transport::SecureUdpCommonMaintained(_)
                | Transport::SecureUdpCommonCarrier { .. }
                | Transport::SecureUdpCommonRaw { .. }
        )
    }
    #[cfg(unix)]
    pub(super) fn secure_udp_transaction(&self) -> bool {
        matches!(&self.data.transport, Transport::SecureUdpTransaction(_))
    }
    #[cfg(unix)]
    pub(super) fn secure_udp_common(&self) -> bool {
        matches!(
            &self.data.transport,
            Transport::SecureUdpCommon(_)
                | Transport::SecureUdpCommonMaintained(_)
                | Transport::SecureUdpCommonCarrier { .. }
                | Transport::SecureUdpCommonRaw { .. }
        )
    }
    /// Pure validation; credentials are already parsed and no provider is invoked.
    pub fn client(
        connection: ConnectionConfig,
        credentials: Client,
        attachment: Attachment,
        options: Options,
    ) -> io::Result<Self> {
        Self::client_endpoint(&credentials)?;
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            Transport::Managed(options),
        )
    }
    /// Base system/frame UDP initiator with TLS-bootstrapped authentication. The
    /// native delivery policy is mandatory; there is no legacy default. Pure
    /// validation of the exact settings and canonical binding precedes any
    /// credential use, socket bind or device work.
    pub fn udp_client(
        connection: ConnectionConfig,
        credentials: Client,
        settings: crate::udp::Settings,
        delivery: managed::DeliveryConfig,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&credentials)?;
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            Transport::UdpFrame { settings, delivery },
        )
    }
    /// Base system/frame UDP acceptor; same validation order as [`Self::udp_client`].
    /// Does not bind the TCP bootstrap listener, a UDP socket or a native device.
    pub fn udp_server(
        connection: ConnectionConfig,
        credentials: Server,
        settings: crate::udp::Settings,
        delivery: managed::DeliveryConfig,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            connection,
            Endpoint::Server(credentials),
            attachment,
            Transport::UdpFrame { settings, delivery },
        )
    }
    /// Swift initiator: TLS-bootstrapped authentication, then paced protected
    /// UDP. The attachment must come from [`Attachment::readable`]. Pure
    /// validation of the complete policy precedes any socket or device work.
    #[cfg(unix)]
    pub fn swift_client(
        connection: ConnectionConfig,
        credentials: Client,
        settings: crate::swift::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::client_endpoint(&credentials)?;
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            Transport::Swift(settings),
        )
    }
    /// Swift acceptor; same validation as [`Self::swift_client`]. Its setup
    /// operation may wait up to [`SWIFT_LISTEN`] for a peer.
    #[cfg(unix)]
    pub fn swift_server(
        connection: ConnectionConfig,
        credentials: Server,
        settings: crate::swift::Settings,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            connection,
            Endpoint::Server(credentials),
            attachment,
            Transport::Swift(settings),
        )
    }
    /// Bound of one accepted setup operation, started at acceptance.
    pub(super) fn setup_timeout(&self) -> Duration {
        match (&self.data.transport, &self.data.endpoint) {
            #[cfg(unix)]
            (Transport::Swift(_), Endpoint::Server(_)) => {
                SWIFT_LISTEN + self.data.connection.handshake_timeout
            }
            _ => self.data.connection.handshake_timeout,
        }
    }
    fn client_endpoint(credentials: &Client) -> io::Result<()> {
        if credentials.remote.port() == 0
            || credentials.remote.ip().is_unspecified()
            || credentials.server_name.is_empty()
            || credentials.server_name.len() > 253
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixed client endpoint/name",
            ));
        }
        Ok(())
    }
    /// Pure validation; does not bind listener or open a native device.
    pub fn server(
        connection: ConnectionConfig,
        credentials: Server,
        attachment: Attachment,
        options: Options,
    ) -> io::Result<Self> {
        Self::new(
            connection,
            Endpoint::Server(credentials),
            attachment,
            Transport::Managed(options),
        )
    }
    fn new(
        connection: ConnectionConfig,
        endpoint: Endpoint,
        attachment: Attachment,
        transport: Transport,
    ) -> io::Result<Self> {
        let profile_interval = match &transport {
            Transport::Managed(options) => {
                match options.delivery {
                    Some(delivery) => {
                        connection.session_with_delivery(delivery)?;
                    }
                    None => {
                        connection.session()?;
                    }
                }
                options.profile_interval
            }
            Transport::Proxy(settings) => {
                let config = crate::proxy::runtime_config(connection, settings)?;
                l2tunnel_runtime::proxy::session_config(&config)?;
                None
            }
            Transport::ProxyMeasured(settings) => {
                let config = crate::proxy_measured::runtime_config(connection, settings)?;
                l2tunnel_runtime::proxy::measured::session_config(&config)?;
                None
            }
            Transport::UdpFrame { settings, delivery } => {
                // Same exact checks the authenticated factory repeats before I/O.
                let profile = crate::udp::runtime_config(connection, *settings)?;
                l2tunnel_runtime::udp::base_session_config(
                    connection.runtime(),
                    profile,
                    *delivery,
                )?;
                None
            }
            #[cfg(unix)]
            Transport::Swift(settings) => {
                settings.session(connection)?;
                if !attachment.readable_kind() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "swift requires a readiness-capable attachment",
                    ));
                }
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpSwift(profile) => {
                let session = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::SecureClient(credentials) => {
                        if credentials.member_key() != session.member {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "configured member differs from actual credential",
                            ));
                        }
                        (credentials.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::SecureServer(server) => (
                        server.credentials.noise(),
                        l2tunnel_security::Role::Responder,
                    ),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "secure UDP requires distinct Noise credentials",
                        ));
                    }
                };
                if noise.profile() != session.profile || !attachment.readable_kind() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "secure UDP profile/credentials or readable attachment differ",
                    ));
                }
                profile.configuration(noise.peers(role))?;
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpTransaction(profile) => {
                let session = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::SecureClient(credentials) => {
                        if credentials.member_key() != session.member {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "configured member differs from actual credential",
                            ));
                        }
                        (credentials.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::SecureServer(server) => (
                        server.credentials.noise(),
                        l2tunnel_security::Role::Responder,
                    ),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "secure UDP requires distinct Noise credentials",
                        ));
                    }
                };
                if noise.profile() != session.profile || !attachment.readable_kind() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "secure UDP profile/credentials or readable attachment differ",
                    ));
                }
                if noise.peers(role) != profile.peers() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "actual Noise credentials differ from transaction plan pins",
                    ));
                }
                profile.runtime_contract(role)?;
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpCommon(profile) | Transport::ProxyCommon(profile) => {
                if profile.proxy_config().is_some()
                    != matches!(&transport, Transport::ProxyCommon(_))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Common proxy requires explicit proxy service selection",
                    ));
                }
                let session = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::SecureClient(credentials) => {
                        if credentials.member_key() != session.member {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "configured member differs from actual credential",
                            ));
                        }
                        (credentials.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::SecureServer(server) => (
                        server.credentials.noise(),
                        l2tunnel_security::Role::Responder,
                    ),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "common UDP requires distinct Noise credentials",
                        ));
                    }
                };
                if noise.profile() != session.profile
                    || (profile.proxy_config().is_none() && !attachment.readable_kind())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "common UDP profile/credentials or readable attachment differ",
                    ));
                }
                if noise.peers(role) != profile.peers() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "actual Noise credentials differ from Common plan pins",
                    ));
                }
                profile.runtime_contract(role)?;
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpCommonRaw { profile, raw, .. }
            | Transport::ProxyCommonRaw { profile, raw, .. } => {
                let proxy = matches!(&transport, Transport::ProxyCommonRaw { .. });
                if proxy != profile.proxy_config().is_some()
                    || (proxy && profile.proxy_measured_config().is_some())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "raw Common proxy requires its explicit fixed service selection",
                    ));
                }
                if proxy
                    && (profile.connection().duplex != l2tunnel_core::Duplex::Full
                        || raw.duplex() != l2tunnel_core::Duplex::Full)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "raw Common proxy currently requires Full",
                    ));
                }
                let session = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::CommonRawClient { outer, inner } => {
                        if outer.remote != session.gate.path.server
                            || outer.member.public_key().0 != session.member.0
                            || inner.member_key() != session.member
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "raw outer/inner member or fixed endpoint differs",
                            ));
                        }
                        (inner.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::CommonRawServer(server) => {
                        if !server
                            .outer
                            .members
                            .contains(l2tunnel_auth::MemberPublicKey(session.member.0))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "raw allowlist excludes configured member",
                            ));
                        }
                        if server.outer.listen != session.gate.path.server {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "raw server fixed tuple differs",
                            ));
                        }
                        (server.inner.noise(), l2tunnel_security::Role::Responder)
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "raw Common requires actual independent TLS/Noise credentials",
                        ));
                    }
                };
                if profile.raw_policy().is_none()
                    || profile.raw_binding().is_some()
                    || profile.carrier_binding().is_some()
                    || noise.profile() != session.profile
                    || (!proxy && !attachment.readable_kind())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "raw Common requires an unbound raw profile and readable attachment",
                    ));
                }
                if noise.peers(role) != profile.peers() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "raw Common actual Noise pins differ",
                    ));
                }
                raw.validate(profile, role)?;
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpCommonMaintained(profile) => {
                use crate::secure_udp::maintained::{
                    Client as OuterClient, Server as OuterServer, Transport as OuterTransport,
                };
                let selected = profile.maintained_settings().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "maintained policy absent")
                })?;
                selected.request(connection)?;
                if profile.maintained_binding().is_some()
                    || !attachment.readable_kind()
                    || profile.proxy_config().is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "maintained native Common requires an unbound readable native plan",
                    ));
                }
                let settings = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::CommonMaintainedClient { outer, inner } => {
                        if outer.member().0 != settings.member.0
                            || inner.member_key() != settings.member
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "maintained member identities differ",
                            ));
                        }
                        match (selected.transport, outer) {
                            (OuterTransport::Tls(_), OuterClient::Tls(tls)) => {
                                Self::client_endpoint(tls)?;
                                if tls.remote != selected.first.server {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "maintained TLS endpoint differs",
                                    ));
                                }
                            }
                            (
                                OuterTransport::Quic(profiles),
                                OuterClient::Quic {
                                    roots, server_name, ..
                                },
                            ) => {
                                if server_name.is_empty()
                                    || server_name.len() > 253
                                    || server_name.as_bytes().contains(&0)
                                {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "invalid QUIC verification name",
                                    ));
                                }
                                for profile in profiles.into_iter().flatten() {
                                    l2tunnel_quic::ClientConfig::from_der_roots(
                                        roots,
                                        profile,
                                        l2tunnel_quic::EndpointLimits::default(),
                                    )
                                    .map_err(io::Error::other)?;
                                }
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "maintained credential/transport mismatch",
                                ));
                            }
                        }
                        (inner.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::CommonMaintainedServer(server) => {
                        if !server
                            .outer
                            .members()
                            .contains(l2tunnel_auth::MemberPublicKey(settings.member.0))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "maintained allowlist excludes member",
                            ));
                        }
                        match (selected.transport, &server.outer) {
                            (OuterTransport::Tls(_), OuterServer::Tls(tls))
                                if tls.listen == selected.first.server => {}
                            (
                                OuterTransport::Quic(profiles),
                                OuterServer::Quic { certs, key, .. },
                            ) => {
                                for profile in profiles.into_iter().flatten() {
                                    l2tunnel_quic::ServerConfig::from_der(
                                        certs,
                                        key,
                                        profile,
                                        l2tunnel_quic::EndpointLimits::default(),
                                    )
                                    .map_err(io::Error::other)?;
                                }
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "maintained server credential/transport mismatch",
                                ));
                            }
                        }
                        (server.inner.noise(), l2tunnel_security::Role::Responder)
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "maintained credentials absent",
                        ));
                    }
                };
                if noise.profile() != settings.profile || noise.peers(role) != profile.peers() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "maintained Noise pins differ",
                    ));
                }
                profile.maintained_session()?;
                None
            }
            #[cfg(unix)]
            Transport::SecureUdpCommonCarrier { profile, outer } => {
                if profile.proxy_config().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Common proxy requires its explicit protected UDP service",
                    ));
                }
                let session = profile.settings();
                let (noise, role) = match &endpoint {
                    Endpoint::CommonCarrierClient { outer: tls, inner } => {
                        if tls.remote != session.gate.path.server
                            || tls.member.public_key().0 != session.member.0
                            || inner.member_key() != session.member
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "outer endpoint/member differs from the common credentials",
                            ));
                        }
                        (inner.noise(), l2tunnel_security::Role::Initiator)
                    }
                    Endpoint::CommonCarrierServer(server) => {
                        if !server
                            .outer
                            .members
                            .contains(l2tunnel_auth::MemberPublicKey(session.member.0))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "outer allowlist excludes the configured common member",
                            ));
                        }
                        if server.outer.listen != session.gate.path.server {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "outer listen endpoint differs from the common fixed path",
                            ));
                        }
                        (server.inner.noise(), l2tunnel_security::Role::Responder)
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "common carrier requires independent TLS and Noise owners",
                        ));
                    }
                };
                if profile.carrier_binding().is_some()
                    || noise.profile() != session.profile
                    || !attachment.readable_kind()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "common carrier requires an unbound plan and readable attachment",
                    ));
                }
                if noise.peers(role) != profile.peers() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "actual Noise credentials differ from the common carrier pins",
                    ));
                }
                let mut base = connection.session()?;
                base.digest = l2tunnel_core::ConfigDigest(profile.requested_configuration()?.0);
                outer.validate().map_err(io::Error::other)?;
                if outer.base != base
                    || outer.path_mtu != profile.initial().descriptor().path_mtu()
                    || outer.outer_overhead_bytes
                        != if session.gate.path.client.is_ipv4() {
                            29
                        } else {
                            49
                        }
                    || outer.max_record_bytes < session.cover.max_packet_bytes
                    || outer.handshake_timeout > connection.handshake_timeout
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "outer policy differs from the requested common plan",
                    ));
                }
                profile.runtime_contract(role)?;
                None
            }
        };
        if attachment.layer != connection.layer
            || profile_interval
                .is_some_and(|d| d < Duration::from_millis(100) || d > Duration::from_secs(60))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment layer or profile interval differs",
            ));
        }
        Ok(Self {
            identity: Arc::new(()),
            data: Arc::new(Data {
                connection,
                endpoint,
                attachment,
                transport,
            }),
        })
    }
    #[cfg(unix)]
    pub(super) fn open_readable(&self) -> io::Result<crate::swift::Native> {
        let device = self.data.attachment.open_readable()?;
        if PacketDevice::layer(&device) != self.data.connection.layer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "opened attachment changed layer",
            ));
        }
        Ok(device)
    }
    pub(super) fn open(&self) -> io::Result<Device> {
        let device = self.data.attachment.open()?;
        if device.layer() != self.data.connection.layer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "opened attachment changed layer",
            ));
        }
        Ok(device)
    }
}

#[cfg(all(test, unix))]
#[path = "prepared_transaction_tests.rs"]
mod transaction_tests;
