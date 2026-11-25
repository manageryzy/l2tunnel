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
    // Sets the device MTU around live inner-size switches.
    device_mtu: Option<Arc<dyn super::device_mtu::DeviceMtuHost>>,
}
#[cfg(windows)]
type Opening = Pin<Box<dyn Future<Output = io::Result<crate::native::Native>> + Send>>;

#[derive(Clone)]
enum Open {
    #[cfg(windows)]
    Deferred(Arc<dyn Fn() -> Opening + Send + Sync>),
    Packet(Arc<dyn Fn() -> io::Result<Device> + Send + Sync>),
    #[cfg(unix)]
    Readable(Arc<dyn Fn() -> io::Result<crate::native::Native> + Send + Sync>),
}
impl Attachment {
    pub(super) fn open(&self) -> io::Result<Device> {
        match &self.open {
            Open::Packet(open) => open(),
            #[cfg(windows)]
            Open::Deferred(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "asynchronous attachment requires a Common owner",
            )),
            #[cfg(unix)]
            Open::Readable(open) => Ok(Box::new(open()?)),
        }
    }
    /// Fresh readiness-capable owner; absent for a plain packet provider.
    #[cfg(unix)]
    pub(super) fn open_readable(&self) -> io::Result<crate::native::Native> {
        match &self.open {
            Open::Readable(open) => open(),
            Open::Packet(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment has no readiness descriptor",
            )),
        }
    }
    /// Native attachment accepted by the current platform's runtime boundary.
    pub(super) fn open_native(&self) -> io::Result<crate::native::Native> {
        #[cfg(unix)]
        {
            self.open_readable()
        }
        #[cfg(not(unix))]
        {
            self.open().map(crate::native::Native::new)
        }
    }
    fn readable_kind(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.open, Open::Readable(_))
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
    /// Bind a layer and a factory of devices that expose a readiness
    /// descriptor. Every backend accepts it; the swift backend requires it.
    #[cfg(unix)]
    pub fn readable(
        layer: PacketLayer,
        open: impl Fn() -> io::Result<crate::native::Native> + Send + Sync + 'static,
    ) -> Self {
        Self {
            layer,
            open: Open::Readable(Arc::new(open)),
            device_mtu: None,
        }
    }
    /// Bind a cancellable Windows native setup future. Its owner must join
    /// outstanding OS work and release an unclaimed device when dropped.
    #[cfg(windows)]
    pub fn deferred_native<F>(
        layer: PacketLayer,
        open: impl Fn() -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = io::Result<crate::native::Native>> + Send + 'static,
    {
        Self {
            layer,
            open: Open::Deferred(Arc::new(move || Box::pin(open()))),
            device_mtu: None,
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
            device_mtu: None,
        }
    }
    /// Let live-tuned sessions on this device set its MTU around inner-size
    /// switches (docs/modules/live-tuning.md, decisions 2 and 9).
    #[must_use]
    pub fn with_device_mtu(mut self, host: Arc<dyn super::device_mtu::DeviceMtuHost>) -> Self {
        self.device_mtu = Some(host);
        self
    }
    pub(super) fn device_mtu(&self) -> Option<&Arc<dyn super::device_mtu::DeviceMtuHost>> {
        self.device_mtu.as_ref()
    }
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
    SecureClient(crate::secure_udp::credentials::Client),
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
    #[cfg(unix)]
    ProxyCommon(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    ProxyCommonMaintained(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    ProxyCommonRaw {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        raw: Arc<crate::raw_packet::common::Settings>,
        opener: crate::raw_packet::common::PacketOpener,
    },
    SecureUdpCommon(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    SecureUdpCommonMaintained(Arc<crate::secure_udp::common_transaction_profile::Profile>),
    #[cfg(unix)]
    SecureUdpCommonCarrier {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        outer: Arc<l2tunnel_openvpn::wire_carrier::common::Config>,
    },
    #[cfg(unix)]
    SecureUdpCommonRaw {
        profile: Arc<crate::secure_udp::common_transaction_profile::Profile>,
        raw: Arc<crate::raw_packet::common::Settings>,
        opener: crate::raw_packet::common::PacketOpener,
    },
}
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
    pub(super) udp_socket_protector: Option<UdpSocketProtector>,
}
type Protection = std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>;
type UdpSocketProtector = Arc<dyn Fn(&tokio::net::UdpSocket) -> Protection + Send + Sync>;
impl Prepared {
    /// Whether this plan connects to a peer or accepts members.
    pub fn role(&self) -> local::Role {
        match &self.data.endpoint {
            Endpoint::SecureServer(_) => local::Role::Server,
            #[cfg(unix)]
            Endpoint::CommonCarrierServer(_)
            | Endpoint::CommonRawServer(_)
            | Endpoint::CommonMaintainedServer(_) => local::Role::Server,
            _ => local::Role::Client,
        }
    }
    /// Require platform protection of each freshly bound client UDP socket before
    /// connecting it or starting authentication. A failed protection stops setup.
    pub fn with_udp_socket_protector<F, Fut>(mut self, protect: F) -> io::Result<Self>
    where
        F: Fn(&tokio::net::UdpSocket) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
    {
        if !matches!(self.data.transport, Transport::SecureUdpCommon(_))
            || !matches!(self.data.endpoint, Endpoint::SecureClient(_))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP client protection requires a Common UDP client",
            ));
        }
        self.identity = Arc::new(());
        self.udp_socket_protector = Some(Arc::new(move |socket| Box::pin(protect(socket))));
        Ok(self)
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
    /// Explicit mixed-profile client using the existing authenticated UDP factory.
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
                outer: Arc::new(outer),
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
    /// Fixed or measured proxy through the same genuine TLS/QUIC Common owner.
    #[cfg(unix)]
    pub fn proxy_common_maintained_client(
        profile: crate::secure_udp::common_transaction_profile::Profile,
        outer: crate::secure_udp::maintained::Client,
        inner: crate::secure_udp::credentials::Client,
        attachment: Attachment,
    ) -> io::Result<Self> {
        Self::new(
            profile.connection(),
            Endpoint::CommonMaintainedClient { outer, inner },
            attachment,
            Transport::ProxyCommonMaintained(Arc::new(profile)),
        )
    }
    /// Matching deferred acceptor with independent own TLS and Noise identities.
    #[cfg(unix)]
    pub fn proxy_common_maintained_server(
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
            Transport::ProxyCommonMaintained(Arc::new(profile)),
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
                outer: Arc::new(outer),
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
    pub(super) fn secure_udp_common(&self) -> bool {
        match &self.data.transport {
            #[cfg(unix)]
            Transport::ProxyCommon(_)
            | Transport::ProxyCommonMaintained(_)
            | Transport::ProxyCommonRaw { .. } => false,
            _ => true,
        }
    }
    /// Bound of one accepted setup operation, started at acceptance.
    pub(super) fn setup_timeout(&self) -> Duration {
        self.data.connection.handshake_timeout
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
    fn validate_datagram(
        profile: &crate::secure_udp::common_transaction_profile::Profile,
        endpoint: &Endpoint,
        attachment: &Attachment,
        proxy: bool,
    ) -> io::Result<()> {
        if profile.proxy_config().is_some() != proxy {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Common proxy requires explicit proxy service selection",
            ));
        }
        let session = profile.settings();
        let (noise, role) = match endpoint {
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
            #[cfg(unix)]
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
        Ok(())
    }
    fn new(
        connection: ConnectionConfig,
        endpoint: Endpoint,
        attachment: Attachment,
        transport: Transport,
    ) -> io::Result<Self> {
        match &transport {
            Transport::SecureUdpCommon(profile) => {
                Self::validate_datagram(profile, &endpoint, &attachment, false)?;
            }
            #[cfg(unix)]
            Transport::ProxyCommon(profile) => {
                Self::validate_datagram(profile, &endpoint, &attachment, true)?;
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
            }
            #[cfg(unix)]
            Transport::SecureUdpCommonMaintained(profile)
            | Transport::ProxyCommonMaintained(profile) => {
                use crate::secure_udp::maintained::{
                    Client as OuterClient, Server as OuterServer, Transport as OuterTransport,
                };
                let selected = profile.maintained_settings().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "maintained policy absent")
                })?;
                selected.request(connection)?;
                let proxy = matches!(&transport, Transport::ProxyCommonMaintained(_));
                if profile.maintained_binding().is_some()
                    || (!proxy && !attachment.readable_kind())
                    || proxy != profile.proxy_config().is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "maintained Common requires its explicit unbound native or proxy plan",
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
            }
        };
        // Common profiles validate their complete runtime bounds above. The
        // retired standalone profiler has no field in these selected plans.
        if attachment.layer != connection.layer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment layer differs from the requested connection",
            ));
        }
        Ok(Self {
            identity: Arc::new(()),
            udp_socket_protector: None,
            data: Arc::new(Data {
                connection,
                endpoint,
                attachment,
                transport,
            }),
        })
    }
    pub(super) async fn open_common_native(&self) -> io::Result<crate::native::Native> {
        #[cfg(windows)]
        if let Open::Deferred(open) = &self.data.attachment.open {
            return self.check_native_layer(open().await?);
        }
        self.open_native()
    }
    pub(super) fn open_native(&self) -> io::Result<crate::native::Native> {
        self.check_native_layer(self.data.attachment.open_native()?)
    }
    fn check_native_layer(
        &self,
        device: crate::native::Native,
    ) -> io::Result<crate::native::Native> {
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
pub(super) mod transaction_tests;
