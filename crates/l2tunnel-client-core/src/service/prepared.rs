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
    open: Arc<dyn Fn() -> io::Result<Device> + Send + Sync>,
}
impl Attachment {
    pub(super) fn open(&self) -> io::Result<Device> {
        (self.open)()
    }
    /// Bind an advertised layer and a fresh-owner factory; does not invoke it.
    pub fn new(
        layer: PacketLayer,
        open: impl Fn() -> io::Result<Device> + Send + Sync + 'static,
    ) -> Self {
        Self {
            layer,
            open: Arc::new(open),
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
    /// Explicit verified name; SNI remains disabled by existing TLS implementation.
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
}
/// Selected setup backend. Each variant names one existing authenticated factory;
/// this is not a carrier preference list and never falls back to another variant.
#[derive(Clone, Copy)]
pub(super) enum Transport {
    Managed(Options),
    UdpFrame {
        settings: crate::udp::Settings,
        delivery: managed::DeliveryConfig,
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
}
impl Prepared {
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
        let profile_interval = match transport {
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
            Transport::UdpFrame { settings, delivery } => {
                // Same exact checks the authenticated factory repeats before I/O.
                let profile = crate::udp::runtime_config(connection, settings)?;
                l2tunnel_runtime::udp::base_session_config(
                    connection.runtime(),
                    profile,
                    delivery,
                )?;
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
