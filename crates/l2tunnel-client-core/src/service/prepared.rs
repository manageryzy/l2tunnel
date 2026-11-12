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
pub(super) struct Data {
    pub connection: ConnectionConfig,
    pub endpoint: Endpoint,
    pub attachment: Attachment,
    pub options: Options,
}
/// Immutable validated managed-TCP plan. Clone retains exact identity. A newly
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
        Self::new(
            connection,
            Endpoint::Client(credentials),
            attachment,
            options,
        )
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
            options,
        )
    }
    fn new(
        connection: ConnectionConfig,
        endpoint: Endpoint,
        attachment: Attachment,
        options: Options,
    ) -> io::Result<Self> {
        match options.delivery {
            Some(delivery) => {
                connection.session_with_delivery(delivery)?;
            }
            None => {
                connection.session()?;
            }
        }
        if attachment.layer != connection.layer
            || options
                .profile_interval
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
                options,
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
