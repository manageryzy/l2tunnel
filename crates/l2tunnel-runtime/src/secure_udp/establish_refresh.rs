//! Explicit selected initial Noise authority on the existing admission/socket loop.
//!
//! Completion here is not member acceptance. Only the selected member owner can
//! consume this value; there is no conversion from public status or a legacy root.

use super::*;

/// Actual selected Noise completion, still held behind the member gate.
pub struct Established(pub(super) EstablishedState);
impl Established {
    /// Actual confirmed session/transcript, copied only for member-context input.
    pub fn binding(&self) -> security::SessionBinding {
        self.0.binding
    }
    /// Actual authenticated initial prologue; this observation is not authority.
    pub fn authenticated(&self) -> hs::Binding {
        self.0.authenticated
    }
    /// Actual pinned peers in global order.
    pub fn peers(&self) -> Peers {
        self.0.peers
    }
    /// Actual original appearance selection.
    pub fn cover(&self) -> cover::Config {
        self.0.cover
    }
    /// Original absolute setup/member deadline, without renewal.
    pub fn deadline(&self) -> Instant {
        self.0.deadline
    }
    /// Retained Noise time origin, also used by managed Joining and later Records.
    pub fn clock_origin(&self) -> Instant {
        self.0.origin
    }
    /// Current bootstrap observations, not member readiness.
    pub fn statistics(&self) -> Statistics {
        self.0.tail.statistics()
    }
    /// Actual original local socket endpoint.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.socket.local_addr()
    }
    /// Actual original peer socket endpoint.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.socket.peer_addr()
    }
    pub(in crate::secure_udp) fn into_state(self) -> EstablishedState {
        self.0
    }
}

/// Retained cookie/quarantine owner with one explicitly selected initial prologue.
pub struct ServerAdmission {
    inner: super::ServerAdmission,
    selection: hs::refresh::Selection,
}
impl ServerAdmission {
    /// Bind the actual original path, credentials and checked refresh selection.
    pub fn new(
        config: Config,
        selection: hs::refresh::Selection,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: super::ServerAdmission::new(config, peers, admission, cookie, origin)?,
            selection,
        })
    }
    /// Current cumulative cookie/quarantine observations.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.inner.statistics()
    }
    /// Original local cover/bootstrap settings.
    pub fn config(&self) -> Config {
        self.inner.config()
    }
    /// Checked selection authenticated by the actual selected Noise exchange.
    pub fn selection(&self) -> hs::refresh::Selection {
        self.selection
    }
}

/// Establish selected initial authority using the sole original socket owner.
pub async fn connect(
    socket: UdpSocket,
    config: Config,
    selection: hs::refresh::Selection,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
) -> Result<Established, Error> {
    connect_observed(
        socket,
        config,
        selection,
        identity,
        admission,
        deadline,
        entropy,
        &mut |_| {},
    )
    .await
}

/// Establish with the same fixed-size observations as the legacy path.
#[allow(clippy::too_many_arguments)] // Explicit selection and the existing setup/observer inputs.
pub async fn connect_observed(
    socket: UdpSocket,
    config: Config,
    selection: hs::refresh::Selection,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> Result<Established, Error> {
    let mut report = Reporter::new(observe);
    let result = Box::pin(super::connect_inner(
        SocketBacking::Udp(socket),
        config,
        identity,
        admission,
        deadline,
        entropy,
        &mut report,
        Some(selection),
    ))
    .await;
    if let Err(error) = &result {
        report.fail(diagnostics::establishment_reason(error));
    }
    result.map(Established)
}

/// Accept selected initial authority while retaining the actual admission owner.
pub async fn accept(
    socket: UdpSocket,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
) -> Result<Established, Error> {
    accept_observed(socket, identity, admission, deadline, entropy, &mut |_| {}).await
}

/// Accept with actual bounded observations and unchanged cookie/quarantine custody.
pub async fn accept_observed(
    socket: UdpSocket,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> Result<Established, Error> {
    let mut report = Reporter::new(observe);
    report.server(admission.statistics());
    let result = Box::pin(super::accept_inner(
        SocketBacking::Udp(socket),
        identity,
        &mut admission.inner,
        deadline,
        entropy,
        &mut report,
        Some(admission.selection),
    ))
    .await;
    report.server(admission.statistics());
    if let Err(error) = &result {
        report.fail(diagnostics::establishment_reason(error));
    }
    result.map(Established)
}
