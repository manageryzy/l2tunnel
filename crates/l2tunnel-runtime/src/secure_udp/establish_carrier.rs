//! Real outer TLS/member custody followed by the existing admission/Noise loop.
//!
//! The outer proof is observed only after verified TLS completes. Its fresh
//! session binding belongs in the effective inner configuration; the immutable
//! requested outer policy remains separately available. No exporter data keys,
//! second socket, caller-created Parts or alternate handshake FSM are introduced.

use super::*;
use crate::secure_udp::original_datagram::OriginalDatagram;
use l2tunnel_openvpn::wire_carrier::{self, common as openvpn};

#[path = "establish_carrier_initial.rs"]
mod initial;
pub use initial::{InitialEstablished, InitialServerAdmission, connect_initial};

/// Genuine completed outer proof and its immutable requested policy.
/// Copied observations never construct socket or Noise authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedOuter {
    info: l2tunnel_auth::SessionInfo,
    requested: openvpn::Config,
    client: SocketAddr,
    server: SocketAddr,
    binding: [u8; 32],
    deadline: Instant,
}
impl AuthenticatedOuter {
    /// Actual verified TLS/member identities, configuration and fresh session ID.
    pub fn info(self) -> l2tunnel_auth::SessionInfo {
        self.info
    }
    /// Immutable policy supplied before TLS; it does not depend on its fresh proof.
    pub fn requested(self) -> openvpn::Config {
        self.requested
    }
    /// Actual original endpoints in global client/server order.
    pub fn endpoints(self) -> (SocketAddr, SocketAddr) {
        (self.client, self.server)
    }
    /// Required effective Config.binding.outer, including actual TLS proof and policy.
    pub fn binding(self) -> [u8; 32] {
        self.binding
    }
    /// Original accepted cap, additionally bounded by the actual outer lifetime.
    pub fn deadline(self) -> Instant {
        self.deadline
    }
    /// Derive the expected existing Noise prologue with this actual outer proof.
    /// This is a pure consistency check, never replacement handshake authority.
    pub fn expected_binding(
        self,
        config: Config,
        peers: Peers,
        session: hs::SessionId,
    ) -> Result<hs::Binding, Error> {
        if config.binding.outer != self.binding
            || config.gate.path.client != self.client
            || config.gate.path.server != self.server
            || config.gate.path_mtu != self.requested.path_mtu
        {
            return Err(Error::Configuration(
                "effective configuration differs from actual outer proof",
            ));
        }
        session_binding(setup_with_extra(config, peers, 1)?, session.0)
    }
}

/// Sole original carrier owner after actual outer authentication, before Noise.
pub struct Outer {
    socket: OriginalDatagram,
    proof: AuthenticatedOuter,
    role: hs::Role,
}
impl Outer {
    /// Run actual OpenVPN control/TLS/member authentication on this connected socket.
    pub async fn client(
        socket: UdpSocket,
        config: openvpn::Config,
        credentials: wire_carrier::ClientCredentials<'_>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        before(Instant::now(), deadline)?;
        let carrier = openvpn::client_connect_until(socket, config, credentials, deadline)
            .await
            .map_err(outer_error)?;
        Self::new(carrier, config, hs::Role::Initiator, deadline)
    }
    /// Server counterpart retaining the same actual socket, TLS owner and accepted cap.
    pub async fn server(
        socket: UdpSocket,
        config: openvpn::Config,
        credentials: wire_carrier::ServerCredentials<'_>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        before(Instant::now(), deadline)?;
        let carrier = openvpn::server_accept_until(socket, config, credentials, deadline)
            .await
            .map_err(outer_error)?;
        Self::new(carrier, config, hs::Role::Responder, deadline)
    }
    fn new(
        carrier: openvpn::Carrier,
        requested: openvpn::Config,
        role: hs::Role,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let deadline = deadline.min(carrier.expires());
        before(Instant::now(), deadline)?;
        let info = *carrier.outer_info();
        if info.config != requested.session_config().map_err(outer_error)?
            || match role {
                hs::Role::Initiator => info.peer_member.is_some(),
                hs::Role::Responder => info.peer_member != Some(info.member),
            }
        {
            return Err(Error::Configuration("actual outer TLS/member policy"));
        }
        let (local, peer) = carrier.addresses();
        let (client, server) = if role == hs::Role::Initiator {
            (local, peer)
        } else {
            (peer, local)
        };
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/openvpn-common/actual-outer/v1\0");
        hash.update(&info.session_id);
        hash.update(&info.member.0);
        hash.update(&info.server.0);
        hash.update(&info.config.digest.0);
        hash.update(&[match info.config.layer {
            l2tunnel_device::PacketLayer::Ethernet => 1,
            l2tunnel_device::PacketLayer::Ip => 2,
        }]);
        for endpoint in [client, server] {
            bind_endpoint(&mut hash, endpoint);
        }
        let mut binding = [0; 32];
        binding.copy_from_slice(hash.finish().as_ref());
        let socket = OriginalDatagram::openvpn(carrier)?;
        before(Instant::now(), deadline)?;
        Ok(Self {
            socket,
            proof: AuthenticatedOuter {
                info,
                requested,
                client,
                server,
                binding,
                deadline,
            },
            role,
        })
    }
    /// Genuine completed proof for deriving the existing effective inner settings.
    pub fn authenticated(&self) -> AuthenticatedOuter {
        self.proof
    }
    fn validate(&self, config: Config, role: hs::Role) -> Result<(), Error> {
        before(Instant::now(), self.proof.deadline)?;
        let geometry = self.socket.geometry();
        if self.role != role
            || config.binding.outer != self.proof.binding
            || config.gate.path.client != self.proof.client
            || config.gate.path.server != self.proof.server
            || config.gate.path_mtu != geometry.path_mtu
            || config.cover.limits().max_packet_bytes > geometry.max_datagram_bytes
            || geometry.extra_wire_bytes != 1
        {
            return Err(Error::Configuration(
                "effective inner binding to actual outer owner/geometry",
            ));
        }
        Ok(())
    }
    /// Consume the actual outer owner into the existing selected admission/Noise loop.
    /// The selected Config must have been derived after TLS using authenticated().
    #[allow(clippy::too_many_arguments)] // Existing explicit selected setup and observation inputs.
    pub async fn connect(
        self,
        config: Config,
        selection: hs::refresh::Selection,
        identity: Identity,
        admission: gate::Secret,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<Established, Error> {
        self.validate(config, hs::Role::Initiator)?;
        let mut report = Reporter::new(observe);
        let result = Box::pin(connect_inner(
            SocketBacking::<NoRaw>::Carrier(self.socket),
            config,
            identity,
            admission,
            self.proof.deadline,
            entropy,
            &mut report,
            Some(selection),
            Tuning::Off,
        ))
        .await;
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| Established {
            state,
            outer: self.proof,
        })
    }
    /// Consume the same outer owner while preserving the caller's quarantine owner.
    pub async fn accept(
        self,
        identity: Identity,
        admission: &mut ServerAdmission,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<Established, Error> {
        self.validate(admission.inner.config(), hs::Role::Responder)?;
        if admission.outer != self.proof.binding {
            return Err(Error::Configuration(
                "retained admission belongs to another outer proof",
            ));
        }
        let mut report = Reporter::new(observe);
        report.server(admission.inner.statistics());
        let result = Box::pin(accept_inner(
            SocketBacking::<NoRaw>::Carrier(self.socket),
            identity,
            &mut admission.inner,
            self.proof.deadline,
            entropy,
            &mut report,
            Some(admission.selection),
            Tuning::Off,
        ))
        .await;
        report.server(admission.inner.statistics());
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| Established {
            state,
            outer: self.proof,
        })
    }
}

/// Retained real cookie/quarantine owner for one authenticated outer session.
pub struct ServerAdmission {
    inner: super::ServerAdmission,
    selection: hs::refresh::Selection,
    outer: [u8; 32],
}
impl ServerAdmission {
    /// Validate effective settings against actual outer custody before creating the gate.
    #[allow(clippy::too_many_arguments)] // Independent keys, selected authority and retained time domain.
    pub fn new(
        outer: &Outer,
        config: Config,
        selection: hs::refresh::Selection,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        outer.validate(config, hs::Role::Responder)?;
        Ok(Self {
            inner: super::ServerAdmission::with_extra(config, peers, admission, cookie, origin, 1)?,
            selection,
            outer: outer.proof.binding,
        })
    }
    /// Actual retained quarantine/admission observations, including failed inner attempts.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.inner.statistics()
    }
    /// Actual effective settings retained by this admission owner.
    pub fn config(&self) -> Config {
        self.inner.config()
    }
}

/// Selected initial Noise completion with the same actual authenticated outer owner.
/// This is not member acceptance and cannot be converted from status or legacy Parts.
pub struct Established {
    state: EstablishedState,
    outer: AuthenticatedOuter,
}
impl Established {
    /// Actual confirmed Noise session and transcript.
    pub fn binding(&self) -> security::SessionBinding {
        self.state.binding
    }
    /// Actual authenticated prologue, including the derived outer binding.
    pub fn authenticated(&self) -> hs::Binding {
        self.state.authenticated
    }
    /// Original pinned keys in global order.
    pub fn peers(&self) -> Peers {
        self.state.peers
    }
    /// Actual outer proof and immutable requested outer policy.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.outer
    }
    /// Original selected local cover.
    pub fn cover(&self) -> cover::Config {
        self.state.cover
    }
    /// Original accepted absolute cap, never restarted by either handshake.
    pub fn deadline(&self) -> Instant {
        self.state.deadline
    }
    /// Actual confirmed Noise time origin retained through member admission.
    pub fn clock_origin(&self) -> Instant {
        self.state.origin
    }
    /// Actual complete bootstrap observations, not readiness authority.
    pub fn statistics(&self) -> Statistics {
        self.state.tail.statistics()
    }
    pub(in crate::secure_udp) fn into_state(self) -> (EstablishedState, AuthenticatedOuter) {
        (self.state, self.outer)
    }
}

/// Complete client outer plus selected inner factory with post-TLS effective binding.
/// The builder receives genuine observations, but only the real handshakes create authority.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    socket: UdpSocket,
    outer: openvpn::Config,
    credentials: wire_carrier::ClientCredentials<'_>,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    build: impl FnOnce(&AuthenticatedOuter) -> Result<(Config, hs::refresh::Selection), Error>,
    observe: &mut diagnostics::Observer<'_>,
) -> Result<Established, Error> {
    let outer = Outer::client(socket, outer, credentials, deadline).await?;
    let (config, selection) = build(&outer.authenticated())?;
    outer
        .connect(config, selection, identity, admission, entropy, observe)
        .await
}

pub(super) fn bind_endpoint(hash: &mut digest::Context, endpoint: SocketAddr) {
    match endpoint {
        SocketAddr::V4(address) => {
            hash.update(&[4]);
            hash.update(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            hash.update(&[6]);
            hash.update(&address.ip().octets());
            hash.update(&address.flowinfo().to_be_bytes());
            hash.update(&address.scope_id().to_be_bytes());
        }
    }
    hash.update(&endpoint.port().to_be_bytes());
}
fn outer_error(error: wire_carrier::Error) -> Error {
    Error::Io(match error {
        wire_carrier::Error::Timeout => io::Error::from(io::ErrorKind::TimedOut),
        wire_carrier::Error::Io(error) => error,
        error => io::Error::other(error),
    })
}
