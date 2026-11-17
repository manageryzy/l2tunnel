//! Initial-only Noise over actual retained TLS or genuine QUIC ownership.
//! Configured maintained-carrier charges are admission allowances, not observed
//! physical packet sizes. The existing cookie/quarantine/Noise state machine and
//! original establishment cap remain the only initial protocol owner.
use super::*;
use crate::secure_udp::{maintained, maintained_io};

fn allowance(config: Config, request: maintained::Request) -> Result<usize, Error> {
    request.validate()?;
    let geometry = request.geometry;
    let ip_udp = if config.gate.path.client.is_ipv4() {
        28
    } else {
        48
    };
    if config.gate.path_mtu != geometry.path_mtu || geometry.bootstrap_overhead_bytes < ip_udp {
        return Err(Error::Configuration(
            "maintained bootstrap admission geometry",
        ));
    }
    Ok(geometry.bootstrap_overhead_bytes)
}
/// Pure preflight of the complete existing setup geometry under explicit charges.
/// No carrier proof, connection, key or admission authority is constructed here.
pub fn validate_requested(
    config: Config,
    peers: Peers,
    request: maintained::Request,
) -> Result<(), Error> {
    // The legacy helper validates the same complete byte budget. Its numeric
    // overhead is an explicit admission allowance for maintained transports.
    requested_setup(config, peers, request)?;
    Ok(())
}
fn requested_setup(
    config: Config,
    peers: Peers,
    request: maintained::Request,
) -> Result<Setup, Error> {
    let setup = setup_with_physical_overhead(config, peers, allowance(config, request)?)?;
    let gate_bytes = gate::GATE_BYTES
        .checked_add(1)
        .ok_or(Error::Configuration("maintained gate size"))?;
    let gate_bytes = gate_bytes
        .checked_add(config.cover.overhead(cover::Phase::Handshake, gate_bytes)?)
        .ok_or(Error::Configuration("maintained covered gate size"))?;
    let joining_bytes =
        crate::secure_udp::member::maintained::maximum_bootstrap_bytes(config.cover)?;
    if setup.max_wire.max(gate_bytes).max(joining_bytes) > request.geometry.max_bootstrap_bytes {
        return Err(Error::Configuration(
            "actual maintained setup exceeds bootstrap maximum",
        ));
    }
    Ok(setup)
}
fn validate_shape(
    proof: maintained::Authenticated,
    config: Config,
    expected: hs::Role,
) -> Result<(), Error> {
    let info = proof.info()?;
    let (client, server) = proof.endpoints()?;
    let actual = if info.peer_member.is_none() {
        hs::Role::Initiator
    } else {
        hs::Role::Responder
    };
    if actual != expected
        || config.binding.outer != proof.binding()
        || config.gate.path.client != client
        || config.gate.path.server != server
    {
        return Err(Error::Configuration(
            "maintained original role/path/authentication binding",
        ));
    }
    allowance(config, proof.requested())?;
    Ok(())
}
impl maintained::Authenticated {
    /// Expected existing Noise prologue from the actual completed outer proof.
    /// This pure consistency result cannot create or replace a handshake owner.
    pub fn expected_binding(
        self,
        config: Config,
        peers: Peers,
        session: hs::SessionId,
    ) -> Result<hs::Binding, Error> {
        let role = if self.info()?.peer_member.is_none() {
            hs::Role::Initiator
        } else {
            hs::Role::Responder
        };
        validate_shape(self, config, role)?;
        session_binding(requested_setup(config, peers, self.requested())?, session.0)
    }
}

/// Actual original maintained transport after TLS/member proof and before Noise.
pub struct Outer {
    carrier: maintained_io::Carrier,
    proof: maintained::Authenticated,
}
impl Outer {
    /// Consume the actual authenticated retained owner, with its unchanged cap.
    pub fn from_carrier(carrier: maintained_io::Carrier) -> Result<Self, Error> {
        carrier.check_failure()?;
        let proof = carrier.authenticated();
        before(Instant::now(), proof.deadline())?;
        if carrier.setup_deadline() != proof.deadline()
            || carrier.geometry() != proof.requested().geometry
            || carrier.final_records()
        {
            return Err(Error::Configuration(
                "maintained original setup owner differs",
            ));
        }
        Ok(Self { carrier, proof })
    }
    /// Actual verified outer observations and immutable requested policy.
    pub fn authenticated(&self) -> maintained::Authenticated {
        self.proof
    }
    fn validate(&self, config: Config, role: hs::Role) -> Result<(), Error> {
        self.carrier.check_failure()?;
        before(Instant::now(), self.proof.deadline())?;
        validate_shape(self.proof, config, role)
    }
    /// Run the existing initial-only cookie/Noise loop on this same retained owner.
    pub async fn connect_initial(
        self,
        config: Config,
        identity: Identity,
        admission: gate::Secret,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<InitialEstablished, Error> {
        self.validate(config, hs::Role::Initiator)?;
        validate_requested(
            config,
            Peers {
                initiator: identity.local.public_key(),
                responder: identity.peer,
            },
            self.proof.requested(),
        )?;
        let mut report = Reporter::new(observe);
        let result = Box::pin(connect_inner(
            SocketBacking::<NoRaw>::Maintained(self.carrier),
            config,
            identity,
            admission,
            self.proof.deadline(),
            entropy,
            &mut report,
            None,
        ))
        .await;
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| InitialEstablished {
            state,
            outer: self.proof,
        })
    }
    /// Server counterpart retaining the same original admission/quarantine owner.
    pub async fn accept_initial(
        self,
        identity: Identity,
        admission: &mut InitialServerAdmission,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<InitialEstablished, Error> {
        self.validate(admission.inner.config(), hs::Role::Responder)?;
        if admission.outer != self.proof.binding() {
            return Err(Error::Configuration(
                "maintained admission belongs to another original owner",
            ));
        }
        let mut report = Reporter::new(observe);
        report.server(admission.inner.statistics());
        let result = Box::pin(accept_inner(
            SocketBacking::<NoRaw>::Maintained(self.carrier),
            identity,
            &mut admission.inner,
            self.proof.deadline(),
            entropy,
            &mut report,
            None,
        ))
        .await;
        report.server(admission.inner.statistics());
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| InitialEstablished {
            state,
            outer: self.proof,
        })
    }
}

/// Original retained cookie/quarantine owner bound to one genuine maintained proof.
pub struct InitialServerAdmission {
    inner: super::ServerAdmission,
    outer: [u8; 32],
}
impl InitialServerAdmission {
    /// Bind existing finite admission to the exact actual original outer geometry.
    pub fn new(
        outer: &Outer,
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        outer.validate(config, hs::Role::Responder)?;
        validate_requested(config, peers, outer.proof.requested())?;
        Ok(Self {
            inner: super::ServerAdmission::with_physical_overhead(
                config,
                peers,
                admission,
                cookie,
                origin,
                allowance(config, outer.proof.requested())?,
            )?,
            outer: outer.proof.binding(),
        })
    }
    /// Actual retained admission observations, including refused attempts.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.inner.statistics()
    }
    /// Exact complete effective setup retained by this owner.
    pub fn config(&self) -> Config {
        self.inner.config()
    }
}

/// Actual initial-only Noise completion; the inner member gate remains required.
pub struct InitialEstablished {
    state: EstablishedState,
    outer: maintained::Authenticated,
}
impl InitialEstablished {
    /// Actual confirmed Noise session and transcript binding.
    pub fn binding(&self) -> security::SessionBinding {
        self.state.binding
    }
    /// Actual authenticated prologue, including the genuine outer proof.
    pub fn authenticated(&self) -> hs::Binding {
        self.state.authenticated
    }
    /// Actual pinned keys in global order.
    pub fn peers(&self) -> Peers {
        self.state.peers
    }
    /// Genuine completed maintained-transport proof.
    pub fn outer(&self) -> maintained::Authenticated {
        self.outer
    }
    /// Original selected complementary cover.
    pub fn cover(&self) -> cover::Config {
        self.state.cover
    }
    /// Original overall outer/admission/Noise/member cap.
    pub fn deadline(&self) -> Instant {
        self.state.deadline
    }
    /// Original Noise clock origin retained for the runtime consumer.
    pub fn clock_origin(&self) -> Instant {
        self.state.origin
    }
    /// Actual bootstrap observations, not inner member authority.
    pub fn statistics(&self) -> Statistics {
        self.state.tail.statistics()
    }
    pub(in crate::secure_udp) fn into_state(self) -> (EstablishedState, maintained::Authenticated) {
        (self.state, self.outer)
    }
}
