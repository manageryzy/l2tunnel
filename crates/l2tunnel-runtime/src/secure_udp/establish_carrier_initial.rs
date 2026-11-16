//! Explicit initial-only Noise authority over the actual authenticated outer owner.
use super::*;

impl Outer {
    /// Consume the real outer owner into the existing initial-only Noise loop.
    /// No later refresh capability or fresh-key age timer is selected.
    pub async fn connect_initial(
        self,
        config: Config,
        identity: Identity,
        admission: gate::Secret,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<InitialEstablished, Error> {
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

    /// Server counterpart using the same cookie, quarantine and Noise state machine.
    pub async fn accept_initial(
        self,
        identity: Identity,
        admission: &mut InitialServerAdmission,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<InitialEstablished, Error> {
        self.validate(admission.inner.config(), hs::Role::Responder)?;
        if admission.outer != self.proof.binding {
            return Err(Error::Configuration(
                "retained initial admission belongs to another outer proof",
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

/// Retained actual initial-only cookie/quarantine authority for one outer session.
/// It has no refresh selection and cannot be passed to the managed entry point.
pub struct InitialServerAdmission {
    inner: super::super::ServerAdmission,
    outer: [u8; 32],
}
impl InitialServerAdmission {
    /// Bind the existing admission owner to verified TLS and exact extra-opcode geometry.
    pub fn new(
        outer: &Outer,
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        outer.validate(config, hs::Role::Responder)?;
        Ok(Self {
            inner: super::super::ServerAdmission::with_extra(
                config, peers, admission, cookie, origin, 1,
            )?,
            outer: outer.proof.binding,
        })
    }
    /// Actual retained admission observations, including refused inner attempts.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.inner.statistics()
    }
    /// Actual complete effective settings retained by this owner.
    pub fn config(&self) -> Config {
        self.inner.config()
    }
}

/// Actual initial-only Noise completion; membership is still a separate gate.
/// There is no public constructor or conversion from the managed initial proof.
pub struct InitialEstablished {
    state: EstablishedState,
    outer: AuthenticatedOuter,
}
impl InitialEstablished {
    /// Actual confirmed Noise session and transcript.
    pub fn binding(&self) -> security::SessionBinding {
        self.state.binding
    }
    /// Actual authenticated prologue, including verified outer binding.
    pub fn authenticated(&self) -> hs::Binding {
        self.state.authenticated
    }
    /// Actual original pinned keys in global order.
    pub fn peers(&self) -> Peers {
        self.state.peers
    }
    /// Verified outer proof and immutable pre-TLS policy.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.outer
    }
    /// Original selected complementary cover.
    pub fn cover(&self) -> cover::Config {
        self.state.cover
    }
    /// Original shared outer/admission/Noise/member cap.
    pub fn deadline(&self) -> Instant {
        self.state.deadline
    }
    /// Actual confirmed Noise origin retained for the runtime consumer.
    pub fn clock_origin(&self) -> Instant {
        self.state.origin
    }
    /// Actual bootstrap observations, never member authority.
    pub fn statistics(&self) -> Statistics {
        self.state.tail.statistics()
    }
    pub(in crate::secure_udp) fn into_state(self) -> (EstablishedState, AuthenticatedOuter) {
        (self.state, self.outer)
    }
}

/// Complete real TLS/member outer setup followed by initial-only cookie/Noise.
/// Effective settings are built from the genuine post-TLS proof, without refresh.
#[allow(clippy::too_many_arguments)]
pub async fn connect_initial(
    socket: UdpSocket,
    outer: openvpn::Config,
    credentials: wire_carrier::ClientCredentials<'_>,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    build: impl FnOnce(&AuthenticatedOuter) -> Result<Config, Error>,
    observe: &mut diagnostics::Observer<'_>,
) -> Result<InitialEstablished, Error> {
    let outer = Outer::client(socket, outer, credentials, deadline).await?;
    let config = build(&outer.authenticated())?;
    outer
        .connect_initial(config, identity, admission, entropy, observe)
        .await
}
