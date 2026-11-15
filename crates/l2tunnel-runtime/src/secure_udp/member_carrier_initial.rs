//! Initial-only membership handoff on the same actual authenticated carrier.
use super::*;

/// Genuine member acceptance plus initial-only root custody, never a status import.
pub struct InitialAuthenticated(InitialParts);
impl InitialAuthenticated {
    /// Actual accepted identity, original pins and socket endpoints.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Genuine verified outer proof and immutable requested policy.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.0.outer
    }
    /// Consume all actual socket, root and tail custody into one runtime owner.
    pub fn into_parts(self) -> InitialParts {
        self.0
    }
}

/// Distinct initial-only authority; managed refresh requires its separate Parts type.
pub struct InitialParts {
    /// Exact original carrier socket and retained TLS actor.
    pub datagram: crate::secure_udp::original_datagram::OriginalDatagram,
    /// Actual initial Noise root after authenticated member Joining consumed its domains.
    pub root: security::SessionRoot,
    /// Original complementary inner cover.
    pub cover: cover::Config,
    /// Original bounded bootstrap confirmation service.
    pub bootstrap: establish::BootstrapTail,
    /// Original cached member acceptance without remaining Joining keys.
    pub joining: JoiningTail,
    /// Shared appearance counter continuing from both actual handshakes.
    pub next_outer: u32,
    /// Original absolute outer/admission/Noise/member cap, never restarted.
    pub deadline: Instant,
    /// Actual member-gated authenticated observations.
    pub info: Info,
    outer: AuthenticatedOuter,
    origin: Instant,
}
impl InitialParts {
    /// Actual retained Noise origin; this initial-only path installs no refresh clock.
    pub fn clock_origin(&self) -> Instant {
        self.origin
    }
    /// Genuine outer proof and immutable requested policy.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.outer
    }
}

impl MemberState {
    fn into_initial_carrier(self, outer: AuthenticatedOuter) -> io::Result<InitialAuthenticated> {
        before(Instant::now(), self.deadline)?;
        let establish::InitialMaterial::Legacy(root) = self.material else {
            return Err(invalid(
                "managed initial cannot become initial-only carrier authority",
            ));
        };
        if self.info.member != outer.info().member || self.deadline != outer.deadline() {
            return Err(denied(
                "inner member or original cap differs from actual outer proof",
            ));
        }
        Ok(InitialAuthenticated(InitialParts {
            datagram: self.socket.into_carrier()?,
            root,
            cover: self.cover,
            bootstrap: self.bootstrap,
            joining: self.joining,
            next_outer: self.next_outer,
            deadline: self.deadline,
            info: self.info,
            outer,
            origin: self.origin,
        }))
    }
}

/// Prove membership through the existing initial-only protected Joining state machine.
pub async fn connect_initial(
    established: establish::carrier::InitialEstablished,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<InitialAuthenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Client(member), settings, observe)
        .await?
        .into_initial_carrier(outer)
}

/// Accept the actual allowlisted initial proof and retain the original carrier/root.
pub async fn accept_initial(
    established: establish::carrier::InitialEstablished,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<InitialAuthenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Server(members), settings, observe)
        .await?
        .into_initial_carrier(outer)
}
