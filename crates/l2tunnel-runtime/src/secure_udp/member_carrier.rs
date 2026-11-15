//! Actual protected member gate over the original authenticated carrier owner.
use super::*;
use establish::carrier::AuthenticatedOuter;
use l2tunnel_handshake as hs;

/// Actual accepted membership and selected initial custody, with no public constructor.
pub struct Authenticated(Parts);
impl Authenticated {
    /// Real accepted identities, pins and original endpoints.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Genuine completed outer proof and immutable requested policy.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.0.outer
    }
    /// Move all original carrier/Noise/tail custody to its sole runtime consumer.
    pub fn into_parts(self) -> Parts {
        self.0
    }
}

/// Opaque selected same-carrier handoff after real managed Joining has retired.
/// Outer TLS remains alive; user records continue to use the selected common security.
pub struct Parts {
    /// Exact original carrier/socket/TLS actor owner; no proxy or replacement socket.
    pub datagram: crate::secure_udp::original_datagram::OriginalDatagram,
    /// Actual member-gated selected Noise proof, consumed only by its Records owner.
    pub initial: hs::refresh::ConfirmedInitial,
    /// Original complementary inner cover selection.
    pub cover: cover::Config,
    /// Original bounded bootstrap confirmation service.
    pub bootstrap: establish::BootstrapTail,
    /// Exact cached acceptance bytes, with no remaining Joining keys.
    pub joining: JoiningTail,
    /// Original shared appearance counter, never restarted at this handoff.
    pub next_outer: u32,
    /// Original absolute outer/admission/Noise/member cap, never renewed.
    pub deadline: Instant,
    /// Actual authenticated inner observations.
    pub info: Info,
    outer: AuthenticatedOuter,
    origin: Instant,
}
impl Parts {
    /// Retained actual Noise clock origin for selected Records and refresh.
    pub fn clock_origin(&self) -> Instant {
        self.origin
    }
    /// Genuine outer proof with its immutable requested policy and effective binding.
    pub fn outer(&self) -> AuthenticatedOuter {
        self.outer
    }
}
impl MemberState {
    fn into_carrier(self, outer: AuthenticatedOuter) -> io::Result<Authenticated> {
        before(Instant::now(), self.deadline)?;
        let establish::InitialMaterial::Managed(initial) = self.material else {
            return Err(invalid(
                "legacy root cannot become selected carrier authority",
            ));
        };
        if self.info.member != outer.info().member || self.deadline != outer.deadline() {
            return Err(denied(
                "inner member or original cap differs from actual outer proof",
            ));
        }
        Ok(Authenticated(Parts {
            datagram: self.socket.into_carrier()?,
            initial,
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
/// Prove actual membership through the existing protected managed Joining owner.
pub async fn connect(
    established: establish::carrier::Established,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Client(member), settings, observe)
        .await?
        .into_carrier(outer)
}
/// Accept only the actual protected allowlisted proof, retaining the same carrier.
pub async fn accept(
    established: establish::carrier::Established,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Server(members), settings, observe)
        .await?
        .into_carrier(outer)
}

#[cfg(test)]
#[path = "member_carrier_tests.rs"]
mod tests;
