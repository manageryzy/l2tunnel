//! Actual initial-only member acceptance over the same maintained outer owner.
use super::*;
use crate::secure_udp::{maintained, maintained_io};

pub(in crate::secure_udp) fn maximum_bootstrap_bytes(cover: cover::Config) -> io::Result<usize> {
    [PROOF_WIRE, ACCEPT_WIRE]
        .into_iter()
        .map(|body| {
            body.checked_add(
                cover
                    .overhead(cover::Phase::Established, body)
                    .map_err(cover_error)?,
            )
            .ok_or_else(|| invalid("maintained Joining covered size overflow"))
        })
        .try_fold(0, |maximum, bytes| Ok(maximum.max(bytes?)))
}

/// Genuine member-gated root custody; public observations cannot construct it.
pub struct InitialAuthenticated(InitialParts);
impl InitialAuthenticated {
    /// Actual member identity, original pins and First-lane endpoints.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Genuine original maintained proof and exact requested policy.
    pub fn outer(&self) -> maintained::Authenticated {
        self.0.outer
    }
    /// Consume all original connection, root and bootstrap-tail custody once.
    pub fn into_parts(self) -> InitialParts {
        self.0
    }
}
/// Initial-only Common handoff; this does not introduce fresh-DH refresh timers.
pub struct InitialParts {
    /// Actual original maintained TLS/QUIC owner, including both Half lanes.
    pub carrier: maintained_io::Carrier,
    /// Actual Noise root after member Joining consumed its protected domains.
    pub root: security::SessionRoot,
    /// Original selected complementary bootstrap cover.
    pub cover: cover::Config,
    /// Exact retained bounded Noise confirmation service.
    pub bootstrap: establish::BootstrapTail,
    /// Exact cached member acceptance, without retained Joining keys.
    pub joining: JoiningTail,
    /// Original shared appearance counter, never reset at handoff.
    pub next_outer: u32,
    /// Original overall TLS/QUIC/admission/Noise/member cap.
    pub deadline: Instant,
    /// Actual authenticated inner member and session observations.
    pub info: Info,
    outer: maintained::Authenticated,
    origin: Instant,
}
impl InitialParts {
    /// Actual original Noise clock origin, not a renewed lifetime.
    pub fn clock_origin(&self) -> Instant {
        self.origin
    }
    /// Genuine original maintained proof and immutable requested policy.
    pub fn outer(&self) -> maintained::Authenticated {
        self.outer
    }
}
impl MemberState {
    fn into_initial_maintained(
        self,
        outer: maintained::Authenticated,
    ) -> io::Result<InitialAuthenticated> {
        before(Instant::now(), self.deadline)?;
        let establish::InitialMaterial::Legacy(root) = self.material else {
            return Err(invalid(
                "managed initial cannot become initial-only maintained authority",
            ));
        };
        if self.info.member != outer.info()?.member || self.deadline != outer.deadline() {
            return Err(denied(
                "inner member or original cap differs from actual maintained proof",
            ));
        }
        let carrier = self.socket.into_maintained()?;
        if carrier.authenticated() != outer {
            return Err(denied(
                "maintained handoff owner differs from actual original proof",
            ));
        }
        Ok(InitialAuthenticated(InitialParts {
            carrier,
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
/// Prove the original member through the existing protected Joining state machine.
pub async fn connect_initial(
    established: establish::maintained::InitialEstablished,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<InitialAuthenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Client(member), settings, observe)
        .await?
        .into_initial_maintained(outer)
}
/// Accept only an actual allowlisted proof and retain the same original owners.
pub async fn accept_initial(
    established: establish::maintained::InitialEstablished,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<InitialAuthenticated> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Server(members), settings, observe)
        .await?
        .into_initial_maintained(outer)
}
