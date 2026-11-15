//! Actual member acceptance while retaining selected managed initial authority.
//!
//! Only the real protected proof/acceptance path can construct this handoff. The
//! copied Info remains observation; it never upgrades a legacy root or a caller flag.

use super::*;
use l2tunnel_handshake as hs;

/// Opaque actual member-authenticated selected initial custody.
pub struct Authenticated(Parts);
impl Authenticated {
    /// Observe the actual accepted member, pins, session and original endpoints.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Transfer the original socket, tails and consume-once managed initial proof.
    pub fn into_parts(self) -> Parts {
        self.0
    }
}

/// Selected same-socket handoff after real managed Joining owners have retired.
/// There is no public constructor or conversion from the legacy Parts/Info.
pub struct Parts {
    /// Exact originally supplied connected socket.
    pub socket: UdpSocket,
    /// Actual selected Noise proof after exact managed Joining owner retirement.
    pub initial: hs::refresh::ConfirmedInitial,
    /// Original local appearance selection.
    pub cover: cover::Config,
    /// Original retained bootstrap/final-confirmation service.
    pub bootstrap: establish::BootstrapTail,
    /// Exact cached acceptance bytes, with no remaining Joining key owner.
    pub joining: JoiningTail,
    /// Original shared appearance counter, never restarted at this handoff.
    pub next_outer: u32,
    /// Original absolute setup/member cap, never renewed.
    pub deadline: Instant,
    /// Observations produced by the actual member admission path.
    pub info: Info,
    origin: Instant,
}
impl Parts {
    /// Original Noise clock origin for installing and servicing selected Records.
    pub fn clock_origin(&self) -> Instant {
        self.origin
    }
}

impl MemberState {
    fn into_managed(self) -> io::Result<Authenticated> {
        let establish::InitialMaterial::Managed(initial) = self.material else {
            return Err(invalid(
                "legacy member custody is not selected initial authority",
            ));
        };
        Ok(Authenticated(Parts {
            socket: self.socket.into_udp()?,
            initial,
            cover: self.cover,
            bootstrap: self.bootstrap,
            joining: self.joining,
            next_outer: self.next_outer,
            deadline: self.deadline,
            info: self.info,
            origin: self.origin,
        }))
    }
}

/// Prove existing membership over the actual managed selected Joining pair.
pub async fn connect(
    established: establish::refresh::Established,
    member: &identity::IdentityKey,
    settings: Settings,
) -> io::Result<Authenticated> {
    connect_observed(established, member, settings, &mut |_| {}).await
}

/// Prove membership with the same bounded setup observations as the legacy path.
pub async fn connect_observed(
    established: establish::refresh::Established,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    drive_observed(
        established.into_state(),
        Local::Client(member),
        settings,
        observe,
    )
    .await?
    .into_managed()
}

/// Accept only the existing verifier's real protected allowlisted member proof.
pub async fn accept(
    established: establish::refresh::Established,
    members: identity::Allowlist,
    settings: Settings,
) -> io::Result<Authenticated> {
    accept_observed(established, members, settings, &mut |_| {}).await
}

/// Verify membership with typed observations and the original socket/deadline.
pub async fn accept_observed(
    established: establish::refresh::Established,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    drive_observed(
        established.into_state(),
        Local::Server(members),
        settings,
        observe,
    )
    .await?
    .into_managed()
}
