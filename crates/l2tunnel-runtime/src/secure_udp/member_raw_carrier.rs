//! Actual original raw owner through the existing protected member Joining gate.
use super::*;
use crate::secure_udp::raw_carrier_io::{RawAdapter, RawBacking};
use establish::raw_carrier::{AuthenticatedRaw, RawInitialEstablished};
use l2tunnel_raw_io::PacketIo;

/// Genuine member acceptance; no public metadata can construct this handoff.
pub struct RawInitialAuthenticated<I: PacketIo + Send + 'static>(RawInitialParts<I>);
impl<I: PacketIo + Send + 'static> RawInitialAuthenticated<I> {
    /// Actual member-gated observations.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Actual original raw outer proof.
    pub fn outer(&self) -> AuthenticatedRaw {
        self.0.outer
    }
    /// Transfer the same original owners, without exposing a root conversion.
    pub fn into_parts(self) -> RawInitialParts<I> {
        self.0
    }
}
/// Move-only complete original owner/root/tail handoff into one Common Driver.
pub struct RawInitialParts<I: PacketIo + Send + 'static> {
    pub(in crate::secure_udp) io: RawAdapter<I>,
    pub(in crate::secure_udp) root: security::SessionRoot,
    pub(in crate::secure_udp) cover: cover::Config,
    pub(in crate::secure_udp) bootstrap: establish::BootstrapTail,
    pub(in crate::secure_udp) joining: JoiningTail,
    pub(in crate::secure_udp) next_outer: u32,
    pub(in crate::secure_udp) deadline: Instant,
    pub(in crate::secure_udp) info: Info,
    outer: AuthenticatedRaw,
    origin: Instant,
}
impl<I: PacketIo + Send + 'static> RawInitialParts<I> {
    /// Actual member-gated observations, not a constructor.
    pub fn info(&self) -> Info {
        self.info
    }
    /// Genuine original outer proof retained beside the actual owner.
    pub fn outer(&self) -> AuthenticatedRaw {
        self.outer
    }
    /// Exact original cap shared by outer, Noise and member phases.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Actual retained Noise origin; no periodic exchange timer is installed.
    pub fn clock_origin(&self) -> Instant {
        self.origin
    }
}
impl<I: PacketIo + Send + 'static> MemberState<RawAdapter<I>> {
    fn into_initial_raw(self, outer: AuthenticatedRaw) -> io::Result<RawInitialAuthenticated<I>> {
        before(Instant::now(), self.deadline)?;
        let establish::InitialMaterial::Legacy(root) = self.material else {
            return Err(invalid(
                "managed authority cannot become initial-only raw authority",
            ));
        };
        if self.info.member != outer.info().member
            || self.deadline != outer.deadline()
            || self.info.role
                != match outer.role() {
                    l2tunnel_handshake::Role::Initiator => security::Role::Initiator,
                    l2tunnel_handshake::Role::Responder => security::Role::Responder,
                }
        {
            return Err(denied(
                "inner member/role/original cap differs from genuine raw outer",
            ));
        }
        let io = self.socket.into_raw()?;
        let expected =
            outer.lane_endpoints()[0].ok_or_else(|| invalid("raw first tuple absent"))?;
        let expected = if outer.role() == l2tunnel_handshake::Role::Initiator {
            expected
        } else {
            (expected.1, expected.0)
        };
        if io.addresses() != expected || io.geometry() != outer.geometry() {
            return Err(denied("actual raw owner differs at member handoff"));
        }
        Ok(RawInitialAuthenticated(RawInitialParts {
            io,
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
/// Real local member proof and actual protected server acceptance on original raw I/O.
pub async fn connect_initial<I: PacketIo + Send + 'static>(
    established: RawInitialEstablished<I>,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<RawInitialAuthenticated<I>> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Client(member), settings, observe)
        .await?
        .into_initial_raw(outer)
}
/// Real allowlisted member verification through the same existing Joining state machine.
pub async fn accept_initial<I: PacketIo + Send + 'static>(
    established: RawInitialEstablished<I>,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<RawInitialAuthenticated<I>> {
    let (state, outer) = established.into_state();
    drive_observed(state, Local::Server(members), settings, observe)
        .await?
        .into_initial_raw(outer)
}
