//! Existing-member admission over the established socket and retained bootstrap.
//!
//! Noise completion is not member acceptance. This owner keeps the data root in
//! custody until the required proof/acceptance, with one socket reader and one
//! original operation deadline. Post-handoff Joining tails retain ciphertext only.

use super::{
    diagnostics::{self, Reason, Reporter, Stage},
    establish,
};
use l2tunnel_cover as cover;
use l2tunnel_identity as identity;
use l2tunnel_security as security;
use std::{future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep_until, timeout_at},
};
use zeroize::Zeroizing;

/// Explicit managed initial authority, released only by actual member acceptance.
#[path = "member_refresh.rs"]
pub mod refresh;

const ROUTE: u8 = 3;
const ACCEPT_BYTES: usize = 34;
const PROOF_WIRE: usize = 1 + 26 + identity::MEMBER_PROOF_BYTES;
const ACCEPT_WIRE: usize = 1 + 26 + ACCEPT_BYTES;
const JOINING_LIMITS: security::Limits = security::Limits {
    max_body_bytes: identity::MEMBER_PROOF_BYTES,
    packets_per_key: security::MAX_PACKETS_PER_KEY,
    max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
};

/// Explicit bounded policy; its complete values belong in canonical configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Locally selected member/session/carrier/configuration/pinned-key binding.
    pub context: identity::Context,
    /// Minimum interval between exact protected Joining retries, positive and <=1s.
    pub retry_interval: Duration,
    /// Total emissions per Joining flight, including its first, in 1..=1024.
    pub max_attempts: u32,
    /// Receive-work refill interval, positive and <=1s.
    pub receive_interval: Duration,
    /// Datagram parse/decrypt attempts per refill interval, in 1..=1024.
    pub receive_packets_per_interval: u32,
}

/// Non-secret established identities and actual retained-socket observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    /// Actual authenticated Noise session/transcript binding.
    pub binding: security::SessionBinding,
    /// Exact public prologue authenticated by Noise, including derived outer binding.
    pub authenticated: l2tunnel_handshake::Binding,
    /// Authenticated client Ed25519 membership identity.
    pub member: identity::MemberPublicKey,
    /// Explicit pinned Noise keys in global role order.
    pub peers: establish::Peers,
    /// Actual root direction, checked before member admission.
    pub role: security::Role,
    /// Actual original connected socket local endpoint.
    pub local_addr: SocketAddr,
    /// Actual original connected socket peer endpoint.
    pub peer_addr: SocketAddr,
    /// Bootstrap observations, including service while Joining was pending.
    pub statistics: establish::Statistics,
}

/// Opaque member-authenticated custody, before creation of data/control readers.
pub struct Authenticated(Parts);
impl Authenticated {
    /// Observe only public identities, endpoints and bootstrap counters.
    pub fn info(&self) -> Info {
        self.0.info
    }
    /// Transfer every original owner to the sole established session reader.
    pub fn into_parts(self) -> Parts {
        self.0
    }
}

/// Same-socket handoff; the caller must retain and service both bounded tails.
pub struct Parts {
    /// Exact original connected UDP socket.
    pub socket: UdpSocket,
    /// Original opaque root, with Joining domains already reserved.
    pub root: security::SessionRoot,
    /// Original selected appearance policy.
    pub cover: cover::Config,
    /// Retained bounded Noise/bootstrap final-flight service.
    pub bootstrap: establish::BootstrapTail,
    /// Retained exact protected member-acceptance service, without Joining keys.
    pub joining: JoiningTail,
    /// Continue this counter for bootstrap, Joining, data and control appearance.
    pub next_outer: u32,
    /// Unchanged original admission/Noise/member deadline.
    pub deadline: Instant,
    /// Non-secret authenticated status.
    pub info: Info,
}

struct MemberState {
    socket: UdpSocket,
    material: establish::InitialMaterial,
    cover: cover::Config,
    bootstrap: establish::BootstrapTail,
    joining: JoiningTail,
    next_outer: u32,
    deadline: Instant,
    info: Info,
    origin: Instant,
}
impl MemberState {
    fn into_legacy(self) -> io::Result<Authenticated> {
        let establish::InitialMaterial::Legacy(root) = self.material else {
            return Err(invalid("selected member custody is not a legacy root"));
        };
        Ok(Authenticated(Parts {
            socket: self.socket,
            root,
            cover: self.cover,
            bootstrap: self.bootstrap,
            joining: self.joining,
            next_outer: self.next_outer,
            deadline: self.deadline,
            info: self.info,
        }))
    }
}

#[allow(clippy::large_enum_variant)] // Both branches retain the actual crypto pair in the same setup loop.
enum JoiningCrypto {
    Legacy {
        sender: security::Sender,
        receiver: security::Receiver,
    },
    Managed(l2tunnel_handshake::refresh::InitialJoining),
}
enum JoiningError {
    Packet(security::Error),
    Managed(l2tunnel_handshake::refresh::Error),
}
impl JoiningError {
    fn reason(&self) -> Reason {
        match *self {
            Self::Packet(error) => security_reason(error),
            Self::Managed(error) => diagnostics::refresh_reason(error),
        }
    }
    fn terminal(&self) -> bool {
        match self {
            Self::Packet(error) => matches!(
                error,
                security::Error::Crypto
                    | security::Error::CounterExhausted
                    | security::Error::KeyUsageExhausted
            ),
            Self::Managed(_) => true,
        }
    }
}
impl JoiningCrypto {
    fn open(
        &mut self,
        origin: Instant,
        now: Instant,
        context: identity::Context,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<security::Opened, JoiningError> {
        match self {
            Self::Legacy { receiver, .. } => receiver
                .open(joining_metadata(context), input, output)
                .map_err(JoiningError::Packet),
            Self::Managed(joining) => {
                let now = joining_time(origin, now).map_err(|_| {
                    JoiningError::Managed(l2tunnel_handshake::refresh::Error::Security(
                        security::refresh::Error::TimeRegression,
                    ))
                })?;
                joining
                    .open(now, input, output)
                    .map_err(|error| match error {
                        l2tunnel_handshake::refresh::Error::Security(
                            security::refresh::Error::Protection(error),
                        ) => JoiningError::Packet(error),
                        error => JoiningError::Managed(error),
                    })
            }
        }
    }
    fn seal(
        &mut self,
        origin: Instant,
        now: Instant,
        context: identity::Context,
        body: &[u8],
        output: &mut [u8],
        report: &mut Reporter<'_, '_>,
    ) -> io::Result<()> {
        match self {
            Self::Legacy { sender, .. } => seal_observed(sender, context, body, output, report),
            Self::Managed(joining) => {
                let destination = output
                    .get_mut(1..)
                    .ok_or_else(|| invalid("Joining output bound"))?;
                let sealed = joining
                    .seal(joining_time(origin, now)?, body, destination)
                    .map_err(|error| refresh_error(error, report))?;
                if sealed.number != security::PacketNumber(0) || sealed.bytes + 1 != output.len() {
                    return Err(invalid("Joining flight must be sealed once at number zero"));
                }
                output[0] = ROUTE;
                Ok(())
            }
        }
    }
    fn deadline(&self, origin: Instant, outer: Instant) -> io::Result<Instant> {
        match self {
            Self::Legacy { .. } => Ok(outer),
            Self::Managed(joining) => origin
                .checked_add(Duration::from_micros(joining.deadline().0))
                .map(|end| end.min(outer))
                .ok_or_else(|| invalid("Joining cap conversion overflow")),
        }
    }
    fn finish(
        self,
        root: Option<security::SessionRoot>,
        origin: Instant,
        now: Instant,
        report: &mut Reporter<'_, '_>,
    ) -> io::Result<establish::InitialMaterial> {
        match self {
            Self::Legacy { sender, receiver } => {
                drop((sender, receiver));
                root.map(establish::InitialMaterial::Legacy)
                    .ok_or_else(|| invalid("legacy member root custody missing"))
            }
            Self::Managed(joining) => {
                if root.is_some() {
                    return Err(invalid("managed member has legacy root custody"));
                }
                joining
                    .retire(joining_time(origin, now)?)
                    .map(establish::InitialMaterial::Managed)
                    .map_err(|error| refresh_error(error, report))
            }
        }
    }
}

struct Cache {
    proof: Zeroizing<[u8; PROOF_WIRE]>,
    accepted: Zeroizing<[u8; ACCEPT_WIRE]>,
}

/// Final-acceptance ciphertext custody. It has no root, key or cryptographic API.
pub struct JoiningTail {
    cover: cover::Config,
    cache: Option<Cache>,
    due: Option<Instant>,
    end: Instant,
    last: Instant,
    last_send: Instant,
    interval: Duration,
    attempts: u32,
    maximum: u32,
}
impl JoiningTail {
    /// Exact complete covered acceptance size, excluding IP/UDP.
    /// This bounds retry storage without reserving the larger cover ceiling.
    pub const fn max_packet_bytes(&self) -> usize {
        ACCEPT_WIRE
            + match self.cover.appearance() {
                cover::Appearance::QuicLike => cover::QUIC_ESTABLISHED_OVERHEAD,
                cover::Appearance::MediaLike => cover::MEDIA_OVERHEAD,
            }
    }
    fn empty(cover: cover::Config, settings: Settings, end: Instant, now: Instant) -> Self {
        Self {
            cover,
            cache: None,
            due: None,
            end,
            last: now,
            last_send: now,
            interval: settings.retry_interval,
            attempts: 0,
            maximum: settings.max_attempts,
        }
    }
    fn server(
        cover: cover::Config,
        settings: Settings,
        end: Instant,
        now: Instant,
        proof: [u8; PROOF_WIRE],
        accepted: [u8; ACCEPT_WIRE],
    ) -> Self {
        let mut tail = Self::empty(cover, settings, end, now);
        tail.attempts = 1;
        if tail.attempts < tail.maximum {
            tail.cache = Some(Cache {
                proof: Zeroizing::new(proof),
                accepted: Zeroizing::new(accepted),
            });
        }
        tail
    }
    fn retire(&mut self) {
        self.cache = None;
        self.due = None;
    }
    fn observe(&mut self, now: Instant) -> io::Result<bool> {
        if now < self.last {
            self.retire();
            return Err(invalid("Joining tail time moved backwards"));
        }
        self.last = now;
        if now >= self.end || self.attempts >= self.maximum {
            self.retire();
        }
        Ok(self.cache.is_some())
    }
    /// Recognize only Joining input; exact previously authenticated proof bytes
    /// may schedule one cached acceptance. Other Joining input is silently consumed.
    pub fn receive(&mut self, decoded: cover::Decoded<'_>, now: Instant) -> io::Result<bool> {
        if decoded.phase != cover::Phase::Established || decoded.protected.first() != Some(&ROUTE) {
            return Ok(false);
        }
        if !self.observe(now)? {
            return Ok(true);
        }
        if self
            .cache
            .as_ref()
            .is_some_and(|cache| decoded.protected == &cache.proof[..])
            && self.due.is_none()
        {
            let earliest = self
                .last_send
                .checked_add(self.interval)
                .ok_or_else(|| invalid("Joining retry time overflow"))?;
            self.due = Some(earliest.max(now).min(self.end));
        }
        Ok(true)
    }
    /// Copy one cached acceptance into a fresh established appearance header.
    /// Output preflight precedes attempt use; there is no re-encryption or reader.
    pub fn poll(
        &mut self,
        now: Instant,
        outer: cover::PacketMeta,
        output: &mut [u8],
    ) -> io::Result<Option<usize>> {
        if outer.phase != cover::Phase::Established {
            return Err(invalid("Joining tail outer phase"));
        }
        if !self.observe(now)? || self.due.is_none_or(|due| now < due) {
            return Ok(None);
        }
        let cache = self
            .cache
            .as_ref()
            .ok_or_else(|| invalid("Joining cache retired"))?;
        let length = self
            .cover
            .encode(outer, &cache.accepted[..], output)
            .map_err(cover_error)?;
        self.attempts += 1;
        self.last_send = now;
        self.due = None;
        if self.attempts >= self.maximum {
            self.retire();
        }
        Ok(Some(length))
    }
    /// Next scheduled output/expiry wake, absent once ciphertext custody retires.
    pub fn deadline(&self) -> Option<Instant> {
        self.cache
            .as_ref()
            .map(|_| self.due.unwrap_or(self.end).min(self.end))
    }
}

/// Prove existing client membership, retaining the root until authenticated accept.
pub async fn connect(
    established: establish::Established,
    member: &identity::IdentityKey,
    settings: Settings,
) -> io::Result<Authenticated> {
    connect_observed(established, member, settings, &mut |_| {}).await
}

/// Verify one actual protected allowlisted member proof on the original socket.
pub async fn accept(
    established: establish::Established,
    members: identity::Allowlist,
    settings: Settings,
) -> io::Result<Authenticated> {
    accept_observed(established, members, settings, &mut |_| {}).await
}

/// Prove membership with actual fixed-size observations, retaining the same root custody.
pub async fn connect_observed(
    established: establish::Established,
    member: &identity::IdentityKey,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    drive_observed(established.into(), Local::Client(member), settings, observe)
        .await?
        .into_legacy()
}

/// Verify membership with observations; no secret or provider error text is published.
pub async fn accept_observed(
    established: establish::Established,
    members: identity::Allowlist,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Authenticated> {
    drive_observed(
        established.into(),
        Local::Server(members),
        settings,
        observe,
    )
    .await?
    .into_legacy()
}

async fn drive_observed(
    established: establish::EstablishedState,
    local: Local<'_>,
    settings: Settings,
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<MemberState> {
    let mut report = Reporter::at(observe, Stage::Membership);
    report.bootstrap(
        established.tail.statistics(),
        established.tail.control_statistics(),
    );
    // Setup-only storage is bounded independently of the embedding task's stack.
    let result = Box::pin(drive(established, local, settings, &mut report)).await;
    if result.is_err() {
        report.fail(Reason::Unknown);
    }
    result
}

enum Local<'a> {
    Client(&'a identity::IdentityKey),
    Server(identity::Allowlist),
}

struct Quota {
    used: u32,
    maximum: u32,
    interval: Duration,
    refill: Instant,
}
impl Quota {
    fn new(settings: Settings, now: Instant) -> io::Result<Self> {
        Ok(Self {
            used: 0,
            maximum: settings.receive_packets_per_interval,
            interval: settings.receive_interval,
            refill: now
                .checked_add(settings.receive_interval)
                .ok_or_else(|| invalid("receive interval overflow"))?,
        })
    }
    fn ready(&mut self, now: Instant) -> io::Result<bool> {
        if now >= self.refill {
            self.used = 0;
            self.refill = now
                .checked_add(self.interval)
                .ok_or_else(|| invalid("receive interval overflow"))?;
        }
        Ok(self.used < self.maximum)
    }
}

async fn drive(
    established: establish::EstablishedState,
    local: Local<'_>,
    settings: Settings,
    report: &mut Reporter<'_, '_>,
) -> io::Result<MemberState> {
    let role = if matches!(&local, Local::Client(_)) {
        security::Role::Initiator
    } else {
        security::Role::Responder
    };
    validate_observed(EstablishedView::from(&established), settings, role, report)
        .inspect_err(|_| report.fail(Reason::Configuration))?;
    report.stage(Stage::Membership);
    let establish::EstablishedState {
        socket,
        material,
        binding,
        authenticated,
        peers,
        cover,
        mut tail,
        mut next_outer,
        deadline,
        statistics: _,
        origin,
    } = established;
    let local_addr = socket
        .local_addr()
        .inspect_err(|_| report.reason(Reason::LocalIo))?;
    let peer_addr = socket
        .peer_addr()
        .inspect_err(|_| report.reason(Reason::LocalIo))?;
    let origin = if matches!(&material, establish::InitialMaterial::Legacy(_)) {
        Instant::now()
    } else {
        origin
    };
    let now = Instant::now();
    observed_before(report, now, deadline)?;
    let identity_deadline = identity_time(origin, deadline)?;
    let (mut crypto, root) = match material {
        establish::InitialMaterial::Legacy(mut root) => {
            let sender = root
                .sender(
                    security::Purpose::Joining,
                    security::LaneId(0),
                    JOINING_LIMITS,
                    security::Protection::ChaCha20Poly1305,
                )
                .map_err(|error| {
                    report.reason(security_reason(error));
                    security_error(error)
                })?;
            let receiver = root
                .receiver(
                    security::Purpose::Joining,
                    security::LaneId(0),
                    JOINING_LIMITS,
                    security::Protection::ChaCha20Poly1305,
                )
                .map_err(|error| {
                    report.reason(security_reason(error));
                    security_error(error)
                })?;
            (JoiningCrypto::Legacy { sender, receiver }, Some(root))
        }
        establish::InitialMaterial::Managed(initial) => {
            let joining = initial
                .joining(
                    JOINING_LIMITS,
                    joining_time(origin, now)?,
                    joining_time(origin, deadline)?,
                )
                .map_err(|error| refresh_error(error, report))?;
            (JoiningCrypto::Managed(joining), None)
        }
    };
    let joining_deadline = crypto.deadline(origin, deadline)?;
    observed_before(report, Instant::now(), joining_deadline)?;
    let mut client_member = None;
    let mut outgoing = [0; PROOF_WIRE];
    let mut retained_root = None;
    let mut pending = None;
    let mut managed_members = None;
    match local {
        Local::Client(member) => {
            let proof = identity::MemberProof::sign(member, settings.context).map_err(|error| {
                report.reason(identity_reason(error));
                identity_error(error)
            })?;
            crypto.seal(
                origin,
                Instant::now(),
                settings.context,
                proof.as_bytes(),
                &mut outgoing,
                report,
            )?;
            client_member = Some(member.public_key());
            retained_root = root;
        }
        Local::Server(members) => {
            if let Some(root) = root {
                pending = Some(
                    identity::ServerPending::new(
                        root,
                        settings.context,
                        members,
                        identity_time(origin, now)?,
                        identity_deadline,
                    )
                    .map_err(|error| {
                        report.reason(identity_reason(error));
                        identity_error(error)
                    })?,
                );
            } else {
                managed_members = Some(members);
            }
        }
    }
    let mut quota = Quota::new(settings, now)?;
    let mut input = vec![
        0;
        cover
            .limits()
            .max_packet_bytes
            .checked_add(1)
            .ok_or_else(|| invalid("receive bound overflow"))?
    ];
    let mut output = vec![0; cover.limits().max_packet_bytes];
    let mut workspace = [0; identity::MEMBER_PROOF_BYTES + 16];
    let mut attempts = 0u32;
    report.member(attempts);
    let mut retry = now;
    loop {
        report.bootstrap(tail.statistics(), tail.control_statistics());
        let now = Instant::now();
        observed_before(report, now, deadline)?;
        observed_before(report, now, joining_deadline)?;
        if let Some(length) = tail
            .poll(
                now,
                metadata(next_outer, cover::Phase::Handshake),
                &mut output,
            )
            .map_err(|error| {
                report.bootstrap(tail.statistics(), tail.control_statistics());
                report.reason(diagnostics::establishment_reason(&error));
                bootstrap_error(error)
            })?
        {
            advance(&mut next_outer)?;
            report.bootstrap(tail.statistics(), tail.control_statistics());
            handoff_observed(joining_deadline, send(&socket, &output[..length]), report).await?;
        }
        let now = Instant::now();
        observed_before(report, now, deadline)?;
        if client_member.is_some() && now >= retry {
            if attempts >= settings.max_attempts {
                report.reason(Reason::JoiningAttempts);
                return Err(timed_out("Joining attempt allowance exhausted"));
            }
            let length = cover
                .encode(
                    metadata(next_outer, cover::Phase::Established),
                    &outgoing,
                    &mut output,
                )
                .map_err(|error| {
                    report.reason(Reason::Cover);
                    cover_error(error)
                })?;
            advance(&mut next_outer)?;
            attempts += 1;
            report.member(attempts);
            report.bootstrap(tail.statistics(), tail.control_statistics());
            handoff_observed(joining_deadline, send(&socket, &output[..length]), report).await?;
            retry = Instant::now()
                .checked_add(settings.retry_interval)
                .ok_or_else(|| invalid("Joining retry overflow"))?;
        }
        let now = Instant::now();
        observed_before(report, now, deadline)?;
        let ready = quota.ready(now)?;
        let mut wake = tail
            .deadline()
            .unwrap_or(deadline)
            .min(deadline)
            .min(joining_deadline);
        if client_member.is_some() {
            wake = wake.min(retry);
        }
        if !ready {
            wake = wake.min(quota.refill);
        }
        if wake <= now {
            wake = now
                .checked_add(settings.retry_interval.min(settings.receive_interval))
                .ok_or_else(|| invalid("Joining wake overflow"))?
                .min(deadline)
                .min(joining_deadline);
        }
        report.bootstrap(tail.statistics(), tail.control_statistics());
        tokio::select! {
            _ = sleep_until(wake) => {}
            received = receive(&socket, &mut input), if ready => {
                let now = Instant::now();
                observed_before(report, now, deadline)?;
                observed_before(report, now, joining_deadline)?;
                quota.used += 1;
                let length = match received {
                    Ok(length) => length,
                    Err(error) if establish::path_loss(&error) => continue,
                    Err(error) => { report.reason(Reason::LocalIo); return Err(error); },
                };
                if length > cover.limits().max_packet_bytes { continue; }
                let decoded = match cover.decode(&input[..length]) { Ok(decoded) => decoded, Err(_) => continue };
                if tail.receive(decoded, now).map_err(|error| { report.bootstrap(tail.statistics(), tail.control_statistics()); report.reason(diagnostics::establishment_reason(&error)); bootstrap_error(error) })? { continue; }
                let expected = if client_member.is_some() { ACCEPT_WIRE } else { PROOF_WIRE };
                if decoded.phase != cover::Phase::Established || decoded.protected.len() != expected
                    || decoded.protected.first() != Some(&ROUTE) { continue; }
                let opened = match crypto.open(origin, now, settings.context, &decoded.protected[1..], &mut workspace) {
                    Ok(opened) => opened,
                    Err(error) if error.terminal() =>
                        { report.reason(error.reason()); return Err(io::Error::new(io::ErrorKind::InvalidData, "Joining security owner failed")); },
                    Err(_) => continue,
                };
                if opened.number != security::PacketNumber(0) { report.reason(Reason::Protocol); return Err(denied("unexpected authenticated Joining number")); }
                if let Some(member) = client_member {
                    if opened.bytes != ACCEPT_BYTES || workspace[..2] != [1, 2] || workspace[2..ACCEPT_BYTES] != member.0 {
                        report.reason(Reason::Authentication);
                        return Err(denied("authenticated member acceptance mismatch"));
                    }
                    observed_before(report, Instant::now(), deadline)?;
                    let material = crypto.finish(retained_root.take(), origin, Instant::now(), report)?;
                    let joining = JoiningTail::empty(cover, settings, joining_deadline, Instant::now());
                    let info = Info { binding, authenticated, member, peers, role, local_addr, peer_addr, statistics: tail.statistics() };
                    observed_before(report, Instant::now(), deadline)?;
                    report.bootstrap(tail.statistics(), tail.control_statistics());
                    return Ok(MemberState { socket, material, cover, bootstrap: tail, joining, next_outer, deadline, info, origin });
                }
                let (member, root) = if let Some(members) = managed_members.as_ref() {
                    let member = identity::verify_member(&workspace[..opened.bytes], settings.context, members)
                        .map_err(|error| { report.reason(identity_reason(error)); identity_error(error) })?;
                    (member, None)
                } else {
                    let admitted = pending.take().ok_or_else(|| invalid("server root custody missing"))?
                        .accept(identity_time(origin, now)?, &workspace[..opened.bytes]).map_err(|error| { report.reason(identity_reason(error)); identity_error(error) })?;
                    (admitted.member, Some(admitted.root))
                };
                observed_before(report, Instant::now(), deadline)?;
                let mut body = [0; ACCEPT_BYTES];
                body[..2].copy_from_slice(&[1, 2]);
                body[2..].copy_from_slice(&member.0);
                let mut accepted = [0; ACCEPT_WIRE];
                crypto.seal(origin, Instant::now(), settings.context, &body, &mut accepted, report)?;
                let length = cover.encode(metadata(next_outer, cover::Phase::Established), &accepted, &mut output).map_err(|error| { report.reason(Reason::Cover); cover_error(error) })?;
                advance(&mut next_outer)?;
                report.member(1);
                report.bootstrap(tail.statistics(), tail.control_statistics());
                handoff_observed(joining_deadline, send_acceptance(&socket, &output[..length]), report).await?;
                let now = Instant::now();
                observed_before(report, now, deadline)?;
                let material = crypto.finish(root, origin, now, report)?;
                let proof: [u8; PROOF_WIRE] = decoded.protected.try_into().map_err(|_| invalid("authenticated proof length"))?;
                let joining = JoiningTail::server(cover, settings, joining_deadline, now, proof, accepted);
                let info = Info { binding, authenticated, member, peers, role, local_addr, peer_addr, statistics: tail.statistics() };
                observed_before(report, Instant::now(), deadline)?;
                report.bootstrap(tail.statistics(), tail.control_statistics());
                return Ok(MemberState { socket, material, cover, bootstrap: tail, joining, next_outer, deadline, info, origin });
            }
        }
    }
}

#[cfg(test)]
fn validate(
    established: &establish::Established,
    settings: Settings,
    role: security::Role,
) -> io::Result<()> {
    let mut noop = |_| {};
    let mut report = Reporter::at(&mut noop, Stage::Membership);
    validate_observed(
        EstablishedView::from(established),
        settings,
        role,
        &mut report,
    )
}
struct EstablishedView<'a> {
    socket: &'a UdpSocket,
    actual_binding: security::SessionBinding,
    role: security::Role,
    binding: security::SessionBinding,
    authenticated: l2tunnel_handshake::Binding,
    peers: establish::Peers,
    cover: cover::Config,
    deadline: Instant,
}
#[cfg(test)]
impl<'a> From<&'a establish::Established> for EstablishedView<'a> {
    fn from(value: &'a establish::Established) -> Self {
        Self {
            socket: &value.socket,
            actual_binding: value.root.binding(),
            role: value.root.role(),
            binding: value.binding,
            authenticated: value.authenticated,
            peers: value.peers,
            cover: value.cover,
            deadline: value.deadline,
        }
    }
}
impl<'a> From<&'a establish::EstablishedState> for EstablishedView<'a> {
    fn from(value: &'a establish::EstablishedState) -> Self {
        Self {
            socket: &value.socket,
            actual_binding: value.material.binding(),
            role: value.material.role(),
            binding: value.binding,
            authenticated: value.authenticated,
            peers: value.peers,
            cover: value.cover,
            deadline: value.deadline,
        }
    }
}
fn validate_observed(
    established: EstablishedView<'_>,
    settings: Settings,
    role: security::Role,
    report: &mut Reporter<'_, '_>,
) -> io::Result<()> {
    observed_before(report, Instant::now(), established.deadline)?;
    if settings.retry_interval.is_zero()
        || settings.retry_interval > Duration::from_secs(1)
        || settings.receive_interval.is_zero()
        || settings.receive_interval > Duration::from_secs(1)
        || !(1..=1024).contains(&settings.max_attempts)
        || !(1..=1024).contains(&settings.receive_packets_per_interval)
    {
        return Err(invalid("Joining interval/attempt/receive policy"));
    }
    let binding = established.actual_binding;
    let authenticated = established.authenticated;
    if established.role != role
        || binding != established.binding
        || binding.session != settings.context.session
        || binding.transcript != settings.context.transcript
        || authenticated.session != settings.context.session
        || authenticated.configuration != settings.context.configuration
        || authenticated.carrier != settings.context.carrier
        || authenticated.outer != settings.context.outer
        || established.peers.initiator.0 != settings.context.initiator_noise.0
        || established.peers.responder.0 != settings.context.responder_noise.0
    {
        return Err(invalid(
            "Joining root/session/transcript/pinned-peer context",
        ));
    }
    for body in [PROOF_WIRE, ACCEPT_WIRE] {
        let length = body
            .checked_add(
                established
                    .cover
                    .overhead(cover::Phase::Established, body)
                    .map_err(|error| {
                        report.reason(Reason::Cover);
                        cover_error(error)
                    })?,
            )
            .ok_or_else(|| invalid("Joining cover size overflow"))?;
        if length > established.cover.limits().max_packet_bytes {
            return Err(invalid("Joining cover packet limit"));
        }
    }
    established
        .socket
        .local_addr()
        .inspect_err(|_| report.reason(Reason::LocalIo))?;
    established
        .socket
        .peer_addr()
        .inspect_err(|_| report.reason(Reason::LocalIo))?;
    Ok(())
}

#[cfg(test)]
fn seal(
    sender: &mut security::Sender,
    context: identity::Context,
    body: &[u8],
    output: &mut [u8],
) -> io::Result<()> {
    let mut noop = |_| {};
    let mut report = Reporter::at(&mut noop, Stage::Membership);
    seal_observed(sender, context, body, output, &mut report)
}
fn seal_observed(
    sender: &mut security::Sender,
    context: identity::Context,
    body: &[u8],
    output: &mut [u8],
    report: &mut Reporter<'_, '_>,
) -> io::Result<()> {
    let destination = output
        .get_mut(1..)
        .ok_or_else(|| invalid("Joining output bound"))?;
    let sealed = sender
        .seal(joining_metadata(context), body, destination)
        .map_err(|error| {
            report.reason(security_reason(error));
            security_error(error)
        })?;
    if sealed.number != security::PacketNumber(0) || sealed.bytes + 1 != output.len() {
        return Err(invalid("Joining flight must be sealed once at number zero"));
    }
    output[0] = ROUTE;
    Ok(())
}
fn joining_metadata(context: identity::Context) -> security::Metadata<'static> {
    security::Metadata {
        epoch: security::Epoch(1),
        configuration: security::ConfigDigest(context.configuration),
        extra: &[ROUTE],
    }
}
fn metadata(number: u32, phase: cover::Phase) -> cover::PacketMeta {
    cover::PacketMeta {
        phase,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number.wrapping_mul(960)),
    }
}
fn advance(number: &mut u32) -> io::Result<()> {
    *number = number
        .checked_add(1)
        .ok_or_else(|| invalid("outer packet numbers exhausted"))?;
    Ok(())
}
fn identity_time(origin: Instant, now: Instant) -> io::Result<identity::Time> {
    let elapsed = now
        .checked_duration_since(origin)
        .ok_or_else(|| timed_out("Joining time moved backwards"))?;
    Ok(identity::Time(u64::try_from(elapsed.as_micros()).map_err(
        |_| invalid("Joining time conversion overflow"),
    )?))
}
fn joining_time(origin: Instant, now: Instant) -> io::Result<l2tunnel_handshake::Time> {
    identity_time(origin, now).map(|at| l2tunnel_handshake::Time(at.0))
}
fn refresh_error(
    error: l2tunnel_handshake::refresh::Error,
    report: &mut Reporter<'_, '_>,
) -> io::Error {
    let reason = diagnostics::refresh_reason(error);
    report.reason(reason);
    let kind = match reason {
        Reason::OriginalDeadline | Reason::BootstrapDeadline | Reason::MembershipDeadline => {
            io::ErrorKind::TimedOut
        }
        Reason::Authentication => io::ErrorKind::PermissionDenied,
        Reason::Configuration => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, "managed Joining owner rejected operation")
}
fn before(now: Instant, end: Instant) -> io::Result<()> {
    if now >= end {
        Err(timed_out("original member operation deadline expired"))
    } else {
        Ok(())
    }
}
fn observed_before(report: &mut Reporter<'_, '_>, now: Instant, end: Instant) -> io::Result<()> {
    before(now, end).inspect_err(|_| {
        report.reason(Reason::OriginalDeadline);
    })
}
#[cfg(test)]
async fn handoff<T>(
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut noop = |_| {};
    let mut report = Reporter::new(&mut noop);
    handoff_observed(deadline, future, &mut report).await
}
async fn handoff_observed<T>(
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
    report: &mut Reporter<'_, '_>,
) -> io::Result<T> {
    observed_before(report, Instant::now(), deadline)?;
    report.publish();
    let result = timeout_at(deadline, future)
        .await
        .map_err(|_| {
            report.reason(Reason::OriginalDeadline);
            timed_out("original member operation deadline expired")
        })?
        .inspect_err(|_| report.reason(Reason::LocalIo))?;
    observed_before(report, Instant::now(), deadline)?;
    Ok(result)
}

async fn send(socket: &UdpSocket, packet: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    let injected = SEND_PATH_ERRORS
        .try_with(|remaining| {
            let count = remaining.get();
            remaining.set(count.saturating_sub(1));
            count != 0
        })
        .unwrap_or(false);
    #[cfg(not(test))]
    let injected = false;
    let sent = if injected {
        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
    } else {
        socket.send(packet).await
    };
    match sent {
        Ok(length) if length == packet.len() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete Joining datagram",
        )),
        Err(error) if establish::path_loss(&error) => Ok(()),
        Err(error) => Err(error),
    }
}
async fn receive(socket: &UdpSocket, output: &mut [u8]) -> io::Result<usize> {
    #[cfg(test)]
    if RECEIVE_PATH_ERRORS
        .try_with(|remaining| {
            let count = remaining.get();
            remaining.set(count.saturating_sub(1));
            count != 0
        })
        .unwrap_or(false)
    {
        return Err(io::Error::from(io::ErrorKind::NetworkUnreachable));
    }
    socket.recv(output).await
}
async fn send_acceptance(socket: &UdpSocket, packet: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if DROP_FIRST_ACCEPTANCE
        .try_with(|drop| drop.replace(false))
        .unwrap_or(false)
    {
        return Ok(());
    }
    send(socket, packet).await
}
#[cfg(test)]
tokio::task_local! {
    static DROP_FIRST_ACCEPTANCE: std::cell::Cell<bool>;
    static SEND_PATH_ERRORS: std::cell::Cell<u32>;
    static RECEIVE_PATH_ERRORS: std::cell::Cell<u32>;
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}
fn cover_error(error: cover::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
fn security_error(error: security::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
fn identity_reason(error: identity::Error) -> Reason {
    match error {
        identity::Error::Deadline => Reason::MembershipDeadline,
        identity::Error::InvalidProof
        | identity::Error::InvalidSignature
        | identity::Error::MemberDenied => Reason::Authentication,
        _ => Reason::Configuration,
    }
}
fn security_reason(error: security::Error) -> Reason {
    match error {
        security::Error::Crypto => Reason::Crypto,
        security::Error::CounterExhausted | security::Error::KeyUsageExhausted => {
            Reason::CounterExhausted
        }
        security::Error::Authentication => Reason::Authentication,
        _ => Reason::Configuration,
    }
}
fn identity_error(error: identity::Error) -> io::Error {
    match error {
        identity::Error::Deadline => timed_out("original membership deadline expired"),
        identity::Error::InvalidProof
        | identity::Error::InvalidSignature
        | identity::Error::MemberDenied => denied("member possession proof rejected"),
        _ => invalid("member identity configuration rejected"),
    }
}
fn bootstrap_error(error: establish::Error) -> io::Error {
    match error {
        establish::Error::Deadline => timed_out("original bootstrap deadline expired"),
        establish::Error::Configuration(_) | establish::Error::OutputTooSmall => {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        }
        establish::Error::Io(error) => error,
        _ => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

#[cfg(test)]
#[path = "member_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "member_refresh_tests.rs"]
mod refresh_tests;
