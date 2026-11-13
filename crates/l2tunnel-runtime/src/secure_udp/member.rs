//! Existing-member admission over the established socket and retained bootstrap.
//!
//! Noise completion is not member acceptance. This owner keeps the data root in
//! custody until the required proof/acceptance, with one socket reader and one
//! original operation deadline. Post-handoff Joining tails retain ciphertext only.

use super::establish;
use l2tunnel_cover as cover;
use l2tunnel_identity as identity;
use l2tunnel_security as security;
use std::{future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep_until, timeout_at},
};
use zeroize::Zeroizing;

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
    drive(established, Local::Client(member), settings).await
}

/// Verify one actual protected allowlisted member proof on the original socket.
pub async fn accept(
    established: establish::Established,
    members: identity::Allowlist,
    settings: Settings,
) -> io::Result<Authenticated> {
    drive(established, Local::Server(members), settings).await
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
    established: establish::Established,
    local: Local<'_>,
    settings: Settings,
) -> io::Result<Authenticated> {
    let role = if matches!(&local, Local::Client(_)) {
        security::Role::Initiator
    } else {
        security::Role::Responder
    };
    validate(&established, settings, role)?;
    let establish::Established {
        socket,
        mut root,
        binding,
        authenticated,
        peers,
        cover,
        mut tail,
        mut next_outer,
        deadline,
        statistics: _,
    } = established;
    let local_addr = socket.local_addr()?;
    let peer_addr = socket.peer_addr()?;
    let origin = Instant::now();
    before(origin, deadline)?;
    let identity_deadline = identity_time(origin, deadline)?;
    let mut sender = root
        .sender(
            security::Purpose::Joining,
            security::LaneId(0),
            JOINING_LIMITS,
            security::Protection::ChaCha20Poly1305,
        )
        .map_err(security_error)?;
    let mut receiver = root
        .receiver(
            security::Purpose::Joining,
            security::LaneId(0),
            JOINING_LIMITS,
            security::Protection::ChaCha20Poly1305,
        )
        .map_err(security_error)?;
    let mut client_member = None;
    let mut outgoing = [0; PROOF_WIRE];
    let mut retained_root = None;
    let mut pending = None;
    match local {
        Local::Client(member) => {
            let proof =
                identity::MemberProof::sign(member, settings.context).map_err(identity_error)?;
            seal(
                &mut sender,
                settings.context,
                proof.as_bytes(),
                &mut outgoing,
            )?;
            client_member = Some(member.public_key());
            retained_root = Some(root);
        }
        Local::Server(members) => {
            pending = Some(
                identity::ServerPending::new(
                    root,
                    settings.context,
                    members,
                    identity::Time(0),
                    identity_deadline,
                )
                .map_err(identity_error)?,
            );
        }
    }
    let mut quota = Quota::new(settings, origin)?;
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
    let mut retry = origin;
    loop {
        let now = Instant::now();
        before(now, deadline)?;
        if let Some(length) = tail
            .poll(
                now,
                metadata(next_outer, cover::Phase::Handshake),
                &mut output,
            )
            .map_err(bootstrap_error)?
        {
            advance(&mut next_outer)?;
            handoff(deadline, send(&socket, &output[..length])).await?;
        }
        let now = Instant::now();
        before(now, deadline)?;
        if client_member.is_some() && now >= retry {
            if attempts >= settings.max_attempts {
                return Err(timed_out("Joining attempt allowance exhausted"));
            }
            let length = cover
                .encode(
                    metadata(next_outer, cover::Phase::Established),
                    &outgoing,
                    &mut output,
                )
                .map_err(cover_error)?;
            advance(&mut next_outer)?;
            attempts += 1;
            handoff(deadline, send(&socket, &output[..length])).await?;
            retry = Instant::now()
                .checked_add(settings.retry_interval)
                .ok_or_else(|| invalid("Joining retry overflow"))?;
        }
        let now = Instant::now();
        before(now, deadline)?;
        let ready = quota.ready(now)?;
        let mut wake = tail.deadline().unwrap_or(deadline).min(deadline);
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
                .min(deadline);
        }
        tokio::select! {
            _ = sleep_until(wake) => {}
            received = receive(&socket, &mut input), if ready => {
                let now = Instant::now();
                before(now, deadline)?;
                quota.used += 1;
                let length = match received {
                    Ok(length) => length,
                    Err(error) if establish::path_loss(&error) => continue,
                    Err(error) => return Err(error),
                };
                if length > cover.limits().max_packet_bytes { continue; }
                let decoded = match cover.decode(&input[..length]) { Ok(decoded) => decoded, Err(_) => continue };
                if tail.receive(decoded, now).map_err(bootstrap_error)? { continue; }
                let expected = if client_member.is_some() { ACCEPT_WIRE } else { PROOF_WIRE };
                if decoded.phase != cover::Phase::Established || decoded.protected.len() != expected
                    || decoded.protected.first() != Some(&ROUTE) { continue; }
                let opened = match receiver.open(joining_metadata(settings.context), &decoded.protected[1..], &mut workspace) {
                    Ok(opened) => opened,
                    Err(security::Error::Crypto | security::Error::CounterExhausted | security::Error::KeyUsageExhausted) =>
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Joining security owner failed")),
                    Err(_) => continue,
                };
                if opened.number != security::PacketNumber(0) { return Err(denied("unexpected authenticated Joining number")); }
                if let Some(member) = client_member {
                    if opened.bytes != ACCEPT_BYTES || workspace[..2] != [1, 2] || workspace[2..ACCEPT_BYTES] != member.0 {
                        return Err(denied("authenticated member acceptance mismatch"));
                    }
                    before(Instant::now(), deadline)?;
                    let root = retained_root.take().ok_or_else(|| invalid("client root custody missing"))?;
                    let joining = JoiningTail::empty(cover, settings, deadline, Instant::now());
                    let info = Info { binding, authenticated, member, peers, role, local_addr, peer_addr, statistics: tail.statistics() };
                    before(Instant::now(), deadline)?;
                    return Ok(Authenticated(Parts { socket, root, cover, bootstrap: tail, joining, next_outer, deadline, info }));
                }
                let admitted = pending.take().ok_or_else(|| invalid("server root custody missing"))?
                    .accept(identity_time(origin, now)?, &workspace[..opened.bytes]).map_err(identity_error)?;
                before(Instant::now(), deadline)?;
                let mut body = [0; ACCEPT_BYTES];
                body[..2].copy_from_slice(&[1, 2]);
                body[2..].copy_from_slice(&admitted.member.0);
                let mut accepted = [0; ACCEPT_WIRE];
                seal(&mut sender, settings.context, &body, &mut accepted)?;
                let length = cover.encode(metadata(next_outer, cover::Phase::Established), &accepted, &mut output).map_err(cover_error)?;
                advance(&mut next_outer)?;
                handoff(deadline, send_acceptance(&socket, &output[..length])).await?;
                let now = Instant::now();
                before(now, deadline)?;
                let proof: [u8; PROOF_WIRE] = decoded.protected.try_into().map_err(|_| invalid("authenticated proof length"))?;
                let joining = JoiningTail::server(cover, settings, deadline, now, proof, accepted);
                let info = Info { binding, authenticated, member: admitted.member, peers, role, local_addr, peer_addr, statistics: tail.statistics() };
                before(Instant::now(), deadline)?;
                return Ok(Authenticated(Parts { socket, root: admitted.root, cover, bootstrap: tail, joining, next_outer, deadline, info }));
            }
        }
    }
}

fn validate(
    established: &establish::Established,
    settings: Settings,
    role: security::Role,
) -> io::Result<()> {
    before(Instant::now(), established.deadline)?;
    if settings.retry_interval.is_zero()
        || settings.retry_interval > Duration::from_secs(1)
        || settings.receive_interval.is_zero()
        || settings.receive_interval > Duration::from_secs(1)
        || !(1..=1024).contains(&settings.max_attempts)
        || !(1..=1024).contains(&settings.receive_packets_per_interval)
    {
        return Err(invalid("Joining interval/attempt/receive policy"));
    }
    let binding = established.root.binding();
    let authenticated = established.authenticated;
    if established.root.role() != role
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
                    .map_err(cover_error)?,
            )
            .ok_or_else(|| invalid("Joining cover size overflow"))?;
        if length > established.cover.limits().max_packet_bytes {
            return Err(invalid("Joining cover packet limit"));
        }
    }
    established.socket.local_addr()?;
    established.socket.peer_addr()?;
    Ok(())
}

fn seal(
    sender: &mut security::Sender,
    context: identity::Context,
    body: &[u8],
    output: &mut [u8],
) -> io::Result<()> {
    let destination = output
        .get_mut(1..)
        .ok_or_else(|| invalid("Joining output bound"))?;
    let sealed = sender
        .seal(joining_metadata(context), body, destination)
        .map_err(security_error)?;
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
fn before(now: Instant, end: Instant) -> io::Result<()> {
    if now >= end {
        Err(timed_out("original member operation deadline expired"))
    } else {
        Ok(())
    }
}
async fn handoff<T>(
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    before(Instant::now(), deadline)?;
    let result = timeout_at(deadline, future)
        .await
        .map_err(|_| timed_out("original member operation deadline expired"))??;
    before(Instant::now(), deadline)?;
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
