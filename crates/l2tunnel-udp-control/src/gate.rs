use super::*;
use std::collections::BTreeMap;

const ADMISSION_DOMAIN: &[u8] = b"l2tunnel/openvpn-like/admission/v1\0";
const COOKIE_DOMAIN: &[u8] = b"l2tunnel/openvpn-like/cookie/v1\0";

/// Bounded admission counters; no secret material or untrusted payloads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GateStatistics {
    /// Exact valid request bytes eligible for a stateless response.
    pub validated_request_bytes: u64,
    /// Actual Retry payload bytes emitted, always at most eligible request bytes.
    pub response_bytes: u64,
    /// Pending or quarantined cookie count.
    pub retained_sessions: usize,
}

/// Opaque one-use proof of admission and return-path validation, NOT TLS membership.
pub struct PathTicket {
    pub(super) config: Config,
    pub(super) session: [u8; 16],
    pub(super) role: u8,
    pub(super) send_key: Secret,
    pub(super) receive_key: Secret,
    pub(super) deadline: Duration,
}
impl PathTicket {
    /// Public, domain-separated bootstrap identifier; not the final TLS session ID.
    pub fn session(&self) -> [u8; 16] {
        self.session
    }
    /// Original local bootstrap deadline, never renewed by a replay.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }
}

/// Server result; only Retry requests output and only Accepted allocates an engine.
// The bounded 424-byte ticket stays inline; do not heap-allocate gate results.
#[allow(clippy::large_enum_variant)]
pub enum GateEvent {
    /// Malformed, unauthenticated, stale, over-budget or wrong-context input.
    Ignored,
    /// One fixed-size stateless response, no larger than its valid request.
    Retry(GateFrame),
    /// First successfully verified Echo for this pending session.
    Accepted(PathTicket),
    /// Exact duplicate Echo for an existing pending session; no new ticket/deadline.
    Duplicate([u8; 16]),
}

struct Entry {
    session: [u8; 16],
    echo: GateFrame,
    deadline: Duration,
    expires: Duration,
    finished: bool,
}

/// Fixed-peer stateless cookie gate with bounded live/quarantined state.
pub struct ServerGate {
    config: Config,
    profile: [u8; 32],
    admission: Secret,
    cookie: Secret,
    entries: BTreeMap<[u8; 16], Entry>,
    last_now: Duration,
    interval_at: Duration,
    responses_left: u32,
    statistics: GateStatistics,
}

impl ServerGate {
    /// Create one fixed-key/tuple gate; a listener must separately bound all such gates.
    pub fn new(
        config: Config,
        admission: Secret,
        cookie: Secret,
        now: Duration,
    ) -> Result<Self, Error> {
        let profile = config.profile_digest()?;
        micros(now)?;
        Ok(Self {
            config,
            profile,
            admission,
            cookie,
            entries: BTreeMap::new(),
            last_now: now,
            interval_at: now,
            responses_left: config.gate_responses,
            statistics: GateStatistics::default(),
        })
    }

    /// Validate one exact record before creating pending state. Invalid peer input is silent.
    /// `server_nonce` must be fresh unpredictable nonzero bytes when producing a Retry.
    pub fn receive(
        &mut self,
        peer: SocketAddr,
        bytes: &[u8],
        server_nonce: [u8; 16],
        now: Duration,
    ) -> Result<GateEvent, Error> {
        self.check_time(now)?;
        let Some(frame) = parse(bytes, &self.admission, self.config, self.profile) else {
            return Ok(GateEvent::Ignored);
        };
        if peer != self.config.path.client || !matches!(frame[2], 1 | 3) {
            return Ok(GateEvent::Ignored);
        }
        self.last_now = now;
        self.prune(now);
        let nonce = array16(&frame[8..24]);
        if frame[2] == 1 {
            if frame[24..48] != [0; 24]
                || frame[80..112] != [0; 32]
                || self.entries.contains_key(&nonce)
                || self.entries.len() >= self.config.pending_sessions
            {
                return Ok(GateEvent::Ignored);
            }
            if server_nonce == [0; 16] {
                return Err(Error::Nonce);
            }
            let expires = add(now, self.config.cookie_ttl)?;
            let eligible = self
                .statistics
                .validated_request_bytes
                .checked_add(GATE_BYTES as u64)
                .ok_or(Error::CounterExhausted)?;
            if now
                .checked_sub(self.interval_at)
                .is_some_and(|elapsed| elapsed >= self.config.interval)
            {
                self.interval_at = now;
                self.responses_left = self.config.gate_responses;
            }
            self.statistics.validated_request_bytes = eligible;
            self.last_now = now;
            if self.responses_left == 0 {
                return Ok(GateEvent::Ignored);
            }
            let response_bytes = self
                .statistics
                .response_bytes
                .checked_add(GATE_BYTES as u64)
                .ok_or(Error::CounterExhausted)?;
            let mut retry = frame;
            retry[0] = 8 << 3;
            retry[2] = 2;
            retry[24..40].copy_from_slice(&server_nonce);
            retry[40..48].copy_from_slice(&micros(expires)?.to_be_bytes());
            let cookie = mac(&self.cookie, COOKIE_DOMAIN, &retry[..80], self.config.path);
            retry[80..112].copy_from_slice(&cookie);
            sign(&mut retry, &self.admission, self.config.path);
            self.responses_left -= 1;
            self.statistics.response_bytes = response_bytes;
            return Ok(GateEvent::Retry(retry));
        }
        if frame[24..40] == [0; 16] {
            return Ok(GateEvent::Ignored);
        }
        let expires = Duration::from_micros(u64::from_be_bytes(array8(&frame[40..48])));
        let Some(issued) = expires.checked_sub(self.config.cookie_ttl) else {
            return Ok(GateEvent::Ignored);
        };
        if issued > now || now >= expires {
            return Ok(GateEvent::Ignored);
        }
        let mut retry = frame;
        retry[0] = 8 << 3;
        retry[2] = 2;
        if !verify_mac(
            &self.cookie,
            COOKIE_DOMAIN,
            &retry[..80],
            self.config.path,
            &frame[80..112],
        ) {
            return Ok(GateEvent::Ignored);
        }
        if let Some(entry) = self.entries.get(&nonce) {
            return Ok(if entry.echo == frame && !entry.finished {
                GateEvent::Duplicate(entry.session)
            } else {
                GateEvent::Ignored
            });
        }
        if self.entries.len() >= self.config.pending_sessions {
            return Ok(GateEvent::Ignored);
        }
        let deadline = add(issued, self.config.handshake_timeout)?;
        let ticket = ticket(self.config, &self.admission, &frame, 1, deadline)?;
        self.entries.insert(
            nonce,
            Entry {
                session: ticket.session,
                echo: frame,
                deadline,
                expires,
                finished: false,
            },
        );
        self.statistics.retained_sessions = self.entries.len();
        self.last_now = now;
        Ok(GateEvent::Accepted(ticket))
    }

    /// Mark the caller-owned pending engine finished; retain replay quarantine until expiry.
    pub fn finish(&mut self, session: [u8; 16], now: Duration) -> Result<(), Error> {
        self.check_time(now)?;
        for entry in self.entries.values_mut() {
            if entry.session == session {
                entry.finished = true;
            }
        }
        self.prune(now);
        self.last_now = now;
        Ok(())
    }

    /// Remove only expired deadlines/quarantine; scans at most configured pending count.
    pub fn expire(&mut self, now: Duration) -> Result<(), Error> {
        self.check_time(now)?;
        self.prune(now);
        self.last_now = now;
        Ok(())
    }
    /// Exact anti-amplification and bounded-retention observations.
    pub fn statistics(&self) -> GateStatistics {
        self.statistics
    }
    fn check_time(&self, now: Duration) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::TimeRegression);
        }
        micros(now)?;
        Ok(())
    }
    fn prune(&mut self, now: Duration) {
        self.entries
            .retain(|_, entry| now < entry.deadline && (!entry.finished || now < entry.expires));
        self.statistics.retained_sessions = self.entries.len();
    }
}

/// Finite Hello/Echo retry owner. It never restarts its original deadline.
pub struct ClientGate {
    config: Config,
    profile: [u8; 32],
    admission: Secret,
    frame: GateFrame,
    accepted: bool,
    confirmed: bool,
    attempts: u32,
    retry_at: Duration,
    rto: Duration,
    last_now: Duration,
    deadline: Duration,
}
impl ClientGate {
    /// Start with a fresh caller-supplied unpredictable nonzero client nonce.
    pub fn new(
        config: Config,
        admission: Secret,
        nonce: [u8; 16],
        now: Duration,
    ) -> Result<Self, Error> {
        if nonce == [0; 16] {
            return Err(Error::Nonce);
        }
        let profile = config.profile_digest()?;
        let deadline = add(now, config.handshake_timeout)?;
        let mut frame = [0; GATE_BYTES];
        frame[..4].copy_from_slice(&[7 << 3, 1, 1, 0]);
        frame[4..8].copy_from_slice(&config.key_id.to_be_bytes());
        frame[8..24].copy_from_slice(&nonce);
        frame[48..80].copy_from_slice(&profile);
        sign(&mut frame, &admission, config.path);
        Ok(Self {
            config,
            profile,
            admission,
            frame,
            accepted: false,
            confirmed: false,
            attempts: 0,
            retry_at: now,
            rto: config.initial_rto,
            last_now: now,
            deadline,
        })
    }
    /// Emit one due Hello/Echo; retries consume a shared total attempt bound.
    pub fn poll(&mut self, now: Duration) -> Result<Option<GateFrame>, Error> {
        now_check(now, self.last_now, self.deadline)?;
        if self.confirmed || now < self.retry_at {
            self.last_now = now;
            return Ok(None);
        }
        if self.attempts >= self.config.gate_attempts {
            return Err(Error::RetryExhausted);
        }
        let next = add(now, self.rto)?;
        self.rto = self
            .rto
            .checked_mul(2)
            .unwrap_or(self.config.maximum_rto)
            .min(self.config.maximum_rto);
        self.retry_at = next;
        self.attempts += 1;
        self.last_now = now;
        Ok(Some(self.frame))
    }
    /// Accept one authenticated Retry and create exactly one client path ticket.
    /// Server-local expiry remains opaque; the client's original deadline governs it.
    pub fn receive_retry(
        &mut self,
        peer: SocketAddr,
        bytes: &[u8],
        now: Duration,
    ) -> Result<Option<PathTicket>, Error> {
        now_check(now, self.last_now, self.deadline)?;
        let Some(mut frame) = parse(bytes, &self.admission, self.config, self.profile) else {
            return Ok(None);
        };
        if peer != self.config.path.server
            || frame[2] != 2
            || frame[8..24] != self.frame[8..24]
            || frame[24..40] == [0; 16]
            || frame[40..48] == [0; 8]
        {
            return Ok(None);
        }
        if self.accepted {
            return Err(Error::AlreadyAccepted);
        }
        frame[0] = 7 << 3;
        frame[2] = 3;
        sign(&mut frame, &self.admission, self.config.path);
        let ticket = ticket(self.config, &self.admission, &frame, 0, self.deadline)?;
        self.frame = frame;
        self.accepted = true;
        self.retry_at = now;
        self.last_now = now;
        Ok(Some(ticket))
    }
    /// Stop Echo retries only after this ticket's control engine authenticates peer input.
    /// The embedding owner must not call this merely because any UDP packet arrived.
    pub fn confirm_peer_control(&mut self, now: Duration) -> Result<(), Error> {
        now_check(now, self.last_now, self.deadline)?;
        if !self.accepted {
            return Err(Error::Configuration);
        }
        self.confirmed = true;
        self.last_now = now;
        Ok(())
    }
    /// The unchanged bootstrap deadline.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }
}

fn parse(bytes: &[u8], key: &Secret, config: Config, profile: [u8; 32]) -> Option<GateFrame> {
    let frame: GateFrame = bytes.try_into().ok()?;
    let opcode = match frame[2] {
        1 | 3 => 7 << 3,
        2 => 8 << 3,
        _ => return None,
    };
    if frame[0] != opcode
        || frame[1] != 1
        || frame[3] != 0
        || frame[4..8] != config.key_id.to_be_bytes()
        || frame[8..24] == [0; 16]
        || frame[48..80] != profile
        || !verify_mac(
            key,
            ADMISSION_DOMAIN,
            &frame[..112],
            config.path,
            &frame[112..],
        )
    {
        return None;
    }
    Some(frame)
}
fn sign(frame: &mut GateFrame, key: &Secret, path: Path) {
    let value = mac(key, ADMISSION_DOMAIN, &frame[..112], path);
    frame[112..].copy_from_slice(&value);
}
fn ticket(
    config: Config,
    admission: &Secret,
    frame: &GateFrame,
    role: u8,
    deadline: Duration,
) -> Result<PathTicket, Error> {
    let mut context = Vec::with_capacity(142);
    context.extend_from_slice(&frame[4..112]);
    context.extend_from_slice(&path_bytes(config.path));
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"l2tunnel/openvpn-like/control-session/v1\0");
    hash.update(&context);
    let value = hash.finish();
    let mut session = [0; 16];
    session.copy_from_slice(&value.as_ref()[..16]);
    Ok(PathTicket {
        config,
        session,
        role,
        send_key: derive(admission, &context, role)?,
        receive_key: derive(admission, &context, 1 - role)?,
        deadline,
    })
}
fn array16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(bytes);
    out
}
fn array8(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0; 8];
    out.copy_from_slice(bytes);
    out
}
