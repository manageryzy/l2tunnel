//! Mutual per-path reachability over the lab's existing authenticated session.
use serde_json::{Value, json};
use std::{error, fmt};

pub(super) const REQUEST: u8 = 0xa4;
pub(super) const ECHO: u8 = 0xa5;
pub(super) const RETRY_US: u64 = 90_000;
pub(super) const SETUP_TIMEOUT_US: u64 = 5_000_000;
const MAX_REQUESTS: u8 = 56;
const MAX_ECHOES: u8 = 64;
const ECHO_INTERVAL_US: u64 = 10_000;
type Challenge = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Configuration,
    Clock,
    Deadline,
    Packet,
    Path,
    Payment,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authenticated path readiness: {self:?}")
    }
}

impl error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Message {
    kind: u8,
    slot: u8,
    challenge: Challenge,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("kind", &self.kind)
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl Message {
    pub(super) fn encode(self) -> [u8; 18] {
        let mut wire = [0; 18];
        wire[0] = self.kind;
        wire[1] = self.slot;
        wire[2..].copy_from_slice(&self.challenge);
        wire
    }

    pub(super) fn is_echo(self) -> bool {
        self.kind == ECHO
    }

    fn decode(slot: u8, wire: &[u8]) -> Result<Self> {
        let [kind @ (REQUEST | ECHO), declared, rest @ ..] = wire else {
            return Err(Error::Packet);
        };
        let challenge = rest.try_into().map_err(|_| Error::Packet)?;
        if *declared != slot {
            return Err(Error::Path);
        }
        Ok(Self {
            kind: *kind,
            slot,
            challenge,
        })
    }
}

#[derive(Default)]
struct Lane {
    local: Challenge,
    peer: Option<Challenge>,
    echo_pending: bool,
    requests_paid: u8,
    echoes_paid: u8,
    last_paid_was_echo: bool,
    first_request_paid: Option<u64>,
    last_request_paid: Option<u64>,
    last_echo_paid: Option<u64>,
    verified_at: Option<u64>,
    verified_requests: u8,
    repeated_requests: u64,
    duplicate_echoes: u64,
    unmatched_echoes: u64,
    changed_challenges: u64,
}

impl Lane {
    fn request_due(&self, start: u64) -> Option<u64> {
        if self.verified_at.is_some() || self.requests_paid >= MAX_REQUESTS {
            return None;
        }
        self.next_request(start)
    }

    fn next_request(&self, start: u64) -> Option<u64> {
        self.last_request_paid
            .map_or(Some(start), |at| at.checked_add(RETRY_US))
    }

    fn echo_due(&self, start: u64) -> Option<u64> {
        if !self.echo_pending || self.echoes_paid >= MAX_ECHOES {
            return None;
        }
        self.last_echo_paid
            .map_or(Some(start), |at| at.checked_add(ECHO_INTERVAL_US))
    }
}

pub(super) struct State {
    lanes: Vec<Lane>,
    start: u64,
    deadline: u64,
    clock: u64,
    verified: usize,
    ready_at: Option<u64>,
}

impl State {
    /// The runtime supplies independent CSPRNG challenges under fresh per-run keys.
    pub(super) fn new(challenges: Vec<Challenge>, start_us: u64) -> Result<Self> {
        if challenges.is_empty()
            || challenges.len() > usize::from(u8::MAX)
            || challenges
                .iter()
                .enumerate()
                .any(|(i, c)| challenges[..i].contains(c))
        {
            return Err(Error::Configuration);
        }
        let deadline = start_us.checked_add(SETUP_TIMEOUT_US).ok_or(Error::Clock)?;
        let lanes = challenges
            .into_iter()
            .map(|local| Lane {
                local,
                ..Lane::default()
            })
            .collect();
        Ok(Self {
            lanes,
            start: start_us,
            deadline,
            clock: start_us,
            verified: 0,
            ready_at: None,
        })
    }

    pub(super) fn ready(&self) -> bool {
        self.verified == self.lanes.len()
    }

    pub(super) fn setup_deadline(&self) -> Option<u64> {
        (!self.ready()).then_some(self.deadline)
    }

    pub(super) fn check(&self, now: u64) -> Result<()> {
        if now < self.clock {
            return Err(Error::Clock);
        }
        if !self.ready() && now >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }

    pub(super) fn path_wake(&self, slot: u8, now: u64) -> Result<Option<u64>> {
        self.check(now)?;
        let lane = self.lanes.get(usize::from(slot)).ok_or(Error::Path)?;
        Ok(lane
            .request_due(self.start)
            .into_iter()
            .chain(lane.echo_due(self.start))
            .min())
    }

    /// Read-only selection. An unfunded or blocked frozen message keeps its bytes.
    pub(super) fn due(&self, slot: u8, now: u64) -> Result<Option<Message>> {
        self.check(now)?;
        let lane = self.lanes.get(usize::from(slot)).ok_or(Error::Path)?;
        let request = lane.request_due(self.start).is_some_and(|at| at <= now);
        let echo = lane.echo_due(self.start).is_some_and(|at| at <= now);
        if echo && (!request || !lane.last_paid_was_echo) {
            return Ok(Some(Message {
                kind: ECHO,
                slot,
                challenge: lane.peer.ok_or(Error::Payment)?,
            }));
        }
        Ok(request.then_some(Message {
            kind: REQUEST,
            slot,
            challenge: lane.local,
        }))
    }

    /// Record one actual complete UDP payment. Even a frozen request overtaken by its
    /// own verified echo remains payable and cannot reopen the lane or extend setup.
    pub(super) fn paid(&mut self, slot: u8, message: Message, now: u64) -> Result<()> {
        if now < self.clock {
            return Err(Error::Clock);
        }
        if message.slot != slot {
            return Err(Error::Path);
        }
        let lane = self.lanes.get_mut(usize::from(slot)).ok_or(Error::Path)?;
        if message.is_echo() {
            if lane.peer != Some(message.challenge)
                || lane.echo_due(self.start).is_none_or(|at| at > now)
            {
                return Err(Error::Payment);
            }
            lane.echoes_paid += 1;
            lane.last_echo_paid = Some(now);
            lane.echo_pending = false;
        } else {
            if message.challenge != lane.local
                || lane.requests_paid >= MAX_REQUESTS
                || lane.next_request(self.start).is_none_or(|at| at > now)
            {
                return Err(Error::Payment);
            }
            lane.requests_paid += 1;
            lane.first_request_paid.get_or_insert(now);
            lane.last_request_paid = Some(now);
        }
        lane.last_paid_was_echo = message.is_echo();
        self.clock = now;
        Ok(())
    }

    /// Only pass plaintext opened by this session's replay-checked AEAD with the
    /// receiving physical slot as associated data. A peer request cannot verify a lane.
    pub(super) fn receive_authenticated(&mut self, slot: u8, wire: &[u8], now: u64) -> Result<()> {
        self.check(now)?;
        let message = Message::decode(slot, wire)?;
        let lane = self.lanes.get_mut(usize::from(slot)).ok_or(Error::Path)?;
        if message.is_echo() {
            if lane.local != message.challenge || lane.first_request_paid.is_none() {
                lane.unmatched_echoes = lane.unmatched_echoes.saturating_add(1);
            } else if lane.verified_at.is_some() {
                lane.duplicate_echoes = lane.duplicate_echoes.saturating_add(1);
            } else {
                lane.verified_at = Some(now);
                lane.verified_requests = lane.requests_paid;
                self.verified += 1;
                if self.verified == self.lanes.len() {
                    self.ready_at = Some(now);
                }
            }
        } else if let Some(peer) = lane.peer
            && peer != message.challenge
        {
            lane.changed_challenges = lane.changed_challenges.saturating_add(1);
        } else {
            if lane.peer.is_some() {
                lane.repeated_requests = lane.repeated_requests.saturating_add(1);
            }
            lane.peer = Some(message.challenge);
            lane.echo_pending = lane.echoes_paid < MAX_ECHOES;
        }
        self.clock = now;
        Ok(())
    }

    pub(super) fn status(&self) -> Value {
        let paths: Vec<_> = self.lanes.iter().enumerate().map(|(slot, l)| json!({
            "slot":slot, "requests_paid":l.requests_paid, "echoes_paid":l.echoes_paid,
            "first_request_paid_us":l.first_request_paid, "last_request_paid_us":l.last_request_paid,
            "ready_at_us":l.verified_at, "echo_pending":l.echo_pending,
            "requests_paid_at_verification":l.verified_requests,
            "rtt_us":if l.verified_requests == 1 {
                l.verified_at.zip(l.first_request_paid).map(|(end, start)| end - start)
            } else { None },
            "duplicate_requests":l.repeated_requests, "duplicate_echoes":l.duplicate_echoes,
            "unmatched_echoes":l.unmatched_echoes, "changed_challenges":l.changed_challenges,
        })).collect();
        json!({"ready":self.ready(), "all_paths_ready":self.ready(), "ready_paths":self.verified, "paths":paths,
               "started_us":self.start, "deadline_us":self.deadline, "ready_at_us":self.ready_at,
               "retry_us":RETRY_US, "echo_min_interval_us":ECHO_INTERVAL_US,
               "max_requests_per_path":MAX_REQUESTS, "max_echoes_per_path":MAX_ECHOES})
    }
}

#[cfg(test)]
mod tests;
