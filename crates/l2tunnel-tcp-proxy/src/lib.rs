//! Bounded explicit TCP relay leg over an authenticated reliable ordered channel.
//!
//! This primitive owns a maintained TCP endpoint, not native I/O or authentication.
//! Its caller must establish authenticated remote-open admission before allowing
//! local SYN acknowledgments. Transparent TUN never selects this implicitly.
use l2tunnel_raw_tcp::{CloseReason, ReadOutcome, TcpEngine};
use std::collections::VecDeque;
use std::fmt;

pub mod adaptive;
pub mod admission;
pub mod measurement;
pub mod session;

/// Injected clock and maintained TCP construction types.
pub use l2tunnel_raw_tcp::{
    Config as TcpConfig, IpConfig as TcpIpConfig, Millis, Role, State, Status as TcpStatus,
    TimeWaitResetPolicy,
};

const HEADER: usize = 56;

/// Authenticated logical identity; direction comes from the retained carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Nonzero authenticated session identifier.
    pub session: [u8; 16],
    /// Nonzero negotiated epoch.
    pub epoch: u64,
    /// Nonzero generation-qualified flow identifier.
    pub flow: u64,
}

/// Cumulative offsets or finite target allowances in original stream units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Window {
    /// Original application stream bytes, excluding tunnel/native overhead.
    pub bytes: u64,
    /// Complete Data records, independent of TCP segmentation.
    pub records: u64,
}
impl Window {
    fn contains(self, other: Self) -> bool {
        self.bytes >= other.bytes && self.records >= other.records
    }
    fn checked_add(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(Error::Exhausted)?,
            records: self
                .records
                .checked_add(other.records)
                .ok_or(Error::Exhausted)?,
        })
    }
}

/// Finite immutable per-leg memory and authenticated record policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Logical session/epoch/flow identity, shared by the two relay legs.
    pub scope: Scope,
    /// Maximum actual payload bytes in one Data record, in 1..=65,535.
    pub max_record_bytes: usize,
    /// Maximum unacknowledged original bytes and record boundaries.
    pub maximum: Window,
    /// Initially offered buffer-backed allowance; future changes never revoke grants.
    pub initial: Window,
}
impl Config {
    /// Reject dimensions before constructing a TCP owner or allocating payloads.
    pub fn validate(self) -> Result<(), Error> {
        if self.scope.session == [0; 16]
            || self.scope.epoch == 0
            || self.scope.flow == 0
            || !(1..=65_535).contains(&self.max_record_bytes)
            || !(1..=4_194_304).contains(&self.maximum.bytes)
            || !(1..=1024).contains(&self.maximum.records)
            || self.max_record_bytes as u64 > self.maximum.bytes
            || self.initial.bytes == 0
            || self.initial.records == 0
            || !self.maximum.contains(self.initial)
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}

/// Explicit validation, state or maintained-transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid resource dimensions or nonzero identity.
    Config,
    /// Noncanonical, truncated, oversized or unsupported record.
    Malformed,
    /// Wrong authenticated session, epoch or flow.
    Scope,
    /// Noncontiguous data/FIN, duplicate data or conflicting end boundary.
    Sequence,
    /// Exceeded, regressed or impossibly large cumulative credit.
    Credit,
    /// Data/FIN arrived before local maintained establishment or after remote FIN.
    State,
    /// Counter cannot advance without wrapping.
    Exhausted,
    /// No immutable output is waiting for carrier ownership transfer.
    NoOutput,
    /// Caller explicitly aborted the relay; reliable continuation is impossible.
    Aborted,
    /// Maintained TCP failed; shrinking buffers are not acknowledged delivery.
    Tcp(l2tunnel_raw_tcp::Error),
    /// Internal ownership accounting no longer agrees with maintained TCP state.
    Accounting,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP proxy leg: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<l2tunnel_raw_tcp::Error> for Error {
    fn from(error: l2tunnel_raw_tcp::Error) -> Self {
        Self::Tcp(error)
    }
}

/// Observable ownership boundaries, not remote application consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Actual maintained TCP queues/state for the local native leg.
    pub native: TcpStatus,
    /// Data accepted from the reliable tunnel, cumulative for this scope.
    pub received: Window,
    /// Received bytes copied into maintained TCP's reliable send ring.
    pub injected_bytes: u64,
    /// Actual native TCP acknowledged bytes and fully acknowledged records.
    pub acknowledged: Window,
    /// Original locally received bytes/records placed into the ordered tunnel.
    pub produced: Window,
    /// Buffer-backed cumulative grants already queued for the peer.
    pub granted: Window,
    /// Cumulative grants authenticated from the peer.
    pub peer_granted: Window,
    /// Current future-credit target; existing grants remain irrevocable.
    pub target: Window,
    /// Bounded outstanding record boundaries, including data in the TCP send ring.
    pub retained_records: usize,
    /// Bytes retained in an immutable tunnel output, including header.
    pub pending_record_bytes: usize,
    /// Received exact remote stream end.
    pub remote_fin: bool,
    /// Local TCP EOF has been queued in the reliable tunnel.
    pub local_fin: bool,
    /// Sticky abnormal TCP/accounting/explicit-abort failure.
    pub failure: Option<Error>,
}

struct Incoming {
    end: u64,
    bytes: Vec<u8>,
}

/// One maintained TCP leg and one bounded authenticated ordered relay direction pair.
pub struct Leg {
    config: Config,
    tcp: TcpEngine,
    send_capacity: usize,
    target: Window,
    received: Window,
    injected: u64,
    acknowledged: Window,
    produced: Window,
    granted: Window,
    peer_granted: Window,
    peer_credit_seen: bool,
    incoming: VecDeque<Incoming>,
    output: Option<Vec<u8>>,
    remote_fin: Option<Window>,
    close_requested: bool,
    local_fin: bool,
    last_was_credit: bool,
    failure: Option<Error>,
}
impl Leg {
    /// Construct bounded state; caller owns authenticated admission before polling SYNs.
    pub fn new(config: Config, tcp: TcpConfig, role: Role, now: Millis) -> Result<Self, Error> {
        Self::new_ip(config, tcp.into(), role, now)
    }
    /// Construct a same-family IPv4/IPv6 relay; authenticated remote admission is required.
    pub fn new_ip(
        config: Config,
        tcp: TcpIpConfig,
        role: Role,
        now: Millis,
    ) -> Result<Self, Error> {
        config.validate()?;
        if config.max_record_bytes > tcp.send_bytes {
            return Err(Error::Config);
        }
        Ok(Self {
            config,
            send_capacity: tcp.send_bytes,
            tcp: TcpEngine::new_ip(tcp, role, now)?,
            target: config.initial,
            received: Window::default(),
            injected: 0,
            acknowledged: Window::default(),
            produced: Window::default(),
            granted: Window::default(),
            peer_granted: Window::default(),
            peer_credit_seen: false,
            incoming: VecDeque::new(),
            output: None,
            remote_fin: None,
            close_requested: false,
            local_fin: false,
            last_was_credit: false,
            failure: None,
        })
    }
    /// Validate and queue a complete exact-tuple native IPv4/IPv6 TCP packet.
    pub fn ingest_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.live()?;
        self.tcp.ingest(packet)?;
        Ok(())
    }
    /// Select explicit TIME-WAIT reset policy before this maintained leg is polled.
    pub fn set_time_wait_reset_policy(&mut self, policy: TimeWaitResetPolicy) -> Result<(), Error> {
        Ok(self.tcp.set_time_wait_reset_policy(policy)?)
    }
    /// Transfer one native packet; caller retains it until actual native transmission.
    pub fn pop_packet(&mut self) -> Option<Vec<u8>> {
        self.tcp.pop_packet()
    }
    /// Borrow the one immutable record until the reliable carrier takes ownership.
    pub fn pending_record(&self) -> Option<&[u8]> {
        self.output.as_deref()
    }
    /// Confirm actual reliable-carrier ownership; never call merely after a failed write.
    pub fn confirm_record_sent(&mut self) -> Result<(), Error> {
        self.live()?;
        self.output.take().ok_or(Error::NoOutput)?;
        Ok(())
    }
    /// Adjust future buffer-backed grants without retracting any issued promise.
    pub fn set_target(&mut self, target: Window) -> Result<(), Error> {
        self.validate_target(target)?;
        self.target = target;
        Ok(())
    }
    fn validate_target(&self, target: Window) -> Result<(), Error> {
        self.live()?;
        if target.bytes == 0 || target.records == 0 || !self.config.maximum.contains(target) {
            return Err(Error::Config);
        }
        Ok(())
    }
    /// Consume one record already authenticated and ordered by the retained carrier.
    ///
    /// This pure method does not authenticate bytes. Validation failures leave state
    /// unchanged; the embedding protocol must terminate on a peer protocol violation.
    pub fn receive_authenticated(&mut self, input: &[u8]) -> Result<(), Error> {
        self.live()?;
        let record = decode(self.config, input)?;
        match record.kind {
            1 => {
                let ceiling = self.produced.checked_add(self.config.maximum)?;
                if !record.value.contains(self.peer_granted)
                    || !record.value.contains(self.produced)
                    || !ceiling.contains(record.value)
                {
                    return Err(Error::Credit);
                }
                self.peer_granted = record.value;
                self.peer_credit_seen = true;
            }
            2 => {
                if !self.tcp.status().established || self.remote_fin.is_some() {
                    return Err(Error::State);
                }
                if record.value != self.received {
                    return Err(Error::Sequence);
                }
                let next = self.received.checked_add(Window {
                    bytes: record.payload.len() as u64,
                    records: 1,
                })?;
                if !self.granted.contains(next) {
                    return Err(Error::Credit);
                }
                self.incoming.push_back(Incoming {
                    end: next.bytes,
                    bytes: record.payload.to_vec(),
                });
                self.received = next;
            }
            3 => {
                if !self.tcp.status().established {
                    return Err(Error::State);
                }
                if record.value != self.received {
                    return Err(Error::Sequence);
                }
                if self
                    .remote_fin
                    .is_some_and(|previous| previous != record.value)
                {
                    return Err(Error::Sequence);
                }
                self.remote_fin = Some(record.value);
            }
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
    /// Bounded native work plus at most one new output and `work_limit` stream writes.
    pub fn poll(&mut self, now: Millis, work_limit: usize) -> Result<(), Error> {
        // Even explicit abort allows the maintained reset packet to be generated.
        self.tcp.poll(now, work_limit)?;
        self.live()?;
        let result = self.advance(work_limit);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }
    /// Fail the relay after lost reliable-channel ownership; no transparent resumption.
    pub fn abort(&mut self) {
        self.tcp.abort();
        self.failure = Some(Error::Aborted);
    }
    /// Inspect real queues and cumulative ownership without producing protocol work.
    pub fn status(&self) -> Status {
        Status {
            native: self.tcp.status(),
            received: self.received,
            injected_bytes: self.injected,
            acknowledged: self.acknowledged,
            produced: self.produced,
            granted: self.granted,
            peer_granted: self.peer_granted,
            target: self.target,
            retained_records: self.incoming.len(),
            pending_record_bytes: self.output.as_ref().map_or(0, Vec::len),
            remote_fin: self.remote_fin.is_some(),
            local_fin: self.local_fin,
            failure: self.failure,
        }
    }
    fn live(&self) -> Result<(), Error> {
        self.failure.map_or(Ok(()), Err)
    }
    fn advance(&mut self, work_limit: usize) -> Result<(), Error> {
        let state = self.tcp.status();
        if let Some(reason) = state.close_reason.filter(|r| *r != CloseReason::Clean) {
            return Err(Error::Tcp(l2tunnel_raw_tcp::Error::Terminated(reason)));
        }
        if !state.established {
            return Ok(());
        }
        let acked = self
            .injected
            .checked_sub(state.send_bytes as u64)
            .ok_or(Error::Accounting)?;
        if acked < self.acknowledged.bytes {
            return Err(Error::Accounting);
        }
        self.acknowledged.bytes = acked;
        while self
            .incoming
            .front()
            .is_some_and(|entry| entry.end <= acked)
        {
            self.incoming.pop_front();
            self.acknowledged.records = self
                .acknowledged
                .records
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
        }
        for entry in self
            .incoming
            .iter_mut()
            .filter(|entry| !entry.bytes.is_empty())
            .take(work_limit)
        {
            let available = self
                .send_capacity
                .checked_sub(self.tcp.status().send_bytes)
                .ok_or(Error::Accounting)?;
            if entry.bytes.len() > available {
                break;
            }
            let count = self.tcp.write(&entry.bytes)?;
            if count != entry.bytes.len() {
                return Err(Error::Accounting);
            }
            self.injected = self
                .injected
                .checked_add(count as u64)
                .ok_or(Error::Exhausted)?;
            entry.bytes = Vec::new();
        }
        if self.remote_fin.is_some()
            && !self.close_requested
            && self.injected == self.received.bytes
        {
            self.tcp.close();
            self.close_requested = true;
        }
        if self.output.is_some() {
            return Ok(());
        }
        let wanted = self.acknowledged.checked_add(self.target)?;
        let grant = Window {
            bytes: self.granted.bytes.max(wanted.bytes),
            records: self.granted.records.max(wanted.records),
        };
        let can_data = !self.local_fin
            && self.peer_granted.bytes > self.produced.bytes
            && self.peer_granted.records > self.produced.records
            && self.tcp.status().receive_bytes != 0;
        if grant != self.granted && (!self.last_was_credit || !can_data) {
            self.output = Some(encode(self.config.scope, 1, grant, &[]));
            self.granted = grant;
            self.last_was_credit = true;
            return Ok(());
        }
        if can_data {
            let available = self.peer_granted.bytes - self.produced.bytes;
            let limit = (self.config.max_record_bytes as u64).min(available) as usize;
            let mut bytes = vec![0; limit];
            if let ReadOutcome::Data(count) = self.tcp.read(&mut bytes)? {
                bytes.truncate(count);
                let next = self.produced.checked_add(Window {
                    bytes: count as u64,
                    records: 1,
                })?;
                self.output = Some(encode(self.config.scope, 2, self.produced, &bytes));
                self.produced = next;
                self.last_was_credit = false;
            }
        } else if !self.local_fin
            && self.peer_credit_seen
            && self.tcp.status().peer_fin
            && self.tcp.status().receive_bytes == 0
        {
            self.output = Some(encode(self.config.scope, 3, self.produced, &[]));
            self.local_fin = true;
            self.last_was_credit = false;
        }
        Ok(())
    }
}

struct Record<'a> {
    kind: u8,
    value: Window,
    payload: &'a [u8],
}
fn encode(scope: Scope, kind: u8, value: Window, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(b"LTPR");
    bytes.extend_from_slice(&[1, kind, 0, 0]);
    bytes.extend_from_slice(&scope.session);
    bytes.extend_from_slice(&scope.epoch.to_be_bytes());
    bytes.extend_from_slice(&scope.flow.to_be_bytes());
    // Data's logical order is record index then byte offset; other kinds are bytes/count.
    let values = if kind == 2 {
        [value.records, value.bytes]
    } else {
        [value.bytes, value.records]
    };
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(payload);
    bytes
}
fn decode(config: Config, bytes: &[u8]) -> Result<Record<'_>, Error> {
    if bytes.len() < HEADER
        || bytes.len() > HEADER + config.max_record_bytes
        || bytes[..4] != *b"LTPR"
        || bytes[4] != 1
        || bytes[6..8] != [0, 0]
        || !matches!(bytes[5], 1..=3)
        || (bytes[5] == 2) == (bytes.len() == HEADER)
    {
        return Err(Error::Malformed);
    }
    let integer = |start: usize| -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ))
    };
    if bytes[8..24] != config.scope.session
        || integer(24)? != config.scope.epoch
        || integer(32)? != config.scope.flow
    {
        return Err(Error::Scope);
    }
    let values = [integer(40)?, integer(48)?];
    let value = if bytes[5] == 2 {
        Window {
            records: values[0],
            bytes: values[1],
        }
    } else {
        Window {
            bytes: values[0],
            records: values[1],
        }
    };
    Ok(Record {
        kind: bytes[5],
        value,
        payload: &bytes[HEADER..],
    })
}

#[cfg(test)]
mod tests;
