//! Built-in tunnel speed and ping tests (TT-02, docs/modules/tunnel-tests.md).
//!
//! The test lives in the upper layers of both ends; the data protocols carry
//! its packets unchanged. Before each test the two ends agree on a fresh
//! random private address pair over the authenticated control channel
//! (owner decisions 6 and 7, 2026-11-24). The tester's packets enter the
//! same native admission as device packets; on each end, packets the
//! protocol hands up for that end's active test address go to the test
//! endpoint instead of the TUN device. Nothing is captured outside a test.
use l2tunnel_device::PacketLayer;
use l2tunnel_tunnel_test::control::{Message, Refusal};
use l2tunnel_tunnel_test::{Addresses, Direction, Phase, Progress, Responder, Tester};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Offers per test before giving up on finding a pair both hosts leave unused.
const OFFERS: u32 = 8;
/// How long the tester waits for the peer's answer to an offer.
const ANSWER_WAIT: Duration = Duration::from_secs(3);
/// A responder with no test traffic and no End for this long is released
/// (longer than the endpoint's connection lifetime).
const RESPONDER_IDLE: Duration = Duration::from_secs(40);
/// Control messages waiting for control-channel capacity.
const OUTGOING: usize = 8;
/// After a test ends, packets still arriving for its addresses (late
/// retransmissions) are discarded for this long instead of reaching the
/// device.
const LINGER: Duration = Duration::from_secs(10);
/// Ended test addresses remembered for [`LINGER`].
const ENDED: usize = 4;
/// Test packets injected per loop turn.
pub(super) const INJECT_PER_TURN: usize = 64;

/// One requested test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelTestRequest {
    /// TCP streaming.
    Speed {
        /// Upload or download, seen from this end.
        direction: Direction,
        /// Parallel streams, 1..=8.
        streams: u8,
        /// Length, 1..=30 s.
        duration: Duration,
    },
    /// ICMP echo.
    Ping {
        /// Probes, 1..=100.
        count: u16,
        /// Gap between probes, 100..=1000 ms.
        interval: Duration,
    },
}

/// Lifecycle of a requested test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelTestPhase {
    /// Agreeing on addresses with the peer.
    Negotiating,
    /// Measuring.
    Running,
    /// Finished with a result.
    Completed,
    /// Ended by an error.
    Failed,
    /// Cancelled locally.
    Cancelled,
}

/// The latest test of this session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelTestReport {
    /// Service-wide test identity.
    pub id: u64,
    /// What was requested.
    pub request: TunnelTestRequest,
    /// Lifecycle.
    pub phase: TunnelTestPhase,
    /// Agreed addresses, once accepted.
    pub addresses: Option<Addresses>,
    /// Endpoint progress, once running.
    pub progress: Option<Progress>,
    /// Why it failed.
    pub error: Option<String>,
}
impl TunnelTestReport {
    /// Whether the test is still negotiating or measuring.
    pub fn active(&self) -> bool {
        matches!(
            self.phase,
            TunnelTestPhase::Negotiating | TunnelTestPhase::Running
        )
    }
}

/// Why a test could not start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelTestRefusal {
    /// Another test is still running.
    Busy,
    /// No running session, or this session cannot run tests.
    Unavailable(String),
}

/// Reports whether an address is used by an interface or route on this
/// host, so agreed test addresses never shadow real ones.
pub type AddressCheck = Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>;

#[derive(Default)]
struct SharedState {
    next_id: u64,
    request: Option<(u64, TunnelTestRequest)>,
    cancel: Option<u64>,
    report: Option<TunnelTestReport>,
    running: bool,
    unavailable: Option<String>,
    check: Option<AddressCheck>,
}

/// State shared by the service's handle and the session runtime.
#[derive(Default)]
pub struct Shared(Mutex<SharedState>);
impl Shared {
    fn lock(&self) -> MutexGuard<'_, SharedState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Queue a test; the runtime starts it on its next turn.
    pub(super) fn start(&self, request: TunnelTestRequest) -> Result<u64, TunnelTestRefusal> {
        let mut state = self.lock();
        if !state.running {
            return Err(TunnelTestRefusal::Unavailable("not connected".into()));
        }
        if let Some(reason) = &state.unavailable {
            return Err(TunnelTestRefusal::Unavailable(reason.clone()));
        }
        if state.request.is_some() || state.report.as_ref().is_some_and(|r| r.active()) {
            return Err(TunnelTestRefusal::Busy);
        }
        state.next_id = state.next_id.wrapping_add(1).max(1);
        let id = state.next_id;
        state.request = Some((id, request));
        state.report = Some(TunnelTestReport {
            id,
            request,
            phase: TunnelTestPhase::Negotiating,
            addresses: None,
            progress: None,
            error: None,
        });
        Ok(id)
    }
    /// The latest test.
    pub(super) fn report(&self) -> Option<TunnelTestReport> {
        self.lock().report.clone()
    }
    /// Ask the runtime to cancel test `id`; false when it is not active.
    pub(super) fn cancel(&self, id: u64) -> bool {
        let mut state = self.lock();
        let active = state
            .report
            .as_ref()
            .is_some_and(|report| report.id == id && report.active());
        if active {
            state.cancel = Some(id);
        }
        active
    }
    /// Why this session cannot run tests, when it cannot.
    pub(super) fn unavailable(&self) -> Option<String> {
        let state = self.lock();
        if !state.running {
            return Some("the session runtime is not running".into());
        }
        state.unavailable.clone()
    }
    /// Install the host address check used for agreed addresses.
    pub(super) fn set_check(&self, check: AddressCheck) {
        self.lock().check = Some(check);
    }
}

enum TesterState {
    Offering {
        addresses: Addresses,
        until: Duration,
        offers: u32,
        avoid: Vec<Ipv4Addr>,
    },
    Running {
        addresses: Addresses,
        tester: Box<Tester>,
    },
}
struct TesterRun {
    id: u64,
    request: TunnelTestRequest,
    state: TesterState,
}
struct ResponderRun {
    id: u64,
    addresses: Addresses,
    responder: Box<Responder>,
    active: Duration,
}

/// The session runtime's side of the tests.
pub(super) struct Port {
    shared: Option<Arc<Shared>>,
    unavailable: Option<&'static str>,
    tester: Option<TesterRun>,
    responder: Option<ResponderRun>,
    // Addresses of ended tests, with the time their late packets stop
    // being discarded.
    ended: VecDeque<(Ipv4Addr, Duration)>,
    outgoing: VecDeque<Message>,
    held: Option<Vec<u8>>,
    turn: bool,
    seed: u64,
    malformed: u64,
}
impl Port {
    /// A port for a session whose device has `layer`; `seed` comes from the
    /// runtime's random source.
    pub(super) fn new(layer: PacketLayer, seed: u64) -> Self {
        Self {
            shared: None,
            unavailable: (layer != PacketLayer::Ip)
                .then_some("tunnel tests run on TUN (IP) sessions; TAP is not supported yet"),
            tester: None,
            responder: None,
            ended: VecDeque::with_capacity(ENDED),
            outgoing: VecDeque::with_capacity(OUTGOING),
            held: None,
            turn: false,
            seed,
            malformed: 0,
        }
    }
    /// Connect the service's handle.
    pub(super) fn attach(&mut self, shared: Arc<Shared>) {
        {
            let mut state = shared.lock();
            state.running = true;
            state.unavailable = self.unavailable.map(str::to_owned);
        }
        self.shared = Some(shared);
    }
    fn next_seed(&mut self) -> u64 {
        self.seed = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.seed
    }
    fn check(&self) -> Option<AddressCheck> {
        self.shared
            .as_ref()
            .and_then(|shared| shared.lock().check.clone())
    }
    fn in_use(check: &Option<AddressCheck>, address: Ipv4Addr) -> bool {
        check.as_ref().is_some_and(|check| check(address))
    }
    /// Keep discarding late packets for `address` after its test ended.
    fn linger(&mut self, address: Ipv4Addr, now: Duration) {
        if self.ended.len() == ENDED {
            self.ended.pop_front();
        }
        self.ended.push_back((address, now.saturating_add(LINGER)));
    }
    fn release_responder(&mut self, now: Duration) {
        if let Some(run) = self.responder.take() {
            self.linger(run.addresses.responder, now);
        }
    }
    fn send(&mut self, message: Message) {
        if self.outgoing.len() == OUTGOING {
            self.outgoing.pop_front();
        }
        self.outgoing.push_back(message);
    }
    /// Next control message to submit.
    pub(super) fn take_message(&mut self) -> Option<Message> {
        self.outgoing.pop_front()
    }
    /// A message the control channel had no room for, tried again later.
    pub(super) fn keep_message(&mut self, message: Message) {
        self.outgoing.push_front(message);
    }
    /// Malformed tunnel-test control messages ignored.
    #[cfg(test)]
    pub(super) fn malformed(&self) -> u64 {
        self.malformed
    }
    fn report(&self, update: impl FnOnce(&mut TunnelTestReport)) {
        if let (Some(shared), Some(run)) = (&self.shared, &self.tester) {
            let mut state = shared.lock();
            if let Some(report) = state.report.as_mut().filter(|report| report.id == run.id) {
                update(report);
            }
        }
    }
    fn finish(&mut self, phase: TunnelTestPhase, error: Option<String>, now: Duration) {
        let Some(run) = self.tester.take() else {
            return;
        };
        let (addresses, progress) = match &run.state {
            TesterState::Running { addresses, tester } => (Some(*addresses), tester.progress(now)),
            TesterState::Offering { .. } => (None, None),
        };
        if let Some(addresses) = addresses {
            self.linger(addresses.tester, now);
        }
        if matches!(run.state, TesterState::Running { .. }) {
            self.send(Message::End { id: run.id });
        }
        if let Some(shared) = &self.shared {
            let mut state = shared.lock();
            if let Some(report) = state.report.as_mut().filter(|report| report.id == run.id) {
                report.phase = phase;
                report.addresses = addresses.or(report.addresses);
                if progress.is_some() {
                    report.progress = progress;
                }
                if error.is_some() {
                    report.error = error;
                }
            }
        }
    }
    fn offer(
        &mut self,
        id: u64,
        request: TunnelTestRequest,
        avoid: Vec<Ipv4Addr>,
        offers: u32,
        now: Duration,
    ) {
        let check = self.check();
        let seed = self.next_seed();
        let pair = Addresses::random(seed, |address| {
            avoid.contains(&address) || Self::in_use(&check, address)
        });
        match pair {
            Ok(addresses) => {
                self.tester = Some(TesterRun {
                    id,
                    request,
                    state: TesterState::Offering {
                        addresses,
                        until: now + ANSWER_WAIT,
                        offers,
                        avoid,
                    },
                });
                self.send(Message::Offer { id, addresses });
            }
            Err(error) => {
                self.tester = Some(TesterRun {
                    id,
                    request,
                    state: TesterState::Offering {
                        addresses: Addresses {
                            tester: Ipv4Addr::UNSPECIFIED,
                            responder: Ipv4Addr::UNSPECIFIED,
                        },
                        until: now,
                        offers,
                        avoid: Vec::new(),
                    },
                });
                self.finish(TunnelTestPhase::Failed, Some(error.to_string()), now);
            }
        }
    }
    /// Take requests from the service, run the endpoints and publish progress.
    pub(super) fn poll(&mut self, now: Duration, mtu: usize) {
        let (request, cancel) = match &self.shared {
            Some(shared) => {
                let mut state = shared.lock();
                (state.request.take(), state.cancel.take())
            }
            None => (None, None),
        };
        if let Some((id, request)) = request {
            if let Some(reason) = self.unavailable {
                self.tester = Some(TesterRun {
                    id,
                    request,
                    state: TesterState::Offering {
                        addresses: Addresses {
                            tester: Ipv4Addr::UNSPECIFIED,
                            responder: Ipv4Addr::UNSPECIFIED,
                        },
                        until: now,
                        offers: 0,
                        avoid: Vec::new(),
                    },
                });
                self.finish(TunnelTestPhase::Failed, Some(reason.into()), now);
            } else {
                self.offer(id, request, Vec::new(), 1, now);
            }
        }
        if let Some(id) = cancel
            && self.tester.as_ref().is_some_and(|run| run.id == id)
        {
            if let Some(TesterRun {
                state: TesterState::Running { tester, .. },
                ..
            }) = &mut self.tester
            {
                tester.cancel();
            }
            self.finish(TunnelTestPhase::Cancelled, None, now);
        }
        // An offer nobody answered: the peer may run a build without tests.
        if let Some(TesterRun {
            state: TesterState::Offering { until, .. },
            ..
        }) = &self.tester
            && now >= *until
        {
            self.finish(
                TunnelTestPhase::Failed,
                Some(
                    "the peer did not answer the test offer (it may run an l2tunnel version \
                     without tunnel tests)"
                        .into(),
                ),
                now,
            );
        }
        let mut ended = None;
        if let Some(TesterRun {
            state: TesterState::Running { tester, .. },
            ..
        }) = &mut self.tester
        {
            if let Err(error) = tester.poll(now) {
                tester.fail("tester clock error");
                let _ = error;
            }
            if let Some(progress) = tester.progress(now) {
                if progress.phase != Phase::Running {
                    ended = Some(match progress.phase {
                        Phase::Completed => TunnelTestPhase::Completed,
                        Phase::Cancelled => TunnelTestPhase::Cancelled,
                        _ => TunnelTestPhase::Failed,
                    });
                }
                self.report(|report| report.progress = Some(progress));
            }
        }
        if let Some(phase) = ended {
            let error = self
                .tester
                .as_ref()
                .and_then(|run| match &run.state {
                    TesterState::Running { tester, .. } => tester.progress(now),
                    TesterState::Offering { .. } => None,
                })
                .and_then(|progress| progress.error.map(str::to_owned));
            self.finish(phase, error, now);
        }
        if let Some(run) = &mut self.responder {
            let _ = run.responder.poll(now);
            if now.saturating_sub(run.active) > RESPONDER_IDLE {
                self.release_responder(now);
            }
        }
        let _ = mtu;
    }
    /// Handle one control message from the peer.
    pub(super) fn receive(&mut self, bytes: &[u8], now: Duration, mtu: usize) {
        let Ok(message) = Message::decode(bytes) else {
            self.malformed = self.malformed.saturating_add(1);
            return;
        };
        match message {
            Message::Offer { id, addresses } => self.offered(id, addresses, now, mtu),
            Message::Accept { id } => self.accepted(id, now, mtu),
            Message::Refuse { id, reason } => self.refused(id, reason, now),
            Message::End { id } => {
                if self.responder.as_ref().is_some_and(|run| run.id == id) {
                    self.release_responder(now);
                }
                if self.tester.as_ref().is_some_and(|run| run.id == id) {
                    self.finish(
                        TunnelTestPhase::Failed,
                        Some("the peer ended the test".into()),
                        now,
                    );
                }
            }
        }
    }
    fn offered(&mut self, id: u64, addresses: Addresses, now: Duration, mtu: usize) {
        if let Some(run) = &self.responder {
            let reply = if run.id == id && run.addresses == addresses {
                Message::Accept { id }
            } else {
                Message::Refuse {
                    id,
                    reason: Refusal::Busy,
                }
            };
            self.send(reply);
            return;
        }
        if self.unavailable.is_some() {
            self.send(Message::Refuse {
                id,
                reason: Refusal::Unavailable,
            });
            return;
        }
        let check = self.check();
        if Self::in_use(&check, addresses.tester) || Self::in_use(&check, addresses.responder) {
            self.send(Message::Refuse {
                id,
                reason: Refusal::AddressInUse,
            });
            return;
        }
        let seed = self.next_seed();
        match Responder::new(addresses, mtu, seed, now) {
            Ok(responder) => {
                self.responder = Some(ResponderRun {
                    id,
                    addresses,
                    responder: Box::new(responder),
                    active: now,
                });
                self.send(Message::Accept { id });
            }
            Err(_) => self.send(Message::Refuse {
                id,
                reason: Refusal::Unavailable,
            }),
        }
    }
    fn accepted(&mut self, id: u64, now: Duration, mtu: usize) {
        let Some(TesterRun {
            id: current,
            request,
            state: TesterState::Offering { addresses, .. },
        }) = &self.tester
        else {
            return;
        };
        if *current != id {
            return;
        }
        let (request, addresses) = (*request, *addresses);
        let seed = self.next_seed();
        let started = Tester::new(addresses, mtu, seed, now).and_then(|mut tester| {
            match request {
                TunnelTestRequest::Speed {
                    direction,
                    streams,
                    duration,
                } => tester.start_speed(direction, streams, duration, now)?,
                TunnelTestRequest::Ping { count, interval } => {
                    tester.start_ping(count, interval, now)?
                }
            }
            Ok(tester)
        });
        match started {
            Ok(tester) => {
                if let Some(run) = &mut self.tester {
                    run.state = TesterState::Running {
                        addresses,
                        tester: Box::new(tester),
                    };
                }
                self.report(|report| {
                    report.phase = TunnelTestPhase::Running;
                    report.addresses = Some(addresses);
                });
            }
            Err(error) => {
                self.send(Message::End { id });
                self.finish(TunnelTestPhase::Failed, Some(error.to_string()), now);
            }
        }
    }
    fn refused(&mut self, id: u64, reason: Refusal, now: Duration) {
        let Some(TesterRun {
            id: current,
            request,
            state:
                TesterState::Offering {
                    addresses,
                    offers,
                    avoid,
                    ..
                },
        }) = &self.tester
        else {
            return;
        };
        if *current != id {
            return;
        }
        match reason {
            Refusal::AddressInUse if *offers < OFFERS => {
                let mut avoid = avoid.clone();
                avoid.extend([addresses.tester, addresses.responder]);
                let (request, offers) = (*request, *offers + 1);
                self.offer(id, request, avoid, offers, now);
            }
            Refusal::AddressInUse => self.finish(
                TunnelTestPhase::Failed,
                Some("the peer uses every offered test address".into()),
                now,
            ),
            Refusal::Busy => self.finish(
                TunnelTestPhase::Failed,
                Some("the peer is serving another test".into()),
                now,
            ),
            Refusal::Unavailable => self.finish(
                TunnelTestPhase::Failed,
                Some("the peer cannot run tunnel tests on this session".into()),
                now,
            ),
        }
    }
    /// Take a packet the protocol handed up when it is for this end's active
    /// test address; it then never reaches the device.
    pub(super) fn capture(&mut self, packet: &[u8], now: Duration) -> bool {
        let Some(destination) = ipv4_destination(packet) else {
            return false;
        };
        if let Some(TesterRun {
            state: TesterState::Running { addresses, tester },
            ..
        }) = &mut self.tester
            && destination == addresses.tester
        {
            tester.deliver(packet);
            return true;
        }
        if let Some(run) = &mut self.responder
            && destination == run.addresses.responder
        {
            run.responder.deliver(packet);
            run.active = now;
            return true;
        }
        // A late packet of an ended test is discarded, never delivered.
        while self.ended.front().is_some_and(|(_, until)| *until <= now) {
            self.ended.pop_front();
        }
        self.ended
            .iter()
            .any(|(address, until)| *address == destination && now < *until)
    }
    /// Next test packet to admit like a device packet.
    pub(super) fn next_packet(&mut self) -> Option<Vec<u8>> {
        if let Some(packet) = self.held.take() {
            return Some(packet);
        }
        for _ in 0..2 {
            self.turn = !self.turn;
            let packet = if self.turn {
                match &mut self.tester {
                    Some(TesterRun {
                        state: TesterState::Running { tester, .. },
                        ..
                    }) => tester.next_outbound(),
                    _ => None,
                }
            } else {
                self.responder
                    .as_mut()
                    .and_then(|run| run.responder.next_outbound())
            };
            if packet.is_some() {
                return packet;
            }
        }
        None
    }
    /// A packet admission refused for now; offered again first.
    pub(super) fn hold(&mut self, packet: Vec<u8>) {
        self.held = Some(packet);
    }
    /// Next time the port needs a turn.
    pub(super) fn poll_at(&mut self, now: Duration) -> Option<Duration> {
        if self.held.is_some() || !self.outgoing.is_empty() {
            return Some(now);
        }
        if self.shared.as_ref().is_some_and(|shared| {
            let state = shared.lock();
            state.request.is_some() || state.cancel.is_some()
        }) {
            return Some(now);
        }
        let mut at = None::<Duration>;
        let mut earliest = |next: Option<Duration>| {
            if let Some(next) = next {
                at = Some(at.map_or(next, |current| current.min(next)));
            }
        };
        match &mut self.tester {
            Some(TesterRun {
                state: TesterState::Running { tester, .. },
                ..
            }) => earliest(tester.poll_at(now)),
            Some(TesterRun {
                state: TesterState::Offering { until, .. },
                ..
            }) => earliest(Some(*until)),
            None => {}
        }
        if let Some(run) = &mut self.responder {
            earliest(run.responder.poll_at(now));
            earliest(Some(run.active + RESPONDER_IDLE));
        }
        at
    }
}
impl Drop for Port {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared {
            let mut state = shared.lock();
            state.running = false;
            state.request = None;
            state.cancel = None;
            if let Some(report) = state.report.as_mut().filter(|report| report.active()) {
                report.phase = TunnelTestPhase::Failed;
                report.error = Some("the session ended".into());
            }
        }
    }
}

/// Destination of an IPv4 packet.
fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    let header = packet.get(..20)?;
    if header[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ))
}

#[cfg(test)]
#[path = "transport_tunnel_tests_tests.rs"]
mod tests;

// The session loop's side: install the port, run it each turn, carry its
// control messages and admit its packets like device reads.
impl super::Driver {
    pub(super) fn install_tunnel_tests(&mut self, layer: PacketLayer, requests: &super::Requests) {
        if self.common.is_none() {
            return;
        }
        let mut seed = [0; 8];
        let seed = match ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
        {
            Ok(()) => u64::from_le_bytes(seed),
            Err(_) => self.origin.elapsed().as_nanos() as u64 ^ 0x5DEE_CE66_D1CE_4E5B,
        };
        let mut port = Port::new(layer, seed);
        let super::Requests::Common(requests) = requests;
        if let Some(requests) = requests {
            port.attach(requests.1.clone());
        }
        self.tunnel_tests = Some(Box::new(port));
    }
    /// Largest test packet: the current protocol's native packet bound.
    fn tunnel_test_mtu(&self) -> std::io::Result<usize> {
        let epoch = super::core::Epoch(self.source_scope.epoch.0);
        Ok(self
            .common_state()?
            .engine(epoch)?
            .configuration()
            .descriptor()
            .local(super::common_contract::mg_role(self.info.role))
            .send()
            .max_native())
    }
    pub(super) fn service_tunnel_tests(&mut self, now: u64) -> std::io::Result<()> {
        let Some(mut port) = self.tunnel_tests.take() else {
            return Ok(());
        };
        let result = self.drive_tunnel_tests(&mut port, now);
        self.tunnel_tests = Some(port);
        result
    }
    fn drive_tunnel_tests(&mut self, port: &mut Port, now: u64) -> std::io::Result<()> {
        let mtu = self.tunnel_test_mtu()?;
        port.poll(Duration::from_micros(now), mtu);
        while let Some(message) = port.take_message() {
            let bytes = message.encode();
            let deadline = super::add(now, Duration::from_secs(5))?.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::TunnelTestV1,
                    bytes: &bytes,
                },
                deadline,
                true,
            )?;
            if submitted.is_none() {
                port.keep_message(message);
                break;
            }
        }
        for _ in 0..INJECT_PER_TURN {
            if !self.check_expiry(now)? || !self.can_admit_common_native()? {
                break;
            }
            let Some(packet) = port.next_packet() else {
                break;
            };
            if packet.is_empty() || packet.len() > mtu {
                continue;
            }
            let epoch = super::core::Epoch(self.source_scope.epoch.0);
            let connection_cap = if self.connection_scope(self.source_scope)? {
                Some(
                    super::add(now, self.config.native.stall_timeout)?
                        .min(self.common_original_cap()?),
                )
            } else {
                None
            };
            let super::owner::DataOwner::Common(state) = &mut self.owner;
            let admitted = match connection_cap {
                Some(cap) => state
                    .entry(epoch)?
                    .ingest_borrowed_at(
                        l2tunnel::record_engine::Tick(now),
                        l2tunnel::record_engine::Tick(now),
                        &packet,
                        l2tunnel::record_engine::Tick(cap),
                    )
                    .map(|_| ()),
                None => state
                    .entry(epoch)?
                    .enqueue_borrowed(l2tunnel::record_engine::Tick(now), &packet)
                    .map(|_| ()),
            };
            if admitted.is_err() {
                // Queue pressure: offer the same packet first next turn.
                port.hold(packet);
                break;
            }
        }
        Ok(())
    }
    pub(super) fn receive_tunnel_test(&mut self, now: u64, bytes: &[u8]) {
        let Ok(mtu) = self.tunnel_test_mtu() else {
            return;
        };
        if let Some(port) = &mut self.tunnel_tests {
            port.receive(bytes, Duration::from_micros(now), mtu);
        }
    }
    /// Next loop time the tests need, in session microseconds.
    pub(super) fn tunnel_test_wake(&mut self, now: u64) -> Option<u64> {
        let at = self
            .tunnel_tests
            .as_mut()?
            .poll_at(Duration::from_micros(now))?;
        Some(u64::try_from(at.as_micros()).unwrap_or(u64::MAX).max(now))
    }
}
