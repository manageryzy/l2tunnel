//! The testing side: TCP streams for the speed test, ICMP echo for ping.
use crate::{
    Addresses, Direction, Error, GRACE, MAX_DURATION, MAX_PING_INTERVAL, MAX_PINGS, MAX_STREAMS,
    MIN_DURATION, MIN_PING_INTERVAL, Measurement, PING_IDENT, PING_TIMEOUT, Phase, PingProgress,
    Progress, RESPONDER_PORT, Stack, echo_reply, echo_request, header, icmp_socket, tcp_socket,
};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{icmp, tcp};
use smoltcp::wire::{IpAddress, Ipv4Address};
use std::time::Duration;

/// Most one-second samples kept.
const SAMPLE_LIMIT: usize = 30;
/// First local port of tester streams.
const FIRST_PORT: u16 = 40_000;

enum Stage {
    /// Waiting for the handshake, then writing the header.
    Opening { written: usize },
    /// Upload: sending until the end; download: counting until the FIN.
    Streaming,
    /// Upload: FIN sent, reading the responder's 8-byte count.
    Confirming { count: [u8; 8], read: usize },
    /// Finished; `counted` holds the result.
    Done,
}

struct Stream {
    handle: SocketHandle,
    stage: Stage,
    /// Bytes counted so far (upload: acknowledged; download: received).
    counted: u64,
    /// Upload bytes handed to the socket.
    queued: u64,
}

struct Speed {
    direction: Direction,
    duration: Duration,
    streams: Vec<Stream>,
    samples: Vec<u64>,
    last_sample: (Duration, u64),
}

struct Ping {
    socket: SocketHandle,
    count: u16,
    interval: Duration,
    sent_at: Vec<Duration>,
    rtts: Vec<Option<Duration>>,
}

enum Kind {
    Speed(Speed),
    Ping(Ping),
}

struct Test {
    kind: Kind,
    start: Duration,
    phase: Phase,
    ended: Option<Duration>,
    error: Option<&'static str>,
}

/// The testing side of a connected session.
pub struct Tester {
    addresses: Addresses,
    stack: Stack,
    test: Option<Test>,
    next_port: u16,
}
impl Tester {
    /// A tester on the agreed `addresses` for test packets up to `mtu`
    /// bytes; `seed` seeds the stack's sequence numbers.
    pub fn new(addresses: Addresses, mtu: usize, seed: u64, now: Duration) -> Result<Self, Error> {
        addresses.validate()?;
        Ok(Self {
            addresses,
            stack: Stack::new(addresses.tester, addresses.responder, mtu, seed, now)?,
            test: None,
            next_port: FIRST_PORT,
        })
    }
    fn idle(&self) -> Result<(), Error> {
        match &self.test {
            Some(test) if test.phase == Phase::Running => Err(Error::Busy),
            _ => Ok(()),
        }
    }
    /// Release the sockets of a finished test.
    fn release(&mut self) {
        if let Some(test) = self.test.take() {
            match test.kind {
                Kind::Speed(speed) => {
                    for stream in speed.streams {
                        self.stack.sockets.remove(stream.handle);
                    }
                }
                Kind::Ping(ping) => {
                    self.stack.sockets.remove(ping.socket);
                }
            }
        }
    }
    /// Start a speed test of `streams` TCP streams for `duration`.
    pub fn start_speed(
        &mut self,
        direction: Direction,
        streams: u8,
        duration: Duration,
        now: Duration,
    ) -> Result<(), Error> {
        self.idle()?;
        if !(1..=MAX_STREAMS).contains(&streams) {
            return Err(Error::Invalid("streams must be 1 through 8"));
        }
        if !(MIN_DURATION..=MAX_DURATION).contains(&duration) {
            return Err(Error::Invalid("duration must be 1 through 30 seconds"));
        }
        self.release();
        let mut handles = Vec::with_capacity(usize::from(streams));
        for _ in 0..streams {
            let mut socket = tcp_socket();
            let port = self.next_port;
            self.next_port = if port >= 60_000 { FIRST_PORT } else { port + 1 };
            let connected = socket.connect(
                self.stack.interface.context(),
                (IpAddress::Ipv4(self.addresses.responder), RESPONDER_PORT),
                (IpAddress::Ipv4(self.addresses.tester), port),
            );
            if connected.is_err() {
                for handle in handles {
                    self.stack.sockets.remove(handle);
                }
                return Err(Error::Stack);
            }
            handles.push(self.stack.sockets.add(socket));
        }
        self.test = Some(Test {
            kind: Kind::Speed(Speed {
                direction,
                duration,
                streams: handles
                    .into_iter()
                    .map(|handle| Stream {
                        handle,
                        stage: Stage::Opening { written: 0 },
                        counted: 0,
                        queued: 0,
                    })
                    .collect(),
                samples: Vec::new(),
                last_sample: (now, 0),
            }),
            start: now,
            phase: Phase::Running,
            ended: None,
            error: None,
        });
        Ok(())
    }
    /// Start `count` pings `interval` apart.
    pub fn start_ping(
        &mut self,
        count: u16,
        interval: Duration,
        now: Duration,
    ) -> Result<(), Error> {
        self.idle()?;
        if !(1..=MAX_PINGS).contains(&count) {
            return Err(Error::Invalid("count must be 1 through 100"));
        }
        if !(MIN_PING_INTERVAL..=MAX_PING_INTERVAL).contains(&interval) {
            return Err(Error::Invalid("interval must be 100 through 1000 ms"));
        }
        self.release();
        let mut socket = icmp_socket();
        socket
            .bind(icmp::Endpoint::Ident(PING_IDENT))
            .map_err(|_| Error::Stack)?;
        let socket = self.stack.sockets.add(socket);
        self.test = Some(Test {
            kind: Kind::Ping(Ping {
                socket,
                count,
                interval,
                sent_at: Vec::with_capacity(usize::from(count)),
                rtts: Vec::with_capacity(usize::from(count)),
            }),
            start: now,
            phase: Phase::Running,
            ended: None,
            error: None,
        });
        Ok(())
    }
    /// Cancel a running test; its sockets are reset.
    pub fn cancel(&mut self) {
        if let Some(test) = &mut self.test
            && test.phase == Phase::Running
        {
            if let Kind::Speed(speed) = &test.kind {
                for stream in &speed.streams {
                    self.stack
                        .sockets
                        .get_mut::<tcp::Socket>(stream.handle)
                        .abort();
                }
            }
            test.phase = Phase::Cancelled;
            test.ended = Some(self.stack.last);
        }
    }
    /// Fail a running test, e.g. because its session ended.
    pub fn fail(&mut self, reason: &'static str) {
        if let Some(test) = &mut self.test
            && test.phase == Phase::Running
        {
            test.phase = Phase::Failed;
            test.ended = Some(self.stack.last);
            test.error = Some(reason);
        }
    }
    /// Queue one flagged test packet from the peer.
    pub fn deliver(&mut self, packet: &[u8]) {
        self.stack.queues.deliver(packet);
    }
    /// Next packet to send to the peer, flagged.
    pub fn next_outbound(&mut self) -> Option<Vec<u8>> {
        self.stack.queues.outgoing.pop_front()
    }
    /// Peer packets dropped (queue full or oversized).
    pub fn dropped(&self) -> u64 {
        self.stack.queues.dropped
    }
    /// When to call [`Tester::poll`] next.
    pub fn poll_at(&mut self, now: Duration) -> Option<Duration> {
        let stack = self.stack.poll_at(now);
        let running = self
            .test
            .as_ref()
            .is_some_and(|test| test.phase == Phase::Running);
        if !running {
            return stack;
        }
        // Sample and refill streams every millisecond while running.
        let soon = now + Duration::from_millis(1);
        Some(stack.map_or(soon, |at| at.min(soon)))
    }
    /// Run the stack and the test at `now`.
    pub fn poll(&mut self, now: Duration) -> Result<(), Error> {
        self.stack.advance(now)?;
        if let Some(test) = &mut self.test
            && test.phase == Phase::Running
        {
            let outcome = match &mut test.kind {
                Kind::Speed(speed) => drive_speed(&mut self.stack, speed, test.start, now),
                Kind::Ping(ping) => drive_ping(
                    &mut self.stack,
                    ping,
                    self.addresses.responder,
                    test.start,
                    now,
                ),
            };
            match outcome {
                Ok(true) => {
                    test.phase = Phase::Completed;
                    test.ended = Some(now);
                }
                Ok(false) => {}
                Err(reason) => {
                    test.phase = Phase::Failed;
                    test.ended = Some(now);
                    test.error = Some(reason);
                    if let Kind::Speed(speed) = &test.kind {
                        for stream in &speed.streams {
                            self.stack
                                .sockets
                                .get_mut::<tcp::Socket>(stream.handle)
                                .abort();
                        }
                    }
                }
            }
        }
        self.stack.advance(now)
    }
    /// The current or last test.
    pub fn progress(&self, now: Duration) -> Option<Progress> {
        let test = self.test.as_ref()?;
        let elapsed = test.ended.unwrap_or(now).saturating_sub(test.start);
        let measurement = match &test.kind {
            Kind::Speed(speed) => Measurement::Speed {
                direction: speed.direction,
                streams: u8::try_from(speed.streams.len()).unwrap_or(MAX_STREAMS),
                duration: speed.duration,
                bytes: speed.streams.iter().map(|stream| stream.counted).sum(),
                samples: speed.samples.clone(),
            },
            Kind::Ping(ping) => Measurement::Ping(PingProgress {
                sent: u16::try_from(ping.sent_at.len()).unwrap_or(MAX_PINGS),
                rtts: ping.rtts.clone(),
            }),
        };
        Some(Progress {
            phase: test.phase,
            elapsed,
            measurement,
            error: test.error,
        })
    }
}

/// Drive every stream; `Ok(true)` when all finished.
fn drive_speed(
    stack: &mut Stack,
    speed: &mut Speed,
    start: Duration,
    now: Duration,
) -> Result<bool, &'static str> {
    let end = start + speed.duration;
    for stream in &mut speed.streams {
        let socket = stack.sockets.get_mut::<tcp::Socket>(stream.handle);
        drive_stream(
            socket,
            stream,
            speed.direction,
            speed.duration,
            start,
            end,
            now,
        )?;
    }
    let total: u64 = speed.streams.iter().map(|stream| stream.counted).sum();
    // One sample per completed second of the measuring window.
    while speed.samples.len() < SAMPLE_LIMIT
        && now >= speed.last_sample.0 + Duration::from_secs(1)
        && speed.last_sample.0 < end
    {
        let delta = total.saturating_sub(speed.last_sample.1);
        speed.samples.push(delta.saturating_mul(8));
        speed.last_sample = (speed.last_sample.0 + Duration::from_secs(1), total);
    }
    Ok(speed
        .streams
        .iter()
        .all(|stream| matches!(stream.stage, Stage::Done)))
}

fn drive_stream(
    socket: &mut tcp::Socket<'static>,
    stream: &mut Stream,
    direction: Direction,
    duration: Duration,
    start: Duration,
    end: Duration,
    now: Duration,
) -> Result<(), &'static str> {
    loop {
        match &mut stream.stage {
            Stage::Opening { written } => {
                if !socket.may_send() {
                    if socket.state() == tcp::State::Closed {
                        return Err("the responder refused the test connection");
                    }
                    if now > start + crate::GRACE {
                        return Err("the test connection did not open (no peer responder?)");
                    }
                    return Ok(());
                }
                let request = header(direction, duration);
                if let Ok(sent) = socket.send_slice(&request[*written..]) {
                    *written += sent;
                }
                if *written < request.len() {
                    return Ok(());
                }
                stream.stage = Stage::Streaming;
            }
            Stage::Streaming => match direction {
                Direction::Upload => {
                    stream.counted = stream.queued.saturating_sub(socket.send_queue() as u64);
                    if now >= end {
                        socket.close();
                        stream.stage = Stage::Confirming {
                            count: [0; 8],
                            read: 0,
                        };
                        continue;
                    }
                    if !socket.may_send() {
                        return Err("the responder closed the upload early");
                    }
                    while socket.can_send() {
                        let sent = socket
                            .send(|buffer| {
                                buffer.fill(0);
                                (buffer.len(), buffer.len())
                            })
                            .unwrap_or(0);
                        if sent == 0 {
                            break;
                        }
                        stream.queued = stream.queued.saturating_add(sent as u64);
                    }
                    return Ok(());
                }
                Direction::Download => {
                    while let Ok(read) = socket.recv(|buffer| (buffer.len(), buffer.len())) {
                        if read == 0 {
                            break;
                        }
                        stream.counted = stream.counted.saturating_add(read as u64);
                    }
                    if !socket.may_recv() {
                        socket.close();
                        stream.stage = Stage::Done;
                        return Ok(());
                    }
                    if now > end + GRACE {
                        return Err("the download did not end");
                    }
                    return Ok(());
                }
            },
            Stage::Confirming { count, read } => {
                stream.counted = stream.queued.saturating_sub(socket.send_queue() as u64);
                if let Ok(got) = socket.recv_slice(&mut count[*read..]) {
                    *read += got;
                }
                if *read == count.len() {
                    // The responder's count is what arrived.
                    stream.counted = u64::from_be_bytes(*count);
                    stream.stage = Stage::Done;
                    return Ok(());
                }
                if !socket.may_recv() || now > end + GRACE {
                    return Err("the responder did not confirm the upload");
                }
                return Ok(());
            }
            Stage::Done => return Ok(()),
        }
    }
}

/// Send due probes and collect replies; `Ok(true)` when all are answered or
/// timed out.
fn drive_ping(
    stack: &mut Stack,
    ping: &mut Ping,
    responder: Ipv4Address,
    start: Duration,
    now: Duration,
) -> Result<bool, &'static str> {
    let socket = stack.sockets.get_mut::<icmp::Socket>(ping.socket);
    while let Ok((bytes, _)) = socket.recv() {
        if let Some(sequence) = echo_reply(PING_IDENT, bytes) {
            let index = usize::from(sequence);
            if let (Some(sent), Some(slot)) = (ping.sent_at.get(index), ping.rtts.get_mut(index))
                && slot.is_none()
                && now.saturating_sub(*sent) <= PING_TIMEOUT
            {
                *slot = Some(now.saturating_sub(*sent));
            }
        }
    }
    let next = ping.sent_at.len();
    if next < usize::from(ping.count) {
        let due = start + ping.interval * u32::try_from(next).unwrap_or(u32::MAX);
        if now >= due && socket.can_send() {
            let sequence = u16::try_from(next).unwrap_or(u16::MAX);
            if socket
                .send_slice(
                    &echo_request(PING_IDENT, sequence),
                    IpAddress::Ipv4(responder),
                )
                .is_ok()
            {
                ping.sent_at.push(now);
                ping.rtts.push(None);
            }
        }
        return Ok(false);
    }
    let last = ping.sent_at.last().copied().unwrap_or(start);
    Ok(ping.rtts.iter().all(Option::is_some) || now > last + PING_TIMEOUT)
}
