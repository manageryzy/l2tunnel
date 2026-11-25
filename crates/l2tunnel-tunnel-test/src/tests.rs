use super::*;
use std::collections::VecDeque;

/// An agreed test pair, as the control exchange would produce.
const PAIR: crate::Addresses = crate::Addresses {
    tester: smoltcp::wire::Ipv4Address::new(10, 77, 0, 1),
    responder: smoltcp::wire::Ipv4Address::new(10, 77, 0, 2),
};

/// A one-way link: at most `per_ms` packets per millisecond, `delay`
/// latency, and every `lose_every`-th packet dropped (0 keeps all).
struct Link {
    per_ms: usize,
    delay: Duration,
    lose_every: u64,
    sent: u64,
    flight: VecDeque<(Duration, Vec<u8>)>,
}
impl Link {
    fn new(per_ms: usize, delay_ms: u64, lose_every: u64) -> Self {
        Self {
            per_ms,
            delay: Duration::from_millis(delay_ms),
            lose_every,
            sent: 0,
            flight: VecDeque::new(),
        }
    }
    fn send(&mut self, now: Duration, next: &mut dyn FnMut() -> Option<Vec<u8>>) {
        for _ in 0..self.per_ms {
            let Some(packet) = next() else { break };
            self.sent += 1;
            if self.lose_every != 0 && self.sent.is_multiple_of(self.lose_every) {
                continue;
            }
            self.flight.push_back((now + self.delay, packet));
        }
    }
    fn arrive(&mut self, now: Duration, deliver: &mut dyn FnMut(&[u8])) {
        while self.flight.front().is_some_and(|(at, _)| *at <= now) {
            if let Some((_, packet)) = self.flight.pop_front() {
                deliver(&packet);
            }
        }
    }
}

struct Pair {
    tester: Tester,
    responder: Responder,
    up: Link,
    down: Link,
    now: Duration,
}
impl Pair {
    fn new(per_ms: usize, delay_ms: u64, lose_every: u64) -> Result<Self, Error> {
        Ok(Self {
            tester: Tester::new(PAIR, 1500, 1, Duration::ZERO)?,
            responder: Responder::new(PAIR, 1500, 2, Duration::ZERO)?,
            up: Link::new(per_ms, delay_ms, lose_every),
            down: Link::new(per_ms, delay_ms, lose_every),
            now: Duration::ZERO,
        })
    }
    /// Advance one millisecond.
    fn step(&mut self) -> Result<(), Error> {
        self.now += Duration::from_millis(1);
        let now = self.now;
        let (tester, responder) = (&mut self.tester, &mut self.responder);
        self.up.arrive(now, &mut |packet| responder.deliver(packet));
        self.down.arrive(now, &mut |packet| tester.deliver(packet));
        tester.poll(now)?;
        responder.poll(now)?;
        self.up.send(now, &mut || tester.next_outbound());
        self.down.send(now, &mut || responder.next_outbound());
        Ok(())
    }
    /// Run until the test ends or `limit` passes.
    fn run(&mut self, limit: Duration) -> Result<Option<Progress>, Error> {
        while self.now < limit {
            self.step()?;
            if self
                .tester
                .progress(self.now)
                .is_some_and(|progress| progress.phase != Phase::Running)
            {
                break;
            }
        }
        Ok(self.tester.progress(self.now))
    }
}

/// 10 packets per millisecond of up to 1500 bytes is at most 120 Mbit/s.
const CAP: u64 = 120_000_000;

#[test]
fn upload_and_download_measure_the_link() -> Result<(), Error> {
    for direction in [Direction::Upload, Direction::Download] {
        let mut pair = Pair::new(10, 5, 0)?;
        pair.tester
            .start_speed(direction, 2, Duration::from_secs(2), Duration::ZERO)?;
        let progress = pair.run(Duration::from_secs(10))?;
        let Some(progress) = progress else {
            return Err(Error::Invalid("no progress"));
        };
        assert_eq!(
            progress.phase,
            Phase::Completed,
            "{direction:?} {progress:?}"
        );
        let rate = progress.bits_per_second();
        assert!(
            rate > CAP / 3 && rate <= CAP,
            "{direction:?} measured {rate} bit/s"
        );
        let Measurement::Speed { samples, bytes, .. } = &progress.measurement else {
            return Err(Error::Invalid("not a speed test"));
        };
        assert!(*bytes > 0);
        assert!((1..=3).contains(&samples.len()), "{samples:?}");
    }
    Ok(())
}

#[test]
fn speed_survives_loss() -> Result<(), Error> {
    let mut pair = Pair::new(10, 5, 50)?;
    pair.tester
        .start_speed(Direction::Upload, 1, Duration::from_secs(2), Duration::ZERO)?;
    let progress = pair.run(Duration::from_secs(15))?;
    assert_eq!(
        progress.map(|progress| progress.phase),
        Some(Phase::Completed)
    );
    Ok(())
}

/// Slow links (~1.5 Mbit/s) must drain their upload queue and receive the
/// responder's confirmation well within `GRACE`.
#[test]
fn slow_upload_confirms_within_grace() -> Result<(), Error> {
    let mut pair = Pair::new(1, 20, 0)?;
    pair.tester
        .start_speed(Direction::Upload, 1, Duration::from_secs(3), Duration::ZERO)?;
    // Pace to ~1.5 Mbit/s (1 packet every 8 ms).
    let mut step = 0_u64;
    while pair.now < Duration::from_secs(12) {
        pair.now += Duration::from_millis(1);
        let now = pair.now;
        pair.up.arrive(now, &mut |pkt| pair.responder.deliver(pkt));
        pair.down.arrive(now, &mut |pkt| pair.tester.deliver(pkt));
        pair.tester.poll(now)?;
        pair.responder.poll(now)?;
        if step.is_multiple_of(8) {
            pair.up.send(now, &mut || pair.tester.next_outbound());
        }
        pair.down.send(now, &mut || pair.responder.next_outbound());
        step += 1;
        if pair
            .tester
            .progress(now)
            .is_some_and(|p| p.phase != Phase::Running)
        {
            break;
        }
    }
    let progress = pair
        .tester
        .progress(pair.now)
        .ok_or(Error::Invalid("none"))?;
    assert_eq!(progress.phase, Phase::Completed, "{progress:?}");
    assert!(progress.elapsed < Duration::from_secs(5), "{progress:?}");
    Ok(())
}

#[test]
fn ping_measures_round_trips_and_loss() -> Result<(), Error> {
    let mut pair = Pair::new(10, 10, 0)?;
    pair.tester
        .start_ping(5, Duration::from_millis(100), Duration::ZERO)?;
    let progress = pair.run(Duration::from_secs(5))?;
    let Some(Progress {
        phase,
        measurement: Measurement::Ping(ping),
        ..
    }) = progress
    else {
        return Err(Error::Invalid("no ping progress"));
    };
    assert_eq!((phase, ping.sent), (Phase::Completed, 5));
    for rtt in &ping.rtts {
        let rtt = rtt.unwrap_or_default();
        assert!(
            rtt >= Duration::from_millis(20) && rtt <= Duration::from_millis(23),
            "{rtt:?}"
        );
    }
    // Every packet lost: all probes time out.
    let mut pair = Pair::new(10, 10, 1)?;
    pair.tester
        .start_ping(3, Duration::from_millis(100), Duration::ZERO)?;
    let progress = pair.run(Duration::from_secs(5))?;
    let Some(Progress {
        phase,
        measurement: Measurement::Ping(ping),
        ..
    }) = progress
    else {
        return Err(Error::Invalid("no ping progress"));
    };
    assert_eq!((phase, ping.sent), (Phase::Completed, 3));
    assert!(ping.rtts.iter().all(Option::is_none));
    Ok(())
}

#[test]
fn no_responder_fails_and_bounds_are_checked() -> Result<(), Error> {
    let mut tester = Tester::new(PAIR, 1500, 1, Duration::ZERO)?;
    assert_eq!(
        tester.start_speed(Direction::Upload, 0, Duration::from_secs(2), Duration::ZERO),
        Err(Error::Invalid("streams must be 1 through 8"))
    );
    assert!(
        tester
            .start_speed(
                Direction::Upload,
                1,
                Duration::from_millis(500),
                Duration::ZERO
            )
            .is_err()
    );
    assert!(
        tester
            .start_ping(0, Duration::from_millis(100), Duration::ZERO)
            .is_err()
    );
    assert!(
        tester
            .start_ping(5, Duration::from_millis(10), Duration::ZERO)
            .is_err()
    );
    assert_eq!(
        Tester::new(PAIR, 100, 1, Duration::ZERO).err(),
        Some(Error::Mtu)
    );
    tester.start_speed(Direction::Upload, 1, Duration::from_secs(2), Duration::ZERO)?;
    assert_eq!(
        tester.start_ping(1, Duration::from_millis(100), Duration::ZERO),
        Err(Error::Busy)
    );
    // Nothing answers: the stream never opens.
    let mut now = Duration::ZERO;
    while now < Duration::from_secs(7) {
        now += Duration::from_millis(10);
        tester.poll(now)?;
        while tester.next_outbound().is_some() {}
    }
    let progress = tester.progress(now);
    assert_eq!(progress.as_ref().map(|p| p.phase), Some(Phase::Failed));
    assert!(
        progress
            .and_then(|p| p.error)
            .is_some_and(|e| e.contains("did not open"))
    );
    assert_eq!(tester.poll(Duration::from_secs(1)), Err(Error::Time));
    Ok(())
}

#[test]
fn cancel_and_session_end_stop_a_test() -> Result<(), Error> {
    let mut pair = Pair::new(10, 5, 0)?;
    pair.tester.start_speed(
        Direction::Download,
        1,
        Duration::from_secs(5),
        Duration::ZERO,
    )?;
    for _ in 0..500 {
        pair.step()?;
    }
    pair.tester.cancel();
    let progress = pair.tester.progress(pair.now);
    assert_eq!(progress.as_ref().map(|p| p.phase), Some(Phase::Cancelled));
    // A new test may start after a cancelled one.
    pair.tester
        .start_ping(1, Duration::from_millis(100), pair.now)?;
    pair.tester.fail("the session ended");
    let progress = pair.tester.progress(pair.now);
    assert_eq!(progress.as_ref().map(|p| p.phase), Some(Phase::Failed));
    assert_eq!(progress.and_then(|p| p.error), Some("the session ended"));
    Ok(())
}

#[test]
fn responder_refuses_bad_headers_and_survives_garbage() -> Result<(), Error> {
    assert_eq!(
        parse_header(&header(Direction::Download, Duration::from_secs(3))),
        Some((Direction::Download, Duration::from_secs(3)))
    );
    let mut bad = header(Direction::Upload, Duration::from_secs(3));
    bad[0] = b'X';
    assert_eq!(parse_header(&bad), None);
    let long = header(Direction::Upload, Duration::from_secs(31));
    assert_eq!(parse_header(&long), None);
    let mut responder = Responder::new(PAIR, 1500, 2, Duration::ZERO)?;
    // Garbage, truncated and oversized packets are dropped without panic.
    for (index, length) in [0usize, 1, 19, 20, 40, 1500, 1501, 9000]
        .into_iter()
        .enumerate()
    {
        let packet: Vec<u8> = (0..length).map(|byte| (byte * 31 + index) as u8).collect();
        responder.deliver(&packet);
        responder.poll(Duration::from_millis(index as u64 + 1))?;
    }
    assert_eq!(responder.dropped(), 3, "empty and two oversized");
    assert_eq!(responder.connections(), 0);
    Ok(())
}
