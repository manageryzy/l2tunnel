use super::*;
use crate::State;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(reverse: bool, ipv6: bool) -> IpConfig {
    let (a, b) = if ipv6 {
        (
            SocketAddr::from(([0xfd42, 0x88, 0, 0, 0, 0, 0, 1], 21000)),
            SocketAddr::from(([0xfd42, 0x88, 0, 0, 0, 0, 0, 2], 21001)),
        )
    } else {
        (
            SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(10, 88, 0, 1), 21000)),
            SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(10, 88, 0, 2), 21001)),
        )
    };
    IpConfig {
        local: if reverse { b } else { a },
        peer: if reverse { a } else { b },
        mtu: if ipv6 { 1280 } else { 576 },
        send_bytes: 4096,
        receive_bytes: 131_072,
        packet_slots: 8,
        random_seed: if reverse { 0x8899 } else { 0x7788 },
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 30_000,
    }
}
fn pair(ipv6: bool) -> Result<(TrackedEngine, TrackedEngine), Error> {
    Ok((
        TrackedEngine::new_ip(config(false, ipv6), Role::Client, Millis(0))?,
        TrackedEngine::new_ip(config(true, ipv6), Role::Server, Millis(0))?,
    ))
}
#[derive(Default)]
struct Network {
    pending: VecDeque<(bool, Vec<u8>)>,
    emitted: usize,
}
impl Network {
    fn step(&mut self, a: &mut TrackedEngine, b: &mut TrackedEngine, now: u64) -> TestResult {
        while let Some((reverse, packet)) = self.pending.pop_front() {
            if reverse { &mut *a } else { &mut *b }.ingest(&packet)?;
        }
        a.poll(Millis(now), 8)?;
        b.poll(Millis(now), 8)?;
        for (reverse, sender) in [(false, a), (true, b)] {
            while let Some(packet) = sender.pop_packet() {
                assert!(packet.len() <= sender.inner.config.mtu);
                self.pending.push_back((reverse, packet));
                self.emitted += 1;
            }
        }
        assert!(self.pending.len() <= 16);
        Ok(())
    }
}
fn connect(
    a: &mut TrackedEngine,
    b: &mut TrackedEngine,
    net: &mut Network,
) -> Result<u64, Box<dyn std::error::Error>> {
    for now in 0..100 {
        net.step(a, b, now)?;
        if a.status().state == State::Established
            && b.status().state == State::Established
            && net.pending.is_empty()
        {
            return Ok(now);
        }
    }
    Err("tracked handshake stalled".into())
}
fn drain(engine: &mut TrackedEngine, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut bytes = [0; 777];
    while let ReadOutcome::Data(n) = engine.read(&mut bytes)? {
        output.extend_from_slice(&bytes[..n]);
    }
    Ok(())
}
fn exchange(
    a: &mut TrackedEngine,
    b: &mut TrackedEngine,
    net: &mut Network,
    start: u64,
    ab: &[u8],
    ba: &[u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let (mut sent_a, mut sent_b) = (0, 0);
    let (mut received_a, mut received_b) = (Vec::new(), Vec::new());
    for now in start..start + 2000 {
        if sent_a < ab.len() {
            sent_a += a.write(&ab[sent_a..])?;
        }
        if sent_b < ba.len() {
            sent_b += b.write(&ba[sent_b..])?;
        }
        net.step(a, b, now)?;
        drain(a, &mut received_a)?;
        drain(b, &mut received_b)?;
        if received_a == ba
            && received_b == ab
            && net.pending.is_empty()
            && a.snapshot(Millis(now)).is_ok()
            && b.snapshot(Millis(now)).is_ok()
        {
            return Ok(now);
        }
    }
    Err("tracked prefixes did not quiesce".into())
}
fn rejected(
    engine: TrackedEngine,
    now: Millis,
    expected: HandoffError,
) -> Result<TrackedEngine, Box<dyn std::error::Error>> {
    let address = std::ptr::from_ref(engine.inner.as_ref());
    let (before, counts, last_time) = (engine.status(), engine.progress(), engine.inner.last_time);
    match engine.try_into_quiescent(now) {
        Err((returned, error)) => {
            assert_eq!(error, expected);
            assert_eq!(std::ptr::from_ref(returned.inner.as_ref()), address);
            assert_eq!(returned.status(), before);
            assert_eq!(returned.progress(), counts);
            assert_eq!(returned.inner.last_time, last_time);
            Ok(returned)
        }
        Ok(_) => Err("rejected consume returned capability".into()),
    }
}
fn consume(engine: TrackedEngine, now: Millis) -> Result<QuiescentTcp, Box<dyn std::error::Error>> {
    engine
        .try_into_quiescent(now)
        .map_err(|(_, error)| error.into())
}

#[test]
fn original_duplex_prefixes_count_partial_io_and_preserve_authoritative_sequences() -> TestResult {
    for ipv6 in [false, true] {
        let (mut a, mut b) = pair(ipv6)?;
        let mut net = Network::default();
        let start = connect(&mut a, &mut b, &mut net)?;
        let ab: Vec<u8> = (0..17_001).map(|i| (i * 31) as u8).collect();
        let ba: Vec<u8> = (0..12_003).map(|i| (i * 13) as u8).collect();
        let now = exchange(&mut a, &mut b, &mut net, start, &ab, &ba)?;
        assert_eq!(
            a.progress(),
            StreamProgress {
                send_admitted: ab.len() as u64,
                receive_consumed: ba.len() as u64
            }
        );
        assert_eq!(
            b.progress(),
            StreamProgress {
                send_admitted: ba.len() as u64,
                receive_consumed: ab.len() as u64
            }
        );
        let emitted = net.emitted;
        let qa = consume(a, Millis(now))?;
        let qb = consume(b, Millis(now))?;
        assert_eq!(qa.snapshot().tcp.send_next, qb.snapshot().tcp.receive_next);
        assert_eq!(qb.snapshot().tcp.send_next, qa.snapshot().tcp.receive_next);
        assert_eq!(qa.snapshot().role, Role::Client);
        assert_eq!(qb.snapshot().role, Role::Server);
        assert_eq!(qa.snapshot().config.local, qb.snapshot().config.peer);
        assert_eq!(qa.snapshot().polled_at, Millis(now));
        drop((qa, qb));
        assert_eq!(net.emitted, emitted);
        assert!(net.pending.is_empty());
    }
    Ok(())
}

#[test]
fn empty_handshake_cannot_turn_unscaled_syn_window_into_phase_window() -> TestResult {
    let (mut a, mut b) = pair(false)?;
    let mut net = Network::default();
    let start = connect(&mut a, &mut b, &mut net)?;
    let socket = b
        .inner
        .endpoint()
        .quiescent_snapshot(super::super::time(Millis(start))?)
        .ok_or("logical snapshot")?;
    assert!(socket.local_window_shift > 0);
    assert_eq!(socket.last_window_sent, u16::MAX);
    b = rejected(b, Millis(start), HandoffError::EmptyPrefix)?;
    a = rejected(a, Millis(start), HandoffError::EmptyPrefix)?;
    let now = exchange(
        &mut a,
        &mut b,
        &mut net,
        start,
        b"TLS ciphertext A",
        b"TLS ciphertext B",
    )?;
    let q = consume(b, Millis(now))?;
    assert!(q.snapshot().tcp.last_window_sent < u16::MAX);
    let advertised =
        usize::from(q.snapshot().tcp.last_window_sent) << q.snapshot().tcp.local_window_shift;
    assert!(advertised <= q.snapshot().config.receive_bytes);
    Ok(())
}

#[test]
fn counter_exhaustion_precedes_send_receive_and_output_mutation() -> TestResult {
    let (mut a, mut b) = pair(false)?;
    let mut net = Network::default();
    let start = connect(&mut a, &mut b, &mut net)?;
    a.progress.send_admitted = u64::MAX - 2;
    let state = a.status();
    assert_eq!(
        a.write(b"four"),
        Err(Error::CounterExhausted(StreamSide::Send))
    );
    assert_eq!(a.status(), state);
    assert_eq!(a.progress().send_admitted, u64::MAX - 2);
    assert_eq!(a.write(b"hi")?, 2);
    assert_eq!(a.progress().send_admitted, u64::MAX);
    assert_eq!(
        a.write(b"x"),
        Err(Error::CounterExhausted(StreamSide::Send))
    );
    for now in start..start + 20 {
        net.step(&mut a, &mut b, now)?;
    }
    assert_eq!(b.status().receive_bytes, 2);
    b.progress.receive_consumed = u64::MAX - 1;
    let state = b.status();
    let mut output = [0xa5; 4];
    assert_eq!(
        b.read(&mut output),
        Err(Error::CounterExhausted(StreamSide::Receive))
    );
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(b.status(), state);
    assert_eq!(b.progress().receive_consumed, u64::MAX - 1);
    assert_eq!(b.read(&mut output[..1])?, ReadOutcome::Data(1));
    assert_eq!(b.progress().receive_consumed, u64::MAX);
    output.fill(0xa5);
    assert_eq!(
        b.read(&mut output),
        Err(Error::CounterExhausted(StreamSide::Receive))
    );
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(b.status().receive_bytes, 1);
    Ok(())
}

#[test]
fn consume_failure_returns_same_owner_for_clock_queues_and_pending_stream() -> TestResult {
    let (mut a, mut b) = pair(false)?;
    a = rejected(a, Millis(0), HandoffError::StalePoll)?;
    a = rejected(a, Millis(u64::MAX), HandoffError::Time)?;
    let mut net = Network::default();
    let start = connect(&mut a, &mut b, &mut net)?;
    let now = exchange(&mut a, &mut b, &mut net, start, b"first", b"second")?;
    a = rejected(a, Millis(now + 1), HandoffError::StalePoll)?;
    assert_eq!(a.write(b"unacknowledged")?, 14);
    a = rejected(a, Millis(now), HandoffError::NotQuiescent)?;
    a.poll(Millis(now), 8)?;
    a = rejected(a, Millis(now), HandoffError::QueuedPacket)?;
    let packet = a.pop_packet().ok_or("data packet")?;
    a = rejected(a, Millis(now), HandoffError::NotQuiescent)?;
    b.ingest(&packet)?;
    b = rejected(b, Millis(now), HandoffError::QueuedPacket)?;
    b.poll(Millis(now + 1), 8)?;
    while b.pop_packet().is_some() {}
    b = rejected(b, Millis(now + 1), HandoffError::NotQuiescent)?;
    assert_eq!(b.status().receive_bytes, 14);
    assert_eq!(a.progress().send_admitted, 19);
    Ok(())
}

#[test]
fn logical_capability_does_not_claim_a_removed_ack_was_physically_sent() -> TestResult {
    let (mut a, mut b) = pair(false)?;
    let mut net = Network::default();
    let start = connect(&mut a, &mut b, &mut net)?;
    let now = exchange(&mut a, &mut b, &mut net, start, b"prefix A", b"prefix B")?;
    a.write(b"tail")?;
    a.poll(Millis(now), 8)?;
    b.ingest(&a.pop_packet().ok_or("tail packet")?)?;
    b.poll(Millis(now + 1), 8)?;
    let mut tail = [0; 4];
    assert_eq!(b.read(&mut tail)?, ReadOutcome::Data(4));
    b.poll(Millis(now + 20), 8)?;
    let retained_ack = b.pop_packet().ok_or("final ACK")?;
    assert!(b.pop_packet().is_none());
    let q = consume(b, Millis(now + 20))?;
    assert_eq!(q.snapshot().progress.receive_consumed, 12);
    assert!(!retained_ack.is_empty());
    a = rejected(a, Millis(now), HandoffError::NotQuiescent)?;
    assert_eq!(a.status().send_bytes, 4);
    // The future I/O driver must reject this transfer while retained_ack is unsent.
    Ok(())
}

#[test]
fn timestamp_close_and_abort_cannot_be_hidden_by_consume() -> TestResult {
    for operation in 0..3 {
        let (mut a, mut b) = pair(false)?;
        let mut net = Network::default();
        let start = connect(&mut a, &mut b, &mut net)?;
        let now = exchange(&mut a, &mut b, &mut net, start, b"A", b"B")?;
        let error = match operation {
            0 => {
                a.inner.endpoint_mut().set_tsval_generator(Some(|| 1));
                HandoffError::UnsupportedOption
            }
            1 => {
                a.close();
                HandoffError::NotQuiescent
            }
            _ => {
                a.abort();
                HandoffError::NotQuiescent
            }
        };
        a = rejected(a, Millis(now), error)?;
        assert_eq!(a.progress().send_admitted, 1);
    }
    Ok(())
}

#[test]
fn delegated_failures_pending_and_zero_progress_do_not_charge_counters() -> TestResult {
    let (mut a, mut b) = pair(false)?;
    assert_eq!(a.ingest(&[]), Err(Error::Engine(crate::Error::Malformed)));
    let mut output = [0xa5; 8];
    assert_eq!(a.read(&mut output)?, ReadOutcome::Pending);
    assert_eq!(output, [0xa5; 8]);
    assert_eq!(
        a.read(&mut []),
        Err(Error::Engine(crate::Error::EmptyBuffer))
    );
    assert_eq!(a.progress(), StreamProgress::default());
    a.set_time_wait_reset_policy(TimeWaitResetPolicy::IgnoreInTimeWait)?;
    let mut net = Network::default();
    let start = connect(&mut a, &mut b, &mut net)?;
    assert_eq!(
        a.set_time_wait_reset_policy(TimeWaitResetPolicy::Maintained),
        Err(Error::Engine(crate::Error::InvalidConfig))
    );
    assert_eq!(a.write(&vec![1; 5000])?, 4096);
    assert_eq!(a.write(b"blocked")?, 0);
    assert_eq!(a.progress().send_admitted, 4096);
    assert_eq!(
        a.poll(Millis(start - 1), 8),
        Err(Error::Engine(crate::Error::Time))
    );
    assert_eq!(a.progress().send_admitted, 4096);
    Ok(())
}
