use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        datagram_bytes: 1448,
        window: 64,
        repair_numerator: 41,
        repair_denominator: 200,
        flow_sources: 1024,
        queue_bytes: 256 * 1024,
        max_packet: 1600,
        flush_micros: 0,
        feedback_micros: 2_000,
        tail_micros: 10_000,
        min_rto_micros: 20_000,
        max_rto_micros: 1_000_000,
    }
}

/// Small deterministic generator; no external crate is needed.
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn packet(index: u32, random: &mut Random) -> Vec<u8> {
    let length = match index % 7 {
        0 => 60,
        1 | 2 => 1514,
        3 => 66,
        4 => 1,
        5 => 1600,
        _ => 200 + (random.next() % 1000) as usize,
    };
    let mut bytes: Vec<u8> = (0..length)
        .map(|i| (i as u32 ^ index.wrapping_mul(31)) as u8)
        .collect();
    // Genuine zero tails must survive packing and recovery.
    if index.is_multiple_of(5) {
        let start = bytes.len() / 2;
        bytes[start..].fill(0);
    }
    bytes
}

struct Link {
    delay: u64,
    loss: u64,
    reorder: u64,
    queue: Vec<(u64, u64, u64, Vec<u8>)>,
    sent: u64,
    lost: u64,
}
impl Link {
    fn new(delay: u64, loss: u64, reorder: u64) -> Self {
        Self {
            delay,
            loss,
            reorder,
            queue: Vec::new(),
            sent: 0,
            lost: 0,
        }
    }
    fn send(&mut self, now: u64, seed: u64, body: Vec<u8>, random: &mut Random) {
        self.sent += 1;
        if random.chance(self.loss) {
            self.lost += 1;
            return;
        }
        let extra = if random.chance(self.reorder) {
            random.next() % 3_000
        } else {
            0
        };
        self.queue
            .push((now + self.delay + extra, self.sent, seed, body));
    }
    fn deliver(&mut self, now: u64) -> Vec<(u64, Vec<u8>)> {
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.queue.len() {
            if self.queue[index].0 <= now {
                ready.push(self.queue.swap_remove(index));
            } else {
                index += 1;
            }
        }
        ready.sort_by_key(|entry| (entry.0, entry.1));
        ready
            .into_iter()
            .map(|(_, _, seed, body)| (seed, body))
            .collect()
    }
}

struct Outcome {
    sender: SenderStats,
    receiver: ReceiverStats,
    datagrams: u64,
    finished_at: u64,
}

/// Drive one direction over an impaired forward link and an impaired feedback
/// link with a per-tick datagram budget, and require exact ordered delivery.
fn transfer(
    config: Config,
    packets: u32,
    loss: u64,
    reorder: u64,
    per_tick: usize,
    seed: u64,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    transfer_from(0, config, packets, loss, reorder, per_tick, seed)
}

/// As [`transfer`], with both engines starting at sequence `start`.
fn transfer_from(
    start: u64,
    config: Config,
    packets: u32,
    loss: u64,
    reorder: u64,
    per_tick: usize,
    seed: u64,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let mut random = Random(seed);
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    sender.start_at(start);
    receiver.start_at(start);
    let mut forward = Link::new(35_000, loss, reorder);
    let mut reverse = Link::new(35_000, loss, reorder);
    let mut offered = 0;
    let mut delivered = 0;
    let mut offered_random = Random(seed ^ 0x5DEECE66D);
    let mut expected = Random(seed ^ 0x5DEECE66D);
    let mut number = 0u64;
    let mut body = Vec::new();
    let mut native = Vec::new();
    let mut now = 0u64;
    loop {
        now += 1_000;
        if now > 600_000_000 || (now > 5_000_000 && std::env::var_os("SWIFT_EARLY").is_some()) {
            return Err(format!("transfer did not finish at {now}: {delivered}/{packets} offered {offered}\n{}\n{}\n{:?}\n{:?}", sender.debug_state(), receiver.debug_state(), sender.stats(), receiver.stats()).into());
        }
        for (_, feedback) in reverse.deliver(now) {
            sender.on_feedback(now, &feedback)?;
        }
        while offered < packets && sender.has_room() {
            let bytes = packet(offered, &mut offered_random);
            assert!(sender.push_packet(now, &bytes)?);
            offered += 1;
        }
        for _ in 0..per_tick {
            number += 1;
            if !sender.poll(now, number, &mut body)? {
                break;
            }
            assert!(
                body.len() <= config.datagram_bytes,
                "datagram exceeds the configured body"
            );
            forward.send(now, number, body.clone(), &mut random);
        }
        for (seed, datagram) in forward.deliver(now) {
            receiver.on_datagram(seed, &datagram)?;
            while receiver.pop_packet(&mut native)? {
                assert_eq!(
                    native,
                    packet(delivered, &mut expected),
                    "packet {delivered}"
                );
                delivered += 1;
            }
        }
        if receiver.feedback(now, &mut body) {
            reverse.send(now, 0, body.clone(), &mut random);
        }
        if delivered == packets && sender.unconfirmed() == 0 && offered == packets {
            return Ok(Outcome {
                sender: sender.stats(),
                receiver: receiver.stats(),
                datagrams: forward.sent,
                finished_at: now,
            });
        }
    }
}

/// The wire carries 32 bits of a 64-bit sequence. A session that crosses the
/// 32-bit boundary keeps delivering exactly, with loss, reordering, repairs
/// and requested retransmissions on both sides of it.
#[test]
fn sequences_cross_the_32_bit_wire_boundary_without_ending_the_session() -> TestResult {
    for start in [(1u64 << 32) - 700, (5u64 << 32) - 1, (1u64 << 32) + 3] {
        let arq = Config {
            repair_numerator: 0,
            ..config()
        };
        for (config, seed) in [(config(), 11), (arq, 12)] {
            let outcome = transfer_from(start, config, 6_000, 15, 10, 8, seed)?;
            assert_eq!(outcome.receiver.packets, 6_000);
            assert!(outcome.sender.sources > 1_400, "{:?}", outcome.sender);
        }
    }
    assert_eq!(crate::expand(0, 5), Some(5));
    assert_eq!(crate::expand(0, u32::MAX), None);
    assert_eq!(crate::expand((1 << 32) - 2, 3), Some((1 << 32) + 3));
    assert_eq!(crate::expand((1 << 32) + 2, u32::MAX), Some((1 << 32) - 1));
    assert_eq!(crate::expand(7 << 32, 9), Some((7 << 32) + 9));
    Ok(())
}

#[test]
fn clean_link_delivers_exact_packets_with_only_proportional_repairs() -> TestResult {
    let outcome = transfer(config(), 4_000, 0, 0, 8, 1)?;
    assert_eq!(outcome.receiver.packets, 4_000);
    assert_eq!(outcome.sender.retransmits, 0);
    assert_eq!(outcome.receiver.recovered, 0);
    // 41/200 of sources, plus a few idle tail repairs at the end.
    let proportional = outcome.sender.sources * 41 / 200;
    assert!(outcome.sender.repairs <= proportional + 1);
    assert!(outcome.sender.tail_repairs <= 8, "{:?}", outcome.sender);
    Ok(())
}

#[test]
fn fifteen_percent_loss_both_ways_recovers_everything_near_the_erasure_bound() -> TestResult {
    for seed in [3, 99, 2026] {
        let outcome = transfer(config(), 8_000, 15, 10, 8, seed)?;
        assert_eq!(outcome.receiver.packets, 8_000);
        assert!(
            outcome.receiver.recovered > 0,
            "coding never recovered a loss"
        );
        let sources = outcome.sender.sources as f64;
        let extra = (outcome.datagrams as f64 - sources) / sources;
        // An ideal erasure code needs 17.6% extra datagrams at 15% loss.
        assert!(
            extra < 0.30,
            "extra datagrams {extra:.3}: {:?}",
            outcome.sender
        );
        // Most losses are repaired by coding rather than a round trip.
        assert!(
            outcome.sender.retransmits * 2 < outcome.receiver.recovered,
            "{:?} {:?}",
            outcome.sender,
            outcome.receiver
        );
    }
    Ok(())
}

#[test]
fn heavy_loss_and_tiny_windows_still_deliver_exactly() -> TestResult {
    let mut small = config();
    small.window = 4;
    small.flow_sources = 16;
    small.queue_bytes = 8 * 1024;
    for (loss, seed) in [(40, 5), (60, 6), (30, 7)] {
        let outcome = transfer(small, 1_500, loss, 30, 3, seed)?;
        assert_eq!(outcome.receiver.packets, 1_500);
        assert!(outcome.sender.retransmits > 0);
        assert!(outcome.finished_at > 0);
    }
    // No repairs at all: pure requested retransmission must still complete.
    let mut plain = config();
    plain.repair_numerator = 0;
    let outcome = transfer(plain, 3_000, 15, 0, 8, 8)?;
    assert_eq!(outcome.receiver.packets, 3_000);
    assert_eq!(outcome.sender.repairs, 0);
    Ok(())
}

#[test]
fn idle_tail_loss_is_repaired_without_new_traffic() -> TestResult {
    let mut config = config();
    config.repair_numerator = 0;
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    assert!(sender.push_packet(0, &[7; 100])?);
    let mut body = Vec::new();
    assert!(sender.poll(0, 1, &mut body)?);
    // The only source is lost. Nothing else is queued.
    assert!(!sender.poll(1_000, 2, &mut body)?);
    assert_eq!(sender.deadline(), Some(10_000));
    assert!(!sender.ready(9_999));
    assert!(sender.ready(10_000));
    assert!(sender.poll(10_000, 3, &mut body)?);
    assert_eq!(body[0], KIND_REPAIR);
    receiver.on_datagram(3, &body)?;
    let mut native = Vec::new();
    assert!(receiver.pop_packet(&mut native)?);
    assert_eq!(native, [7; 100]);
    assert!(receiver.feedback(20_000, &mut body));
    sender.on_feedback(20_000, &body)?;
    assert_eq!(sender.unconfirmed(), 0);
    assert_eq!(sender.deadline(), None);
    assert!(!sender.poll(5_000_000, 4, &mut body)?);
    Ok(())
}

#[test]
fn packets_span_symbols_and_partial_symbols_flush_immediately() -> TestResult {
    let config = config();
    let mut sender = Sender::new(config)?;
    let mut receiver = Receiver::new(config)?;
    let big = vec![0xAB; 1600];
    assert!(sender.push_packet(0, &[1, 2, 3])?);
    assert!(sender.push_packet(0, &big)?);
    let mut body = Vec::new();
    let mut native = Vec::new();
    let mut lengths = Vec::new();
    let mut seed = 0;
    while sender.poll(0, seed, &mut body)? {
        seed += 1;
        if body[0] == KIND_SOURCE {
            lengths.push(body.len() - SOURCE_HEADER);
        }
        receiver.on_datagram(seed - 1, &body)?;
    }
    // 5 + 1602 packed bytes: one full symbol and one exact remainder.
    assert_eq!(
        lengths,
        [config.symbol_bytes(), 1607 - config.symbol_bytes()]
    );
    assert!(receiver.pop_packet(&mut native)?);
    assert_eq!(native, [1, 2, 3]);
    assert!(receiver.pop_packet(&mut native)?);
    assert_eq!(native, big);
    assert!(!receiver.pop_packet(&mut native)?);
    Ok(())
}

#[test]
fn bounded_queue_and_flow_window_apply_backpressure() -> TestResult {
    let mut config = config();
    config.queue_bytes = 4_000;
    config.flow_sources = 64;
    config.repair_numerator = 0;
    let mut sender = Sender::new(config)?;
    assert!(sender.push_packet(0, &[0; 1600])?);
    assert!(sender.push_packet(0, &[0; 1600])?);
    assert!(!sender.has_room());
    assert!(
        !sender.push_packet(0, &[0; 1600])?,
        "queue bound was exceeded"
    );
    assert_eq!(sender.push_packet(0, &[]).err(), Some(Error::PacketSize));
    assert_eq!(
        sender.push_packet(0, &[0; 1601]).err(),
        Some(Error::PacketSize)
    );
    // Without feedback at most flow_sources sources are ever outstanding.
    let mut body = Vec::new();
    let mut sources = 0;
    for seed in 0..10_000 {
        while sender.has_room() {
            assert!(sender.push_packet(0, &[9; 1500])?);
        }
        if !sender.poll(0, seed, &mut body)? {
            break;
        }
        sources += 1;
    }
    assert_eq!(sources, 64);
    assert_eq!(sender.unconfirmed(), 64);
    Ok(())
}

#[test]
fn malformed_authenticated_input_is_rejected_without_panicking() -> TestResult {
    let config = config();
    let mut receiver = Receiver::new(config)?;
    for bad in [
        &[][..],
        &[9, 0, 0, 0, 0, 1][..],
        &[KIND_SOURCE, 0, 0, 0, 0][..],
        &[KIND_SOURCE, 0, 0][..],
        &[KIND_REPAIR, 0, 0, 0, 1, 0, 1, 2, 3][..],
        &[KIND_REPAIR, 0, 0, 0, 1, 2, 1, 2, 3][..],
        &[KIND_REPAIR, 0, 0, 0, 1, 1, 1][..],
    ] {
        assert_eq!(
            receiver.on_datagram(1, bad).err(),
            Some(Error::Malformed),
            "{bad:?}"
        );
    }
    // A source beyond the flow bound cannot make the receiver allocate.
    let mut far = vec![KIND_SOURCE];
    far.extend_from_slice(&5_000u32.to_be_bytes());
    far.push(1);
    assert_eq!(receiver.on_datagram(1, &far).err(), Some(Error::Malformed));
    // A packed length of zero or beyond the maximum is rejected on unpacking.
    let mut stream = vec![KIND_SOURCE, 0, 0, 0, 0];
    stream.extend_from_slice(&[0xFF, 0xFF, 1, 2, 3]);
    receiver.on_datagram(1, &stream)?;
    assert_eq!(
        receiver.pop_packet(&mut Vec::new()).err(),
        Some(Error::Malformed)
    );

    let mut sender = Sender::new(config)?;
    for bad in [
        &[][..],
        &[KIND_FEEDBACK, 0, 0, 0, 0][..],
        // end beyond anything sent
        &[KIND_FEEDBACK, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0][..],
        // base above end
        &[KIND_FEEDBACK, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0][..],
        // request count without the list
        &[KIND_FEEDBACK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2][..],
    ] {
        assert_eq!(
            sender.on_feedback(1, bad).err(),
            Some(Error::Malformed),
            "{bad:?}"
        );
    }
    let mut invalid = config;
    invalid.window = 0;
    assert_eq!(Sender::new(invalid).err().map(|_| ()), Some(()));
    invalid = config;
    invalid.flow_sources = 10;
    assert!(Receiver::new(invalid).is_err());
    Ok(())
}

/// An application that pauses leaves gaps inside the newest window with no
/// later source to age them out; delivery must still complete promptly.
#[test]
fn bursty_application_limited_traffic_never_waits_for_new_data() -> TestResult {
    for (window, permille) in [(64, 100), (8, 50), (128, 205)] {
        let mut config = config();
        config.window = window;
        config.repair_numerator = permille;
        config.repair_denominator = 1000;
        let mut random = Random(77 + window as u64);
        let mut sender = Sender::new(config)?;
        let mut receiver = Receiver::new(config)?;
        let mut forward = Link::new(35_000, 15, 0);
        let mut reverse = Link::new(35_000, 15, 0);
        let (mut offered, mut delivered, mut number) = (0u32, 0u32, 0u64);
        let (mut body, mut native) = (Vec::new(), Vec::new());
        let mut worst = 0u64;
        let mut sent_at = std::collections::VecDeque::new();
        let mut now = 0u64;
        while delivered < 6_000 {
            now += 1_000;
            assert!(
                now < 120_000_000,
                "stalled at {delivered}: {}",
                receiver.debug_state()
            );
            for (_, feedback) in reverse.deliver(now) {
                sender.on_feedback(now, &feedback)?;
            }
            // Bursts of 150 packets separated by 400 ms of silence.
            if now % 400_000 < 20_000 && offered < 6_000 {
                for _ in 0..8 {
                    if offered < 6_000 && sender.has_room() {
                        assert!(sender.push_packet(now, &[offered as u8; 1400])?);
                        sent_at.push_back(now);
                        offered += 1;
                    }
                }
            }
            for _ in 0..8 {
                number += 1;
                if !sender.poll(now, number, &mut body)? {
                    break;
                }
                forward.send(now, number, body.clone(), &mut random);
            }
            for (seed, datagram) in forward.deliver(now) {
                receiver.on_datagram(seed, &datagram)?;
                while receiver.pop_packet(&mut native)? {
                    assert_eq!(native, [delivered as u8; 1400]);
                    delivered += 1;
                    if let Some(at) = sent_at.pop_front() {
                        worst = worst.max(now - at);
                    }
                }
            }
            if receiver.feedback(now, &mut body) {
                reverse.send(now, 0, body.clone(), &mut random);
            }
        }
        // Every packet arrives well within the silence that follows its burst
        // plus a few lost round trips, never a multiple of the burst period.
        assert!(worst < 1_500_000, "window {window}: worst delay {worst} us");
    }
    Ok(())
}

#[test]
fn partial_symbols_wait_for_the_flush_time_and_full_ones_do_not() -> TestResult {
    let mut config = config();
    config.flush_micros = 1_000;
    config.repair_numerator = 0;
    let mut sender = Sender::new(config)?;
    let mut body = Vec::new();
    assert!(sender.push_packet(100, &[1; 66])?);
    assert!(!sender.ready(100));
    assert!(!sender.poll(1_099, 1, &mut body)?);
    assert_eq!(sender.deadline(), Some(1_100));
    // More small packets keep sharing the same symbol without restarting the clock.
    assert!(sender.push_packet(600, &[2; 66])?);
    assert_eq!(sender.deadline(), Some(1_100));
    assert!(sender.poll(1_100, 2, &mut body)?);
    assert_eq!(body.len(), SOURCE_HEADER + 2 * 68);
    assert_eq!(sender.queued(), 0);
    // A full symbol leaves at once; its remainder starts a new wait.
    assert!(sender.push_packet(2_000, &[3; 1500])?);
    assert!(sender.poll(2_000, 3, &mut body)?);
    assert_eq!(body.len(), SOURCE_HEADER + config.symbol_bytes());
    assert!(!sender.poll(2_999, 4, &mut body)?);
    assert!(sender.poll(3_000, 5, &mut body)?);
    assert_eq!(body.len(), SOURCE_HEADER + 1502 - config.symbol_bytes());
    assert!(!sender.urgent());
    let mut invalid = config;
    invalid.flush_micros = 1_000_001;
    assert!(Sender::new(invalid).is_err());
    Ok(())
}

/// Without proportional repairs a gap is requested after a few later sources
/// and every loss costs about one retransmission.
#[test]
fn pure_retransmission_costs_close_to_the_loss_rate() -> TestResult {
    let mut plain = config();
    plain.repair_numerator = 0;
    let outcome = transfer(plain, 8_000, 15, 0, 8, 41)?;
    assert_eq!(outcome.receiver.packets, 8_000);
    let sources = outcome.sender.sources as f64;
    let extra = (outcome.datagrams as f64 - sources) / sources;
    // 15% loss needs 17.6% extra transmissions; allow tail probes and a few
    // duplicates but nothing like a proportional repair stream on top.
    assert!(
        (0.16..0.20).contains(&extra),
        "extra {extra:.4}: {:?}",
        outcome.sender
    );
    assert!(
        outcome.receiver.duplicates * 50 < outcome.sender.sources,
        "{:?}",
        outcome.receiver
    );
    Ok(())
}

/// High-BDP 70 ms RTT + 15% bidirectional packet loss across 200/20, 300/30,
/// 500/50, and 1000/100 Mbit/s wire budgets (both ARQ and FEC).
///
/// Theoretical erasure ceiling at 15% loss is 85% of the wire budget (~82%
/// after 49 B UDP+record framing overhead). Verifies rotating gap-request
/// scanning (`request_cursor`) keeps both ARQ and FEC near that ceiling
/// without stalling as BDP grows to 1000 Mbit/s x 70 ms (~8.75 MB).
#[test]
fn high_bdp_15_percent_loss_70ms_rtt_scales_across_budgets() -> TestResult {
    const WIRE_OVERHEAD: usize = 49; // 28 B IP+UDP + 21 B record protection
    const PAYLOAD_BYTES: usize = 1400;
    const RTT_ONE_WAY_US: u64 = 35_000; // 70 ms RTT
    const LOSS_PERCENT: u64 = 15;
    #[cfg(debug_assertions)]
    const DURATION_MS: u64 = 400; // fast in debug; covers both endpoints of the budget sweep
    #[cfg(not(debug_assertions))]
    const DURATION_MS: u64 = 2_500; // >35 full 70 ms RTTs in release

    #[cfg(debug_assertions)]
    let budgets: &[(u64, u64)] = &[(200, 20), (1000, 100)];
    #[cfg(not(debug_assertions))]
    let budgets: &[(u64, u64)] = &[(200, 20), (300, 30), (500, 50), (1000, 100)];

    let payload = vec![0x5a_u8; PAYLOAD_BYTES];
    for &(fwd_mbps, rev_mbps) in budgets {
        let wire_bps = fwd_mbps * 125_000;
        let rev_bps = rev_mbps * 125_000;
        let flow_sources = ((wire_bps as usize * 70 / 1000) / 1400 * 4)
            .next_power_of_two()
            .clamp(2048, 32_768);
        let queue_bytes = (wire_bps as usize / 32).clamp(512 << 10, 4 << 20);
        for (label, repair_num, repair_den, min_eff) in [
            ("arq", 0_u32, 4_u32, 0.72_f64),
            ("fec-9/40", 9_u32, 40_u32, 0.75_f64),
            ("fec-1/4", 1_u32, 4_u32, 0.74_f64),
        ] {
            let cfg = Config {
                datagram_bytes: 1500 - WIRE_OVERHEAD,
                window: 64,
                repair_numerator: repair_num,
                repair_denominator: repair_den,
                flow_sources,
                queue_bytes,
                max_packet: 1600,
                flush_micros: 250,
                feedback_micros: 1_000,
                tail_micros: 10_000,
                min_rto_micros: 80_000,
                max_rto_micros: 1_000_000,
            };
            let mut random = Random(0x2026_1125 ^ fwd_mbps ^ (u64::from(repair_num) << 16));
            let mut sender = Sender::new(cfg)?;
            let mut receiver = Receiver::new(cfg)?;
            let mut forward = Link::new(RTT_ONE_WAY_US, LOSS_PERCENT, 0);
            let mut reverse = Link::new(RTT_ONE_WAY_US, LOSS_PERCENT, 0);
            let mut body = Vec::new();
            let mut native = Vec::new();
            let mut number = 0_u64;
            let mut fwd_tokens = 0_u64;
            let mut rev_tokens = 0_u64;
            let mut offered_packets = 0_u64;
            let mut delivered_packets = 0_u64;
            let mut reverse_wire_bytes = 0_u64;
            let mut now = 0_u64;
            let warmup_us = 140_000_u64; // 2 RTTs to fill the pipe
            let measure_end_us = warmup_us + DURATION_MS * 1_000;
            let mut warmup_delivered = 0_u64;
            let mut warmup_sources = 0_u64;
            let mut measure_delivered = 0_u64;
            let mut measure_sources = 0_u64;
            let mut window_full_ticks = 0_u64;
            let mut max_unconfirmed = 0_usize;
            // Warm up 2 RTTs, measure steady-state delivery over DURATION_MS,
            // then stop injecting and verify 100% lossless ordered drain.
            loop {
                now += 1_000;
                assert!(
                    now < measure_end_us + 5_000_000,
                    "{fwd_mbps}/{rev_mbps} [{label}] failed to drain: {delivered_packets}/{offered_packets}"
                );
                fwd_tokens = (fwd_tokens + wire_bps / 1_000).min(wire_bps / 100);
                rev_tokens = (rev_tokens + rev_bps / 1_000).min(rev_bps / 100);
                for (_, feedback) in reverse.deliver(now) {
                    sender.on_feedback(now, &feedback)?;
                }
                if now <= measure_end_us {
                    while sender.has_room() {
                        if !sender.push_packet(now, &payload)? {
                            break;
                        }
                        offered_packets += 1;
                    }
                }
                while fwd_tokens >= (cfg.datagram_bytes + WIRE_OVERHEAD) as u64 {
                    number += 1;
                    if !sender.poll(now, number, &mut body)? {
                        if now <= measure_end_us && sender.unconfirmed() >= cfg.flow_sources {
                            window_full_ticks += 1;
                        }
                        break;
                    }
                    let wire = (body.len() + WIRE_OVERHEAD) as u64;
                    fwd_tokens = fwd_tokens.saturating_sub(wire);
                    forward.send(now, number, body.clone(), &mut random);
                }
                max_unconfirmed = max_unconfirmed.max(sender.unconfirmed());
                for (seed, datagram) in forward.deliver(now) {
                    receiver.on_datagram(seed, &datagram)?;
                    while receiver.pop_packet(&mut native)? {
                        assert_eq!(native.len(), PAYLOAD_BYTES);
                        delivered_packets += 1;
                    }
                }
                if receiver.feedback(now, &mut body) {
                    let wire = (body.len() + WIRE_OVERHEAD) as u64;
                    if rev_tokens >= wire {
                        rev_tokens -= wire;
                        reverse_wire_bytes += wire;
                        reverse.send(now, 0, body.clone(), &mut random);
                    }
                }
                if now == warmup_us {
                    warmup_delivered = delivered_packets;
                    warmup_sources = sender.stats().packed_bytes;
                }
                if now == measure_end_us {
                    measure_delivered = delivered_packets.saturating_sub(warmup_delivered);
                    measure_sources = sender.stats().packed_bytes.saturating_sub(warmup_sources);
                }
                if now > measure_end_us && delivered_packets == offered_packets {
                    break;
                }
            }
            let delivered_mbps = (measure_delivered as f64 * PAYLOAD_BYTES as f64 * 8.0)
                / (DURATION_MS as f64 * 1e3);
            let active_mbps = (measure_sources as f64 * 8.0) / (DURATION_MS as f64 * 1e3);
            let goodput_mbps = if cfg!(debug_assertions) {
                active_mbps
            } else {
                delivered_mbps
            };
            let efficiency = goodput_mbps / fwd_mbps as f64;
            let rev_mbps_used = (reverse_wire_bytes as f64 * 8.0) / (now as f64);
            eprintln!(
                "high_bdp {fwd_mbps}/{rev_mbps} Mb/s [{label}] (70ms RTT, 15% loss): \
                 goodput={goodput_mbps:.1} Mb/s ({:.1}% of wire budget), active={active_mbps:.1} Mb/s, rev_fb={rev_mbps_used:.2} Mb/s, \
                 sources={}, repairs={}, retrans={}, recovered={}, full_ticks={window_full_ticks}, max_unconf={max_unconfirmed}/{flow_sources}, drain_ms={:.0}",
                efficiency * 100.0,
                sender.stats().sources,
                sender.stats().repairs,
                sender.stats().retransmits,
                receiver.stats().recovered,
                now.saturating_sub(measure_end_us) as f64 / 1_000.0,
            );
            assert!(
                efficiency >= min_eff,
                "{fwd_mbps}/{rev_mbps} [{label}] goodput {goodput_mbps:.1} Mb/s ({:.1}%) below {:.0}% floor",
                efficiency * 100.0,
                min_eff * 100.0
            );
            assert!(
                rev_mbps_used < rev_mbps as f64 * 0.25,
                "{fwd_mbps}/{rev_mbps} [{label}] reverse feedback {rev_mbps_used:.2} Mb/s exceeded 25% of reverse cap"
            );
        }
    }
    Ok(())
}
