use super::*;
use std::collections::VecDeque;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DATAGRAM: u64 = 1_400;

fn config() -> Config {
    Config {
        floor_datagrams: 64,
        ceiling_datagrams: 4_096,
        floor_bytes: 64 * DATAGRAM,
        ceiling_bytes: 4_096 * DATAGRAM,
        period: Duration::from_millis(10),
        idle_period: Duration::from_millis(250),
    }
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn sample() -> Credit {
    Credit {
        serial: 1,
        processed: 0x0102_0304_0506_0708,
        limit: 0x0102_0304_0506_0808,
        bytes_above: 89_600,
        drain_bytes: 12_500_000,
        drain_datagrams: 8_928,
    }
}

/// A record-receive range far above every window used here.
const RANGE: u64 = 1 << 28;

#[test]
fn credit_encodes_canonical_literal_bytes_and_round_trips() -> TestResult {
    let bytes = sample().encode()?;
    let mut expected = Vec::new();
    expected.extend_from_slice(b"L2CR\x01\0\0\0");
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 8, 8]);
    expected.extend_from_slice(&89_600_u64.to_be_bytes());
    expected.extend_from_slice(&12_500_000_u64.to_be_bytes());
    expected.extend_from_slice(&8_928_u64.to_be_bytes());
    expected.extend_from_slice(&[0; 8]);
    assert_eq!(&bytes[..], &expected[..]);
    assert!(Credit::is_tagged(&bytes));
    assert_eq!(Credit::decode(&bytes)?, sample());
    Ok(())
}

#[test]
fn credit_rejects_noncanonical_and_truncated_bodies() -> TestResult {
    let bytes = sample().encode()?;
    for length in 0..WIRE_BYTES {
        assert_eq!(Credit::decode(&bytes[..length]), Err(Error::Malformed));
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert_eq!(Credit::decode(&extended), Err(Error::Malformed));
    for index in (0..8).chain(56..64) {
        let mut changed = bytes;
        changed[index] ^= 0x40;
        assert_eq!(
            Credit::decode(&changed),
            Err(Error::Malformed),
            "byte {index}"
        );
    }
    let zero_serial = Credit {
        serial: 0,
        ..sample()
    };
    assert_eq!(zero_serial.encode(), Err(Error::Malformed));
    let backwards = Credit {
        limit: sample().processed - 1,
        ..sample()
    };
    assert_eq!(backwards.encode(), Err(Error::Malformed));
    let mut forged = bytes;
    forged[24..32].copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(Credit::decode(&forged), Err(Error::Malformed));
    Ok(())
}

#[test]
fn configuration_bounds_are_enforced() {
    assert_eq!(config().validate(DATAGRAM), Ok(()));
    let bad = [
        Config {
            floor_datagrams: 15,
            ..config()
        },
        Config {
            ceiling_datagrams: 63,
            ..config()
        },
        Config {
            ceiling_datagrams: 65_537,
            ..config()
        },
        Config {
            floor_bytes: 16 * DATAGRAM - 1,
            ..config()
        },
        Config {
            ceiling_bytes: (64 << 20) + 1,
            ..config()
        },
        Config {
            period: Duration::from_micros(999),
            ..config()
        },
        Config {
            idle_period: ms(9),
            ..config()
        },
        Config {
            idle_period: Duration::from_millis(1_001),
            ..config()
        },
    ];
    for config in bad {
        assert_eq!(
            config.validate(DATAGRAM),
            Err(Error::Configuration),
            "{config:?}"
        );
    }
    assert_eq!(config().validate(0), Err(Error::Configuration));
}

#[test]
fn receiver_follows_the_highest_number_so_loss_never_leaks_credit() -> TestResult {
    let mut receiver = Receiver::new(config(), DATAGRAM, 100 * DATAGRAM)?;
    // Packets 10..20 with 12 and 15 lost, and 17 before 16.
    for number in [10, 11, 13, 14, 17, 16, 18, 19] {
        receiver.processed(number, DATAGRAM, ms(1))?;
    }
    let credit = receiver.issue(ms(2), None)?;
    assert_eq!(credit.processed, 20);
    assert!(credit.limit >= 20 + config().floor_datagrams);
    Ok(())
}

#[test]
fn receiver_grant_starts_at_allowance_and_grows_with_drain_and_rtt() -> TestResult {
    let allowance = 200 * DATAGRAM;
    let mut receiver = Receiver::new(config(), DATAGRAM, allowance)?;
    let (limit, bytes) = receiver.grant(ms(0), None);
    assert_eq!(bytes, allowance);
    assert_eq!(limit, allowance / 1024 + 1);
    // 4 datagrams per millisecond for 300 ms: about 5.6 MB/s.
    let mut number = 0;
    for at in 0..300 {
        for _ in 0..4 {
            receiver.processed(number, DATAGRAM, ms(at))?;
            number += 1;
        }
    }
    let (drain_bytes, drain_datagrams) = receiver.drain(ms(300));
    assert_eq!(drain_datagrams, 4_000);
    assert_eq!(drain_bytes, 4_000 * DATAGRAM);
    let (limit, bytes) = receiver.grant(ms(300), Some(ms(70)));
    // 4,000 datagrams/s over 70 ms plus one 10 ms period.
    assert_eq!(bytes, 320 * DATAGRAM + allowance);
    assert_eq!(limit, number + 320 + allowance / 1024 + 1);
    // The ceiling bounds both.
    let (limit, bytes) = receiver.grant(ms(300), Some(Duration::from_secs(10)));
    assert_eq!(bytes, config().ceiling_bytes);
    assert_eq!(limit, number + config().ceiling_datagrams);
    Ok(())
}

#[test]
fn receiver_freeze_holds_the_grant_and_the_limit_never_decreases() -> TestResult {
    let mut receiver = Receiver::new(config(), DATAGRAM, 100 * DATAGRAM)?;
    for number in 0..50 {
        receiver.processed(number, DATAGRAM, ms(1))?;
    }
    let first = receiver.issue(ms(2), None)?;
    receiver.set_frozen(true);
    for number in 50..100 {
        receiver.processed(number, DATAGRAM, ms(3))?;
    }
    let frozen = receiver.issue(ms(4), None)?;
    assert_eq!(frozen.limit, first.limit.max(100));
    assert_eq!(frozen.bytes_above, first.bytes_above);
    receiver.set_frozen(false);
    let released = receiver.issue(ms(5), None)?;
    assert!(released.limit > frozen.limit);
    assert!(released.serial > frozen.serial);
    Ok(())
}

#[test]
fn receiver_due_rule_follows_growth_period_and_heartbeat() -> TestResult {
    let mut receiver = Receiver::new(config(), DATAGRAM, 100 * DATAGRAM)?;
    // Nothing before the first data datagram, then a Credit at once.
    assert_eq!(receiver.due(ms(0), None), None);
    receiver.processed(0, DATAGRAM, ms(0))?;
    assert_eq!(receiver.due(ms(0), None), Some(ms(0)));
    receiver.issue(ms(0), None)?;
    // No further data: only the idle heartbeat.
    assert_eq!(receiver.due(ms(1), None), Some(ms(250)));
    receiver.processed(1, DATAGRAM, ms(1))?;
    assert_eq!(receiver.due(ms(1), None), Some(ms(10)));
    // Growth of a quarter window is due at once.
    for number in 2..40 {
        receiver.processed(number, DATAGRAM, ms(2))?;
    }
    assert_eq!(receiver.due(ms(2), None), Some(ms(2)));
    assert_eq!(receiver.issue(ms(2), None)?.serial, 2);
    assert_eq!(receiver.processed(1, DATAGRAM, ms(1)), Err(Error::Time));
    Ok(())
}

#[test]
fn sender_gates_on_limit_bytes_and_pacing() -> TestResult {
    let mut sender = Sender::new(config(), DATAGRAM, 100, 10_000_000, 1 << 20, RANGE)?;
    // Initial window: 64 datagrams from 100, 64 datagrams of bytes.
    for number in 100..164 {
        assert_eq!(sender.gate(number, ms(0))?, Gate::Open, "{number}");
        sender.sent(number, DATAGRAM, ms(0))?;
        // Keep the pacing bucket full for this check.
        sender.tokens = sender.burst;
    }
    assert_eq!(sender.gate(164, ms(0))?, Gate::Credit);
    // Out-of-order sends are refused.
    assert_eq!(sender.sent(163, DATAGRAM, ms(0)), Err(Error::Window));
    // A Credit releasing 100..140 reopens bytes and extends the limit.
    sender.apply(
        Credit {
            serial: 1,
            processed: 140,
            limit: 300,
            bytes_above: 64 * DATAGRAM,
            drain_bytes: 1_000_000,
            drain_datagrams: 714,
        },
        ms(70),
    )?;
    let status = sender.status(ms(70));
    assert_eq!(status.inflight_datagrams, 24);
    assert_eq!(status.inflight_bytes, 24 * DATAGRAM);
    // max(5/4 drain = 1.25 MB/s, 89,600 B / (70 + 10) ms = 1.12 MB/s).
    assert_eq!(status.pacing_rate, 1_250_000);
    assert_eq!(status.min_rtt, Some(ms(70)));
    // Pacing: drain the bucket, then the refill time is reported.
    sender.tokens = 0;
    let Gate::Pacing(ready) = sender.gate(164, ms(70))? else {
        return Err("expected pacing".into());
    };
    assert_eq!(ready, ms(70) + Duration::from_micros(1_120));
    assert_eq!(sender.gate(164, ready)?, Gate::Open);
    // A larger byte window is spread over the round trip instead.
    sender.apply(
        Credit {
            serial: 2,
            processed: 150,
            limit: 400,
            bytes_above: 200 * DATAGRAM,
            drain_bytes: 1_000_000,
            drain_datagrams: 714,
        },
        ready,
    )?;
    assert_eq!(
        sender.status(ready).pacing_rate,
        200 * DATAGRAM * 1_000 / 80
    );
    // Before any RTT sample the rate is twice the drain.
    let mut fresh = Sender::new(config(), DATAGRAM, 0, 10_000_000, 1 << 20, RANGE)?;
    fresh.apply(
        Credit {
            serial: 1,
            processed: 0,
            limit: 64,
            bytes_above: 64 * DATAGRAM,
            drain_bytes: 1_000_000,
            drain_datagrams: 714,
        },
        ms(1),
    )?;
    assert_eq!(fresh.status(ms(1)).pacing_rate, 2_000_000);
    Ok(())
}

#[test]
fn sender_ignores_stale_and_never_shrinks_its_limit() -> TestResult {
    let mut sender = Sender::new(config(), DATAGRAM, 0, 10_000_000, 1 << 20, RANGE)?;
    let newer = Credit {
        serial: 5,
        processed: 10,
        limit: 500,
        bytes_above: 100 * DATAGRAM,
        drain_bytes: 0,
        drain_datagrams: 0,
    };
    assert_eq!(sender.apply(newer, ms(1))?, Applied::Accepted);
    let older = Credit {
        serial: 4,
        limit: 900,
        ..newer
    };
    assert_eq!(sender.apply(older, ms(2))?, Applied::Stale);
    assert_eq!(sender.status(ms(2)).limit, 500);
    let smaller = Credit {
        serial: 6,
        processed: 20,
        limit: 300,
        ..newer
    };
    sender.apply(smaller, ms(3))?;
    let status = sender.status(ms(3));
    assert_eq!((status.limit, status.peer_processed), (500, 20));
    assert_eq!(status.pacing_rate, 10_000_000);
    assert_eq!(sender.apply(newer, ms(2)), Err(Error::Time));
    Ok(())
}

/// A sender limited only by its configured rate floods a receiver that drains
/// at a third of it; credit must keep the receiver's socket from dropping while
/// still approaching the drain rate, with 20% random loss of data and credit
/// and a 70 ms path. As in the runtime, the allowance is half the socket's
/// real buffer.
#[test]
fn credit_keeps_a_slow_receiver_socket_within_its_allowance_under_loss() -> TestResult {
    let allowance = 150 * DATAGRAM;
    let mut sender = Sender::new(config(), DATAGRAM, 1, 30_000_000, 64 * DATAGRAM, RANGE)?;
    let mut receiver = Receiver::new(config(), DATAGRAM, allowance)?;
    // Receiver drains 10 MB/s: one datagram every 140 us.
    let drain_interval = 140;
    let one_way = 35_000;
    let mut forward: VecDeque<(u64, u64)> = VecDeque::new();
    let mut backward: VecDeque<(u64, Credit)> = VecDeque::new();
    let mut socket: VecDeque<u64> = VecDeque::new();
    let mut number = 1;
    let mut rng = 0x2545_f491_4f6c_dd1d_u64;
    let mut lose = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng.is_multiple_of(5)
    };
    let mut drops = 0;
    let mut processed = 0_u64;
    let mut peak = 0;
    let mut next_drain = 0;
    let mut at_two_seconds = 0;
    for now_us in (0..4_000_000_u64).step_by(10) {
        let now = Duration::from_micros(now_us);
        if now_us == 2_000_000 {
            at_two_seconds = processed;
        }
        // Sender: as many datagrams as the gate allows.
        while sender.gate(number, now)? == Gate::Open {
            sender.sent(number, DATAGRAM, now)?;
            if !lose() {
                forward.push_back((now_us + one_way, number));
            }
            number += 1;
        }
        while forward.front().is_some_and(|(at, _)| *at <= now_us) {
            let Some((_, packet)) = forward.pop_front() else {
                break;
            };
            if (socket.len() as u64 + 1) * DATAGRAM > 2 * allowance {
                drops += 1;
            } else {
                socket.push_back(packet);
            }
        }
        peak = peak.max(socket.len());
        if now_us >= next_drain
            && let Some(packet) = socket.pop_front()
        {
            receiver.processed(packet, DATAGRAM, now)?;
            processed += 1;
            next_drain = now_us + drain_interval;
        }
        let min_rtt = sender.min_rtt(now);
        if receiver.due(now, min_rtt).is_some_and(|due| due <= now) {
            let credit = receiver.issue(now, min_rtt)?;
            if !lose() {
                backward.push_back((now_us + one_way, credit));
            }
        }
        while backward.front().is_some_and(|(at, _)| *at <= now_us) {
            let Some((_, credit)) = backward.pop_front() else {
                break;
            };
            sender.apply(credit, now)?;
        }
    }
    assert_eq!(drops, 0, "socket overflowed; peak {peak}");
    // The drain rate is 7,142 datagrams per second. Including the ramp from
    // the initial window, require 75% over 4 s and 95% in the last 2 s.
    let steady = processed - at_two_seconds;
    assert!(processed > 21_400, "processed only {processed}");
    assert!(steady > 13_570, "steady state only {steady} of 14,285");
    let status = sender.status(Duration::from_secs(4));
    assert!(status.accepted > 100);
    assert!(status.credit_blocked > 0 || status.pacing_blocked > 0);
    Ok(())
}

/// Losing the whole in-flight tail leaves an idle receiver with no progress;
/// its heartbeat must let the sender declare that tail lost instead of
/// waiting forever for `processed` to move.
#[test]
fn idle_receiver_heartbeat_releases_a_lost_tail() -> TestResult {
    let mut sender = Sender::new(config(), DATAGRAM, 0, 10_000_000, 1 << 20, RANGE)?;
    let mut receiver = Receiver::new(config(), DATAGRAM, 100 * DATAGRAM)?;
    // 0..10 arrive and are processed; one Credit returns with an RTT sample.
    for number in 0..64 {
        sender.tokens = sender.burst;
        assert_eq!(sender.gate(number, ms(0))?, Gate::Open);
        sender.sent(number, DATAGRAM, ms(0))?;
    }
    for number in 0..10 {
        receiver.processed(number, DATAGRAM, ms(35))?;
    }
    let credit = receiver.issue(ms(35), None)?;
    sender.apply(credit, ms(70))?;
    // 10..64 were lost; the window is still full of them.
    sender.tokens = sender.burst;
    let window = credit.limit - credit.processed;
    assert!(sender.status(ms(70)).inflight_datagrams >= window.min(54));
    // A busy receiver (drain > 0) without progress declares nothing.
    sender.apply(
        Credit {
            serial: credit.serial + 1,
            drain_datagrams: 1,
            ..credit
        },
        ms(400),
    )?;
    assert_eq!(sender.status(ms(400)).declared_lost, 0);
    // The idle heartbeat (no drain, no progress) releases the old tail.
    let heartbeat = receiver.issue(ms(400), None)?;
    assert_eq!((heartbeat.processed, heartbeat.drain_datagrams), (10, 0));
    // (The hand-made busy Credit above used the receiver's next serial.)
    let heartbeat = Credit {
        serial: heartbeat.serial + 1,
        ..heartbeat
    };
    sender.apply(heartbeat, ms(435))?;
    let status = sender.status(ms(435));
    assert_eq!(status.declared_lost, 54);
    assert_eq!(status.inflight_datagrams, 0);
    sender.tokens = sender.burst;
    assert_eq!(sender.gate(64, ms(435))?, Gate::Open);
    Ok(())
}

/// The sender keeps data within half the peer's record-receive range above
/// the newest processed number, with or without Credits, and the floor keeps
/// that bound outside every credit window.
#[test]
fn sender_stays_within_half_the_receive_range() -> TestResult {
    let range = config().minimum_range()?;
    assert_eq!(
        Sender::new(config(), DATAGRAM, 0, 10_000_000, 1 << 20, range - 1).err(),
        Some(Error::Configuration)
    );
    let mut sender = Sender::new(config(), DATAGRAM, 0, 10_000_000, 1 << 20, range)?;
    // Before any Credit, `peer_processed` is the first number.
    sender.window = range;
    sender.capacity = usize::try_from(range)?;
    sender.bytes_above = u64::MAX;
    for number in 0..range / 2 {
        sender.tokens = sender.burst;
        assert_eq!(sender.gate(number, ms(0))?, Gate::Open, "{number}");
        sender.sent(number, DATAGRAM, ms(0))?;
    }
    sender.tokens = sender.burst;
    assert_eq!(sender.gate(range / 2, ms(0))?, Gate::Credit);
    assert_eq!(sender.status(ms(0)).range_blocked, 1);
    // A Credit reporting progress moves the bound with `processed`.
    let mut receiver = Receiver::new(config(), DATAGRAM, 100 * DATAGRAM)?;
    for number in 0..10 {
        receiver.processed(number, DATAGRAM, ms(35))?;
    }
    let credit = receiver.issue(ms(35), None)?;
    sender.apply(credit, ms(70))?;
    sender.window = range;
    sender.bytes_above = u64::MAX;
    for number in range / 2..range / 2 + 10 {
        sender.tokens = sender.burst;
        assert_eq!(sender.gate(number, ms(70))?, Gate::Open, "{number}");
        sender.sent(number, DATAGRAM, ms(70))?;
    }
    // At half the range above the new `processed`, one probe per accepted
    // Credit may enter the upper half, and only one.
    let next = range / 2 + 10;
    sender.tokens = sender.burst;
    assert_eq!(sender.gate(next, ms(70))?, Gate::Open);
    sender.sent(next, DATAGRAM, ms(70))?;
    sender.tokens = sender.burst;
    assert_eq!(sender.gate(next + 1, ms(70))?, Gate::Credit);
    let status = sender.status(ms(70));
    assert_eq!((status.range_probes, status.range_blocked), (1, 2));
    // A Credit without progress grants the next probe, never one at or past
    // `range - 1` above `processed`.
    sender.apply(
        Credit {
            serial: credit.serial + 1,
            drain_datagrams: 1,
            ..credit
        },
        ms(80),
    )?;
    sender.window = range;
    sender.bytes_above = u64::MAX;
    sender.tokens = sender.burst;
    assert_eq!(sender.gate(next + 1, ms(80))?, Gate::Open);
    assert_eq!(sender.gate(10 + range - 1, ms(80))?, Gate::Credit);
    // With the floor, a full credit window never reaches the bound.
    assert!(config().ceiling_datagrams < range / 2);
    assert_eq!(sender.status(ms(70)).range, range);
    Ok(())
}

/// A small record-receive range lowers the ceiling (and a higher floor) to a
/// quarter of the range instead of refusing; below 64 there is no valid window.
#[test]
fn fit_range_clamps_the_ceiling_to_a_quarter_of_the_range() -> TestResult {
    let config = Config {
        floor_datagrams: 64,
        ceiling_datagrams: 8192,
        ..config()
    };
    assert_eq!(config.fit_range(32_768)?, config);
    assert_eq!(config.fit_range(RANGE)?, config);
    let clamped = config.fit_range(8192)?;
    assert_eq!(
        (clamped.floor_datagrams, clamped.ceiling_datagrams),
        (64, 2048)
    );
    assert_eq!(
        Config {
            ceiling_bytes: clamped.ceiling_bytes,
            floor_datagrams: 64,
            ceiling_datagrams: 8192,
            ..clamped
        },
        config
    );
    let low = config.fit_range(100)?;
    assert_eq!((low.floor_datagrams, low.ceiling_datagrams), (25, 25));
    low.validate(DATAGRAM)?;
    assert!(low.minimum_range()? <= 100);
    assert_eq!(config.fit_range(63), Err(Error::Configuration));
    let edge = config.fit_range(64)?;
    assert_eq!((edge.floor_datagrams, edge.ceiling_datagrams), (16, 16));
    Ok(())
}

/// A 75 ms ARQ pause after a 50 ms burst must not slash the drain estimate or
/// grant; once all completed bins are empty, drain returns to zero and `due`
/// fires immediately to tell the sender so any lost tail can be released.
#[test]
fn receiver_preserves_burst_drain_across_arq_pause_and_signals_idle_transition() -> TestResult {
    let allowance = 106_496;
    let mut receiver = Receiver::new(config(), DATAGRAM, allowance)?;
    // 50 ms burst at 4 datagrams/ms (bins 0 and 1), then a 75 ms pause (bins 2..4).
    let mut number = 0;
    for at in 0..50 {
        for _ in 0..4 {
            receiver.processed(number, DATAGRAM, ms(at))?;
            number += 1;
        }
    }
    let active = receiver.issue(ms(50), Some(ms(70)))?;
    assert_eq!(active.drain_datagrams, 4_000);
    assert_eq!(active.drain_bytes, 4_000 * DATAGRAM);
    // 75 ms later (t = 125 ms), 3 empty bins have elapsed, but the best 2-bin
    // window still reflects the receiver's 4,000 dgram/s drain capacity.
    let (drain_bytes, drain_datagrams) = receiver.drain(ms(125));
    assert_eq!(drain_datagrams, 4_000);
    assert_eq!(drain_bytes, 4_000 * DATAGRAM);
    // Before idle decay completes, `due` schedules the exact bin boundary when
    // drain will become zero (225 ms, earlier than idle_period at 300 ms).
    assert_eq!(receiver.due(ms(125), Some(ms(70))), Some(ms(225)));
    // Once all 7 completed bins are empty (t = 225 ms), drain becomes zero and
    // `due` fires immediately instead of waiting until t = 300 ms.
    assert_eq!(receiver.drain(ms(225)), (0, 0));
    assert_eq!(receiver.due(ms(225), Some(ms(70))), Some(ms(225)));
    let idle = receiver.issue(ms(225), Some(ms(70)))?;
    assert_eq!(idle.drain_datagrams, 0);
    // After reporting idle once, further heartbeats return to the quiet idle_period.
    assert_eq!(receiver.due(ms(230), Some(ms(70))), Some(ms(475)));
    Ok(())
}

/// Small-datagram streams scale their allowance datagram count with the
/// measured wire size (clamped to [256, 1024] bytes/datagram) instead of
/// starving below the configured byte allowance.
#[test]
fn small_datagram_allowance_scales_with_measured_datagram_size() -> TestResult {
    let allowance = 106_496;
    let mut receiver = Receiver::new(config(), DATAGRAM, allowance)?;
    // Send 100 small 320-byte datagrams across two completed bins.
    for number in 0..100 {
        receiver.processed(number, 320, ms(number / 2))?;
    }
    let (limit, bytes) = receiver.grant(ms(50), Some(ms(70)));
    let window = limit - 100;
    // With 320 B/dgram, allowance alone contributes 106,496 / 320 + 1 = 333 dgrams
    // (vs only 105 with a fixed 1024 B divisor), plus drain * 80 ms = 160 dgrams.
    assert_eq!(window, 160 + (allowance / 320) + 1);
    assert!(bytes >= allowance);
    Ok(())
}

/// Quiescent idle heartbeats fire once at `idle_period` (for prompt tail-loss
/// recovery), then back off exponentially up to 10 s, and reset immediately
/// when new data arrives.
#[test]
fn quiet_idle_heartbeats_back_off_and_reset_on_new_data() -> TestResult {
    let mut receiver = Receiver::new(config(), DATAGRAM, 106_496)?;
    receiver.processed(0, DATAGRAM, ms(0))?;
    let _ = receiver.issue(ms(0), None)?;
    // Once drain drops to zero, the first idle heartbeat is due at idle_period (250 ms).
    let d0 = receiver.due(ms(200), None).ok_or(Error::Configuration)?;
    assert_eq!(d0, ms(250));
    let _ = receiver.issue(d0, None)?;
    // Subsequent quiet heartbeats back off exponentially: 500 ms, 1000 ms, ..., capped at 10 s.
    let d1 = receiver.due(d0, None).ok_or(Error::Configuration)?;
    assert_eq!(d1, d0 + ms(500));
    let _ = receiver.issue(d1, None)?;
    let d2 = receiver.due(d1, None).ok_or(Error::Configuration)?;
    assert_eq!(d2, d1 + ms(1_000));
    let mut now = d2;
    for _ in 0..8 {
        let _ = receiver.issue(now, None)?;
        now = receiver.due(now, None).ok_or(Error::Configuration)?;
    }
    let _ = receiver.issue(now, None)?;
    assert_eq!(
        receiver.due(now, None),
        Some(now + Duration::from_secs(10)),
        "capped at 10 s"
    );
    // Any new data datagram resets immediately back to active period.
    receiver.processed(1, DATAGRAM, now + ms(1))?;
    assert_eq!(receiver.due(now + ms(1), None), Some(now + ms(10)));
    Ok(())
}

/// High-BDP live budget increases scale pacing burst and grant/ring ceilings
/// without dropping tokens on 1 ms event-loop wakeups.
#[test]
fn high_bdp_live_rate_and_ceiling_scaling_unlocks_gigabit_bursts() -> TestResult {
    let cfg = config();
    let range = 1 << 20;
    let mut receiver = Receiver::new(cfg, DATAGRAM, 106_496)?;
    let mut sender = Sender::new(cfg, DATAGRAM, 0, 12_500_000, 64 << 10, range)?;
    // Upgrade live to 1 Gbit/s (125 MB/s) and high-BDP credit ceiling.
    sender.set_configured_rate(125_000_000);
    sender.raise_ceiling(32_768);
    receiver.raise_ceiling(32_768, 64 << 20);
    // Grant a large window from the receiver after high drain.
    for i in 0..10_000_u64 {
        receiver.processed(i, DATAGRAM, ms(i / 200))?;
    }
    let grant = receiver.issue(ms(60), Some(ms(70)))?;
    assert!(
        grant.limit - grant.processed > cfg.ceiling_datagrams,
        "raised receiver ceiling should exceed initial {}",
        cfg.ceiling_datagrams
    );
    assert!(grant.bytes_above > cfg.ceiling_bytes);
    // Sender accepts the larger grant and can burst >80 datagrams (~1 ms at 1 Gb/s)
    // immediately after a 1 ms refill without hitting the old 16-datagram burst cap.
    let _ = sender.apply(grant, ms(60))?;
    let mut sent = 0_u64;
    for n in 0..90_u64 {
        if sender.gate(n, ms(61))? == Gate::Open {
            sender.sent(n, DATAGRAM, ms(61))?;
            sent += 1;
        } else {
            break;
        }
    }
    assert!(
        sent >= 80,
        "expected >=80 datagrams in a 1 ms 1 Gbit/s burst, got {sent}"
    );
    Ok(())
}
