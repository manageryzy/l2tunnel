use super::*;
use crate::tests::{config, ip, open_only, pair, pump};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn options() -> Config {
    Config {
        publication_micros: 10,
        demand_ttl_micros: 100,
        probe_interval_micros: 100,
        probe_timeout_micros: 80,
        measurement_ttl_micros: 100,
        rate_window_micros: 10,
        output_interval_micros: 10,
        output_burst: 32,
        peer_queue: Credit {
            bytes: 16384,
            records: 128,
        },
        peer_retained: config().send_capacity.credit,
    }
}

fn snapshot(flow: u64) -> LocalDemand {
    LocalDemand {
        scope: Scope {
            session: 42,
            epoch: 7,
            direction: Direction::Forward,
        },
        flow: FlowId(flow),
        queued: Credit {
            bytes: 256,
            records: 2,
        },
        head_bytes: 128,
        in_flight: Credit {
            bytes: 128,
            records: 1,
        },
        blocked: BlockReason::FlowCredit,
    }
}

fn deliver_observations(
    source: &mut Observer,
    destination: &mut Observer,
    active: &Active,
    sent: u64,
    received: u64,
) -> TestResult {
    for _ in 0..64 {
        let Some(token) = source.poll_output(Micros(sent))? else {
            return Ok(());
        };
        destination.receive(active, &token, Micros(received))?;
    }
    Err("unbounded observations".into())
}

#[test]
fn literal_golden_and_strict_all_kind_framing() -> TestResult {
    let message = Message::Demand {
        sequence: 9,
        snapshot: snapshot(0),
    };
    let hex = concat!(
        "4c41010100010000",
        "0000000000000000000000000000002a",
        "0000000000000007",
        "0000000000000009",
        "0000000000000000",
        "0000000000000100",
        "0000000000000002",
        "0000000000000080",
        "0000000000000080",
        "0000000000000001",
        "0000000000000000"
    );
    let golden: Result<Vec<_>, _> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16))
        .collect();
    assert_eq!(encode(message)?.as_slice(), golden?.as_slice());
    for direction in [Direction::Forward, Direction::Reverse] {
        for blocked in [
            BlockReason::Ready,
            BlockReason::FlowCredit,
            BlockReason::SessionCredit,
            BlockReason::LocalRetention,
        ] {
            let mut row = snapshot(4);
            row.scope.direction = direction;
            row.blocked = blocked;
            let value = Message::Demand {
                sequence: 3,
                snapshot: row,
            };
            assert_eq!(decode(&encode(value)?)?, value);
        }
        for value in [
            Message::Ping {
                scope: Scope {
                    direction,
                    ..snapshot(0).scope
                },
                nonce: 1,
            },
            Message::Pong {
                scope: Scope {
                    direction,
                    ..snapshot(0).scope
                },
                nonce: 2,
            },
        ] {
            assert_eq!(decode(&encode(value)?)?, value);
            for at in 40..96 {
                let mut token = encode(value)?;
                token[at] = 1;
                assert_eq!(decode(&token), Err(WireError::Reserved));
            }
        }
    }
    let token = encode(message)?;
    for length in 0..96 {
        assert_eq!(decode(&token[..length]), Err(WireError::Length));
    }
    assert_eq!(decode(&[0; 97]), Err(WireError::Length));
    for at in [6, 7, 88, 89, 90, 91, 92, 93, 94, 95] {
        let mut malformed = token;
        malformed[at] = 1;
        assert_eq!(decode(&malformed), Err(WireError::Reserved));
    }
    for at in [0, 1, 2, 3, 4, 5] {
        let mut malformed = token;
        malformed[at] = 255;
        assert_eq!(decode(&malformed), Err(WireError::Tag));
    }
    let mut malformed = token;
    malformed[32..40].fill(0);
    assert_eq!(decode(&malformed), Err(WireError::Value));
    let mut row = snapshot(0);
    row.queued.records = 0;
    assert_eq!(
        encode(Message::Demand {
            sequence: 1,
            snapshot: row
        }),
        Err(WireError::Value)
    );
    row = snapshot(0);
    row.in_flight.bytes = 0;
    assert_eq!(
        encode(Message::Demand {
            sequence: 1,
            snapshot: row
        }),
        Err(WireError::Value)
    );
    row = snapshot(0);
    row.head_bytes = 300;
    assert_eq!(
        encode(Message::Demand {
            sequence: 1,
            snapshot: row
        }),
        Err(WireError::Value)
    );
    Ok(())
}

#[test]
fn snapshots_do_not_spend_credit_change_head_or_earn_deficit() -> TestResult {
    let (mut a, mut b) = pair()?;
    for size in [128, 80, 96] {
        a.enqueue_ip(&ip(1234, size, false, size as u8), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    let before = a.status();
    for _ in 0..100 {
        let rows = a.demand_snapshots()?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].head_bytes, 128);
        assert_eq!(rows[0].blocked, BlockReason::Ready);
        assert_eq!(
            rows[0].queued,
            Credit {
                bytes: 304,
                records: 3
            }
        );
        assert_eq!(a.status(), before);
    }
    let first = a.poll_data()?.ok_or("missing first record")?;
    assert_eq!(first.record.id.0, 0);
    let rows = a.demand_snapshots()?;
    assert_eq!(rows[0].head_bytes, 80);
    assert_eq!(
        rows[0].queued,
        Credit {
            bytes: 176,
            records: 2
        }
    );
    assert_eq!(
        rows[0].in_flight,
        Credit {
            bytes: 128,
            records: 1
        }
    );
    assert_eq!(rows[0].blocked, BlockReason::FlowCredit);
    assert!(a.poll_data()?.is_none());
    Ok(())
}

#[test]
fn local_sender_retention_is_not_peer_credit_exhaustion() -> TestResult {
    let mut source_config = config();
    source_config.send_capacity.credit = Credit {
        bytes: 128,
        records: 1,
    };
    let mut a = Active::new(source_config, Direction::Forward, Micros(0))?;
    let mut b = Active::new(config(), Direction::Reverse, Micros(0))?;
    a.enqueue_ip(&ip(1234, 128, false, 1), 1, Micros(0))?;
    a.enqueue_ip(&ip(1234, 128, false, 2), 1, Micros(0))?;
    open_only(&mut a, &mut b, 0)?;
    let flow = a.demand_snapshots()?[0].flow;
    let grant = b.receiver.grant(
        flow,
        Credit {
            bytes: 512,
            records: 4,
        },
    )?;
    a.sender.apply_grant(grant)?;
    a.poll_data()?.ok_or("missing first record")?;
    let row = a.demand_snapshots()?[0];
    assert_eq!(row.blocked, BlockReason::LocalRetention);
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    observer.receive(
        &b,
        &encode(Message::Demand {
            sequence: 1,
            snapshot: row,
        })?,
        Micros(0),
    )?;
    let measured = observer.feedback(&b, Micros(0))?;
    assert_eq!(measured.demanding, vec![flow]);
    assert!(!measured.feedback.sender_credit_exhausted);
    assert!(!measured.feedback.receiver_pressure);
    Ok(())
}

#[test]
fn demand_high_water_survives_expiry_and_reordering_does_not_sum_aggregate() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1234, 128, false, 1), 1, Micros(0))?;
    a.enqueue_ip(&ip(1235, 128, false, 2), 1, Micros(0))?;
    pump(&mut a, &mut b, 0)?;
    let rows = a.demand_snapshots()?;
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    let mut newer = rows[1];
    newer.queued = Credit {
        bytes: 128,
        records: 1,
    };
    newer.head_bytes = 128;
    newer.blocked = BlockReason::SessionCredit;
    let token = encode(Message::Demand {
        sequence: 20,
        snapshot: newer,
    })?;
    observer.receive(&b, &token, Micros(1))?;
    observer.receive(
        &b,
        &encode(Message::Demand {
            sequence: 19,
            snapshot: rows[0],
        })?,
        Micros(2),
    )?;
    let measured = observer.feedback(&b, Micros(2))?;
    assert_eq!(
        measured.feedback.in_flight,
        Credit {
            bytes: 256,
            records: 2
        }
    );
    assert_eq!(measured.demanding, vec![newer.flow]);
    observer.receive(&b, &token, Micros(100))?;
    assert!(observer.feedback(&b, Micros(101))?.demanding.is_empty());
    observer.receive(&b, &token, Micros(102))?;
    assert!(observer.feedback(&b, Micros(102))?.demanding.is_empty());
    assert_eq!(observer.remote.len(), 2);
    newer.blocked = BlockReason::Ready;
    assert_eq!(
        observer.receive(
            &b,
            &encode(Message::Demand {
                sequence: 20,
                snapshot: newer
            })?,
            Micros(103)
        ),
        Err(Error::ConflictingSequence)
    );
    observer.receive(
        &b,
        &encode(Message::Demand {
            sequence: 21,
            snapshot: newer,
        })?,
        Micros(103),
    )?;
    assert_eq!(
        observer.feedback(&b, Micros(103))?.demanding,
        vec![newer.flow]
    );
    Ok(())
}

#[test]
fn wrong_scope_bounds_and_unopened_flow_are_atomic() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1234, 128, false, 1), 1, Micros(0))?;
    open_only(&mut a, &mut b, 0)?;
    let original = a.demand_snapshots()?[0];
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    for (row, error) in [
        (
            LocalDemand {
                scope: Scope {
                    epoch: 99,
                    ..original.scope
                },
                ..original
            },
            Error::WrongScope,
        ),
        (
            LocalDemand {
                head_bytes: 129,
                queued: Credit {
                    bytes: 129,
                    records: 1,
                },
                ..original
            },
            Error::Bounds,
        ),
        (
            LocalDemand {
                queued: Credit {
                    bytes: 16385,
                    records: 1,
                },
                ..original
            },
            Error::Bounds,
        ),
        (
            LocalDemand {
                in_flight: Credit {
                    bytes: 4097,
                    records: 1,
                },
                ..original
            },
            Error::Bounds,
        ),
        (
            LocalDemand {
                flow: FlowId(999),
                ..original
            },
            Error::UnknownFlow,
        ),
    ] {
        assert_eq!(
            observer.receive(
                &b,
                &encode(Message::Demand {
                    sequence: 1,
                    snapshot: row
                })?,
                Micros(20)
            ),
            Err(error)
        );
        assert!(observer.remote.is_empty());
        assert!(observer.aggregate.is_none());
        assert_eq!(observer.last_time, Micros(0));
    }
    assert_eq!(observer.tick(&a, Micros(0)), Err(Error::WrongScope));
    Ok(())
}

#[test]
fn probe_handoff_time_timeout_zero_elapsed_and_duplicates_are_honest() -> TestResult {
    let (a, b) = pair()?;
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    observer.tick(&b, Micros(0))?;
    for now in 1..20 {
        observer.tick(&b, Micros(now))?;
    }
    assert_eq!(observer.pending_outputs(), 1);
    let token = observer.poll_output(Micros(20))?.ok_or("missing ping")?;
    let Message::Ping { scope, nonce } = decode(&token)? else {
        return Err("not ping".into());
    };
    assert_eq!(scope, a.send_scope);
    let pong = encode(Message::Pong { scope, nonce })?;
    observer.receive(&b, &pong, Micros(50))?;
    assert_eq!(
        observer.feedback(&b, Micros(50))?.feedback.rtt_micros,
        Some(30)
    );
    observer.receive(&b, &pong, Micros(149))?;
    assert_eq!(
        observer.feedback(&b, Micros(150))?.feedback.rtt_micros,
        None
    );
    observer.tick(&b, Micros(150))?;
    let token = observer
        .poll_output(Micros(150))?
        .ok_or("missing second ping")?;
    let Message::Ping { scope, nonce } = decode(&token)? else {
        return Err("not ping".into());
    };
    observer.receive(&b, &encode(Message::Pong { scope, nonce })?, Micros(230))?;
    assert!(observer.probe.is_none());
    assert_eq!(
        observer.feedback(&b, Micros(230))?.feedback.rtt_micros,
        None
    );
    observer.tick(&b, Micros(250))?;
    let token = observer
        .poll_output(Micros(250))?
        .ok_or("missing third ping")?;
    let Message::Ping { scope, nonce } = decode(&token)? else {
        return Err("not ping".into());
    };
    observer.receive(&b, &encode(Message::Pong { scope, nonce })?, Micros(250))?;
    assert_eq!(
        observer.feedback(&b, Micros(250))?.feedback.rtt_micros,
        None
    );
    assert!(observer.probe.is_none());
    Ok(())
}

#[test]
fn coalesced_replies_and_all_outputs_obey_finite_burst() -> TestResult {
    let (a, _) = pair()?;
    let mut config = options();
    config.output_burst = 1;
    let mut observer = Observer::new(config, &a, Micros(0))?;
    observer.tick(&a, Micros(0))?;
    for nonce in 1..100 {
        observer.receive(
            &a,
            &encode(Message::Ping {
                scope: a.send_scope,
                nonce,
            })?,
            Micros(0),
        )?;
    }
    assert_eq!(observer.pending_outputs(), 2);
    assert!(observer.poll_output(Micros(0))?.is_some());
    assert!(observer.poll_output(Micros(0))?.is_none());
    assert!(observer.poll_output(Micros(9))?.is_none());
    let pong = observer
        .poll_output(Micros(10))?
        .ok_or("missing coalesced pong")?;
    assert_eq!(
        decode(&pong)?,
        Message::Pong {
            scope: a.send_scope,
            nonce: 99
        }
    );
    observer.receive(
        &a,
        &encode(Message::Ping {
            scope: a.send_scope,
            nonce: 99,
        })?,
        Micros(10),
    )?;
    assert_eq!(observer.pending_outputs(), 0);
    for nonce in 100..200 {
        observer.receive(
            &a,
            &encode(Message::Ping {
                scope: a.send_scope,
                nonce,
            })?,
            Micros(10),
        )?;
    }
    assert_eq!(observer.pending_outputs(), 1);
    assert!(observer.poll_output(Micros(10))?.is_none());
    assert!(observer.poll_output(Micros(1000))?.is_some());
    assert!(observer.poll_output(Micros(1000))?.is_none());
    Ok(())
}

#[test]
fn actual_native_samples_keep_first_receipt_and_static_calls_do_not_invent_rates() -> TestResult {
    let (mut a, mut b) = pair()?;
    for value in 1..5 {
        a.enqueue_ip(&ip(1234, 128, false, value), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    let data = a.poll_data()?.ok_or("missing data")?;
    b.receive_data(&data.token, data.channel, &data.payload, Micros(10))?;
    b.receive_data(&data.token, data.channel, &data.payload, Micros(20))?;
    b.confirm_delivery_at(data.record, Micros(30))?;
    let sample = b.native_sample().ok_or("missing native sample")?;
    assert_eq!(sample.queue_delay_micros, 20);
    b.confirm_delivery_at(data.record, Micros(40))?;
    assert_eq!(b.native_sample(), Some(sample));
    let mut observer = Observer::new(options(), &b, Micros(40))?;
    assert_eq!(
        observer
            .feedback(&b, Micros(40))?
            .feedback
            .delivery_bytes_per_second,
        None
    );
    pump(&mut a, &mut b, 40)?;
    let second = b.delivery().ok_or("missing second")?.record;
    b.confirm_delivery(second)?;
    assert_eq!(b.native_sample(), Some(sample));
    pump(&mut a, &mut b, 40)?;
    let third = b.delivery().ok_or("missing third")?.record;
    b.confirm_delivery_at(third, Micros(50))?;
    let measured = observer.feedback(&b, Micros(50))?;
    assert_eq!(
        measured.feedback.delivery_bytes_per_second,
        Some(12_800_000)
    );
    assert_eq!(measured.feedback.queue_delay_micros, 10);
    assert_eq!(
        b.native_sample().ok_or("missing sample")?.confirmed,
        Credit {
            bytes: 384,
            records: 3
        }
    );
    assert_eq!(
        observer
            .feedback(&b, Micros(149))?
            .feedback
            .delivery_bytes_per_second,
        Some(12_800_000)
    );
    assert_eq!(
        observer
            .feedback(&b, Micros(150))?
            .feedback
            .delivery_bytes_per_second,
        None
    );
    assert_eq!(
        b.confirm_delivery_at(third, Micros(49)),
        Err(crate::Error::NonMonotonicTime)
    );
    Ok(())
}

#[test]
fn checked_time_counter_and_deadline_failures_preserve_pending_output() -> TestResult {
    let (mut a, b) = pair()?;
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    observer.nonce = u64::MAX;
    assert_eq!(observer.tick(&b, Micros(0)), Err(Error::RenewalRequired));
    assert_eq!(observer.pending_outputs(), 0);
    observer.nonce = 0;
    observer.tick(&b, Micros(1))?;
    assert_eq!(observer.tick(&b, Micros(0)), Err(Error::NonMonotonicTime));
    assert_eq!(
        observer.poll_output(Micros(u64::MAX)).err(),
        Some(Error::RenewalRequired)
    );
    assert_eq!(observer.pending_outputs(), 1);
    assert!(Observer::new(options(), &b, Micros(u64::MAX)).is_err());
    a.enqueue_ip(&ip(1234, 128, false, 1), 1, Micros(0))?;
    let mut sender = Observer::new(options(), &a, Micros(0))?;
    sender.sequence = u64::MAX;
    assert_eq!(sender.tick(&a, Micros(0)), Err(Error::RenewalRequired));
    assert_eq!(sender.pending_outputs(), 0);
    let mut config = options();
    config.output_burst = 0;
    assert!(Observer::new(config, &b, Micros(0)).is_err());
    Ok(())
}

#[test]
fn actual_two_endpoint_measurements_allow_growth_then_pressure_stops_it() -> TestResult {
    let (mut a, mut b) = pair()?;
    for value in 0..8 {
        a.enqueue_ip(&ip(1234, 128, false, value), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    let mut source = Observer::new(options(), &a, Micros(0))?;
    let mut receiver = Observer::new(options(), &b, Micros(0))?;
    source.tick(&a, Micros(0))?;
    receiver.tick(&b, Micros(0))?;
    deliver_observations(&mut source, &mut receiver, &b, 0, 0)?;
    let fallback = receiver.feedback(&b, Micros(0))?;
    b.update_targets(Micros(0), fallback.feedback, &fallback.demanding)?;
    assert_eq!(b.status().target, config().target.initial);
    deliver_observations(&mut receiver, &mut source, &a, 0, 10)?;
    deliver_observations(&mut source, &mut receiver, &b, 10, 20)?;
    pump(&mut a, &mut b, 20)?;
    let first = b.delivery().ok_or("missing first data")?.record;
    b.confirm_delivery_at(first, Micros(20))?;
    receiver.feedback(&b, Micros(20))?;
    pump(&mut a, &mut b, 30)?;
    let second = b.delivery().ok_or("missing second data")?.record;
    b.confirm_delivery_at(second, Micros(30))?;
    source.tick(&a, Micros(30))?;
    deliver_observations(&mut source, &mut receiver, &b, 30, 30)?;
    let measured = receiver.feedback(&b, Micros(30))?;
    assert_eq!(measured.feedback.rtt_micros, Some(20));
    assert_eq!(
        measured.feedback.delivery_bytes_per_second,
        Some(12_800_000)
    );
    assert!(measured.feedback.sender_credit_exhausted);
    assert!(!measured.demanding.is_empty());
    b.update_targets(Micros(30), measured.feedback, &measured.demanding)?;
    // Measured BDP (256 bytes) plus the 512-byte queue policy caps the 2x step.
    assert_eq!(b.status().target.bytes, 768);
    let issued = b.status().receiver_reserved;
    let mut pressure = receiver.feedback(&b, Micros(50))?;
    pressure.feedback.receiver_pressure = true;
    b.update_targets(Micros(50), pressure.feedback, &pressure.demanding)?;
    assert!(b.status().target.bytes <= config().target.initial.bytes * 2);
    assert_eq!(b.status().receiver_reserved, issued);
    pump(&mut a, &mut b, 50)?;
    let retained = b.status().receiver_payload;
    receiver.feedback(&b, Micros(60))?;
    assert_eq!(b.status().receiver_payload, retained);
    Ok(())
}

#[test]
fn retired_demand_cannot_recreate_state_across_many_flow_slots() -> TestResult {
    let mut cfg = config();
    cfg.pipeline.flows.idle_timeout = std::time::Duration::from_micros(10);
    let mut a = Active::new(cfg, Direction::Forward, Micros(0))?;
    let mut b = Active::new(cfg, Direction::Reverse, Micros(0))?;
    let mut source = Observer::new(options(), &a, Micros(0))?;
    let mut receiver = Observer::new(options(), &b, Micros(0))?;
    for cycle in 0..100 {
        let now = cycle * 1000;
        let metadata = a.enqueue_ip(
            &ip(1000 + cycle as u16, 128, false, cycle as u8),
            1,
            Micros(now),
        )?;
        open_only(&mut a, &mut b, now)?;
        source.tick(&a, Micros(now))?;
        let old = encode(Message::Demand {
            sequence: cycle + 1,
            snapshot: a.demand_snapshots()?[0],
        })?;
        receiver.receive(&b, &old, Micros(now))?;
        deliver_observations(&mut source, &mut receiver, &b, now, now)?;
        deliver_observations(&mut receiver, &mut source, &a, now, now)?;
        pump(&mut a, &mut b, now)?;
        let record = b.delivery().ok_or("missing native payload")?.record;
        b.confirm_delivery_at(record, Micros(now))?;
        pump(&mut a, &mut b, now)?;
        assert_eq!(source.pending_outputs(), 0);
        a.request_idle_retirement(
            &metadata.classification.key,
            Micros(now + 10),
            crate::RetirementPolicy {
                retry_micros: 100,
                max_attempts: 3,
            },
            crate::ExternalDrain::default(),
        )?;
        pump(&mut a, &mut b, now + 10)?;
        assert!(
            receiver
                .feedback(&b, Micros(now + 10))?
                .demanding
                .is_empty()
        );
        receiver.receive(&b, &old, Micros(now + 11))?;
        assert!(receiver.remote.is_empty());
        source.tick(&a, Micros(now + 11))?;
        assert!(source.pending_outputs() <= 2);
        assert!(
            source
                .pending
                .keys()
                .all(|key| !matches!(key, Key::Demand(_)))
        );
        assert_eq!(a.status().outgoing_flows, 0);
        assert_eq!(b.status().incoming_flows, 0);
    }
    Ok(())
}

#[test]
fn unmatched_probe_scope_and_nonce_never_complete_measurement() -> TestResult {
    let (_, b) = pair()?;
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    observer.tick(&b, Micros(0))?;
    let token = observer.poll_output(Micros(0))?.ok_or("ping")?;
    let Message::Ping { scope, nonce } = decode(&token)? else {
        return Err("not ping".into());
    };
    let wrong = encode(Message::Pong {
        scope: Scope {
            epoch: scope.epoch + 1,
            ..scope
        },
        nonce,
    })?;
    assert_eq!(
        observer.receive(&b, &wrong, Micros(10)),
        Err(Error::WrongScope)
    );
    observer.receive(
        &b,
        &encode(Message::Pong {
            scope,
            nonce: nonce + 1,
        })?,
        Micros(10),
    )?;
    assert!(observer.probe.is_some());
    assert_eq!(observer.feedback(&b, Micros(10))?.feedback.rtt_micros, None);
    observer.receive(&b, &encode(Message::Pong { scope, nonce })?, Micros(20))?;
    assert_eq!(
        observer.feedback(&b, Micros(20))?.feedback.rtt_micros,
        Some(20)
    );
    Ok(())
}

#[test]
fn rate_arithmetic_overflow_does_not_commit_native_anchor() -> TestResult {
    let (_, b) = pair()?;
    let mut observer = Observer::new(options(), &b, Micros(0))?;
    let anchor = NativeSample {
        scope: b.receive_scope,
        confirmed: Credit {
            bytes: 20,
            records: 1,
        },
        at: Micros(1),
        queue_delay_micros: 0,
    };
    observer.observe_native(Some(anchor))?;
    let oversized = NativeSample {
        confirmed: Credit {
            bytes: u64::MAX,
            records: 2,
        },
        at: Micros(11),
        ..anchor
    };
    assert_eq!(
        observer.observe_native(Some(oversized)),
        Err(Error::RenewalRequired)
    );
    assert_eq!(observer.native_anchor, Some(anchor));
    assert_eq!(observer.native_seen, 1);
    assert!(observer.rate.is_none());
    Ok(())
}
