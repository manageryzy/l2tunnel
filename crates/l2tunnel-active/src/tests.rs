use super::*;
use l2tunnel_flow_control::{FinalOffset, LimitDomain, RetirementMode};
use l2tunnel_pipeline::{FlowTableConfig, ParseLimits, QueueLimits, TunQosConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn config() -> ActiveConfig {
    let cap = Credit {
        bytes: 4096,
        records: 32,
    };
    let minimum = Credit {
        bytes: 512,
        records: 4,
    };
    ActiveConfig {
        session: 42,
        epoch: 7,
        pipeline: PipelineConfig {
            profile: Profile::TunDrr(TunQosConfig {
                base_quantum_bytes: 128,
                max_weight: 8,
                per_flow: QueueLimits {
                    bytes: 8192,
                    packets: 64,
                },
            }),
            flows: FlowTableConfig {
                capacity: 4,
                channels: 3,
                mapping: Mapping::Crc32,
                idle_timeout: Duration::from_secs(30),
            },
            parse: ParseLimits {
                max_packet_bytes: 128,
                ..ParseLimits::default()
            },
            queue: QueueLimits {
                bytes: 16384,
                packets: 128,
            },
        },
        send_capacity: Capacity {
            credit: cap,
            max_flows: 4,
        },
        receive_capacity: Capacity {
            credit: cap,
            max_flows: 4,
        },
        target: TargetConfig {
            initial: minimum,
            minimum,
            session_cap: cap,
            per_flow_cap: cap,
            policy_cap: cap,
            queue_allowance_bytes: 512,
            queue_delay_target_micros: 10,
            many_flow_step: Credit {
                bytes: 128,
                records: 1,
            },
            few_flow_threshold: 4,
            max_flows: 4,
            bootstrap_rtt_micros: 100,
            recovery_rtts: 1,
        },
    }
}

pub(super) fn pair() -> Result<(Active, Active), Error> {
    Ok((
        Active::new(config(), Direction::Forward, Micros(0))?,
        Active::new(config(), Direction::Reverse, Micros(0))?,
    ))
}

pub(super) fn ip(port: u16, length: usize, reverse: bool, value: u8) -> Vec<u8> {
    let mut packet = vec![value; length];
    packet[..40].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    let (src, dst, sport, dport) = if reverse {
        ([10, 0, 0, 2], [10, 0, 0, 1], 443, port)
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2], port, 443)
    };
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..22].copy_from_slice(&sport.to_be_bytes());
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x10;
    packet
}

fn transfer(output: Output, receiver: &mut Active, now: u64) -> Result<(), Error> {
    match output {
        Output::Control(token) => receiver.receive_control(&token, Micros(now)),
        Output::Data(data) => receiver
            .receive_data(&data.token, data.channel, &data.payload, Micros(now))
            .map(|_| ()),
    }
}

fn bounded(engine: &Active) {
    let status = engine.status();
    assert!(fits(status.receiver_payload, status.receiver_reserved));
    assert!(fits(
        status.receiver_reserved,
        engine.config.receive_capacity.credit
    ));
    assert!(fits(
        status.sender_retained,
        engine.config.send_capacity.credit
    ));
    assert!(status.pending_controls <= engine.control_capacity);
    assert_eq!(engine.controls.len(), engine.control_order.len());
    assert!(engine.keys.len() <= engine.config.receive_capacity.max_flows);
    assert!(status.queued.bytes <= engine.config.pipeline.queue.bytes);
    assert!(status.queued.packets <= engine.config.pipeline.queue.packets);
    for state in engine.incoming.values() {
        assert!(state.pending.len() as u64 <= status.receiver_payload.records);
    }
}

pub(super) fn pump(a: &mut Active, b: &mut Active, now: u64) -> Result<usize, Error> {
    let mut count = 0;
    for _ in 0..1024 {
        let ab = a.poll_output()?;
        let ba = b.poll_output()?;
        if ab.is_none() && ba.is_none() {
            return Ok(count);
        }
        if let Some(output) = ab {
            transfer(output, b, now)?;
            count += 1;
        }
        if let Some(output) = ba {
            transfer(output, a, now)?;
            count += 1;
        }
        bounded(a);
        bounded(b);
    }
    Err(Error::Invariant)
}

fn confirm_all(engine: &mut Active, delivered: &mut Vec<Vec<u8>>) -> Result<(), Error> {
    while let Some(delivery) = engine.delivery() {
        let record = delivery.record;
        delivered.push(delivery.payload.to_vec());
        assert_eq!(engine.confirm_delivery(record)?, ConfirmOutcome::Confirmed);
        bounded(engine);
    }
    Ok(())
}

fn feedback() -> Feedback {
    Feedback {
        rtt_micros: Some(100),
        delivery_bytes_per_second: Some(100_000_000),
        sender_credit_exhausted: true,
        ..Feedback::default()
    }
}

pub(super) fn open_only(a: &mut Active, b: &mut Active, now: u64) -> TestResult {
    let output = a.poll_output()?.ok_or("missing Open")?;
    assert!(matches!(output, Output::Control(_)));
    transfer(output, b, now)?;
    let output = b.poll_output()?.ok_or("missing Grant")?;
    assert!(matches!(output, Output::Control(_)));
    transfer(output, a, now)?;
    Ok(())
}

fn take_data(engine: &mut Active) -> Result<Data, Box<dyn std::error::Error>> {
    match engine.poll_output()?.ok_or("missing Data")? {
        Output::Data(data) => Ok(data),
        Output::Control(_) => Err("unexpected control".into()),
    }
}

#[test]
fn two_independent_endpoints_transfer_bidirectional_actual_bytes_after_zero_credit() -> TestResult {
    let (mut a, mut b) = pair()?;
    let mut expected_a = Vec::new();
    let mut expected_b = Vec::new();
    for n in 0..9 {
        let outbound = ip(1200 + n % 2, 128, false, n as u8);
        let reverse = ip(1200 + n % 2, 80, true, (n + 30) as u8);
        let am = a.enqueue_ip(&outbound, 1, Micros(0))?;
        let bm = b.enqueue_ip(&reverse, 1, Micros(0))?;
        assert_eq!(am.binding.channel, bm.binding.channel);
        expected_b.push(outbound);
        expected_a.push(reverse);
    }
    assert!(pump(&mut a, &mut b, 0)? > 0);
    assert_eq!(a.status().queued.packets, 7);
    assert_eq!(b.status().queued.packets, 7);
    assert!(a.poll_output()?.is_none());
    assert!(b.poll_output()?.is_none());
    assert_eq!(a.status().receiver_payload.records, 2);
    assert_eq!(b.status().receiver_payload.records, 2);
    let mut actual_a = Vec::new();
    let mut actual_b = Vec::new();
    for time in 1..12 {
        confirm_all(&mut a, &mut actual_a)?;
        confirm_all(&mut b, &mut actual_b)?;
        pump(&mut a, &mut b, time)?;
    }
    expected_a.sort();
    expected_b.sort();
    actual_a.sort();
    actual_b.sort();
    assert_eq!(actual_a, expected_a);
    assert_eq!(actual_b, expected_b);
    assert_eq!(a.status().queued, QueueUsage::default());
    assert_eq!(b.status().queued, QueueUsage::default());
    assert_eq!(a.status().sender_retained, Credit::default());
    assert_eq!(b.status().sender_retained, Credit::default());
    assert_eq!(a.status().receiver_payload, Credit::default());
    assert_eq!(b.status().receiver_payload, Credit::default());
    // Released packets still leave bounded, reusable live-flow bootstrap promises.
    assert_eq!(
        a.status().receiver_reserved,
        Credit {
            bytes: 256,
            records: 2
        }
    );
    assert_eq!(
        b.status().receiver_reserved,
        Credit {
            bytes: 256,
            records: 2
        }
    );
    Ok(())
}

#[test]
fn receive_reorder_duplicates_and_native_prefix_are_independent_of_network_receipt() -> TestResult {
    let (mut a, mut b) = pair()?;
    for n in 0..3 {
        a.enqueue_ip(&ip(1000, 128, false, n), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    b.update_targets(Micros(0), feedback(), &[FlowId(1)])?;
    b.update_targets(Micros(100), feedback(), &[FlowId(1)])?;
    // Only transfer the updated Grant, holding all three actual Data records separately.
    transfer(b.poll_output()?.ok_or("grant")?, &mut a, 100)?;
    let data = [take_data(&mut a)?, take_data(&mut a)?, take_data(&mut a)?];
    assert_eq!(
        b.receive_data(
            &data[2].token,
            data[2].channel,
            &data[2].payload,
            Micros(100)
        )?,
        Received::New
    );
    assert!(b.delivery().is_none());
    assert_eq!(
        b.confirm_delivery(data[2].record),
        Err(Error::NonContiguous)
    );
    for index in [0, 0, 1, 2] {
        let item = &data[index];
        b.receive_data(&item.token, item.channel, &item.payload, Micros(100))?;
    }
    assert_eq!(
        b.status().receiver_payload,
        Credit {
            bytes: 384,
            records: 3
        }
    );
    let promised = b.status().receiver_reserved;
    for item in &data {
        let delivery = b.delivery().ok_or("native prefix")?;
        assert_eq!(delivery.record, item.record);
        assert_eq!(delivery.payload, item.payload);
        assert_eq!(b.delivery().ok_or("stable borrow")?.record, item.record);
        assert_eq!(b.status().receiver_reserved, promised);
        b.confirm_delivery(item.record)?;
        assert_eq!(
            b.confirm_delivery(item.record)?,
            ConfirmOutcome::AlreadyConfirmed
        );
        assert_eq!(
            b.receive_data(&item.token, item.channel, &item.payload, Micros(100))?,
            Received::AlreadyReleased
        );
    }
    assert!(b.delivery().is_none());
    assert_eq!(b.status().receiver_payload, Credit::default());
    // Latest Release and Grant are coalesced per flow, despite repeated confirmations.
    assert_eq!(b.status().pending_controls, 2);
    pump(&mut a, &mut b, 100)?;
    assert_eq!(a.status().sender_retained, Credit::default());
    Ok(())
}

#[test]
fn hostile_scope_length_channel_key_and_duplicate_payload_fail_before_mutation() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(10))?;
    open_only(&mut a, &mut b, 10)?;
    let data = take_data(&mut a)?;
    let initial = b.status();
    for scope in [
        Scope {
            session: 99,
            ..data.record.scope
        },
        Scope {
            epoch: 8,
            ..data.record.scope
        },
        Scope {
            direction: Direction::Reverse,
            ..data.record.scope
        },
    ] {
        let token = wire::encode(Message::Record(Record {
            scope,
            ..data.record
        }))?;
        assert_eq!(
            b.receive_data(&token, data.channel, &data.payload, Micros(10)),
            Err(Error::WrongScope)
        );
        assert_eq!(b.status(), initial);
    }
    assert_eq!(
        b.receive_data(&data.token, data.channel, &data.payload[..127], Micros(10)),
        Err(Error::Length)
    );
    assert_eq!(
        b.receive_data(
            &data.token,
            (data.channel + 1) % 3,
            &data.payload,
            Micros(10)
        ),
        Err(Error::Channel)
    );
    assert_eq!(
        b.receive_data(&data.token, data.channel, &data.payload, Micros(9)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(b.status(), initial);
    b.receive_data(&data.token, data.channel, &data.payload, Micros(10))?;
    let retained = b.status();
    let mut corrupt = data.payload.clone();
    corrupt[127] ^= 1;
    assert_eq!(
        b.receive_data(&data.token, data.channel, &corrupt, Micros(10)),
        Err(Error::ConflictingPayload)
    );
    let changed_key = ip(1001, 128, false, 2);
    let channel = (b.pipeline.classify(&changed_key)?.key.crc32() % 3) as u16;
    assert_eq!(
        b.receive_data(&data.token, channel, &changed_key, Micros(10)),
        Err(Error::FlowKey)
    );
    assert_eq!(
        b.confirm_delivery(Record {
            byte_len: 127,
            ..data.record
        }),
        Err(Error::RecordMismatch)
    );
    assert_eq!(b.status(), retained);
    b.receive_control(
        &wire::encode(Message::Open {
            scope: data.record.scope,
            flow: FlowId(2),
        })?,
        Micros(10),
    )?;
    let second = Record {
        flow: FlowId(2),
        ..data.record
    };
    let status = b.status();
    assert_eq!(
        b.receive_data(
            &wire::encode(Message::Record(second))?,
            data.channel,
            &data.payload,
            Micros(10)
        ),
        Err(Error::FlowKey)
    );
    assert_eq!(b.status(), status);
    Ok(())
}

#[test]
fn first_aggressive_flow_cannot_take_later_small_flow_bootstrap_or_stall_it() -> TestResult {
    let (mut a, mut b) = pair()?;
    for n in 0..40 {
        a.enqueue_ip(&ip(1000, 128, false, n), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    for time in [0, 100, 200, 300, 400] {
        b.update_targets(Micros(time), feedback(), &[FlowId(1)])?;
    }
    assert_eq!(
        b.status().receiver_reserved,
        Credit {
            bytes: 3712,
            records: 29
        }
    );
    assert_eq!(
        b.status().protected_unopened,
        Credit {
            bytes: 384,
            records: 3
        }
    );
    pump(&mut a, &mut b, 400)?;
    assert_eq!(a.status().queued.packets, 11);
    assert!(a.poll_output()?.is_none());
    a.enqueue_ip(&ip(1001, 40, false, 90), 1, Micros(400))?;
    pump(&mut a, &mut b, 400)?;
    assert_eq!(a.status().queued.packets, 11);
    assert_eq!(b.status().incoming_flows, 2);
    assert_eq!(b.status().receiver_payload.records, 30);
    // One bulk confirmation rotates native service to the newly eligible small flow.
    let first = b.delivery().ok_or("bulk native head")?.record;
    assert_eq!(first.flow, FlowId(1));
    b.confirm_delivery(first)?;
    let small = b.delivery().ok_or("small native head")?;
    assert_eq!(small.record.flow, FlowId(2));
    assert_eq!(small.payload, ip(1001, 40, false, 90));
    let record = small.record;
    b.confirm_delivery(record)?;
    // Backpressure reduces targets, never revokes the outstanding bulk promise.
    let before = b.incoming.get(&FlowId(1)).ok_or("flow")?.grant.flow_limit;
    let reduced = b.update_targets(
        Micros(500),
        Feedback {
            receiver_pressure: true,
            ..feedback()
        },
        &[FlowId(1), FlowId(2)],
    )?;
    assert!(reduced.total().bytes < 4096);
    assert!(fits(
        before,
        b.incoming.get(&FlowId(1)).ok_or("flow")?.grant.flow_limit
    ));
    a.enqueue_ip(&ip(1001, 40, false, 91), 1, Micros(500))?;
    pump(&mut a, &mut b, 500)?;
    assert_eq!(b.incoming.get(&FlowId(2)).ok_or("small")?.pending.len(), 1);
    bounded(&a);
    bounded(&b);
    Ok(())
}

#[test]
fn queue_and_flow_failures_preserve_ids_accounting_and_original_admission() -> TestResult {
    let mut cfg = config();
    cfg.pipeline.queue = QueueLimits {
        bytes: 128,
        packets: 1,
    };
    if let Profile::TunDrr(ref mut policy) = cfg.pipeline.profile {
        policy.per_flow = cfg.pipeline.queue;
    }
    let mut a = Active::new(cfg, Direction::Forward, Micros(0))?;
    a.enqueue_ip(&ip(1000, 128, false, 0), 1, Micros(5))?;
    let status = a.status();
    assert!(
        a.enqueue_ip(&ip(1001, 128, false, 0), 1, Micros(6))
            .is_err()
    );
    assert!(
        a.enqueue_ip(&ip(1001, 128, false, 0), 0, Micros(6))
            .is_err()
    );
    assert!(a.enqueue_ip(&[0; 128], 1, Micros(6)).is_err());
    assert_eq!(a.status(), status);
    assert_eq!(a.last_time, Micros(5));
    let mut b = Active::new(config(), Direction::Reverse, Micros(0))?;
    pump(&mut a, &mut b, 5)?;
    let second = a.enqueue_ip(&ip(1001, 128, false, 0), 1, Micros(6))?;
    assert_eq!(second.binding.id.0, 2);
    pump(&mut a, &mut b, 6)?;
    for port in [1002, 1003] {
        a.enqueue_ip(&ip(port, 128, false, 0), 1, Micros(6))?;
        pump(&mut a, &mut b, 6)?;
    }
    let before = a.status();
    assert!(
        a.enqueue_ip(&ip(1004, 128, false, 0), 1, Micros(6))
            .is_err()
    );
    assert_eq!(a.status(), before);
    assert_eq!(a.status().outgoing_flows, 4);
    Ok(())
}

#[test]
fn slow_native_consumer_reserves_unreceived_data_and_never_creates_fake_release() -> TestResult {
    let (mut a, mut b) = pair()?;
    for n in 0..10 {
        a.enqueue_ip(&ip(1000, 128, false, n), 1, Micros(0))?;
    }
    open_only(&mut a, &mut b, 0)?;
    assert_eq!(
        b.status().receiver_reserved,
        Credit {
            bytes: 128,
            records: 1
        }
    );
    assert_eq!(b.status().receiver_payload, Credit::default());
    let data = take_data(&mut a)?;
    for _ in 0..100 {
        b.receive_data(&data.token, data.channel, &data.payload, Micros(0))?;
        assert!(a.poll_output()?.is_none());
        assert!(b.poll_output()?.is_none());
        assert_eq!(
            a.status().sender_retained,
            Credit {
                bytes: 128,
                records: 1
            }
        );
        assert_eq!(
            b.status().receiver_payload,
            Credit {
                bytes: 128,
                records: 1
            }
        );
    }
    b.confirm_delivery(data.record)?;
    pump(&mut a, &mut b, 1)?;
    assert_eq!(a.status().queued.packets, 8);
    assert_eq!(b.delivery().ok_or("next delivery")?.record.id, RecordId(1));
    Ok(())
}

#[test]
fn controls_coalesce_and_open_order_and_abandon_are_explicit() -> TestResult {
    let (mut a, mut b) = pair()?;
    let scope = a.send_scope;
    for _ in 0..100 {
        b.receive_control(
            &wire::encode(Message::Open {
                scope,
                flow: FlowId(2),
            })?,
            Micros(0),
        )?;
    }
    assert_eq!(b.status().pending_controls, 1);
    assert_eq!(b.status().incoming_flows, 1);
    let status = b.status();
    assert_eq!(
        b.receive_control(
            &wire::encode(Message::Open {
                scope,
                flow: FlowId(1)
            })?,
            Micros(0)
        ),
        Err(Error::Credit(CreditError::FlowIdNotIncreasing))
    );
    assert_eq!(b.status(), status);
    let offset = FinalOffset {
        scope,
        flow: FlowId(2),
        admitted: Credit::default(),
    };
    for message in [
        Message::Final {
            offset,
            mode: RetirementMode::Abandon,
        },
        Message::FinalAck {
            offset: FinalOffset {
                scope: b.send_scope,
                ..offset
            },
            mode: RetirementMode::Abandon,
        },
    ] {
        assert_eq!(
            b.receive_control(&wire::encode(message)?, Micros(0)),
            Err(Error::UnsupportedRetirement)
        );
    }
    a.enqueue_ip(&ip(1000, 128, false, 0), 1, Micros(0))?;
    assert_eq!(
        a.sender.preview_admit(FlowId(1), 128),
        Err(CreditError::SenderExhausted(LimitDomain::Flow))
    );
    assert_eq!(b.status(), status);
    Ok(())
}

#[test]
fn targets_require_measured_rtt_and_known_bounded_demand_without_retracting_grants() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(0))?;
    open_only(&mut a, &mut b, 0)?;
    b.update_targets(Micros(0), feedback(), &[FlowId(1)])?;
    assert_eq!(
        b.update_targets(Micros(99), feedback(), &[FlowId(1)])?
            .total()
            .bytes,
        512
    );
    assert_eq!(
        b.update_targets(Micros(100), feedback(), &[FlowId(1)])?
            .total()
            .bytes,
        1024
    );
    assert_eq!(
        b.update_targets(Micros(199), feedback(), &[FlowId(1)])?
            .total()
            .bytes,
        1024
    );
    let status = b.status();
    assert_eq!(
        b.update_targets(Micros(199), feedback(), &[FlowId(99)]),
        Err(Error::UnknownFlow)
    );
    assert_eq!(
        b.update_targets(Micros(199), feedback(), &[FlowId(1); 5]),
        Err(Error::Target(TargetError::TooManyFlows))
    );
    assert_eq!(
        b.update_targets(Micros(199), feedback(), &[FlowId(1); 2]),
        Err(Error::Target(TargetError::DuplicateFlow))
    );
    assert_eq!(b.status(), status);
    let before = b.incoming.get(&FlowId(1)).ok_or("flow")?.grant;
    b.update_targets(
        Micros(200),
        Feedback {
            receiver_pressure: true,
            ..feedback()
        },
        &[FlowId(1)],
    )?;
    assert_eq!(b.incoming.get(&FlowId(1)).ok_or("flow")?.grant, before);
    Ok(())
}

#[test]
fn configuration_rejects_tap_rr_mismatched_caps_and_underfunded_bootstrap() -> TestResult {
    let mut cfg = config();
    cfg.pipeline.profile = Profile::TapSystem;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::UnsupportedProfile)
    ));
    cfg = config();
    cfg.pipeline.flows.mapping = Mapping::ConnectionRoundRobin;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::UnsupportedProfile)
    ));
    cfg = config();
    cfg.send_capacity.max_flows = 3;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::InvalidConfig)
    ));
    cfg = config();
    cfg.target.minimum.bytes = 511;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::InvalidConfig)
    ));
    cfg = config();
    cfg.target.minimum.records = 3;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::InvalidConfig)
    ));
    cfg = config();
    cfg.receive_capacity.credit.bytes -= 1;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::InvalidConfig)
    ));
    cfg = config();
    cfg.target.queue_allowance_bytes = 1;
    assert!(matches!(
        Active::new(cfg, Direction::Forward, Micros(0)),
        Err(Error::Target(TargetError::InvalidConfig))
    ));
    Ok(())
}

#[test]
fn source_retention_blocks_without_spending_credit_and_other_flows_resume_on_release() -> TestResult
{
    let mut cfg = config();
    cfg.send_capacity.credit = Credit {
        bytes: 128,
        records: 1,
    };
    let mut a = Active::new(cfg, Direction::Forward, Micros(0))?;
    let mut b = Active::new(config(), Direction::Reverse, Micros(0))?;
    a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(0))?;
    a.enqueue_ip(&ip(1001, 128, false, 2), 1, Micros(0))?;
    pump(&mut a, &mut b, 0)?;
    assert_eq!(a.status().queued.packets, 1);
    let before = a.status();
    for _ in 0..100 {
        assert!(a.poll_output()?.is_none());
    }
    assert_eq!(a.status(), before);
    let first = b.delivery().ok_or("first")?.record;
    b.confirm_delivery(first)?;
    pump(&mut a, &mut b, 1)?;
    let second = b.delivery().ok_or("second")?.record;
    assert_ne!(first.flow, second.flow);
    assert_eq!(second.id, RecordId(0));
    assert_eq!(second.byte_start, 0);
    assert_eq!(a.status().queued.packets, 0);
    bounded(&a);
    bounded(&b);
    Ok(())
}

#[test]
fn queued_control_and_ready_data_both_get_bounded_service() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(0))?;
    open_only(&mut a, &mut b, 0)?;
    a.enqueue_ip(&ip(1001, 128, false, 2), 1, Micros(0))?;
    let first = a.poll_output()?.ok_or("data")?;
    assert!(matches!(first, Output::Data(_)));
    transfer(first, &mut b, 0)?;
    let second = a.poll_output()?.ok_or("open")?;
    assert!(matches!(second, Output::Control(_)));
    transfer(second, &mut b, 0)?;
    pump(&mut a, &mut b, 0)?;
    assert_eq!(b.status().receiver_payload.records, 2);
    Ok(())
}

#[test]
fn receive_bounds_unknown_flow_and_wrong_message_rejections_are_atomic() -> TestResult {
    let (mut a, mut b) = pair()?;
    a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(0))?;
    open_only(&mut a, &mut b, 0)?;
    let data = take_data(&mut a)?;
    let initial = b.status();
    assert_eq!(
        b.receive_control(&data.token, Micros(0)),
        Err(Error::WrongMessage)
    );
    let open = wire::encode(Message::Open {
        scope: data.record.scope,
        flow: FlowId(2),
    })?;
    assert_eq!(
        b.receive_data(&open, data.channel, &data.payload, Micros(0)),
        Err(Error::WrongMessage)
    );
    let unknown = Record {
        flow: FlowId(99),
        ..data.record
    };
    assert_eq!(
        b.receive_data(
            &wire::encode(Message::Record(unknown))?,
            data.channel,
            &data.payload,
            Micros(0)
        ),
        Err(Error::UnknownFlow)
    );
    let beyond = Record {
        id: RecordId(1),
        byte_start: 128,
        ..data.record
    };
    assert_eq!(
        b.receive_data(
            &wire::encode(Message::Record(beyond))?,
            data.channel,
            &data.payload,
            Micros(0)
        ),
        Err(Error::Credit(CreditError::GrantExceeded))
    );
    assert_eq!(b.status(), initial);
    for id in 2..=4 {
        b.receive_control(
            &wire::encode(Message::Open {
                scope: data.record.scope,
                flow: FlowId(id),
            })?,
            Micros(0),
        )?;
    }
    let before = b.status();
    assert_eq!(
        b.receive_control(
            &wire::encode(Message::Open {
                scope: data.record.scope,
                flow: FlowId(5)
            })?,
            Micros(0)
        ),
        Err(Error::Credit(CreditError::TooManyFlows))
    );
    assert_eq!(b.status(), before);
    assert_eq!(b.status().protected_unopened, Credit::default());
    bounded(&b);
    Ok(())
}

fn retirement_pair() -> Result<(Active, Active), Error> {
    let mut cfg = config();
    cfg.pipeline.flows.capacity = 2;
    cfg.pipeline.flows.idle_timeout = Duration::from_micros(10);
    cfg.send_capacity.max_flows = 2;
    cfg.receive_capacity.max_flows = 2;
    cfg.target.max_flows = 2;
    Ok((
        Active::new(cfg, Direction::Forward, Micros(0))?,
        Active::new(cfg, Direction::Reverse, Micros(0))?,
    ))
}

fn policy() -> RetirementPolicy {
    RetirementPolicy {
        retry_micros: 100,
        max_attempts: 3,
    }
}

fn drained_packet(
    a: &mut Active,
    b: &mut Active,
    port: u16,
    time: u64,
) -> Result<PacketMetadata, Box<dyn std::error::Error>> {
    let metadata = a.enqueue_ip(&ip(port, 128, false, 1), 1, Micros(time))?;
    pump(a, b, time)?;
    let record = b.delivery().ok_or("native packet")?.record;
    b.confirm_delivery(record)?;
    pump(a, b, time)?;
    Ok(metadata)
}

fn take_control(engine: &mut Active) -> Result<[u8; WIRE_LEN], Box<dyn std::error::Error>> {
    match engine.poll_output()?.ok_or("control")? {
        Output::Control(token) => Ok(token),
        Output::Data(_) => Err("unexpected data".into()),
    }
}

#[test]
fn serialized_retirement_reuses_bounded_slots_for_hundreds_of_bidirectional_flows() -> TestResult {
    let (mut a, mut b) = retirement_pair()?;
    for cycle in 0..100 {
        let time = cycle * 20;
        let payload_a = ip(1000 + cycle as u16, 128, false, cycle as u8);
        let payload_b = ip(1000 + cycle as u16, 80, true, cycle as u8);
        let am = a.enqueue_ip(&payload_a, 1, Micros(time))?;
        let bm = b.enqueue_ip(&payload_b, 1, Micros(time))?;
        assert_eq!(am.binding.id.0, cycle + 1);
        assert_eq!(bm.binding.id.0, cycle + 1);
        pump(&mut a, &mut b, time)?;
        let ar = a.delivery().ok_or("a delivery")?;
        assert_eq!(ar.payload, payload_b);
        a.confirm_delivery(ar.record)?;
        let br = b.delivery().ok_or("b delivery")?;
        assert_eq!(br.payload, payload_a);
        b.confirm_delivery(br.record)?;
        pump(&mut a, &mut b, time)?;
        let retirement_time = Micros(time + 10);
        assert_eq!(
            a.idle_candidate(retirement_time)?,
            Some(am.classification.key)
        );
        a.request_idle_retirement(
            &am.classification.key,
            retirement_time,
            policy(),
            ExternalDrain::default(),
        )?;
        b.request_idle_retirement(
            &bm.classification.key,
            retirement_time,
            policy(),
            ExternalDrain::default(),
        )?;
        pump(&mut a, &mut b, time + 10)?;
        for engine in [&a, &b] {
            assert_eq!(engine.status().outgoing_flows, 0);
            assert_eq!(engine.status().incoming_flows, 0);
            assert_eq!(engine.status().receiver_reserved, Credit::default());
            assert_eq!(engine.status().receiver_payload, Credit::default());
            assert!(engine.status().pending_retirement.is_none());
            assert_eq!(engine.status().cached_final_ack, Some(FlowId(cycle + 1)));
            assert!(engine.keys.is_empty());
            assert!(engine.controls.is_empty());
            bounded(engine);
        }
    }
    Ok(())
}

#[test]
fn final_retries_recover_a_lost_ack_and_freeze_the_key_until_exact_ack() -> TestResult {
    let (mut a, mut b) = retirement_pair()?;
    let metadata = drained_packet(&mut a, &mut b, 1000, 0)?;
    let offset = a.request_idle_retirement(
        &metadata.classification.key,
        Micros(10),
        policy(),
        ExternalDrain::default(),
    )?;
    assert_eq!(
        a.request_idle_retirement(
            &metadata.classification.key,
            Micros(11),
            policy(),
            ExternalDrain::default()
        )?,
        offset
    );
    assert_eq!(
        a.enqueue_ip(&ip(1000, 128, false, 2), 1, Micros(11)),
        Err(Error::FlowFrozen)
    );
    let final_token = take_control(&mut a)?;
    b.receive_control(&final_token, Micros(11))?;
    let lost_ack = take_control(&mut b)?;
    assert_eq!(b.status().receiver_reserved, Credit::default());
    assert_eq!(a.status().outgoing_flows, 1);
    a.poll_retirement(Micros(109))?;
    assert!(a.poll_output()?.is_none());
    a.poll_retirement(Micros(110))?;
    let retry = take_control(&mut a)?;
    assert_eq!(retry, final_token);
    b.receive_control(&retry, Micros(110))?;
    let ack = take_control(&mut b)?;
    assert_eq!(ack, lost_ack);
    let conflict = FinalOffset {
        admitted: Credit {
            bytes: 127,
            records: 1,
        },
        ..offset
    };
    let bad_ack = wire::encode(Message::FinalAck {
        offset: conflict,
        mode: RetirementMode::Drained,
    })?;
    assert_eq!(
        a.receive_control(&bad_ack, Micros(110)),
        Err(Error::FinalMismatch)
    );
    assert_eq!(a.status().outgoing_flows, 1);
    a.receive_control(&ack, Micros(110))?;
    a.receive_control(&ack, Micros(110))?;
    assert_eq!(a.status().outgoing_flows, 0);
    assert!(a.poll_output()?.is_none());
    let next = a.enqueue_ip(&ip(1000, 128, false, 2), 1, Micros(111))?;
    assert_eq!(next.binding.id.0, 2);
    Ok(())
}

#[test]
fn queued_final_coalescing_does_not_spend_attempts_and_exhaustion_never_unfreezes() -> TestResult {
    let (mut a, mut b) = retirement_pair()?;
    let metadata = drained_packet(&mut a, &mut b, 1000, 0)?;
    a.request_idle_retirement(
        &metadata.classification.key,
        Micros(10),
        policy(),
        ExternalDrain::default(),
    )?;
    for time in [110, 210, 310] {
        a.poll_retirement(Micros(time))?;
    }
    assert_eq!(a.status().pending_controls, 1);
    let token = take_control(&mut a)?;
    a.poll_retirement(Micros(310))?;
    assert_eq!(take_control(&mut a)?, token);
    a.poll_retirement(Micros(410))?;
    assert_eq!(take_control(&mut a)?, token);
    assert_eq!(
        a.poll_retirement(Micros(510)),
        Err(Error::RetirementRetriesExhausted)
    );
    assert!(a.status().renewal_required);
    assert_eq!(a.status().pending_retirement, Some(FlowId(1)));
    assert_eq!(a.status().outgoing_flows, 1);
    assert_eq!(
        a.enqueue_ip(&ip(1000, 128, false, 2), 1, Micros(510)),
        Err(Error::RenewalRequired)
    );
    assert_eq!(
        a.poll_retirement(Micros(610)),
        Err(Error::RetirementRetriesExhausted)
    );
    assert!(a.poll_output()?.is_none());
    // A late authentic ACK can finish the barrier but cannot undo terminal renewal.
    b.receive_control(&token, Micros(610))?;
    a.receive_control(&take_control(&mut b)?, Micros(610))?;
    assert_eq!(a.status().outgoing_flows, 0);
    assert!(a.status().renewal_required);
    Ok(())
}

#[test]
fn retirement_requires_local_native_and_external_drain_and_serializes_different_keys() -> TestResult
{
    let (mut a, mut b) = retirement_pair()?;
    let metadata = a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(0))?;
    let key = metadata.classification.key;
    let before = a.status();
    assert_eq!(
        a.request_idle_retirement(&key, Micros(10), policy(), ExternalDrain::default()),
        Err(Error::Pipeline(PipelineError::Busy))
    );
    assert_eq!(a.status(), before);
    pump(&mut a, &mut b, 0)?;
    assert_eq!(
        a.request_idle_retirement(&key, Micros(9), policy(), ExternalDrain::default()),
        Err(Error::NotIdle)
    );
    assert_eq!(
        a.request_idle_retirement(&key, Micros(10), policy(), ExternalDrain::default()),
        Err(Error::Credit(CreditError::OutstandingRecords))
    );
    let record = b.delivery().ok_or("pending native")?.record;
    let malicious = FinalOffset {
        scope: record.scope,
        flow: record.flow,
        admitted: Credit {
            bytes: 128,
            records: 1,
        },
    };
    let token = wire::encode(Message::Final {
        offset: malicious,
        mode: RetirementMode::Drained,
    })?;
    let state = b.status();
    assert_eq!(
        b.receive_control(&token, Micros(10)),
        Err(Error::Credit(CreditError::OutstandingRecords))
    );
    assert_eq!(b.status(), state);
    b.confirm_delivery(record)?;
    pump(&mut a, &mut b, 0)?;
    for external in [
        ExternalDrain {
            pending_outputs: 1,
            pending_recovery_records: 0,
        },
        ExternalDrain {
            pending_outputs: 0,
            pending_recovery_records: 1,
        },
    ] {
        assert_eq!(
            a.request_idle_retirement(&key, Micros(10), policy(), external),
            Err(Error::ExternalPending)
        );
    }
    assert_eq!(
        a.request_idle_retirement(
            &key,
            Micros(10),
            RetirementPolicy {
                retry_micros: 0,
                max_attempts: 1
            },
            ExternalDrain::default()
        ),
        Err(Error::InvalidRetirementPolicy)
    );
    let second = drained_packet(&mut a, &mut b, 1001, 0)?;
    a.request_idle_retirement(&key, Micros(10), policy(), ExternalDrain::default())?;
    assert_eq!(
        a.request_idle_retirement(
            &second.classification.key,
            Micros(10),
            policy(),
            ExternalDrain::default()
        ),
        Err(Error::RetirementBusy)
    );
    assert!(a.idle_candidate(Micros(10))?.is_none());
    pump(&mut a, &mut b, 10)?;
    a.request_idle_retirement(
        &second.classification.key,
        Micros(10),
        policy(),
        ExternalDrain::default(),
    )?;
    pump(&mut a, &mut b, 10)?;
    assert_eq!(a.status().outgoing_flows, 0);
    Ok(())
}

#[test]
fn stale_uncached_final_cannot_replace_new_ack_or_close_live_session() -> TestResult {
    let (mut a, mut b) = retirement_pair()?;
    let first = drained_packet(&mut a, &mut b, 1000, 0)?;
    let old = a.request_idle_retirement(
        &first.classification.key,
        Micros(10),
        policy(),
        ExternalDrain::default(),
    )?;
    let old_token = take_control(&mut a)?;
    b.receive_control(&old_token, Micros(10))?;
    let old_ack = take_control(&mut b)?;
    a.receive_control(&old_ack, Micros(10))?;
    let second = drained_packet(&mut a, &mut b, 1001, 20)?;
    let current = a.request_idle_retirement(
        &second.classification.key,
        Micros(30),
        policy(),
        ExternalDrain::default(),
    )?;
    let token = take_control(&mut a)?;
    b.receive_control(&token, Micros(30))?;
    let before = b.status();
    b.receive_control(&old_token, Micros(30))?;
    let older_conflict = FinalOffset {
        admitted: Credit {
            bytes: 1,
            records: 1,
        },
        ..old
    };
    b.receive_control(
        &wire::encode(Message::Final {
            offset: older_conflict,
            mode: RetirementMode::Drained,
        })?,
        Micros(30),
    )?;
    assert_eq!(b.status(), before);
    assert_eq!(b.status().cached_final_ack, Some(current.flow));
    let new_ack = take_control(&mut b)?;
    assert_eq!(
        wire::decode(&new_ack)?,
        Message::FinalAck {
            offset: current,
            mode: RetirementMode::Drained
        }
    );
    a.receive_control(&old_ack, Micros(30))?;
    assert_eq!(a.status().pending_retirement, Some(current.flow));
    a.receive_control(&new_ack, Micros(30))?;
    let malformed_current = FinalOffset {
        admitted: Credit {
            bytes: 1,
            records: 1,
        },
        ..current
    };
    assert_eq!(
        b.receive_control(
            &wire::encode(Message::Final {
                offset: malformed_current,
                mode: RetirementMode::Drained
            })?,
            Micros(30)
        ),
        Err(Error::FinalMismatch)
    );
    assert_eq!(b.status().cached_final_ack, Some(current.flow));
    let third = drained_packet(&mut a, &mut b, 1002, 40)?;
    assert_eq!(third.binding.id.0, 3);
    bounded(&a);
    bounded(&b);
    Ok(())
}

#[test]
fn split_control_polling_keeps_release_live_while_outbound_bulk_is_held() -> TestResult {
    let (mut a, mut b) = pair()?;
    for value in 0..2 {
        a.enqueue_ip(&ip(1000, 128, false, value), 1, Micros(0))?;
        b.enqueue_ip(&ip(1000, 128, true, value), 1, Micros(0))?;
    }
    let a_open = a.poll_control()?.ok_or("a Open")?;
    let b_open = b.poll_control()?.ok_or("b Open")?;
    b.receive_control(&a_open, Micros(0))?;
    a.receive_control(&b_open, Micros(0))?;
    let a_grant = a.poll_control()?.ok_or("a Grant")?;
    let b_grant = b.poll_control()?.ok_or("b Grant")?;
    b.receive_control(&a_grant, Micros(0))?;
    a.receive_control(&b_grant, Micros(0))?;
    let held_bulk = a.poll_data()?.ok_or("held A data")?;
    assert_eq!(held_bulk.record.id, RecordId(0));
    let b_data = b.poll_data()?.ok_or("B data")?;
    a.receive_data(&b_data.token, b_data.channel, &b_data.payload, Micros(0))?;
    let delivery = a.delivery().ok_or("native")?.record;
    a.confirm_delivery(delivery)?;
    let before = a.status();
    while let Some(control) = a.poll_control()? {
        b.receive_control(&control, Micros(0))?;
    }
    assert_eq!(a.status().queued, before.queued);
    assert_eq!(a.status().sender_retained, before.sender_retained);
    assert_eq!(b.poll_data()?.ok_or("B progresses")?.record.id, RecordId(1));
    assert_eq!(b.status().receiver_payload, Credit::default());
    assert_eq!(held_bulk.payload, ip(1000, 128, false, 0));
    Ok(())
}
