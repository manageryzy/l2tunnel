use super::*;
use crate::tests::{config, ip, pair, pump};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy() -> RetirementPolicy {
    RetirementPolicy {
        retry_micros: 10,
        max_attempts: 2,
    }
}

fn next(engine: &Active, channels: u16) -> ActiveConfig {
    let mut config = engine.config;
    config.epoch += 1;
    config.pipeline.flows.channels = channels;
    config
}

fn control(engine: &mut Active) -> Result<[u8; WIRE_LEN], Box<dyn std::error::Error>> {
    engine
        .poll_control()?
        .ok_or_else(|| "missing control".into())
}

fn finish_flows(a: &mut Active, b: &mut Active, now: u64) -> TestResult {
    for _ in 0..8 {
        for engine in [&mut *a, &mut *b] {
            if let Some(key) = engine.drained_candidate()? {
                engine.request_drained_retirement(
                    &key,
                    Micros(now),
                    policy(),
                    ExternalDrain::default(),
                )?;
            }
        }
        pump(a, b, now)?;
        if a.status().outgoing_flows == 0 && b.status().outgoing_flows == 0 {
            return Ok(());
        }
    }
    Err("drain did not finish".into())
}

#[test]
fn explicit_retirement_preserves_release_and_ack_proof_without_idle_wait() -> TestResult {
    let (mut a, mut b) = pair()?;
    let metadata = a.enqueue_ip(&ip(1000, 128, false, 9), 1, Micros(0))?;
    let key = metadata.classification.key;
    assert!(a.drained_candidate()?.is_none());
    assert_eq!(
        a.request_drained_retirement(&key, Micros(0), policy(), ExternalDrain::default()),
        Err(Error::Pipeline(PipelineError::Busy))
    );
    pump(&mut a, &mut b, 0)?;
    assert_eq!(a.drained_candidate()?, Some(key));
    assert_eq!(
        a.request_drained_retirement(&key, Micros(0), policy(), ExternalDrain::default()),
        Err(Error::Credit(CreditError::OutstandingRecords))
    );
    assert!(a.idle_candidate(Micros(0))?.is_none());
    b.confirm_delivery(b.delivery().ok_or("delivery")?.record)?;
    pump(&mut a, &mut b, 0)?;
    let offset =
        a.request_drained_retirement(&key, Micros(0), policy(), ExternalDrain::default())?;
    assert_eq!(
        offset.admitted,
        Credit {
            bytes: 128,
            records: 1
        }
    );
    assert_eq!(
        a.enqueue_ip(&ip(1000, 128, false, 2), 1, Micros(0)),
        Err(Error::FlowFrozen)
    );
    let final_token = control(&mut a)?;
    b.receive_control(&final_token, Micros(0))?;
    assert_eq!(
        b.drained_reader(ExternalDrain::default()),
        Err(Error::EpochNotDrained)
    );
    assert_eq!(a.status().outgoing_flows, 1);
    assert_eq!(b.status().receiver_reserved, Credit::default());
    let ack = control(&mut b)?;
    a.receive_control(&ack, Micros(0))?;
    assert_eq!(a.status().outgoing_flows, 0);
    assert_eq!(
        a.enqueue_ip(&ip(1000, 128, false, 3), 2, Micros(0))?
            .binding
            .id
            .0,
        2
    );
    Ok(())
}

#[test]
fn opened_without_data_requires_final_and_actual_ack_handoff_before_epoch_commit() -> TestResult {
    let mut b = Active::new(config(), Direction::Reverse, Micros(0))?;
    let staged = b.prepare_epoch(next(&b, 1), Micros(0))?;
    let scope = b.receive_scope;
    b.receive_control(
        &wire::encode(Message::Open {
            scope,
            flow: FlowId(1),
        })?,
        Micros(0),
    )?;
    let before = b.status();
    assert!(before.receiver_reserved.bytes > 0);
    let error = b
        .commit_epoch(staged, Micros(0), ExternalDrain::default())
        .err()
        .ok_or("must reject reservation")?;
    assert_eq!(error.error, Error::EpochNotDrained);
    assert_eq!(b.status(), before);
    let _grant = control(&mut b)?;
    let offset = FinalOffset {
        scope,
        flow: FlowId(1),
        admitted: Credit::default(),
    };
    let final_token = wire::encode(Message::Final {
        offset,
        mode: RetirementMode::Drained,
    })?;
    b.receive_control(&final_token, Micros(0))?;
    let error = b
        .commit_epoch(error.prepared, Micros(0), ExternalDrain::default())
        .err()
        .ok_or("must reject queued ack")?;
    assert_eq!(error.error, Error::EpochNotDrained);
    let _ack = control(&mut b)?;
    let reader = b.drained_reader(ExternalDrain::default())?;
    for _ in 0..32 {
        reader.check_control(&final_token)?;
    }
    assert_eq!(b.status().pending_controls, 0);
    let error = b
        .commit_epoch(
            error.prepared,
            Micros(0),
            ExternalDrain {
                pending_outputs: 1,
                pending_recovery_records: 0,
            },
        )
        .err()
        .ok_or("must reject unflushed ack")?;
    assert_eq!(error.error, Error::ExternalPending);
    let retired = b.commit_epoch(error.prepared, Micros(0), ExternalDrain::default())?;
    assert_eq!(retired.epoch(), 7);
    retired.check_control(&final_token)?;
    assert_eq!(
        b.receive_control(&final_token, Micros(0)),
        Err(Error::WrongScope)
    );
    let replay = wire::encode(Message::Open {
        scope: b.receive_scope,
        flow: FlowId(1),
    })?;
    let status = b.status();
    assert_eq!(
        b.receive_control(&replay, Micros(0)),
        Err(Error::Credit(CreditError::FlowIdNotIncreasing))
    );
    assert_eq!(b.status(), status);
    b.receive_control(
        &wire::encode(Message::Open {
            scope: b.receive_scope,
            flow: FlowId(2),
        })?,
        Micros(0),
    )?;
    Ok(())
}

#[test]
fn epoch_commit_rejections_return_same_allocation_and_never_mutate_live_engine() -> TestResult {
    let (mut a, mut b) = pair()?;
    let staged = a.prepare_epoch(next(&a, 256), Micros(5))?;
    let allocation = std::ptr::from_ref(&staged.inner.engine);
    let error = a
        .commit_epoch(staged, Micros(4), ExternalDrain::default())
        .err()
        .ok_or("backwards staging time")?;
    assert_eq!(error.error, Error::NonMonotonicTime);
    assert_eq!(std::ptr::from_ref(&error.prepared.inner.engine), allocation);
    let metadata = a.enqueue_ip(&ip(1000, 128, false, 1), 1, Micros(5))?;
    let before = a.status();
    let error = a
        .commit_epoch(error.prepared, Micros(5), ExternalDrain::default())
        .err()
        .ok_or("queued source")?;
    assert_eq!(error.error, Error::EpochNotDrained);
    assert_eq!(a.status(), before);
    pump(&mut a, &mut b, 5)?;
    let before = a.status();
    let error = a
        .commit_epoch(error.prepared, Micros(5), ExternalDrain::default())
        .err()
        .ok_or("retained source")?;
    assert_eq!(error.error, Error::EpochNotDrained);
    assert_eq!(a.status(), before);
    b.confirm_delivery(b.delivery().ok_or("native")?.record)?;
    pump(&mut a, &mut b, 5)?;
    a.request_drained_retirement(
        &metadata.classification.key,
        Micros(5),
        policy(),
        ExternalDrain::default(),
    )?;
    let final_token = control(&mut a)?;
    let error = a
        .commit_epoch(error.prepared, Micros(5), ExternalDrain::default())
        .err()
        .ok_or("pending final")?;
    assert_eq!(error.error, Error::EpochNotDrained);
    b.receive_control(&final_token, Micros(5))?;
    a.receive_control(&control(&mut b)?, Micros(5))?;
    let error = a
        .commit_epoch(
            error.prepared,
            Micros(5),
            ExternalDrain {
                pending_outputs: 0,
                pending_recovery_records: 1,
            },
        )
        .err()
        .ok_or("external recovery")?;
    assert_eq!(error.error, Error::ExternalPending);
    assert_eq!(std::ptr::from_ref(&error.prepared.inner.engine), allocation);
    a.commit_epoch(error.prepared, Micros(6), ExternalDrain::default())?;
    assert_eq!(a.config.epoch, 8);
    assert_eq!(a.config.pipeline.flows.channels, 256);
    assert_eq!(a.last_time, Micros(6));
    Ok(())
}

#[test]
fn bidirectional_rotation_preserves_bytes_global_ids_and_changes_channels_weights() -> TestResult {
    let (mut a, mut b) = pair()?;
    for (round, channels) in [1, 256, 2].into_iter().enumerate() {
        let time = round as u64;
        let sa = a.prepare_epoch(next(&a, channels), Micros(time))?;
        let sb = b.prepare_epoch(next(&b, channels), Micros(time))?;
        for flow in 0..4 {
            let payload = ip(1000 + flow, 100 + usize::from(flow), false, round as u8);
            let reverse = ip(1000 + flow, 110 + usize::from(flow), true, 9);
            let am = a.enqueue_ip(&payload, round as u32 + 1, Micros(time))?;
            let bm = b.enqueue_ip(&reverse, round as u32 + 1, Micros(time))?;
            assert_eq!(am.binding.id.0, time * 4 + u64::from(flow) + 1);
            assert_eq!(bm.binding.id.0, am.binding.id.0);
            assert!(am.binding.channel < a.config.pipeline.flows.channels);
            pump(&mut a, &mut b, time)?;
            let ad = a.delivery().ok_or("reverse native")?;
            assert_eq!(ad.payload, reverse);
            let ar = ad.record;
            a.confirm_delivery_at(ar, Micros(time))?;
            let bd = b.delivery().ok_or("forward native")?;
            assert_eq!(bd.payload, payload);
            let br = bd.record;
            b.confirm_delivery_at(br, Micros(time))?;
            pump(&mut a, &mut b, time)?;
        }
        finish_flows(&mut a, &mut b, time)?;
        let ra = a.commit_epoch(sa, Micros(time), ExternalDrain::default())?;
        let rb = b.commit_epoch(sb, Micros(time), ExternalDrain::default())?;
        assert_eq!(ra.epoch(), 7 + time);
        assert_eq!(rb.epoch(), ra.epoch());
        for engine in [&a, &b] {
            assert_eq!(engine.config.pipeline.flows.channels, channels);
            assert_eq!(engine.highest_outgoing, Some(FlowId((time + 1) * 4)));
            assert_eq!(engine.highest_incoming, engine.highest_outgoing);
            assert_eq!(engine.status().receiver_reserved, Credit::default());
            assert!(engine.native_sample().is_none());
        }
    }
    Ok(())
}

#[test]
fn invalid_staging_wrong_owner_terminal_and_exhausted_epochs_cannot_reset_state() -> TestResult {
    let (mut a, b) = pair()?;
    let original = a.status();
    for changed in 0..6 {
        let mut c = next(&a, 2);
        match changed {
            0 => c.session += 1,
            1 => c.epoch += 1,
            2 => c.target.bootstrap_rtt_micros += 1,
            3 => c.pipeline.flows.capacity += 1,
            4 => c.pipeline.flows.idle_timeout += Duration::from_secs(1),
            _ => c.pipeline.parse.max_packet_bytes -= 1,
        }
        assert!(matches!(
            a.prepare_epoch(c, Micros(0)),
            Err(Error::InvalidEpoch)
        ));
        assert_eq!(a.status(), original);
    }
    let staged = b.prepare_epoch(next(&b, 2), Micros(0))?;
    let rejected = a
        .commit_epoch(staged, Micros(0), ExternalDrain::default())
        .err()
        .ok_or("wrong direction")?;
    assert_eq!(rejected.error, Error::InvalidEpoch);
    let staged = a.prepare_epoch(next(&a, 2), Micros(0))?;
    a.renewal_required = true;
    let rejected = a
        .commit_epoch(staged, Micros(0), ExternalDrain::default())
        .err()
        .ok_or("terminal")?;
    assert_eq!(rejected.error, Error::RenewalRequired);
    a.renewal_required = false;
    a.highest_incoming = Some(FlowId(u64::MAX));
    let rejected = a
        .commit_epoch(rejected.prepared, Micros(0), ExternalDrain::default())
        .err()
        .ok_or("flow exhaustion")?;
    assert_eq!(rejected.error, Error::RenewalRequired);
    assert_eq!(a.config.epoch, 7);
    a.config.epoch = u64::MAX;
    assert!(matches!(
        a.prepare_epoch(a.config, Micros(0)),
        Err(Error::RenewalRequired)
    ));
    Ok(())
}

#[test]
fn old_tombstone_is_constant_context_and_never_grants_or_recreates_new_state() -> TestResult {
    let (mut a, mut b) = pair()?;
    let metadata = a.enqueue_ip(&ip(1000, 100, false, 1), 1, Micros(0))?;
    let open = control(&mut a)?;
    b.receive_control(&open, Micros(0))?;
    let grant = control(&mut b)?;
    a.receive_control(&grant, Micros(0))?;
    let data = a.poll_data()?.ok_or("data")?;
    b.receive_data(&data.token, data.channel, &data.payload, Micros(0))?;
    b.confirm_delivery(data.record)?;
    let release = control(&mut b)?;
    a.receive_control(&release, Micros(0))?;
    let offset = a.request_drained_retirement(
        &metadata.classification.key,
        Micros(0),
        policy(),
        ExternalDrain::default(),
    )?;
    let final_token = control(&mut a)?;
    b.receive_control(&final_token, Micros(0))?;
    let ack = control(&mut b)?;
    a.receive_control(&ack, Micros(0))?;
    // Grant coalesced by native regrant must also leave the old control queue.
    pump(&mut a, &mut b, 0)?;
    let ra = a.commit_epoch(
        a.prepare_epoch(next(&a, 1), Micros(0))?,
        Micros(0),
        ExternalDrain::default(),
    )?;
    let rb = b.commit_epoch(
        b.prepare_epoch(next(&b, 1), Micros(0))?,
        Micros(0),
        ExternalDrain::default(),
    )?;
    let status = a.status();
    for token in [grant, release, ack] {
        ra.check_control(&token)?;
        assert_eq!(a.receive_control(&token, Micros(0)), Err(Error::WrongScope));
        assert_eq!(a.status(), status);
    }
    rb.check_control(&open)?;
    rb.check_control(&final_token)?;
    assert_eq!(rb.check_control(&data.token), Err(Error::WrongMessage));
    assert!(matches!(
        ra.check_control(&ack[..71]),
        Err(Error::Wire(wire::Error::Length))
    ));
    let bad = wire::encode(Message::Final {
        offset: FinalOffset {
            admitted: Credit {
                bytes: 99,
                records: 1,
            },
            ..offset
        },
        mode: RetirementMode::Drained,
    })?;
    assert_eq!(rb.check_control(&bad), Err(Error::FinalMismatch));
    let future = wire::encode(Message::Open {
        scope: offset.scope,
        flow: FlowId(2),
    })?;
    assert_eq!(rb.check_control(&future), Err(Error::UnknownFlow));
    Ok(())
}
