use super::*;

fn advance(lab: &mut Lab, until: Micros) -> TestResult {
    for _ in 0..200 {
        if lab.at() >= until {
            return Ok(());
        }
        lab.step()?;
    }
    Err("bounded actual table advance exhausted".into())
}

// Deliver genuine native input and relay records while withholding B's native
// polls/ACKs. This creates actual sender exhaustion, not invented feedback.
fn source_step(lab: &mut Lab) -> TestResult {
    lab.now += 1;
    let now = Millis(lab.now);
    let host = &mut lab.hosts[0][0];
    host.poll(now, 8)?;
    while let Some(bytes) = host.pop_packet() {
        assert_eq!(
            lab.a.ingest_native(&bytes, false, now)?,
            session::Disposition::Owned(1)
        );
    }
    lab.a.poll(now, 64, 8)?;
    if let Some(bytes) = lab.a.pending_native(1).map(<[u8]>::to_vec) {
        host.ingest(&bytes)?;
        lab.a.confirm_native_written(1)?;
    }
    exchange(&mut lab.a, &mut lab.b, now)
}

fn exhaust(lab: &mut Lab) -> TestResult {
    assert_eq!(lab.hosts[0][0].write(&[0x73; 1024])?, 1024);
    for _ in 0..30 {
        source_step(lab)?;
        let status = lab.a.relay_status(1).ok_or("actual source relay")?;
        if status.native.receive_bytes > 0
            && (status.produced.bytes == status.peer_granted.bytes
                || status.produced.records == status.peer_granted.records)
        {
            return Ok(());
        }
    }
    Err("actual source did not exhaust its finite grant".into())
}

fn report(
    peer: &mut Owner,
    table: &session::Table,
    flow: u64,
    now: Micros,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    peer.stage_demand(table, flow, now)?;
    let pending = peer.pending(table, now)?.ok_or("actual demand output")?;
    assert_eq!(pending.flow, flow);
    let (id, bytes) = (pending.id, pending.bytes.to_vec());
    peer.confirm_admission(id.clone(), now)?;
    peer.confirm_written(id, now)?;
    Ok(bytes)
}

fn echo(
    c: &mut Controller,
    peer: &mut Owner,
    lab: &Lab,
) -> Result<Micros, Box<dyn std::error::Error>> {
    let at = lab.at();
    let (id, bytes) = request(c, &lab.b, at)?;
    c.confirm_written(&lab.b, id, at)?;
    let response = reply(peer, &lab.a, &bytes, Micros(at.0 + 1000))?;
    let received = Micros(at.0 + 2000);
    assert_eq!(
        c.receive_authenticated(&lab.b, &response, received)?,
        Ingress::Accepted
    );
    Ok(received)
}

fn bootstrap(lab: &mut Lab) -> Result<(Controller, Owner), Box<dyn std::error::Error>> {
    let start = lab.at();
    let mut c = controller(&lab.b, start)?;
    c.observe_table(&lab.b, start)?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), start)?;
    c.apply(&mut lab.b, plan, start)?;
    let peer = Owner::new(config().ownership, &lab.a, start)?;
    lab.transfer(&[128])?;
    advance(lab, Micros(start.0 + 10_000))?;
    c.observe_table(&lab.b, lab.at())?;
    assert!(
        c.observations(&lab.b, lab.at())?
            .ack_rate
            .is_some_and(|rate| rate.bytes == 128 && rate.bytes_per_second > 0)
    );
    Ok((c, peer))
}

#[test]
fn real_ack_echo_and_retained_native_demand_grow_once_per_service_interval() -> TestResult {
    let mut lab = Lab::new(1)?;
    let (mut c, mut peer) = bootstrap(&mut lab)?;
    exhaust(&mut lab)?;
    let bytes = report(&mut peer, &lab.a, 1, lab.at())?;
    c.receive_authenticated(&lab.b, &bytes, lab.at())?;
    let at = echo(&mut c, &mut peer, &lab)?;
    let observations = c.observations(&lab.b, at)?;
    assert_eq!(observations.unknown_flows, 0);
    assert!(observations.grant_exhausted);
    assert_eq!(
        observations.service_latency.ok_or("echo")?.smoothed_micros,
        2000
    );
    let issued = lab.b.credit_status(1).ok_or("issued grant")?.granted;
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    assert_eq!(plan.allocation().state, adaptive::TargetState::Probing);
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 1024,
            records: 4
        }
    );
    c.apply(&mut lab.b, plan, at)?;
    assert_eq!(
        lab.b
            .credit_status(1)
            .ok_or("unchanged issued grant")?
            .granted,
        issued
    );
    let too_soon = Micros(at.0 + 1999);
    let plan = c.prepare(&lab.b, LocalPressure::default(), too_soon)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 1024,
            records: 4
        }
    );
    c.apply(&mut lab.b, plan, too_soon)?;
    let next = Micros(at.0 + 2000);
    let plan = c.prepare(&lab.b, LocalPressure::default(), next)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 2048,
            records: 8
        }
    );
    Ok(())
}

#[test]
fn an_unknown_active_flow_blocks_aggregate_growth_until_actual_fresh_report() -> TestResult {
    let mut lab = Lab::new(2)?;
    let (mut c, mut peer) = bootstrap(&mut lab)?;
    exhaust(&mut lab)?;
    let bytes = report(&mut peer, &lab.a, 1, lab.at())?;
    c.receive_authenticated(&lab.b, &bytes, lab.at())?;
    let at = echo(&mut c, &mut peer, &lab)?;
    let state = c.observations(&lab.b, at)?;
    assert_eq!(
        (
            state.active_flows,
            state.demanding_flows,
            state.unknown_flows
        ),
        (2, 2, 1)
    );
    assert!(state.grant_exhausted && state.ack_rate.is_some());
    assert!(state.service_latency.ok_or("fresh echo")?.fresh);
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 512,
            records: 2
        }
    );
    c.apply(&mut lab.b, plan, at)?;
    let bytes = report(&mut peer, &lab.a, 2, at)?;
    c.receive_authenticated(&lab.b, &bytes, at)?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 1024,
            records: 4
        }
    );
    assert_eq!(c.observations(&lab.b, at)?.unknown_flows, 0);
    Ok(())
}

#[test]
fn stale_demand_blocks_growth_despite_new_real_ack_rate_echo_and_in_flight() -> TestResult {
    let mut lab = Lab::new(1)?;
    let (mut c, mut peer) = bootstrap(&mut lab)?;
    exhaust(&mut lab)?;
    let report_at = lab.at();
    c.receive_authenticated(&lab.b, &report(&mut peer, &lab.a, 1, report_at)?, report_at)?;
    advance(&mut lab, Micros(report_at.0 + 30_000))?;
    c.observe_table(&lab.b, lab.at())?; // A genuine long sampling gap discards old bins.
    let previous = lab
        .b
        .credit_status(1)
        .ok_or("ACK baseline")?
        .acknowledged
        .bytes;
    assert_eq!(lab.hosts[0][0].write(&[0x26; 128])?, 128);
    for _ in 0..50 {
        lab.step()?;
        if lab.b.credit_status(1).ok_or("new ACK")?.acknowledged.bytes >= previous + 128 {
            break;
        }
    }
    assert_eq!(
        lab.b.credit_status(1).ok_or("new ACK")?.acknowledged.bytes,
        previous + 128
    );
    advance(&mut lab, Micros(report_at.0 + 40_000))?;
    c.observe_table(&lab.b, lab.at())?;
    exhaust(&mut lab)?;
    let at = echo(&mut c, &mut peer, &lab)?;
    let state = c.observations(&lab.b, at)?;
    assert_eq!(state.unknown_flows, 1);
    assert_eq!(state.demanding_flows, 1);
    assert!(
        state
            .ack_rate
            .is_some_and(|r| r.bytes == 128 && r.bytes_per_second > 0)
    );
    assert!(state.service_latency.ok_or("fresh echo")?.fresh);
    assert!(state.in_flight.bytes >= 512 || state.in_flight.records >= 2);
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 512,
            records: 2
        }
    );
    c.apply(&mut lab.b, plan, at)?;
    c.receive_authenticated(&lab.b, &report(&mut peer, &lab.a, 1, at)?, at)?;
    let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
    assert_eq!(
        plan.allocation().candidate,
        Window {
            bytes: 1024,
            records: 4
        }
    );
    Ok(())
}

#[test]
fn obsolete_byte_or_record_grants_do_not_qualify_exhaustion_after_real_release() -> TestResult {
    for byte_dimension in [true, false] {
        let mut lab = Lab::new(1)?;
        let (mut c, mut peer) = bootstrap(&mut lab)?;
        let delivered = lab
            .b
            .credit_status(1)
            .ok_or("ACK baseline")?
            .acknowledged
            .bytes;
        exhaust(&mut lab)?;
        let actual = report(&mut peer, &lab.a, 1, lab.at())?;
        let wire::Body::Demand(mut value) = wire::decode(&actual)?.body else {
            return Err("actual source report was not Demand".into());
        };
        assert!(value.native_unread_bytes > 0);
        // Remove the other valid signal so each obsolete dimension is exercised.
        value.byte_blocked = byte_dimension;
        value.record_blocked = !byte_dimension;
        let bytes = demand(&lab.b, 1, value)?;
        c.receive_authenticated(&lab.b, &bytes, lab.at())?;
        assert!(c.observations(&lab.b, lab.at())?.grant_exhausted);
        for _ in 0..100 {
            lab.step()?;
            if lab
                .b
                .credit_status(1)
                .ok_or("released native")?
                .acknowledged
                .bytes
                >= delivered + 1024
            {
                break;
            }
        }
        let credit = lab.b.credit_status(1).ok_or("released native")?;
        assert_eq!(credit.acknowledged.bytes, delivered + 1024);
        assert_eq!(credit.received, credit.acknowledged);
        assert!(if byte_dimension {
            credit.granted.bytes > value.observed_grant.bytes
        } else {
            credit.granted.records > value.observed_grant.records
        });
        c.observe_table(&lab.b, lab.at())?;
        let at = echo(&mut c, &mut peer, &lab)?;
        let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
        assert_eq!(
            plan.allocation().candidate,
            Window {
                bytes: 512,
                records: 2
            }
        );
        assert!(!c.observations(&lab.b, at)?.grant_exhausted);
        // Even a new authenticated serial cannot make the obsolete grant current.
        c.receive_authenticated(&lab.b, &demand(&lab.b, 2, value)?, at)?;
        let plan = c.prepare(&lab.b, LocalPressure::default(), at)?;
        assert_eq!(
            plan.allocation().candidate,
            Window {
                bytes: 512,
                records: 2
            }
        );
        assert!(!c.observations(&lab.b, at)?.grant_exhausted);
    }
    Ok(())
}

#[test]
fn ack_catchup_starts_idle_only_at_first_successful_observe_or_prepare() -> TestResult {
    for observe_first in [true, false] {
        let mut lab = Lab::new(1)?;
        let mut c = controller(&lab.b, lab.at())?;
        let mut peer = Owner::new(config().ownership, &lab.a, lab.at())?;
        assert_eq!(lab.hosts[0][0].write(&[0x19; 128])?, 128);
        for _ in 0..30 {
            source_step(&mut lab)?;
            if lab.a.relay_status(1).ok_or("source relay")?.produced.bytes == 128 {
                break;
            }
        }
        let report_at = lab.at();
        let bytes = report(&mut peer, &lab.a, 1, report_at)?;
        let wire::Body::Demand(value) = wire::decode(&bytes)?.body else {
            return Err("actual source report was not Demand".into());
        };
        assert_eq!(
            (value.native_unread_bytes, value.pending_data_bytes),
            (0, 0)
        );
        assert_eq!(value.produced.bytes, 128);
        assert_eq!(
            lab.b
                .credit_status(1)
                .ok_or("unreleased")?
                .acknowledged
                .bytes,
            0
        );
        c.receive_authenticated(&lab.b, &bytes, report_at)?;
        for _ in 0..30 {
            lab.step()?;
            if lab
                .b
                .credit_status(1)
                .ok_or("ACK catchup")?
                .acknowledged
                .contains(value.produced)
            {
                break;
            }
        }
        assert!(
            lab.b
                .credit_status(1)
                .ok_or("ACK catchup")?
                .acknowledged
                .contains(value.produced)
        );
        let first = Micros(report_at.0 + 15_000);
        assert!(lab.at() < first);
        let diagnostic = c.observations(&lab.b, Micros(first.0 - 1000))?;
        assert_eq!(diagnostic.authoritative_at, report_at);
        assert_eq!(diagnostic.demanding_flows, 1);
        unchanged(
            &mut c,
            |c| {
                c.prepare(
                    &lab.b,
                    LocalPressure {
                        queue_delay_micros: u64::MAX,
                        ..Default::default()
                    },
                    Micros(first.0 - 1000),
                )
            },
            ControllerError::Configuration,
        );
        if observe_first {
            c.observe_table(&lab.b, first)?;
        } else {
            let plan = c.prepare(&lab.b, LocalPressure::default(), first)?;
            assert_ne!(plan.allocation().candidate, Window::default());
        }
        let plan = c.prepare(&lab.b, LocalPressure::default(), Micros(first.0 + 9999))?;
        assert_ne!(plan.allocation().candidate, Window::default());
        let plan = c.prepare(&lab.b, LocalPressure::default(), Micros(first.0 + 10_000))?;
        assert_eq!(plan.allocation().candidate, Window::default());
    }
    Ok(())
}
