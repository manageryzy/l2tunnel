use super::*;

// The client sends application data. The server half-closes with a
// data-bearing FIN whose sequence space wraps to four.
fn tcp(client: bool, port: u16, len: usize, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut frame = packet(true, 0x31, len);
    let (src, dst, sport, dport) = if client {
        (1, 2, port, 443)
    } else {
        (2, 1, 443, port)
    };
    frame[15] = src;
    frame[19] = dst;
    frame[20..22].copy_from_slice(&sport.to_be_bytes());
    frame[22..24].copy_from_slice(&dport.to_be_bytes());
    frame[24..28].copy_from_slice(&seq.to_be_bytes());
    frame[28..32].copy_from_slice(&ack.to_be_bytes());
    frame[33] = flags;
    frame
}

#[test]
fn covering_ack_waits_for_older_record_while_another_flow_releases_early() -> TestResult {
    let mut config = short_config(64, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    for end in [&mut sender, &mut receiver] {
        end.enable_queue_aware_repair_budget(1500)?;
    }
    let fin = tcp(false, 1000, 48, u32::MAX - 4, 0, 0x11);
    receiver
        .enqueue_admitted_identified(Tick(0), 0, &fin)?
        .ok_or("local FIN admission")?;
    let frames = [
        tcp(true, 1000, 100, 100, 3, 0x10),
        tcp(true, 1000, 40, 160, 4, 0x10),
        tcp(true, 1001, 40, 160, 4, 0x10),
    ];
    let mut rows = Vec::new();
    let mut number = 1;
    for frame in &frames {
        let id = sender
            .enqueue_admitted_identified(Tick(0), 0, frame)?
            .ok_or("frame admission")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (_, data) = emit(&mut sender, Tick(0), &mut number, true)?.ok_or("source output")?;
        rows.push((id, data));
    }
    for (_, data) in &rows[1..] {
        receiver.accept_authenticated(Tick(1), data.kind, &data.bytes)?;
        service_until(&mut receiver, Tick(1), |e| !e.work_pending())?;
    }
    let mut buf = [0; 1024];
    let unrelated = ready(&mut receiver, Tick(1), &mut buf)?;
    assert_eq!(unrelated.identity(), rows[2].0);
    assert!(unrelated.early());
    assert_eq!(&buf[..unrelated.bytes()], frames[2]);
    receiver.commit_native(Tick(1), unrelated.token())?;
    for _ in 0..receiver.receive_config.receiver.channels {
        assert_eq!(
            receiver.prepare_native(Tick(1), 1, Tick(1_000_000), &mut buf)?,
            NativePreparation::Idle
        );
    }
    receiver.accept_authenticated(Tick(2), rows[0].1.kind, &rows[0].1.bytes)?;
    service_until(&mut receiver, Tick(2), |e| !e.work_pending())?;
    for i in [0, 1] {
        let n = ready(&mut receiver, Tick(2), &mut buf)?;
        assert_eq!(n.identity(), rows[i].0);
        assert!(!n.early());
        assert_eq!(&buf[..n.bytes()], frames[i]);
        receiver.commit_native(Tick(2), n.token())?;
        assert_eq!(receiver.fin_order.active(), i == 0);
    }
    Ok(())
}

#[test]
fn unclassified_traffic_and_stale_acks_do_not_change_other_flow_eligibility() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let policy = NativePolicy::RawIp;
    let mut guard = Guard::new(cfg.forward)?;
    guard.admitted(policy, &[0xff; 16]);
    assert!(!guard.active());
    let old = tcp(true, 1000, 40, 0, 3, 0x10);
    let ack = tcp(true, 1000, 40, 0, 4, 0x10);
    let other = tcp(true, 1001, 40, 0, 4, 0x10);
    guard.admitted(policy, &tcp(false, 1000, 48, u32::MAX - 4, 0, 0x11));
    guard.admitted(policy, &[0xff; 16]);
    guard.ordered_commit(policy, &old);
    assert!(guard.may_deliver_early(policy, &old));
    assert!(!guard.may_deliver_early(policy, &ack));
    assert!(guard.may_deliver_early(policy, &other));
    let mut new = Guard::new(cfg.forward)?;
    new.inherit(&guard);
    assert!(!new.may_deliver_early(policy, &ack));
    new.ordered_commit(policy, &ack);
    assert!(!new.active());
    Ok(())
}

fn vlan_ipv6(packet: &[u8], vid: u16) -> Vec<u8> {
    // A VLAN, IPv6 and one destination-options header precede the same TCP
    // segment. Ethernet padding does not occupy TCP sequence space.
    let mut bytes = vec![0; 18 + 40 + 8];
    bytes[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&vid.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x86ddu16.to_be_bytes());
    bytes[18] = 0x60;
    bytes[22..24].copy_from_slice(&((packet.len() - 20 + 8) as u16).to_be_bytes());
    bytes[24] = 60;
    bytes[25] = 64;
    bytes[41] = packet[15];
    bytes[57] = packet[19];
    bytes[58] = 6;
    bytes.extend_from_slice(&packet[20..]);
    bytes.extend_from_slice(&[0; 8]);
    bytes
}

#[test]
fn guard_uses_ipv6_extensions_vlan_domain_and_reverse_direction() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = NativePolicy::EthernetHeaders;
    let fin = tcp(false, 1000, 48, u32::MAX - 4, 0, 0x11);
    let ack = tcp(true, 1000, 40, 123, 4, 0x10);
    guard.admitted(policy, &vlan_ipv6(&fin, 17));
    assert!(!guard.may_deliver_early(policy, &vlan_ipv6(&ack, 17)));
    assert!(guard.may_deliver_early(policy, &vlan_ipv6(&ack, 18)));
    assert!(guard.may_deliver_early(policy, &vlan_ipv6(&tcp(false, 1000, 40, 123, 4, 0x10), 17)));
    guard.ordered_commit(policy, &vlan_ipv6(&ack, 17));
    assert!(!guard.active());
    Ok(())
}

#[test]
fn overflow_keeps_live_fences_and_allows_other_buckets() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = NativePolicy::RawIp;
    let capacity = guard.capacity_bytes();
    for port in 1000..1017 {
        guard.admitted(policy, &tcp(false, port, 48, u32::MAX - 4, 0, 0x11));
    }
    assert_eq!(capacity, guard.capacity_bytes());
    for port in 1000..1017 {
        let ack = tcp(true, port, 40, 123, 4, 0x10);
        assert!(!guard.may_deliver_early(policy, &ack));
        guard.ordered_commit(policy, &ack);
    }
    assert!(guard.active());
    assert!(!guard.may_deliver_early(policy, &tcp(true, 1016, 40, 123, 4, 0x10)));
    assert!(
        (2000..2100)
            .any(|port| guard.may_deliver_early(policy, &tcp(true, port, 40, 123, 4, 0x10)))
    );
    assert!(guard.may_deliver_early(policy, &tcp(true, 1016, 40, 123, 4, 0)));
    Ok(())
}

#[test]
fn tun_delivers_future_tcp_data_and_sacks_before_late_predecessor_exactly_once() -> TestResult {
    let mut config = short_config(64, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.receiver.lookahead_records = 16;
    config.forward.native_release = NativeRelease::Independent;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    for end in [&mut sender, &mut receiver] {
        end.enable_queue_aware_repair_budget(1500)?;
    }
    let mut sack = tcp(true, 1000, 52, 1077, 600, 0x10);
    sack[32] = 0x80;
    sack[40..52].copy_from_slice(&[1, 1, 5, 10, 0, 0, 3, 0, 0, 0, 3, 16]);
    sack[36..38].copy_from_slice(&0xb88bu16.to_be_bytes());
    let frames = [
        tcp(true, 1000, 40, 1000, 0, 2),
        tcp(true, 1001, 40, 2000, 0, 2),
        tcp(true, 1000, 100, 1001, 0, 0x10),
        tcp(true, 1002, 100, 8000, 0, 0x10),
        tcp(true, 1000, 160, 1061, 0, 0x10),
        tcp(true, 1001, 56, 2001, 0, 0x10),
        sack.clone(),
        sack,
    ];
    let mut rows = Vec::new();
    let mut number = 1;
    for frame in &frames {
        let id = sender
            .enqueue_admitted_identified(Tick(0), 0, frame)?
            .ok_or("admission")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (_, data) = emit(&mut sender, Tick(0), &mut number, true)?.ok_or("source")?;
        rows.push((id, data));
    }
    let accept = |receiver: &mut Endpoint, i: usize, now: Tick| -> TestResult {
        let (_, data) = &rows[i];
        receiver.accept_authenticated(now, data.kind, &data.bytes)?;
        service_until(receiver, now, |owner| !owner.work_pending())
    };
    let mut buf = [0; 1024];
    for i in [0, 1] {
        accept(&mut receiver, i, Tick(1))?;
        let n = ready(&mut receiver, Tick(1), &mut buf)?;
        assert_eq!(n.identity(), rows[i].0);
        receiver.commit_native(Tick(1), n.token())?;
    }
    for i in 4..8 {
        accept(&mut receiver, i, Tick(2))?;
    }
    for i in 4..8 {
        let n = ready(&mut receiver, Tick(2), &mut buf)?;
        assert_eq!(n.identity(), rows[i].0);
        assert!(n.early());
        assert_eq!(&buf[..n.bytes()], frames[i]);
        assert_eq!(
            receiver.prepare_native(Tick(2), 8, Tick(8_000_000), &mut buf)?,
            NativePreparation::AlreadyPending(n)
        );
        assert_eq!(n.deadline(), Tick(5_000_002));
        receiver.commit_native(Tick(2), n.token())?;
    }
    for _ in 0..config.forward.receiver.channels {
        assert_eq!(
            receiver.prepare_native(Tick(3), 8, Tick(8_000_000), &mut buf)?,
            NativePreparation::Idle
        );
    }
    accept(&mut receiver, 2, Tick(4))?;
    let older = ready(&mut receiver, Tick(4), &mut buf)?;
    assert_eq!(older.identity(), rows[2].0);
    assert_eq!(&buf[..older.bytes()], frames[2]);
    assert_eq!(
        receiver.prepare_native(Tick(5), 8, Tick(8_000_000), &mut buf)?,
        NativePreparation::AlreadyPending(older)
    );
    receiver.commit_native(Tick(5), older.token())?;
    assert_eq!(receiver.record_status().early_tombstones, 4);
    accept(&mut receiver, 4, Tick(7))?;
    accept(&mut receiver, 3, Tick(8))?;
    let last = ready(&mut receiver, Tick(8), &mut buf)?;
    assert_eq!(last.identity(), rows[3].0);
    receiver.commit_native(Tick(8), last.token())?;
    for _ in 0..16 {
        assert!(matches!(
            receiver.prepare_native(Tick(8), 16, Tick(8_000_000), &mut buf)?,
            NativePreparation::Idle | NativePreparation::Progress
        ));
    }
    assert_eq!(receiver.statistics().committed, frames.len() as u64);
    assert_eq!(receiver.record_status().early_tombstones, 0);
    Ok(())
}

#[test]
fn payload_edge_wraps_and_requires_live_ordered_evidence_after_tuple_reuse() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Ordered, Wait};
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = NativePolicy::RawIp;
    let start = u32::MAX - 4;
    let syn = tcp(true, 1000, 40, start, 0, 2);
    let first = tcp(true, 1000, 48, start + 1, 0, 0x10);
    let second = tcp(true, 1000, 56, 4, 0, 0x10);
    let Wait(unknown) = guard.decision(policy, &first, 0) else {
        return Err("unknown edge should wait".into());
    };
    guard.native_commit(policy, &first, true, 0);
    assert!(!guard.changed(unknown));
    guard.native_commit(policy, &syn, false, 1);
    assert!(guard.changed(unknown));
    let Wait(gap) = guard.decision(policy, &second, 1) else {
        return Err("eight missing bytes across wrap should hold the tail".into());
    };
    assert!(matches!(guard.decision(policy, &first, 1), Allow));
    guard.native_commit(policy, &first, true, 2);
    assert!(guard.changed(gap));
    assert!(matches!(guard.decision(policy, &first, 2), Allow));
    assert!(matches!(guard.decision(policy, &second, 2), Allow));
    let ambiguous = tcp(true, 1000, 48, 4 + (1 << 31), 0, 0x10);
    assert!(matches!(guard.decision(policy, &ambiguous, 2), Wait(_)));
    assert!(matches!(
        guard.decision(policy, &second, 5_000_002),
        Wait(_)
    ));
    let new_syn = tcp(true, 1000, 44, 8000, 0, 2);
    assert!(matches!(
        guard.decision(policy, &new_syn, 5_000_003),
        Ordered
    ));
    guard.native_commit(policy, &new_syn, false, 5_000_003);
    let fresh = tcp(true, 1000, 56, 8005, 0, 0x10);
    assert!(matches!(guard.decision(policy, &fresh, 5_000_003), Allow));
    let new_future = tcp(true, 1000, 56, 8021, 0, 0x10);
    assert!(matches!(
        guard.decision(policy, &new_future, 5_000_003),
        Wait(_)
    ));
    Ok(())
}

#[test]
fn unknown_midstream_flow_learns_from_contiguous_ordered_commits_and_preserves_live_storage()
-> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Wait};
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let policy = NativePolicy::RawIp;
    let mut guard = Guard::new(cfg.forward)?;
    let capacity = guard.capacity_bytes();
    let first = tcp(true, 1000, 48, 100, 0, 0x10);
    let missing = tcp(true, 1000, 48, 108, 0, 0x10);
    let far = tcp(true, 1000, 48, 116, 0, 0x10);
    let tail = tcp(true, 1000, 56, 124, 0, 0x10);
    guard.native_commit(policy, &first, false, 0);
    assert!(matches!(guard.decision(policy, &missing, 1), Wait(_)));
    guard.native_commit(policy, &far, false, 1);
    assert!(matches!(guard.decision(policy, &tail, 2), Wait(_)));
    guard.native_commit(policy, &missing, false, 2);
    assert!(matches!(guard.decision(policy, &tail, 3), Allow));
    let mut overflow = 0;
    for port in 2000..2128 {
        guard.native_commit(policy, &tcp(true, port, 40, 100, 0, 2), false, 4);
        if matches!(
            guard.decision(policy, &tcp(true, port, 48, 101, 0, 0x10), 4),
            Wait(_)
        ) {
            overflow += 1;
        }
    }
    assert!(overflow > 0);
    assert!(matches!(guard.decision(policy, &tail, 5), Allow));
    assert_eq!(guard.capacity_bytes(), capacity);
    Ok(())
}

#[test]
fn independent_tun_data_requires_live_flow_and_keeps_lifecycle_fences() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Ordered, Wait};

    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = NativePolicy::IpHeaders;
    let start = u32::MAX - 32;
    let future = tcp(true, 1000, 150, 48, 0, 0x10);
    assert!(matches!(
        guard.independent_ip_decision(policy, &future, 0, false),
        Wait(_)
    ));
    guard.native_commit(policy, &tcp(true, 1000, 40, start, 0, 2), false, 0);
    assert!(matches!(
        guard.independent_ip_decision(policy, &future, 1, false),
        Allow
    ));
    assert!(matches!(
        guard.independent_ip_decision(policy, &future, 5_000_000, false),
        Wait(_)
    ));
    for flags in [0x12, 0x11, 0x14] {
        let control = tcp(true, 1000, 150, 48, 0, flags);
        assert!(matches!(
            guard.independent_ip_decision(policy, &control, 1, false),
            Ordered
        ));
    }
    let ambiguous = tcp(true, 1000, 150, (start + 1).wrapping_add(1 << 31), 0, 0x10);
    assert!(matches!(
        guard.independent_ip_decision(policy, &ambiguous, 1, false),
        Wait(_)
    ));
    guard.admitted(policy, &tcp(false, 1000, 40, 999, 0, 0x11));
    let covering = tcp(true, 1000, 150, 48, 1000, 0x10);
    assert!(matches!(
        guard.independent_ip_decision(policy, &covering, 1, false),
        Ordered
    ));
    Ok(())
}

#[test]
fn hold35_keeps_first_deadline_bypasses_old_gap_and_rearms_after_commit() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Wait};
    let mut cfg = short_config(64, rolling::wire::SourceWire::TargetedNear8Hold35);
    cfg.forward.native_policy = NativePolicy::RawIp;
    let policy = cfg.forward.native_policy;
    let mut guard = Guard::new(cfg.forward)?;
    let first = u32::MAX - 15;
    let frame = |offset: u32| tcp(true, 1000, 56, first.wrapping_add(offset), 0, 0x10);
    let syn = tcp(true, 1000, 40, first.wrapping_sub(1), 0, 2);
    guard.native_commit(policy, &syn, false, 0);
    let Wait(token) = guard.held_ip_decision(policy, &frame(16), 30, false, false) else {
        return Err("channel head did not wait".into());
    };
    assert_eq!(guard.hold_wake(), Some(35_030));
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(32), 35_029, false, true),
        Wait(_)
    ));
    assert!(!guard.expire_holds(35_029));
    assert_eq!(guard.hold_wake(), Some(35_030));
    assert!(guard.expire_holds(35_030));
    assert!(guard.changed(token));
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(16), 35_030, false, true),
        Allow
    ));
    guard.native_commit(policy, &frame(16), true, 35_030);
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(32), 90_000, false, true),
        Allow
    ));
    guard.native_commit(policy, &frame(32), true, 90_000);
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(0), 100_000, false, true),
        Allow
    ));
    guard.native_commit(policy, &frame(0), true, 100_000);
    let Wait(second) = guard.held_ip_decision(policy, &frame(64), 100_001, false, true) else {
        return Err("second independent gap did not rearm".into());
    };
    guard.native_commit(policy, &frame(48), false, 100_002);
    assert!(guard.changed(second));
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(64), 100_002, false, true),
        Allow
    ));
    guard.native_commit(policy, &frame(64), true, 100_002);
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(96), 100_003, false, true),
        Wait(_)
    ));
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(80 + 256 * 1024), 100_004, false, true),
        Allow
    ));
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(96), 100_004, false, true),
        Allow
    ));
    let counts = guard.hold_status().ok_or("selected hold counters")?;
    assert_eq!(counts.starts, 3);
    assert_eq!(counts.deadline_releases, 1);
    assert_eq!(counts.span_releases, 1);
    assert_eq!(counts.bypass_writes, 2);
    assert_eq!(counts.prefix_closes, 1);
    assert_eq!(counts.bypass_prefix_closes, 1);
    assert_eq!(counts.range_overflows, 0);
    Ok(())
}

#[test]
fn hold35_endpoint_wakes_for_a_complete_channel_head_with_an_inner_tcp_hole() -> TestResult {
    hold35_endpoint(true)?;
    hold35_endpoint(false)
}

fn hold35_endpoint(timeout: bool) -> TestResult {
    let mut cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    cfg.forward.scheduler.source_wire = rolling::wire::SourceWire::TargetedNear8Hold35;
    cfg.forward.scheduler.feedback_ticks = 100_000;
    let mut a = endpoint(cfg, Role::Client)?;
    let mut b = make_receiver(cfg, true)?;
    a.enable_compact_wire(41)?;
    b.enable_compact_wire(73)?;
    a.enable_queue_aware_repair_budget(1500)?;
    b.enable_queue_aware_repair_budget(1500)?;
    a.configure_near8(1500, 100_000_000)?;
    let mut buf = [0; 1024];
    let mut pn = 1;
    let mut rows = Vec::new();
    let syn = tcp(true, 1000, 40, 1000, 0, 2);
    let future = tcp(true, 1000, 56, 1017, 1, 0x10);
    let missing = tcp(true, 1000, 56, 1001, 1, 0x10);
    for frame in [&syn, &future, &missing] {
        a.enqueue_admitted_identified(Tick(0), 0, frame)?
            .ok_or("native admission")?;
        a.flush(Tick(0))?;
        a.step(Tick(0), work())?;
        let (_, packet) = emit(&mut a, Tick(0), &mut pn, true)?.ok_or("source")?;
        rows.push(packet);
    }
    for (i, row) in rows[..2].iter().enumerate() {
        b.accept_authenticated(Tick(1), row.kind, &row.bytes)?;
        service_until(&mut b, Tick(1), |e| !e.work_pending())?;
        if i == 0 {
            let native = ready(&mut b, Tick(1), &mut buf)?;
            assert_eq!(&buf[..native.bytes()], syn);
            b.commit_native(Tick(1), native.token())?;
        }
    }
    for _ in 0..8 {
        assert!(matches!(
            b.prepare_native(Tick(2), 16, Tick(1_000_000), &mut buf)?,
            NativePreparation::Idle | NativePreparation::Progress
        ));
    }
    assert_eq!(b.fin_order.hold_wake(), Some(35_002));
    assert!(b.wake_at().is_some_and(|t| t.0 <= 35_002));
    if !timeout {
        // The held channel head must not hide an independently decodable
        // later record that fills the missing inner TCP bytes.
        b.accept_authenticated(Tick(50), rows[2].kind, &rows[2].bytes)?;
        service_until(&mut b, Tick(50), |e| !e.work_pending())?;
        for expected in [&missing, &future] {
            let packet = ready(&mut b, Tick(50), &mut buf)?;
            assert_eq!(&buf[..packet.bytes()], expected);
            b.commit_native(Tick(50), packet.token())?;
        }
        let status = b.native_reorder_status().ok_or("hold status")?;
        assert_eq!(
            (
                status.starts,
                status.prefix_closes,
                status.deadline_releases
            ),
            (1, 1, 0)
        );
        return Ok(());
    }
    // No new authenticated input while the missing bytes are unavailable.
    assert!(b.step(Tick(35_002), work())?.native_progress);
    let native = ready(&mut b, Tick(35_002), &mut buf)?;
    assert_eq!(&buf[..native.bytes()], future);
    b.commit_native(Tick(35_002), native.token())?;
    b.accept_authenticated(Tick(36_000), rows[2].kind, &rows[2].bytes)?;
    service_until(&mut b, Tick(36_000), |e| !e.work_pending())?;
    let repaired = ready(&mut b, Tick(36_000), &mut buf)?;
    assert_eq!(&buf[..repaired.bytes()], missing);
    b.commit_native(Tick(36_000), repaired.token())?;
    assert_eq!(b.statistics().committed, 3);
    Ok(())
}

#[test]
fn hold35_requires_actual_contiguous_delivery_across_disjoint_released_ranges() -> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Wait};
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedNear8Hold35);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = cfg.forward.native_policy;
    let start = u32::MAX - 32;
    let syn = tcp(true, 1000, 40, start.wrapping_sub(1), 0, 2);
    let frame = |offset: u32| tcp(true, 1000, 56, start.wrapping_add(offset), 0, 0x10);
    guard.native_commit(policy, &syn, false, 0);
    for offset in [16, 48, 80] {
        assert!(matches!(
            guard.held_ip_decision(policy, &frame(offset), 1, false, true),
            Wait(_)
        ));
    }
    assert!(guard.expire_holds(35_001));
    for offset in [16, 48, 80, 0, 64] {
        guard.native_commit(policy, &frame(offset), true, 35_002);
    }
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(112), 35_003, false, true),
        Allow
    ));
    guard.native_commit(policy, &frame(32), true, 35_004);
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(112), 35_005, false, true),
        Wait(_)
    ));
    assert!(guard.expire_holds(70_005));
    for i in 0..33 {
        guard.native_commit(policy, &frame(112 + i * 32), true, 70_006);
    }
    // Overflow of the exact range ledger fails open until the tuple is reset.
    for i in 0..33 {
        guard.native_commit(policy, &frame(96 + i * 32), true, 70_007);
    }
    assert!(matches!(
        guard.held_ip_decision(policy, &frame(1300), 70_008, false, true),
        Allow
    ));
    let new_syn = tcp(true, 1000, 40, 5000, 0, 2);
    guard.native_commit(policy, &new_syn, false, 70_009);
    let future = tcp(true, 1000, 56, 5100, 0, 0x10);
    assert!(matches!(
        guard.held_ip_decision(policy, &future, 70_010, false, true),
        Wait(_)
    ));
    Ok(())
}

#[test]
fn flow_ordered_tun_holds_gap_crossing_data_but_releases_other_flows_and_short_acks() -> TestResult
{
    let mut config = short_config(64, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.receiver.lookahead_records = 16;
    assert_eq!(config.forward.native_release, NativeRelease::Default);
    assert_eq!(
        config.forward.effective_release(),
        EffectiveRelease::FlowOrdered
    );
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    assert_eq!(
        receiver.native_release_status(),
        (NativeRelease::Default, EffectiveRelease::FlowOrdered)
    );
    for end in [&mut sender, &mut receiver] {
        end.enable_queue_aware_repair_budget(1500)?;
    }
    let mut sack = tcp(true, 1000, 52, 1077, 600, 0x10);
    sack[32] = 0x80;
    sack[40..52].copy_from_slice(&[1, 1, 5, 10, 0, 0, 3, 0, 0, 0, 3, 16]);
    sack[36..38].copy_from_slice(&0xb88bu16.to_be_bytes());
    let frames = [
        tcp(true, 1000, 40, 1000, 0, 2),
        tcp(true, 1001, 40, 2000, 0, 2),
        tcp(true, 1000, 100, 1001, 0, 0x10),
        tcp(true, 1002, 100, 8000, 0, 0x10),
        tcp(true, 1000, 160, 1061, 0, 0x10),
        tcp(true, 1001, 56, 2001, 0, 0x10),
        sack.clone(),
        sack,
    ];
    let mut rows = Vec::new();
    let mut number = 1;
    for frame in &frames {
        let id = sender
            .enqueue_admitted_identified(Tick(0), 0, frame)?
            .ok_or("admission")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (_, data) = emit(&mut sender, Tick(0), &mut number, true)?.ok_or("source")?;
        rows.push((id, data));
    }
    let accept = |receiver: &mut Endpoint, i: usize, now: Tick| -> TestResult {
        let (_, data) = &rows[i];
        receiver.accept_authenticated(now, data.kind, &data.bytes)?;
        service_until(receiver, now, |owner| !owner.work_pending())
    };
    let mut buf = [0; 1024];
    let mut deliver = |receiver: &mut Endpoint, i: usize, now: Tick, early: bool| -> TestResult {
        let n = ready(receiver, now, &mut buf)?;
        assert_eq!(n.identity(), rows[i].0);
        assert_eq!(n.early(), early);
        assert_eq!(&buf[..n.bytes()], frames[i]);
        receiver.commit_native(now, n.token())?;
        Ok(())
    };
    for i in [0, 1] {
        accept(&mut receiver, i, Tick(1))?;
        deliver(&mut receiver, i, Tick(1), false)?;
    }
    // Records 2 and 3 are missing. Flow 1000's next data (4) starts after its edge.
    for i in 4..8 {
        accept(&mut receiver, i, Tick(2))?;
    }
    for i in [5, 6, 7] {
        deliver(&mut receiver, i, Tick(2), true)?;
    }
    let mut idle = [0; 1024];
    for _ in 0..config.forward.receiver.channels {
        assert_eq!(
            receiver.prepare_native(Tick(3), 8, Tick(8_000_000), &mut idle)?,
            NativePreparation::Idle
        );
    }
    // The predecessor arrives as the channel head; its commit advances the edge
    // and wakes the waiting segment ahead of the still-missing record 3.
    accept(&mut receiver, 2, Tick(4))?;
    deliver(&mut receiver, 2, Tick(4), false)?;
    deliver(&mut receiver, 4, Tick(5), true)?;
    // Record 3 belongs to an unproven flow and is released as the channel head.
    accept(&mut receiver, 3, Tick(6))?;
    deliver(&mut receiver, 3, Tick(6), false)?;
    for _ in 0..16 {
        assert!(matches!(
            receiver.prepare_native(Tick(7), 16, Tick(8_000_000), &mut idle)?,
            NativePreparation::Idle | NativePreparation::Progress
        ));
    }
    assert_eq!(receiver.statistics().committed, frames.len() as u64);
    Ok(())
}

#[test]
fn flow_ordered_decision_differs_from_independent_only_across_gaps_and_keeps_close_ordered()
-> TestResult {
    use crate::rolling_records::fin_order::Guard;
    use receiver::EarlyDecision::{Allow, Ordered, Wait};
    let cfg = short_config(64, rolling::wire::SourceWire::TargetedExact);
    let mut guard = Guard::new(cfg.forward)?;
    let policy = NativePolicy::RawIp;
    guard.native_commit(policy, &tcp(true, 1000, 40, 1000, 0, 2), false, 0);
    let contiguous = tcp(true, 1000, 100, 1001, 0, 0x10);
    let gap = tcp(true, 1000, 100, 1500, 0, 0x10);
    let fin = tcp(true, 1000, 100, 1001, 0, 0x11);
    let rst = tcp(true, 1000, 40, 1001, 0, 0x14);
    let other_flow_unknown = tcp(true, 2000, 100, 7, 0, 0x10);
    let flow = |bytes: &[u8], short| guard.flow_ordered_ip_decision(policy, bytes, 1, short);
    let independent = |bytes: &[u8], short| guard.independent_ip_decision(policy, bytes, 1, short);
    assert!(matches!(flow(&contiguous, false), Allow));
    assert!(matches!(independent(&contiguous, false), Allow));
    assert!(matches!(flow(&gap, false), Wait(_)));
    assert!(matches!(independent(&gap, false), Allow));
    for close in [&fin, &rst] {
        assert!(matches!(flow(close, true), Ordered));
        assert!(matches!(independent(close, true), Ordered));
    }
    // The existing TAP rule lets a short bare RST go early; IP rules do not.
    assert!(matches!(guard.decision(policy, &rst, 1), Allow));
    assert!(matches!(flow(&other_flow_unknown, false), Wait(_)));
    Ok(())
}
