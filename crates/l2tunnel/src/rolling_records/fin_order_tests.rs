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
