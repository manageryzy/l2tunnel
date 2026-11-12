use super::*;
use crate::admission::{
    Bypass, Error as AdmissionError, InitialSyn, Inspection, Opening, Phase, inspect_open,
    inspect_syn,
};
use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, TcpPacket};

fn candidate(bytes: &[u8]) -> Result<InitialSyn, Box<dyn std::error::Error>> {
    match inspect_syn(bytes, 1500)? {
        Inspection::Candidate(syn) => Ok(syn),
        Inspection::Bypass(reason) => Err(format!("unexpected bypass {reason:?}").into()),
    }
}
fn native_syn(ipv6: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut client = TcpEngine::new_ip(tcp_ip(false, 11, ipv6), Role::Client, Millis(0))?;
    client.poll(Millis(0), 1)?;
    client
        .pop_packet()
        .ok_or_else(|| "missing maintained SYN".into())
}
fn refresh(packet: &mut [u8]) -> TestResult {
    let length = packet.len();
    let (source, destination, offset) = if packet[0] >> 4 == 4 {
        let mut ip = Ipv4Packet::new_unchecked(&mut *packet);
        ip.set_total_len(length as u16);
        ip.fill_checksum();
        (
            IpAddress::Ipv4(ip.src_addr()),
            IpAddress::Ipv4(ip.dst_addr()),
            20,
        )
    } else {
        let mut ip = Ipv6Packet::new_unchecked(&mut *packet);
        ip.set_payload_len((length - 40) as u16);
        (
            IpAddress::Ipv6(ip.src_addr()),
            IpAddress::Ipv6(ip.dst_addr()),
            40,
        )
    };
    let mut tcp = TcpPacket::new_checked(&mut packet[offset..])?;
    tcp.fill_checksum(&source, &destination);
    Ok(())
}
fn with_options(ipv6: bool, options: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert!(options.len().is_multiple_of(4) && options.len() <= 40);
    let mut packet = native_syn(ipv6)?;
    let offset = if ipv6 { 40 } else { 20 };
    packet.truncate(offset + 20);
    packet.extend_from_slice(options);
    packet[offset + 12] = ((20 + options.len()) as u8 / 4) << 4;
    refresh(&mut packet)?;
    Ok(packet)
}

#[test]
fn initial_syn_policy_preserves_protected_and_unsupported_flows() -> TestResult {
    for ipv6 in [false, true] {
        let original = with_options(
            ipv6,
            &[
                2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 17, 0, 0, 0, 0, 1, 3, 3, 7,
            ],
        )?;
        let syn = candidate(&original)?;
        assert_eq!(syn.source(), tcp_ip(false, 11, ipv6).local);
        assert_eq!(syn.destination(), tcp_ip(false, 11, ipv6).peer);
        assert_eq!(syn.bytes(), original);
        for kind in [19, 29, 30, 34, 253] {
            let packet = with_options(ipv6, &[kind, 4, 0, 0])?;
            assert_eq!(
                inspect_syn(&packet, 1500)?,
                Inspection::Bypass(Bypass::Option(kind))
            );
        }
        for options in [
            vec![3, 3, 15, 0],
            vec![4, 2, 4, 2],
            vec![2, 4, 0, 0],
            vec![0, 1, 0, 0],
        ] {
            assert_eq!(
                inspect_syn(&with_options(ipv6, &options)?, 1500)?,
                Inspection::Bypass(Bypass::OptionPolicy)
            );
        }
        let offset = if ipv6 { 40 } else { 20 };
        for flags in [0x42, 0x82, 0xc2, 0x22, 0x03, 0x0a, 0x06] {
            let mut packet = original.clone();
            packet[offset + 13] = flags;
            refresh(&mut packet)?;
            assert_eq!(
                inspect_syn(&packet, 1500)?,
                Inspection::Bypass(Bypass::Flags)
            );
        }
        let mut packet = original.clone();
        packet.push(77);
        refresh(&mut packet)?;
        assert_eq!(
            inspect_syn(&packet, 1500)?,
            Inspection::Bypass(Bypass::SynData)
        );
        packet = original.clone();
        packet[offset + 13] = 0x12;
        refresh(&mut packet)?;
        assert_eq!(
            inspect_syn(&packet, 1500)?,
            Inspection::Bypass(Bypass::NotInitialSyn)
        );
        for length in 0..original.len() {
            assert!(inspect_syn(&original[..length], 1500).is_err());
        }
        let mut corrupt = original.clone();
        corrupt[offset + 16] ^= 1;
        assert_eq!(inspect_syn(&corrupt, 1500), Err(AdmissionError::Checksum));
        assert_eq!(inspect_syn(&original, 1), Err(AdmissionError::Bounds));
        let mut malformed_option = with_options(ipv6, &[2, 4, 5, 180])?;
        malformed_option[offset + 21] = 1;
        refresh(&mut malformed_option)?;
        assert_eq!(
            inspect_syn(&malformed_option, 1500),
            Err(AdmissionError::Malformed)
        );
        let mut extension = original.clone();
        if ipv6 {
            extension[6] = 44;
        } else {
            extension[6] |= 0x20;
        }
        refresh(&mut extension)?;
        assert_eq!(
            inspect_syn(&extension, 1500)?,
            Inspection::Bypass(Bypass::IpProfile)
        );
    }
    Ok(())
}

fn reserved_lab(ipv6: bool) -> Result<Lab, Box<dyn std::error::Error>> {
    let mut lab = Lab::new_family(ipv6)?;
    lab.apps[0].poll(Millis(0), 1)?;
    let syn = candidate(&lab.apps[0].pop_packet().ok_or("missing client SYN")?)?;
    let mut local = Opening::local(config(), tcp_ip(true, 17, ipv6), syn, Millis(0), 1000)?;
    let open = local.pending_record().ok_or("missing Open")?.to_vec();
    let inspected = inspect_open(config().scope, &open)?;
    assert_eq!(inspected.source(), tcp_ip(false, 11, ipv6).local);
    assert_eq!(inspected.destination(), tcp_ip(false, 11, ipv6).peer);
    for length in 0..open.len() {
        assert!(inspect_open(config().scope, &open[..length]).is_err());
    }
    let mut wrong_scope = config().scope;
    wrong_scope.flow += 1;
    assert_eq!(inspect_open(wrong_scope, &open), Err(AdmissionError::Scope));
    for now in 0..100 {
        local.tick(Millis(now))?;
        assert!(matches!(
            local.take_leg(Millis(now)),
            Err(AdmissionError::State)
        ));
        assert_eq!(local.pending_record(), Some(open.as_slice()));
        let status = local.native_status().ok_or("missing local reservation")?;
        assert_eq!(status.incoming_packets, 0);
        assert_eq!(status.outgoing_packets, 0);
        assert!(!status.established);
    }
    local.confirm_record_sent(Millis(100))?;
    let mut remote = Opening::remote(config(), tcp_ip(false, 23, ipv6), &open, Millis(100), 1000)?;
    let ready = remote.pending_record().ok_or("missing Ready")?.to_vec();
    assert_eq!(
        inspect_open(config().scope, &ready),
        Err(AdmissionError::State)
    );
    assert!(matches!(
        remote.take_leg(Millis(100)),
        Err(AdmissionError::State)
    ));
    remote.confirm_record_sent(Millis(100))?;
    local.receive_authenticated(&ready, Millis(100))?;
    let commit = local.pending_record().ok_or("missing Commit")?.to_vec();
    for now in 100..200 {
        local.tick(Millis(now))?;
        remote.tick(Millis(now))?;
        assert_eq!(local.pending_record(), Some(commit.as_slice()));
        for pending in [&mut local, &mut remote] {
            assert!(matches!(
                pending.take_leg(Millis(now)),
                Err(AdmissionError::State)
            ));
            assert_eq!(
                pending
                    .native_status()
                    .ok_or("missing reservation")?
                    .outgoing_packets,
                0
            );
        }
    }
    local.confirm_record_sent(Millis(200))?;
    assert_eq!(
        local
            .native_status()
            .ok_or("missing local reservation")?
            .incoming_packets,
        1
    );
    assert_eq!(
        local
            .native_status()
            .ok_or("missing local reservation")?
            .outgoing_packets,
        0
    );
    remote.receive_authenticated(&commit, Millis(200))?;
    lab.legs = [local.take_leg(Millis(200))?, remote.take_leg(Millis(200))?];
    assert_eq!(local.phase(), Phase::Taken);
    assert!(matches!(
        local.take_leg(Millis(200)),
        Err(AdmissionError::State)
    ));
    lab.now = 200;
    Ok(lab)
}

#[test]
fn authenticated_reservations_precede_native_ack_then_real_duplex_bytes_flow() -> TestResult {
    for ipv6 in [false, true] {
        for impaired in [false, true] {
            let mut lab = reserved_lab(ipv6)?;
            lab.connect()?;
            let original: [Vec<u8>; 2] = [
                (0..8193).map(|i| (i * 37 + 17) as u8).collect(),
                (0..6151).map(|i| (i * 19 + 9) as u8).collect(),
            ];
            let mut sent = [0; 2];
            let mut received = [Vec::new(), Vec::new()];
            let mut closed = [false; 2];
            for _ in 0..60_000 {
                for index in 0..2 {
                    if sent[index] < original[index].len() {
                        sent[index] += lab.apps[index].write(&original[index][sent[index]..])?;
                    } else if !closed[index] {
                        lab.apps[index].close();
                        closed[index] = true;
                    }
                    drain(&mut lab.apps[index], &mut received[index])?;
                }
                lab.step(impaired, false)?;
                if lab
                    .apps
                    .iter()
                    .all(|app| app.status().close_reason == Some(CloseReason::Clean))
                    && lab
                        .legs
                        .iter()
                        .all(|leg| leg.status().native.close_reason == Some(CloseReason::Clean))
                {
                    break;
                }
            }
            assert_eq!(received[0], original[1]);
            assert_eq!(received[1], original[0]);
            for leg in &lab.legs {
                assert_eq!(leg.status().native.close_reason, Some(CloseReason::Clean));
            }
            for app in &lab.apps {
                assert_eq!(app.status().close_reason, Some(CloseReason::Clean));
            }
            if impaired {
                assert!(lab.drops > 0 && lab.duplicates > 0);
            }
        }
    }
    Ok(())
}

#[test]
fn malformed_scope_order_and_expiry_never_unlock_a_reserved_leg() -> TestResult {
    for ipv6 in [false, true] {
        let syn = candidate(&native_syn(ipv6)?)?;
        let mut local = Opening::local(
            config(),
            tcp_ip(true, 17, ipv6),
            syn.clone(),
            Millis(0),
            1000,
        )?;
        let open = local.pending_record().ok_or("missing Open")?.to_vec();
        for length in 0..open.len() {
            assert!(
                Opening::remote(
                    config(),
                    tcp_ip(false, 23, ipv6),
                    &open[..length],
                    Millis(0),
                    1000
                )
                .is_err()
            );
        }
        assert!(matches!(
            Opening::local(
                config(),
                tcp_ip(false, 17, ipv6),
                syn.clone(),
                Millis(0),
                1000
            ),
            Err(AdmissionError::Tuple)
        ));
        let mut remote =
            Opening::remote(config(), tcp_ip(false, 23, ipv6), &open, Millis(0), 1000)?;
        let ready = remote.pending_record().ok_or("missing Ready")?.to_vec();
        assert_eq!(
            local.receive_authenticated(&ready, Millis(0)),
            Err(AdmissionError::State)
        );
        local.confirm_record_sent(Millis(0))?;
        for index in [0, 4, 5, 6, 8, 24, 32] {
            let mut corrupt = ready.clone();
            corrupt[index] ^= 1;
            assert!(local.receive_authenticated(&corrupt, Millis(0)).is_err());
            assert_eq!(local.phase(), Phase::AwaitingReady);
        }
        for length in 0..ready.len() {
            assert!(
                local
                    .receive_authenticated(&ready[..length], Millis(0))
                    .is_err()
            );
        }
        local.receive_authenticated(&ready, Millis(1))?;
        let commit = local.pending_record().ok_or("missing Commit")?.to_vec();
        assert_eq!(
            local.receive_authenticated(&ready, Millis(1)),
            Err(AdmissionError::State)
        );
        assert_eq!(
            remote.receive_authenticated(&commit, Millis(1)),
            Err(AdmissionError::State)
        );
        assert_eq!(local.pending_record(), Some(commit.as_slice()));
        assert_eq!(local.tick(Millis(0)), Err(AdmissionError::Time));
        local.tick(Millis(999))?;
        assert_eq!(local.deadline(), Millis(1000));
        assert_eq!(
            local.confirm_record_sent(Millis(1000)),
            Err(AdmissionError::Expired)
        );
        assert_eq!(local.phase(), Phase::Failed);
        assert!(local.pending_record().is_none() && local.native_status().is_none());
        assert_eq!(
            local.receive_authenticated(&ready, Millis(1000)),
            Err(AdmissionError::Expired)
        );
        remote.confirm_record_sent(Millis(999))?;
        assert_eq!(
            remote.receive_authenticated(&commit, Millis(1000)),
            Err(AdmissionError::Expired)
        );
        for timeout in [0, 120_001] {
            assert!(matches!(
                Opening::local(
                    config(),
                    tcp_ip(true, 17, ipv6),
                    syn.clone(),
                    Millis(0),
                    timeout
                ),
                Err(AdmissionError::Bounds)
            ));
        }
        assert!(matches!(
            Opening::local(config(), tcp_ip(true, 17, ipv6), syn, Millis(u64::MAX), 1),
            Err(AdmissionError::Time)
        ));
    }
    Ok(())
}
