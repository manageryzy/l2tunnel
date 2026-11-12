use super::*;
type ResultTest = Result<(), Box<dyn std::error::Error>>;

fn config(reverse: bool) -> Config {
    let a = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 77, 0, 1), 20000);
    let b = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 77, 0, 2), 20001);
    Config {
        local: if reverse { b } else { a },
        peer: if reverse { a } else { b },
        mtu: 576,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 8,
        random_seed: if reverse { 0x87654321 } else { 0x12345678 },
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 30_000,
    }
}
fn pair() -> Result<(TcpEngine, TcpEngine), Error> {
    Ok((
        TcpEngine::new(config(false), Role::Client, Millis(0))?,
        TcpEngine::new(config(true), Role::Server, Millis(0))?,
    ))
}
fn config6(reverse: bool) -> IpConfig {
    let a = SocketAddr::from(([0xfd42, 0x77, 0, 0, 0, 0, 0, 1], 20000));
    let b = SocketAddr::from(([0xfd42, 0x77, 0, 0, 0, 0, 0, 2], 20001));
    IpConfig {
        local: if reverse { b } else { a },
        peer: if reverse { a } else { b },
        mtu: 1280,
        ..config(reverse).into()
    }
}
fn pair6() -> Result<(TcpEngine, TcpEngine), Error> {
    Ok((
        TcpEngine::new_ip(config6(false), Role::Client, Millis(0))?,
        TcpEngine::new_ip(config6(true), Role::Server, Millis(0))?,
    ))
}
#[derive(Default)]
struct Network {
    packets: Vec<(u64, bool, Vec<u8>)>,
    count: [usize; 2],
    dropped: usize,
    maximum: usize,
}
impl Network {
    fn step(
        &mut self,
        a: &mut TcpEngine,
        b: &mut TcpEngine,
        now: u64,
        impaired: bool,
    ) -> ResultTest {
        let due: Vec<_> = self
            .packets
            .extract_if(.., |packet| packet.0 <= now)
            .collect();
        for (_, reverse, packet) in due {
            let receiver = if reverse { &mut *a } else { &mut *b };
            match receiver.ingest(&packet) {
                Ok(()) => {}
                Err(Error::QueueFull) => self.dropped += 1,
                Err(error) => return Err(error.into()),
            }
        }
        a.poll(Millis(now), 4)?;
        b.poll(Millis(now), 4)?;
        for (index, sender) in [a, b].into_iter().enumerate() {
            while let Some(packet) = sender.pop_packet() {
                self.maximum = self.maximum.max(packet.len());
                assert!(packet.len() <= sender.config.mtu);
                assert_eq!(
                    packet[0] >> 4,
                    if sender.config.local.is_ipv4() { 4 } else { 6 }
                );
                self.count[index] += 1;
                let ordinal = self.count[index];
                if impaired && ordinal.is_multiple_of(7) {
                    self.dropped += 1;
                    continue;
                }
                if impaired && ordinal.is_multiple_of(11) {
                    self.packets.push((now + 3, index == 1, packet.clone()));
                }
                let delay = if impaired && ordinal.is_multiple_of(5) {
                    17
                } else {
                    1
                };
                self.packets.push((now + delay, index == 1, packet));
            }
            let state = sender.status();
            assert!(state.incoming_packets <= sender.config.packet_slots);
            assert!(state.outgoing_packets <= sender.config.packet_slots);
            assert!(state.send_bytes <= sender.config.send_bytes);
            assert!(state.receive_bytes <= sender.config.receive_bytes);
        }
        assert!(self.packets.len() <= 128);
        Ok(())
    }
}
fn connect(
    a: &mut TcpEngine,
    b: &mut TcpEngine,
    network: &mut Network,
) -> Result<u64, Box<dyn std::error::Error>> {
    for now in 0..2000 {
        network.step(a, b, now, false)?;
        if a.status().state == State::Established && b.status().state == State::Established {
            return Ok(now);
        }
    }
    Err("handshake did not establish".into())
}
fn drain(engine: &mut TcpEngine, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut buffer = [0; 777];
    while let ReadOutcome::Data(length) = engine.read(&mut buffer)? {
        output.extend_from_slice(&buffer[..length]);
    }
    Ok(())
}

#[test]
fn independent_real_streams_survive_loss_reorder_duplicates_and_preserve_bytes() -> ResultTest {
    for impaired in [false, true] {
        let (mut a, mut b) = pair()?;
        let mut network = Network::default();
        let start = connect(&mut a, &mut b, &mut network)?;
        let ab: Vec<_> = (0..16384).map(|x| (x * 37 + 11) as u8).collect();
        let ba: Vec<_> = (0..12289).map(|x| (x * 19 + 101) as u8).collect();
        let (mut sent_a, mut sent_b) = (0, 0);
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        for now in start..60_000 {
            if sent_a < ab.len() {
                sent_a += a.write(&ab[sent_a..])?;
            }
            if sent_b < ba.len() {
                sent_b += b.write(&ba[sent_b..])?;
            }
            network.step(&mut a, &mut b, now, impaired)?;
            drain(&mut a, &mut got_a)?;
            drain(&mut b, &mut got_b)?;
            if got_a.len() == ba.len()
                && got_b.len() == ab.len()
                && a.status().send_bytes == 0
                && b.status().send_bytes == 0
            {
                break;
            }
        }
        assert_eq!(got_a, ba);
        assert_eq!(got_b, ab);
        if impaired {
            assert!(network.dropped > 0);
        }
        assert!(network.maximum > 500);
    }
    Ok(())
}

#[test]
fn receive_pressure_is_bounded_and_release_restores_stream_progress() -> ResultTest {
    let (mut a, mut b) = pair()?;
    let mut network = Network::default();
    let start = connect(&mut a, &mut b, &mut network)?;
    let original = vec![0x5a; 32768];
    let mut sent = 0;
    for now in start..2000 {
        sent += a.write(&original[sent..])?;
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(b.status().receive_bytes, config(true).receive_bytes);
    assert!(sent < original.len());
    assert_eq!(a.write(&original[sent..])?, 0);
    let mut received = Vec::new();
    for now in 2000..20_000 {
        if sent < original.len() {
            sent += a.write(&original[sent..])?;
        }
        network.step(&mut a, &mut b, now, false)?;
        drain(&mut b, &mut received)?;
        if received.len() == original.len() {
            break;
        }
    }
    assert_eq!(received, original);
    Ok(())
}

#[test]
fn malformed_checksum_tuple_mtu_and_queue_failures_do_not_advance_state() -> ResultTest {
    let (mut a, mut b) = pair()?;
    a.poll(Millis(0), 1)?;
    let syn = a.pop_packet().ok_or("missing SYN")?;
    let before = b.status();
    for length in 0..syn.len() {
        assert!(b.ingest(&syn[..length]).is_err());
        assert_eq!(b.status(), before);
    }
    let mut corrupt = syn.clone();
    corrupt[10] ^= 1;
    assert_eq!(b.ingest(&corrupt), Err(Error::Checksum));
    corrupt = syn.clone();
    corrupt[36] ^= 1;
    assert_eq!(b.ingest(&corrupt), Err(Error::Checksum));
    corrupt = syn.clone();
    corrupt[20] ^= 1;
    assert_eq!(b.ingest(&corrupt), Err(Error::Tuple));
    corrupt = syn.clone();
    corrupt[12] ^= 1;
    assert_eq!(b.ingest(&corrupt), Err(Error::Tuple));
    corrupt = syn.clone();
    corrupt[6] |= 0x20;
    assert_eq!(b.ingest(&corrupt), Err(Error::Malformed));
    assert_eq!(b.ingest(&vec![0; 577]), Err(Error::Mtu));
    for _ in 0..config(true).packet_slots {
        b.ingest(&syn)?;
    }
    let full = b.status();
    assert_eq!(b.ingest(&syn), Err(Error::QueueFull));
    assert_eq!(b.status(), full);
    b.poll(Millis(1), 1)?;
    assert_eq!(b.status().incoming_packets, config(true).packet_slots - 1);
    Ok(())
}

#[test]
fn graceful_fin_preserves_buffered_bytes_and_reset_is_visible() -> ResultTest {
    let (mut a, mut b) = pair()?;
    let mut network = Network::default();
    let start = connect(&mut a, &mut b, &mut network)?;
    assert_eq!(a.write(b"stream then FIN")?, 15);
    a.close();
    let mut received = Vec::new();
    let mut eof = false;
    for now in start..5000 {
        network.step(&mut a, &mut b, now, false)?;
        let mut buffer = [0; 64];
        match b.read(&mut buffer)? {
            ReadOutcome::Data(length) => received.extend_from_slice(&buffer[..length]),
            ReadOutcome::Eof => {
                eof = true;
                break;
            }
            ReadOutcome::Pending => {}
        }
    }
    assert_eq!(received, b"stream then FIN");
    assert!(eof);
    assert_eq!(b.status().state, State::CloseWait);
    b.abort();
    for now in 5000..5100 {
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(a.status().state, State::Closed);
    Ok(())
}

#[test]
fn absent_peer_times_out_and_invalid_time_work_or_config_are_explicit() -> ResultTest {
    let mut a = TcpEngine::new(config(false), Role::Client, Millis(0))?;
    for now in (0..35_000).step_by(10) {
        a.poll(Millis(now), 1)?;
        while a.pop_packet().is_some() {}
    }
    assert_eq!(a.status().state, State::Closed);
    assert_eq!(
        a.read(&mut [0; 1]),
        Err(Error::Terminated(CloseReason::Timeout))
    );
    let old = a.status();
    assert_eq!(a.poll(Millis(0), 1), Err(Error::Time));
    assert_eq!(a.poll(Millis(u64::MAX), 1), Err(Error::Time));
    assert_eq!(a.poll(Millis(35_000), 0), Err(Error::WorkLimit));
    assert_eq!(a.status(), old);
    assert_eq!(a.read(&mut []), Err(Error::EmptyBuffer));
    for bad in [
        Config {
            mtu: 575,
            ..config(false)
        },
        Config {
            packet_slots: 0,
            ..config(false)
        },
        Config {
            send_bytes: 1,
            ..config(false)
        },
        Config {
            random_seed: 0,
            ..config(false)
        },
        Config {
            ack_delay_millis: 201,
            ..config(false)
        },
        Config {
            peer: config(false).local,
            ..config(false)
        },
    ] {
        assert!(matches!(
            TcpEngine::new(bad, Role::Client, Millis(0)),
            Err(Error::InvalidConfig)
        ));
    }
    Ok(())
}

#[test]
fn batched_handshake_ack_and_immediate_fin_preserve_established_history() -> ResultTest {
    for include_separate_ack in [false, true] {
        let (mut a, mut b) = pair()?;
        a.poll(Millis(0), 1)?;
        while let Some(packet) = a.pop_packet() {
            b.ingest(&packet)?;
        }
        b.poll(Millis(1), 1)?;
        while let Some(packet) = b.pop_packet() {
            a.ingest(&packet)?;
        }
        a.poll(Millis(2), 1)?;
        a.close();
        a.poll(Millis(2), 1)?;
        let mut count = 0;
        while let Some(packet) = a.pop_packet() {
            if include_separate_ack || packet[33] & 1 != 0 {
                b.ingest(&packet)?;
                count += 1;
            }
        }
        assert!(count > 0);
        b.poll(Millis(3), 32)?;
        assert_eq!(b.status().state, State::CloseWait);
        assert!(b.status().established);
        assert!(b.status().peer_fin);
        assert_eq!(b.status().close_reason, None);
        assert_eq!(b.read(&mut [0; 16])?, ReadOutcome::Eof);
        assert_eq!(b.write(b"half-close response")?, 19);
    }
    Ok(())
}

#[test]
fn reset_or_timeout_after_local_shutdown_never_becomes_clean_eof() -> ResultTest {
    let (mut a, mut b) = pair()?;
    let mut network = Network::default();
    let start = connect(&mut a, &mut b, &mut network)?;
    a.close();
    for now in start..start + 20 {
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(a.status().state, State::FinWait2);
    assert!(!a.status().peer_fin);
    b.abort();
    for now in start + 20..start + 40 {
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(a.status().close_reason, Some(CloseReason::PeerReset));
    assert_eq!(
        a.read(&mut [0; 16]),
        Err(Error::Terminated(CloseReason::PeerReset))
    );
    let (mut a, mut b) = pair()?;
    let start = connect(&mut a, &mut b, &mut Network::default())?;
    a.close();
    for now in (start..start + 35_000).step_by(10) {
        a.poll(Millis(now), 4)?;
        while a.pop_packet().is_some() {}
    }
    assert_eq!(a.status().close_reason, Some(CloseReason::Timeout));
    assert_eq!(
        a.read(&mut [0; 16]),
        Err(Error::Terminated(CloseReason::Timeout))
    );
    let mut initial = TcpEngine::new(config(false), Role::Client, Millis(0))?;
    initial.close();
    assert_eq!(
        initial.read(&mut [0; 16]),
        Err(Error::Terminated(CloseReason::LocalAbort))
    );
    Ok(())
}

#[test]
fn maintained_timewait_has_clean_expiry_but_unread_ring_loss_is_explicit() -> ResultTest {
    for unread in [false, true] {
        let mut ac = config(false);
        ac.keepalive_millis = 100;
        ac.idle_timeout_millis = 1000;
        let mut bc = config(true);
        bc.keepalive_millis = 100;
        bc.idle_timeout_millis = 1000;
        let mut a = TcpEngine::new(ac, Role::Client, Millis(0))?;
        let mut b = TcpEngine::new(bc, Role::Server, Millis(0))?;
        let mut network = Network::default();
        let start = connect(&mut a, &mut b, &mut network)?;
        assert_eq!(a.write(b"a-to-b")?, 6);
        assert_eq!(b.write(b"b-to-a")?, 6);
        a.close();
        b.close();
        let mut received_a = Vec::new();
        let mut received_b = Vec::new();
        for now in start..start + 12_000 {
            network.step(&mut a, &mut b, now, false)?;
            if !unread {
                drain(&mut a, &mut received_a)?;
            }
            drain(&mut b, &mut received_b)?;
        }
        assert_eq!(received_b, b"a-to-b");
        assert_eq!(b.status().close_reason, Some(CloseReason::Clean));
        assert!(a.status().peer_fin && a.status().established);
        if unread {
            assert_eq!(a.status().close_reason, Some(CloseReason::UndrainedReceive));
            assert_eq!(
                a.read(&mut [0; 16]),
                Err(Error::Terminated(CloseReason::UndrainedReceive))
            );
        } else {
            assert_eq!(received_a, b"b-to-a");
            assert_eq!(a.status().close_reason, Some(CloseReason::Clean));
            assert_eq!(a.read(&mut [0; 16])?, ReadOutcome::Eof);
        }
    }
    Ok(())
}

#[test]
fn ipv6_retains_pressure_then_exact_duplex_bytes_and_clean_fin_under_loss() -> ResultTest {
    for impaired in [false, true] {
        let (mut a, mut b) = pair6()?;
        let mut network = Network::default();
        let start = connect(&mut a, &mut b, &mut network)?;
        let originals: [Vec<u8>; 2] = [
            (0..32773).map(|i| (i * 37 + 13) as u8).collect(),
            (0..16391).map(|i| (i * 19 + 31) as u8).collect(),
        ];
        let mut sent = [0; 2];
        for now in start..2000 {
            sent[0] += a.write(&originals[0][sent[0]..])?;
            network.step(&mut a, &mut b, now, false)?;
        }
        assert_eq!(b.status().receive_bytes, config6(true).receive_bytes);
        assert_eq!(a.write(&originals[0][sent[0]..])?, 0);
        let mut received = [Vec::new(), Vec::new()];
        let mut closed = [false; 2];
        for now in 2000..100_000 {
            for (index, endpoint) in [&mut a, &mut b].into_iter().enumerate() {
                if sent[index] < originals[index].len() {
                    sent[index] += endpoint.write(&originals[index][sent[index]..])?;
                } else if !closed[index] {
                    endpoint.close();
                    closed[index] = true;
                }
                drain(endpoint, &mut received[index])?;
            }
            network.step(&mut a, &mut b, now, impaired)?;
            if a.status().state == State::Closed && b.status().state == State::Closed {
                break;
            }
        }
        assert_eq!(received[0], originals[1]);
        assert_eq!(received[1], originals[0]);
        for engine in [&a, &b] {
            assert_eq!(engine.status().close_reason, Some(CloseReason::Clean));
            assert!(engine.status().peer_fin);
        }
        assert!(network.maximum > 1200);
        if impaired {
            assert!(network.dropped > 0);
        }
    }
    Ok(())
}

#[test]
fn ipv6_rejects_unbounded_or_unsupported_packets_before_state_changes() -> ResultTest {
    let (mut a, mut b) = pair6()?;
    a.poll(Millis(0), 1)?;
    let syn = a.pop_packet().ok_or("missing IPv6 SYN")?;
    let before = b.status();
    for length in 0..syn.len() {
        assert!(b.ingest(&syn[..length]).is_err());
        assert_eq!(b.status(), before);
    }
    for (index, value, error) in [
        (6, 0, Error::Malformed),  // Hop-by-hop.
        (6, 44, Error::Malformed), // Even atomic fragments are outside the profile.
        (6, 43, Error::Malformed), // Routing header.
        (6, 59, Error::Malformed), // No next header.
        (4, 0xff, Error::Malformed),
        (5, 0, Error::Malformed),
        (8, syn[8] ^ 1, Error::Tuple),
        (24, syn[24] ^ 1, Error::Tuple),
        (40, syn[40] ^ 1, Error::Tuple),
        (56, syn[56] ^ 1, Error::Checksum),
        (52, 0x10, Error::Malformed),
    ] {
        let mut bad = syn.clone();
        bad[index] = value;
        assert_eq!(b.ingest(&bad), Err(error));
        assert_eq!(b.status(), before);
    }
    let mut suffix = syn.clone();
    suffix.push(0);
    assert_eq!(b.ingest(&suffix), Err(Error::Malformed));
    let (mut ipv4, _) = pair()?;
    ipv4.poll(Millis(0), 1)?;
    assert_eq!(
        b.ingest(&ipv4.pop_packet().ok_or("missing IPv4 SYN")?),
        Err(Error::Tuple)
    );
    assert_eq!(b.ingest(&vec![0; 1281]), Err(Error::Mtu));
    assert_eq!(b.status(), before);
    for _ in 0..config6(true).packet_slots {
        b.ingest(&syn)?;
    }
    let full = b.status();
    assert_eq!(b.ingest(&syn), Err(Error::QueueFull));
    assert_eq!(b.status(), full);
    Ok(())
}

#[test]
fn ipv6_configuration_and_reset_outcomes_are_explicit() -> ResultTest {
    let baseline = config6(false);
    let mut bads = vec![
        IpConfig {
            mtu: 1279,
            ..baseline
        },
        IpConfig {
            peer: config(false).peer.into(),
            ..baseline
        },
    ];
    for peer in [
        "[::]:20001",
        "[ff02::1]:20001",
        "[fe80::2]:20001",
        "[::ffff:10.77.0.2]:20001",
        "[fd42:77::2%1]:20001",
    ] {
        bads.push(IpConfig {
            peer: peer.parse()?,
            ..baseline
        });
    }
    let mut flowinfo = baseline;
    if let SocketAddr::V6(peer) = &mut flowinfo.peer {
        peer.set_flowinfo(1);
    }
    bads.push(flowinfo);
    for bad in bads {
        assert!(matches!(
            TcpEngine::new_ip(bad, Role::Client, Millis(0)),
            Err(Error::InvalidConfig)
        ));
    }
    let (mut a, mut b) = pair6()?;
    let mut network = Network::default();
    let start = connect(&mut a, &mut b, &mut network)?;
    a.close();
    for now in start..start + 30 {
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(a.status().state, State::FinWait2);
    b.abort();
    for now in start + 30..start + 60 {
        network.step(&mut a, &mut b, now, false)?;
    }
    assert_eq!(a.status().close_reason, Some(CloseReason::PeerReset));
    assert_eq!(
        a.read(&mut [0; 4]),
        Err(Error::Terminated(CloseReason::PeerReset))
    );
    Ok(())
}

#[test]
fn optional_timewait_policy_filters_at_each_ingress_step_without_clean_shortcuts() -> ResultTest {
    for ipv6 in [false, true] {
        for policy in [
            TimeWaitResetPolicy::Maintained,
            TimeWaitResetPolicy::IgnoreInTimeWait,
        ] {
            for unread in [false, true] {
                let (mut a, mut b) = if ipv6 { pair6()? } else { pair()? };
                a.set_time_wait_reset_policy(policy)?;
                b.set_time_wait_reset_policy(policy)?;
                let mut network = Network::default();
                let start = connect(&mut a, &mut b, &mut network)?;
                assert_eq!(
                    a.set_time_wait_reset_policy(policy),
                    Err(Error::InvalidConfig)
                );
                assert_eq!(b.write(b"buffer")?, 6);
                for now in start..start + 50 {
                    network.step(&mut a, &mut b, now, false)?;
                }
                assert_eq!(a.status().receive_bytes, 6);
                if !unread {
                    let mut received = Vec::new();
                    drain(&mut a, &mut received)?;
                    assert_eq!(received, b"buffer");
                }
                a.close();
                for now in start + 50..start + 100 {
                    network.step(&mut a, &mut b, now, false)?;
                }
                assert_eq!(a.status().state, State::FinWait2);
                assert_eq!(b.status().state, State::CloseWait);
                b.close();
                b.poll(Millis(start + 100), 4)?;
                let offset = if ipv6 { 40 } else { 20 };
                let mut fin = None;
                while let Some(packet) = b.pop_packet() {
                    if packet[offset + 13] & 1 != 0 {
                        fin = Some(packet);
                    }
                }
                let fin = fin.ok_or("maintained FIN")?;
                let mut reset = fin.clone();
                let seq = u32::from_be_bytes(reset[offset + 4..offset + 8].try_into()?);
                reset[offset + 4..offset + 8].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
                reset[offset + 13] = 4;
                let src = IpAddress::from(a.config.peer.ip());
                let dst = IpAddress::from(a.config.local.ip());
                TcpPacket::new_unchecked(&mut reset[offset..]).fill_checksum(&src, &dst);
                a.ingest(&fin)?;
                a.ingest(&reset)?;
                assert_eq!(a.status().state, State::FinWait2);
                a.poll(Millis(start + 101), 2)?;
                assert_eq!(a.status().incoming_packets, 0);
                if policy == TimeWaitResetPolicy::Maintained {
                    assert_eq!(a.status().close_reason, Some(CloseReason::PeerReset));
                } else {
                    assert_eq!(a.status().state, State::TimeWait);
                    assert_eq!(a.status().close_reason, None);
                    assert_eq!(a.status().receive_bytes, if unread { 6 } else { 0 });
                    // The existing maintained timer remains authoritative, and
                    // unread data still makes its expiry an explicit failure.
                    a.poll(Millis(start + 12100), 4)?;
                    assert_eq!(a.status().state, State::Closed);
                    assert_eq!(
                        a.status().close_reason,
                        Some(if unread {
                            CloseReason::UndrainedReceive
                        } else {
                            CloseReason::Clean
                        })
                    );
                }
            }
        }
        let (mut a, mut b) = if ipv6 { pair6()? } else { pair()? };
        a.set_time_wait_reset_policy(TimeWaitResetPolicy::IgnoreInTimeWait)?;
        let mut network = Network::default();
        let start = connect(&mut a, &mut b, &mut network)?;
        b.abort();
        for now in start..start + 20 {
            network.step(&mut a, &mut b, now, false)?;
        }
        assert_eq!(a.status().close_reason, Some(CloseReason::PeerReset));
    }
    Ok(())
}

#[test]
fn maintained_peer_window_is_absent_before_establishment_and_tracks_real_zero_reopen() -> ResultTest
{
    for ipv6 in [false, true] {
        let (mut a, mut b) = if ipv6 { pair6()? } else { pair()? };
        assert_eq!(a.status().peer_receive_window_bytes, None);
        assert_eq!(b.status().peer_receive_window_bytes, None);
        let mut network = Network::default();
        let start = connect(&mut a, &mut b, &mut network)?;
        assert!(a.status().peer_receive_window_bytes.is_some_and(|w| w > 0));
        let payload = vec![0x39; 8192];
        let mut written = 0;
        let mut stopped = None;
        for now in start..start + 4000 {
            written += a.write(&payload[written..])?;
            network.step(&mut a, &mut b, now, false)?;
            if a.status().peer_receive_window_bytes == Some(0) && a.status().send_bytes > 0 {
                stopped = Some(now);
                break;
            }
        }
        let stopped = stopped.ok_or("actual downstream zero receive window")?;
        let status = a.status();
        assert_eq!(status, a.status());
        assert!(status.established);
        assert_eq!(status.peer_receive_window_bytes, Some(0));
        assert!(status.send_bytes > 0);
        let mut received = Vec::new();
        for now in stopped + 1..stopped + 4000 {
            written += a.write(&payload[written..])?;
            drain(&mut b, &mut received)?;
            network.step(&mut a, &mut b, now, false)?;
            if received.len() == payload.len()
                && a.status().send_bytes == 0
                && a.status().peer_receive_window_bytes.is_some_and(|w| w > 0)
            {
                break;
            }
        }
        assert_eq!(received, payload);
        assert_eq!(written, payload.len());
        assert!(a.status().peer_receive_window_bytes.is_some_and(|w| w > 0));
        a.abort();
        assert_eq!(a.status().peer_receive_window_bytes, None);
    }
    Ok(())
}
