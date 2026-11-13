use super::*;

fn config(channels: usize) -> Config {
    Config {
        codec: crate::Config {
            datagram_bytes: 256,
            window: 8,
            repair_numerator: 0,
            repair_denominator: 1,
            flow_sources: 128,
            queue_bytes: 64 * 1024,
            max_packet: 701,
            flush_micros: 0,
            feedback_micros: 100,
            tail_micros: 1_000,
            min_rto_micros: 1_000,
            max_rto_micros: 10_000,
        },
        channels,
        layer: Layer::Ip,
        max_native: 700,
    }
}
fn checksum(bytes: &[u8], initial: u32) -> [u8; 2] {
    let mut sum = initial;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let sum = (sum & 0xffff) + (sum >> 16);
    (!(sum as u16)).to_be_bytes()
}
fn packet(port: u16, counter: u32, payload: usize) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload];
    packet[0] = 0x45;
    let length = packet.len() as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[4..6].copy_from_slice(&(counter as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet[22..24].copy_from_slice(&24_500_u16.to_be_bytes());
    packet[24..28].copy_from_slice(&(counter * payload as u32).to_be_bytes());
    packet[28..32].copy_from_slice(&5_u32.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x10;
    packet[34..36].copy_from_slice(&1024_u16.to_be_bytes());
    if payload >= 4 {
        packet[40..44].copy_from_slice(&counter.to_be_bytes());
    }
    let ip_checksum = checksum(&packet[..20], 0);
    packet[10..12].copy_from_slice(&ip_checksum);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    let tcp_checksum = checksum(&pseudo, 0);
    packet[36..38].copy_from_slice(&tcp_checksum);
    packet
}
fn body(engine: &mut Engine, now: u64, number: u64, allow: bool) -> Result<Vec<u8>, Error> {
    engine
        .poll(now, RecordNumber(number), allow)?
        .map(<[u8]>::to_vec)
        .ok_or(Error::Admission)
}

#[test]
fn frozen_source_feedback_and_full_number_repair_match_legacy_bodies() -> Result<(), Error> {
    let mut c = config(1);
    c.codec.repair_numerator = 1;
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    let native = [0xaa, 0, 0xbb];
    assert_eq!(left.offer(0, &native)?, Admission::Accepted);
    let source = body(&mut left, 0, 1, true)?;
    assert_eq!(source, [0, 0, 0, 0, 0, 0, 4, 0, 0xaa, 0, 0xbb]);
    let seed = 0x1_0000_0007;
    let mut repair = body(&mut left, 0, seed, true)?;
    // Independently computed polynomial-0x11d multiplication and full64 seed
    // coefficient 127. Truncating the seed to an outer32 number changes bytes.
    assert_eq!(repair, [1, 0, 0, 0, 1, 1, 0, 31, 0, 225, 0, 11, 0, 215]);
    right.accept(1, RecordNumber(seed), &mut repair)?;
    assert_eq!(right.pop()?, Some(native.as_slice()));
    assert_eq!(right.pop()?, None);
    let mut feedback = body(&mut right, 100, seed + 1, false)?;
    assert_eq!(feedback, [2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
    left.accept(101, RecordNumber(seed + 1), &mut feedback)?;
    assert!(left.send_drained());
    assert_eq!(right.stats().receiver.recovered, 1);
    assert_eq!(left.stats().sender.repairs, 1);
    Ok(())
}

#[test]
fn rejected_queue_admission_does_not_advance_exact_header_contexts() -> Result<(), Error> {
    let mut c = config(1);
    c.max_native = 96;
    c.codec.max_packet = 97;
    c.codec.queue_bytes = 99;
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    let packets = [
        packet(40_000, 0, 56),
        packet(40_000, 1, 56),
        packet(40_000, 2, 56),
    ];
    assert_eq!(left.offer(0, &packets[0])?, Admission::Accepted);
    assert_eq!(left.offer(0, &packets[1])?, Admission::Full);
    let mut first = body(&mut left, 0, 0, true)?;
    right.accept(0, RecordNumber(0), &mut first)?;
    assert_eq!(right.pop()?, Some(packets[0].as_slice()));
    assert_eq!(right.pop()?, None);
    assert_eq!(left.offer(1, &packets[2])?, Admission::Accepted);
    let mut next = body(&mut left, 1, 1, true)?;
    right.accept(1, RecordNumber(1), &mut next)?;
    assert_eq!(right.pop()?, Some(packets[2].as_slice()));
    assert!(left.stats().header_bytes_saved > 0);
    assert_eq!(left.stats().native_read, 2);
    assert_eq!(left.stats().native_dropped, 1);
    Ok(())
}

#[test]
fn literal_ip_ethernet_and_zero_tails_remain_exact() -> Result<(), Error> {
    for layer in [Layer::Ip, Layer::Ethernet] {
        let mut c = config(1);
        c.layer = layer;
        let mut left = Engine::new(c)?;
        let mut right = Engine::new(c)?;
        let packets = [
            vec![0],
            vec![0; 700],
            vec![0x86, 0xdd, 0, 0, 0],
            packet(123, 4, 80),
        ];
        for packet in &packets {
            assert_eq!(left.offer(0, packet)?, Admission::Accepted);
        }
        let mut number = 0;
        while let Some(bytes) = left.poll(0, RecordNumber(number), true)? {
            let mut bytes = bytes.to_vec();
            right.accept(0, RecordNumber(number), &mut bytes)?;
            number += 1;
        }
        let mut delivered = Vec::new();
        while let Some(packet) = right.pop()? {
            delivered.push(packet.to_vec());
        }
        assert_eq!(delivered, packets);
        assert_eq!(left.offer(1, &[])?, Admission::PacketSize);
        assert_eq!(left.offer(1, &[0; 701])?, Admission::PacketSize);
    }
    Ok(())
}

#[test]
fn sixteen_channels_preserve_each_flow_under_loss_reorder_and_duplicates() -> Result<(), Error> {
    let mut c = config(16);
    c.codec.datagram_bytes = 512;
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    let mut offered = [0_u32; 16];
    let mut delivered = [0_u32; 16];
    let mut forward = 1_u64 << 40;
    let mut backward = 1_u64 << 48;
    let mut delayed: Option<(RecordNumber, Vec<u8>)> = None;
    let mut concatenated = false;
    for tick in 1..20_000_u64 {
        let now = tick * 100;
        for port in 0..16_u16 {
            let index = usize::from(port);
            if offered[index] < 20 && left.has_room() {
                assert_eq!(
                    left.offer(now, &packet(port, offered[index], 80))?,
                    Admission::Accepted
                );
                offered[index] += 1;
            }
        }
        while let Some(bytes) = left.poll(now, RecordNumber(forward), true)? {
            let number = RecordNumber(forward);
            let mut bytes = bytes.to_vec();
            forward += 1;
            if forward.is_multiple_of(7) {
                continue;
            }
            if delayed.is_none() && forward.is_multiple_of(11) {
                delayed = Some((number, bytes));
                continue;
            }
            let mut duplicate = bytes.clone();
            right.accept(now, number, &mut bytes)?;
            if forward.is_multiple_of(5) {
                right.accept(now, number, &mut duplicate)?;
            }
            if let Some((number, mut bytes)) = delayed.take() {
                right.accept(now, number, &mut bytes)?;
            }
        }
        while let Some(bytes) = right.poll(now, RecordNumber(backward), false)? {
            let number = RecordNumber(backward);
            let mut bytes = bytes.to_vec();
            backward += 1;
            let first_requests = usize::from(bytes[crate::FEEDBACK_HEADER - 1]);
            concatenated |= bytes.len() > crate::FEEDBACK_HEADER + 2 * first_requests;
            if !backward.is_multiple_of(9) {
                left.accept(now, number, &mut bytes)?;
            }
        }
        while let Some(bytes) = right.pop()? {
            let port = usize::from(u16::from_be_bytes([bytes[20], bytes[21]]));
            let count = u32::from_be_bytes(bytes[40..44].try_into().map_err(|_| Error::Admission)?);
            assert_eq!(count, delivered[port]);
            assert_eq!(bytes, packet(port as u16, count, 80));
            delivered[port] += 1;
        }
        if delivered.iter().all(|count| *count == 20) && left.send_drained() {
            break;
        }
    }
    assert_eq!(delivered, [20; 16]);
    assert!(left.send_drained());
    assert!(left.stats().sender.retransmits > 0);
    assert!(concatenated);
    Ok(())
}

#[test]
fn directional_replacement_requires_drain_preserves_stats_and_filters_old_numbers()
-> Result<(), Error> {
    let c = config(1);
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    left.offer(0, &[7, 0, 0])?;
    assert_eq!(
        left.replace_send(c, RecordNumber(10)),
        Err(Error::NotDrained)
    );
    let old_source = body(&mut left, 0, 1, true)?;
    right.accept(0, RecordNumber(1), &mut old_source.clone())?;
    assert_eq!(
        right.replace_receive(c, RecordNumber(10)),
        Err(Error::NotDrained)
    );
    assert_eq!(right.pop()?, Some([7, 0, 0].as_slice()));
    assert_eq!(right.pop()?, None);
    let old_feedback = body(&mut right, 100, 2, false)?;
    left.accept(100, RecordNumber(2), &mut old_feedback.clone())?;
    let before = left.stats();
    let mut next = c;
    next.channels = 2;
    next.codec.datagram_bytes = 512;
    left.replace_send(next, RecordNumber(20))?;
    right.replace_receive(next, RecordNumber(10))?;
    assert_eq!(left.stats(), before);
    assert_eq!(left.receive_config(), c);
    assert_eq!(right.send_config(), c);
    assert_eq!(right.body_limit(), 512);
    let duplicates = right.stats().receiver.duplicates;
    right.accept(101, RecordNumber(1), &mut old_source.clone())?;
    assert_eq!(right.stats().receiver.duplicates, duplicates + 1);
    left.offer(102, &[8, 0, 0])?;
    let mut new_source = body(&mut left, 102, 21, true)?;
    left.accept(102, RecordNumber(2), &mut old_feedback.clone())?;
    assert_eq!(
        left.unconfirmed(),
        1,
        "old feedback acknowledged fresh state"
    );
    right.accept(102, RecordNumber(21), &mut new_source)?;
    assert_eq!(right.pop()?, Some([8, 0, 0].as_slice()));
    assert_eq!(right.pop()?, None);
    let mut new_feedback = body(&mut right, 200, 22, false)?;
    left.accept(200, RecordNumber(22), &mut new_feedback)?;
    assert!(left.send_drained());
    assert_eq!(left.stats().native_read, 2);
    assert_eq!(left.stats().sender.sources, 2);
    for changed in [
        Config {
            layer: Layer::Ethernet,
            ..next
        },
        Config {
            max_native: 699,
            codec: crate::Config {
                max_packet: 700,
                ..next.codec
            },
            ..next
        },
    ] {
        assert_eq!(
            left.replace_send(changed, RecordNumber(30)),
            Err(Error::Configuration)
        );
    }
    Ok(())
}

#[test]
fn authenticated_parser_lengths_channels_and_partial_feedback_are_bounded() -> Result<(), Error> {
    let malformed = [
        vec![],
        vec![0; 257],
        vec![tagged(crate::KIND_SOURCE, 5), 0, 0, 0, 0, 1],
        vec![tagged(crate::KIND_FEEDBACK, 1), 0, 0],
        vec![3, 0, 0, 0, 0, 1],
        {
            let mut bytes = vec![0; crate::FEEDBACK_HEADER + 2 * 65];
            bytes[0] = crate::KIND_FEEDBACK;
            bytes[11] = 65;
            bytes
        },
    ];
    for mut bytes in malformed {
        let mut engine = Engine::new(config(4))?;
        assert_eq!(
            engine.accept(0, RecordNumber(0), &mut bytes),
            Err(Error::Codec(crate::Error::Malformed))
        );
    }
    let mut header = [0; crate::FEEDBACK_HEADER];
    header[0] = crate::KIND_FEEDBACK;
    for end in 1..header.len() {
        let mut engine = Engine::new(config(1))?;
        assert!(
            engine
                .accept(0, RecordNumber(0), &mut header[..end].to_vec())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn feedback_is_available_when_outer_data_pacer_is_blocked() -> Result<(), Error> {
    let mut left = Engine::new(config(1))?;
    let mut right = Engine::new(config(1))?;
    left.offer(0, &[9])?;
    assert!(left.poll(0, RecordNumber(0), false)?.is_none());
    assert!(left.data_ready(0));
    let mut source = body(&mut left, 0, 0, true)?;
    right.accept(0, RecordNumber(0), &mut source)?;
    assert_eq!(right.feedback_deadline(), Some(0));
    assert_eq!(body(&mut right, 100, 1, false)?[0], crate::KIND_FEEDBACK);
    Ok(())
}

#[test]
fn scalar_bounds_and_legacy_small_feedback_limit_are_explicit() -> Result<(), Error> {
    for invalid in [
        Config {
            channels: 0,
            ..config(1)
        },
        Config {
            channels: 65,
            ..config(1)
        },
        Config {
            max_native: usize::MAX,
            ..config(1)
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    let mut c = config(1);
    c.codec.datagram_bytes = 64;
    let mut left = Engine::new(c)?;
    let mut right = Engine::new(c)?;
    left.offer(0, &[1])?;
    let mut source = body(&mut left, 0, 0, true)?;
    right.accept(0, RecordNumber(0), &mut source)?;
    assert!(right.poll(100, RecordNumber(1), false)?.is_none());
    assert!(right.feedback_deadline().is_some());
    Ok(())
}
