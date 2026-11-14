use super::*;

fn config(channels: usize, datagram_bytes: usize) -> Config {
    Config {
        codec: crate::Config {
            datagram_bytes,
            window: 4,
            repair_numerator: 1,
            repair_denominator: 4,
            flow_sources: 24,
            queue_bytes: 4096,
            max_packet: 701,
            flush_micros: 0,
            feedback_micros: 100,
            tail_micros: 1000,
            min_rto_micros: 1000,
            max_rto_micros: 10_000,
        },
        channels,
        layer: Layer::Ip,
        max_native: 700,
    }
}

fn reserved(send: Config, receive: Config) -> Result<Engine, Error> {
    let bytes = Engine::reserved_heap_bytes(send, receive)?;
    let mut allocation = crate::storage::Allocation::new(bytes);
    let engine = Engine::new_reserved(send, receive, &mut allocation)?;
    assert_eq!(allocation.used(), bytes);
    Ok(engine)
}

#[test]
fn exact_asymmetric_inventory_is_constructed_and_one_byte_short_fails() -> Result<(), Error> {
    let send = config(2, 256);
    let receive = config(3, 320);
    let engine = reserved(send, receive)?;
    assert_eq!(engine.send_config(), send);
    assert_eq!(engine.receive_config(), receive);
    assert_eq!(engine.body.capacity(), 320);
    assert_eq!(
        engine.block.capacity(),
        crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS
    );
    assert_eq!(engine.native.capacity(), receive.max_native);
    assert_eq!(engine.record.capacity(), send.codec.max_packet);
    assert_eq!(engine.senders.capacity(), 2);
    assert_eq!(engine.receivers.capacity(), 3);
    assert_eq!(engine.compressors.capacity(), 2);
    assert_eq!(engine.decompressors.capacity(), 3);
    let bytes = Engine::reserved_heap_bytes(send, receive)?;
    let mut short = crate::storage::Allocation::new(bytes - 1);
    assert!(matches!(
        Engine::new_reserved(send, receive, &mut short),
        Err(Error::Codec(crate::Error::Storage))
    ));
    let mut invalid = receive;
    invalid.layer = Layer::Ethernet;
    assert_eq!(
        Engine::reserved_heap_bytes(send, invalid),
        Err(Error::Configuration)
    );
    invalid = receive;
    invalid.max_native -= 1;
    assert_eq!(
        Engine::reserved_heap_bytes(send, invalid),
        Err(Error::Configuration)
    );
    Ok(())
}

// Complete IPv6/UDP packets exercise literal records, opaque nonzero payloads,
// varying sizes and actual flow classification. Header delta storage has separate
// byte-exact tests in header.rs.
fn native(serial: usize, reverse: bool) -> Vec<u8> {
    let payload = 1 + serial * 37 % 652;
    let mut packet = vec![0; 48 + payload];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].fill(if reverse { 2 } else { 1 });
    packet[24..40].fill(if reverse { 1 } else { 2 });
    packet[40..42].copy_from_slice(&(40_000 + serial as u16 % 17).to_be_bytes());
    packet[42..44].copy_from_slice(&24_500u16.to_be_bytes());
    packet[44..46].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    for (index, byte) in packet[48..].iter_mut().enumerate() {
        *byte = (serial * 13 + index * 19) as u8;
    }
    packet
}

fn capacities(engine: &Engine) -> [usize; 8] {
    [
        engine.senders.capacity(),
        engine.receivers.capacity(),
        engine.compressors.capacity(),
        engine.decompressors.capacity(),
        engine.body.capacity(),
        engine.block.capacity(),
        engine.native.capacity(),
        engine.record.capacity(),
    ]
}

fn pointers(engine: &Engine) -> [usize; 8] {
    [
        engine.senders.as_ptr() as usize,
        engine.receivers.as_ptr() as usize,
        engine.compressors.as_ptr() as usize,
        engine.decompressors.as_ptr() as usize,
        engine.body.as_ptr() as usize,
        engine.block.as_ptr() as usize,
        engine.native.as_ptr() as usize,
        engine.record.as_ptr() as usize,
    ]
}

fn extracted(engine: &mut Engine) -> Result<Option<(NativeIdentity, Vec<u8>)>, Error> {
    Ok(engine
        .pop_identified()?
        .map(|packet| (packet.identity, packet.bytes.to_vec())))
}

#[test]
fn actual_duplex_engines_match_legacy_bytes_identities_and_counters_under_loss() -> Result<(), Error>
{
    let forward = config(2, 256);
    let reverse = config(3, 320);
    let mut old = [Engine::new(forward)?, Engine::new(reverse)?];
    old[0].replace_receive(reverse, RecordNumber(0))?;
    old[1].replace_receive(forward, RecordNumber(0))?;
    let mut new = [reserved(forward, reverse)?, reserved(reverse, forward)?];
    let original_capacities = [capacities(&new[0]), capacities(&new[1])];
    let original_pointers = [pointers(&new[0]), pointers(&new[1])];
    let packets = [
        (0..120).map(|i| native(i, false)).collect::<Vec<_>>(),
        (0..90).map(|i| native(i, true)).collect::<Vec<_>>(),
    ];
    let mut admitted = [0; 2];
    let mut delivered = [0; 2];
    let mut expected = [
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
    ];
    let mut channel_delivered = [[0_u64; crate::MAX_CHANNELS]; 2];
    let mut pending = Vec::<(u64, usize, RecordNumber, Vec<u8>)>::new();
    let mut complete = false;
    for tick in 0..50_000u64 {
        let now = tick * 100;
        for side in 0..2 {
            if let Some(packet) = packets[side].get(admitted[side]) {
                let a = old[side].offer_identified(now, packet)?;
                let channel = ChannelId::new(crate::flow::classify_ip(
                    packet,
                    new[side].send_config().channels,
                ))
                .ok_or(Error::Configuration)?;
                let b = new[side].offer_on_channel_identified(now, channel, packet)?;
                assert_eq!(a, b);
                if let IdentifiedAdmission::Accepted(identity) = a {
                    assert!(
                        expected[side]
                            .insert(
                                (identity.channel.index(), identity.record.0),
                                packet.clone()
                            )
                            .is_none()
                    );
                    admitted[side] += 1;
                }
            }
            let number = RecordNumber((1 << 40) + tick * 2 + side as u64);
            let a = old[side].poll(now, number, true)?.map(<[u8]>::to_vec);
            let b = new[side].poll_emission(now, number, true)?.map(|emission| {
                let expected_kind = match emission.kind() {
                    EmissionKind::Source => crate::KIND_SOURCE,
                    EmissionKind::Repair => crate::KIND_REPAIR,
                    EmissionKind::Feedback => crate::KIND_FEEDBACK,
                };
                assert_eq!(emission.body()[0] & crate::KIND_MASK, expected_kind);
                emission.body().to_vec()
            });
            assert_eq!(a, b);
            if let Some(body) = a
                && number.0 % 17 != 5
            {
                pending.push((now + (number.0 % 3) * 200, 1 - side, number, body));
            }
        }
        let mut index = 0;
        while index < pending.len() {
            if pending[index].0 > now {
                index += 1;
                continue;
            }
            let (_, side, number, mut body) = pending.remove(index);
            let mut second = body.clone();
            old[side].accept(now, number, &mut body)?;
            new[side].accept(now, number, &mut second)?;
        }
        for side in 0..2 {
            loop {
                let a = extracted(&mut old[side])?;
                let b = extracted(&mut new[side])?;
                assert_eq!(a, b);
                let Some((identity, packet)) = a else { break };
                let origin = 1 - side;
                let channel = identity.channel.index();
                assert_eq!(identity.record.0, channel_delivered[origin][channel]);
                channel_delivered[origin][channel] += 1;
                assert_eq!(
                    expected[origin].remove(&(channel, identity.record.0)),
                    Some(packet)
                );
                delivered[origin] += 1;
            }
            assert_eq!(old[side].stats(), new[side].stats());
            assert_eq!(old[side].data_deadline(), new[side].data_deadline());
            assert_eq!(old[side].feedback_deadline(), new[side].feedback_deadline());
            assert_eq!(capacities(&new[side]), original_capacities[side]);
            assert_eq!(pointers(&new[side]), original_pointers[side]);
        }
        if delivered == [120, 90]
            && pending.is_empty()
            && new.iter().all(|e| e.send_drained() && e.receive_drained())
        {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(admitted, [120, 90]);
    assert_eq!(delivered, [120, 90]);
    assert!(expected.iter().all(|packets| packets.is_empty()));
    for side in 0..2 {
        for channel in 0..crate::MAX_CHANNELS {
            let channel = ChannelId::new(channel).ok_or(Error::Configuration)?;
            assert_eq!(
                old[side].boundary(Direction::Send, channel),
                new[side].boundary(Direction::Send, channel)
            );
            assert_eq!(
                old[side].boundary(Direction::Receive, channel),
                new[side].boundary(Direction::Receive, channel)
            );
        }
    }
    Ok(())
}

#[test]
fn two_generations_keep_native_identity_owners_and_number_input_separate()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::storage::{Limits, Plan, Set};
    let old_forward = config(2, 256);
    let old_reverse = config(3, 320);
    let target_forward = config(4, 320);
    let target_reverse = config(1, 256);
    let left_plans = [
        Plan::for_engine(old_forward, old_reverse)?,
        Plan::for_engine(target_forward, target_reverse)?,
    ];
    let right_plans = [
        Plan::for_engine(old_reverse, old_forward)?,
        Plan::for_engine(target_reverse, target_forward)?,
    ];
    let mut left = Set::new(
        Limits {
            capacity_bytes: std::mem::size_of::<Set>()
                + left_plans.iter().map(Plan::capacity_bytes).sum::<usize>(),
        },
        0,
    )?;
    let mut right = Set::new(
        Limits {
            capacity_bytes: std::mem::size_of::<Set>()
                + right_plans.iter().map(Plan::capacity_bytes).sum::<usize>(),
        },
        0,
    )?;
    let left_ids = [left.prepare(left_plans[0])?, left.prepare(left_plans[1])?];
    let right_ids = [
        right.prepare(right_plans[0])?,
        right.prepare(right_plans[1])?,
    ];
    let mut next_number = [1_u64 << 41, 1_u64 << 45];
    // These are local engine generations. Authentication, activation and the
    // physical scope/epoch fences remain the runtime's separate responsibility.
    for generation in 0..2 {
        let packets = [
            native(43 + generation, false),
            native(71 + generation, true),
        ];
        let left_identity = match left
            .entry(left_ids[generation])?
            .offer_identified(0, &packets[0])?
        {
            IdentifiedAdmission::Accepted(identity) => identity,
            _ => return Err(Box::new(Error::Admission)),
        };
        let right_identity = match right
            .entry(right_ids[generation])?
            .offer_identified(0, &packets[1])?
        {
            IdentifiedAdmission::Accepted(identity) => identity,
            _ => return Err(Box::new(Error::Admission)),
        };
        assert_eq!(left_identity.record, NativeRecordId(0));
        assert_eq!(right_identity.record, NativeRecordId(0));
        let before_numbers = next_number;
        let mut received = [false; 2];
        let mut complete = false;
        for tick in 0..1000u64 {
            let now = tick * 100;
            let number = RecordNumber(next_number[0]);
            let body = left
                .entry(left_ids[generation])?
                .poll(now, number, true)?
                .map(<[u8]>::to_vec);
            if let Some(mut body) = body {
                next_number[0] += 1;
                right
                    .entry(right_ids[generation])?
                    .accept(now, number, &mut body)?;
            }
            let number = RecordNumber(next_number[1]);
            let body = right
                .entry(right_ids[generation])?
                .poll(now, number, true)?
                .map(<[u8]>::to_vec);
            if let Some(mut body) = body {
                next_number[1] += 1;
                left.entry(left_ids[generation])?
                    .accept(now, number, &mut body)?;
            }
            {
                let mut entry = right.entry(right_ids[generation])?;
                if let Some(packet) = entry.pop_identified()? {
                    assert!(!received[0]);
                    assert_eq!(packet.identity, left_identity);
                    assert_eq!(packet.bytes, packets[0]);
                    received[0] = true;
                }
            }
            {
                let mut entry = left.entry(left_ids[generation])?;
                if let Some(packet) = entry.pop_identified()? {
                    assert!(!received[1]);
                    assert_eq!(packet.identity, right_identity);
                    assert_eq!(packet.bytes, packets[1]);
                    received[1] = true;
                }
            }
            if received == [true; 2]
                && left.engine(left_ids[generation])?.send_drained()
                && right.engine(right_ids[generation])?.send_drained()
                && left.engine(left_ids[generation])?.receive_drained()
                && right.engine(right_ids[generation])?.receive_drained()
            {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert!(next_number[0] > before_numbers[0] && next_number[1] > before_numbers[1]);
        if generation == 0 {
            assert_eq!(left.engine(left_ids[1])?.stats(), Stats::default());
            assert_eq!(right.engine(right_ids[1])?.stats(), Stats::default());
        }
        left.retire(left_ids[generation])?;
        right.retire(right_ids[generation])?;
        assert!(matches!(
            left.engine(left_ids[generation]),
            Err(crate::storage::Error::Stale)
        ));
        assert!(matches!(
            right.engine(right_ids[generation]),
            Err(crate::storage::Error::Stale)
        ));
    }
    assert_eq!(left.usage().engine_bytes, 0);
    assert_eq!(right.usage().engine_bytes, 0);
    Ok(())
}
