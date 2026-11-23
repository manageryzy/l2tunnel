//! Byte-exact native completion and retained gaps under the selected KCP-like policy.
use super::*;
use l2tunnel_codec::aligned_body::BodyKind;
use l2tunnel_recovery::KcpLikeConfig;

#[path = "kcp_like_loss_tests.rs"]
mod lossy;

const KCP: KcpLikeConfig = KcpLikeConfig {
    fast_resend: 2,
    interval_ms: 10,
    minimum_rto_ms: 30,
    maximum_rto_ms: 1000,
};

fn stateless_profiles() -> impl Iterator<Item = NativePolicy> {
    [NativePolicy::RawEthernet, NativePolicy::Lz4Ethernet]
        .into_iter()
        .filter(|policy| policy.available())
}

fn selected(native: NativePolicy, packed: bool) -> TestResult<packed::CompactConfig> {
    selected_policy(native, packed, KCP)
}

fn selected_policy(
    native: NativePolicy,
    packed: bool,
    kcp: KcpLikeConfig,
) -> TestResult<packed::CompactConfig> {
    let mut selected = policy(false, packed)?;
    let old = selected.base.recovery.arq();
    selected.base.recovery = CompactReliableConfig::new(
        CompactArqConfig::new(
            old.bounds(),
            old.timing(),
            old.maximum_feedback_bytes(),
            old.history_entries(),
            old.maximum_attempts(),
            CompactRecovery::KcpLike(kcp),
        )?,
        selected.base.recovery.outer_overhead_bytes(),
    )?;
    selected.base.native_policy = native;
    selected.base.receiver.body.elide_payload_length = false;
    selected.base.receiver.body.predictive = false;
    selected.base.receiver.body.timestamp_pair_dictionary = false;
    selected.base.receiver.body.independent_short_frame_bytes = 0;
    Ok(selected)
}

#[test]
fn kcp_like_policy_roundtrips_and_binds_every_parameter_without_growing_descriptors() -> TestResult
{
    let mut digests = Vec::new();
    for native in [
        NativePolicy::RawEthernet,
        NativePolicy::EthernetHeaders,
        NativePolicy::Lz4Ethernet,
    ] {
        let selected = selected(native, true)?;
        let mut bytes = [0; packed::COMPACT_CONFIG_BYTES];
        if !native.available() {
            assert!(matches!(
                selected.encode_into(&mut bytes),
                Err(Error::Configuration)
            ));
            continue;
        }
        selected
            .encode_into(&mut bytes)
            .map_err(|e| format!("encode {native:?}: {e}"))?;
        assert_eq!(
            packed::CompactConfig::decode(&bytes).map_err(|e| format!("decode {native:?}: {e}"))?,
            selected
        );
        let digest = selected.digest()?;
        assert!(!digests.contains(&digest));
        digests.push(digest);
    }
    for changed in [
        KcpLikeConfig {
            fast_resend: 3,
            ..KCP
        },
        KcpLikeConfig {
            interval_ms: 11,
            ..KCP
        },
        KcpLikeConfig {
            minimum_rto_ms: 31,
            ..KCP
        },
        KcpLikeConfig {
            maximum_rto_ms: 1001,
            ..KCP
        },
    ] {
        let config = selected_policy(NativePolicy::RawEthernet, true, changed)?;
        let mut bytes = [0; packed::COMPACT_CONFIG_BYTES];
        config.encode_into(&mut bytes)?;
        assert_eq!(packed::CompactConfig::decode(&bytes)?, config);
        let digest = config.digest()?;
        assert!(
            !digests.contains(&digest),
            "duplicate digest for {changed:?}"
        );
        digests.push(digest);
    }
    Ok(())
}

#[test]
fn kcp_like_channel_order_has_distinct_canonical_native_bytes() -> TestResult {
    for native in stateless_profiles() {
        let original = selected(native, true)?;
        let mut ordered = original;
        ordered.base.native_delivery = NativeDelivery::ChannelOrdered;
        let mut old_bytes = [0; packed::COMPACT_CONFIG_BYTES];
        let mut bytes = old_bytes;
        original.encode_into(&mut old_bytes)?;
        ordered.encode_into(&mut bytes)?;
        assert_eq!(old_bytes[0], native.wire());
        assert_eq!(bytes[0], native.wire() + 0x80);
        assert_eq!(bytes[1..], old_bytes[1..]);
        assert_eq!(packed::CompactConfig::decode(&old_bytes)?, original);
        assert_eq!(packed::CompactConfig::decode(&bytes)?, ordered);
        assert_ne!(original.digest()?, ordered.digest()?);
        bytes[0] = 0x81;
        assert!(matches!(
            packed::CompactConfig::decode(&bytes),
            Err(Error::Configuration)
        ));
        let mut old_recovery = policy(false, true)?;
        old_recovery.base.native_policy = native;
        old_recovery.base.receiver = original.base.receiver;
        old_recovery.encode_into(&mut bytes)?;
        bytes[0] = native.wire() + 0x80;
        assert!(matches!(
            packed::CompactConfig::decode(&bytes),
            Err(Error::Configuration)
        ));
    }
    Ok(())
}

#[test]
fn kcp_like_channel_order_holds_only_its_native_head_and_keeps_selective_feedback() -> TestResult {
    for native in stateless_profiles() {
        for packed in [false, true] {
            let mut config = selected(native, packed)?;
            config.base.native_delivery = NativeDelivery::ChannelOrdered;
            let plan = if packed {
                compact_storage::Plan::for_packed_duplex(config, config)?
            } else {
                compact_storage::Plan::for_duplex(config.base, config.base)?
            };
            let limits = storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            };
            let mut a =
                Endpoint::assemble_compact(plan, tests::context(EndpointRole::Initiator), limits)?;
            let mut b =
                Body::construct(config, config, EndpointRole::Responder, packed, usize::MAX)?;
            a.enable_compact_wire(49)?;
            body!(&mut b, enable_compact_wire(49))?;
            let frames = [[0x41; 63], [0x42; 63], [0x43; 63]];
            let mut out = vec![0; a.max_packet_bytes().max(b.maximum())];
            let budget = || OutboundBudget {
                packets: 1,
                wire_bytes: 4096,
            };
            let mut packets = Vec::new();
            for (i, ch) in [0, 0, 1].into_iter().enumerate() {
                let at = Duration::from_millis(i as u64 * 3);
                a.enqueue_admitted(ChannelId(ch), &frames[i], at)?;
                let paid = at + Duration::from_millis(1);
                let len = a
                    .poll_data_independent(paid, &mut out, &mut budget())?
                    .ok_or("fresh source")?;
                a.confirm_output_at(paid, paid, a.pending_data_output().ok_or("fresh token")?)?;
                packets.push(out[..len].to_vec());
            }
            let now = Duration::from_millis(10);
            b.receive(now, &packets[1])?;
            b.receive(now, &packets[2])?;
            assert_eq!(
                body!(&mut b, prepare(ChannelId(0), now, 8))?,
                Prepared::Idle
            );
            let now = Duration::from_millis(20);
            let len = b
                .poll(now, true, &mut out, &mut budget())?
                .ok_or("selective feedback before native write")?;
            b.confirm(now, b.token(true).ok_or("feedback token")?)?;
            a.receive_authenticated_at(&out[..len], now, now)?;
            assert!(!a.source_confirmed(l2tunnel_recovery::SourceId(0))?);
            for id in [1, 2] {
                assert!(a.source_confirmed(l2tunnel_recovery::SourceId(id))?);
            }
            assert_eq!(
                body!(&mut b, prepare(ChannelId(1), now, 8))?,
                Prepared::Ready
            );
            assert_eq!(
                body!(&b, pending()).ok_or("other channel")?.bytes,
                &frames[2]
            );
            b.receive(now, &packets[2])?;
            assert_eq!(
                body!(&b, pending()).ok_or("held native write")?.bytes,
                &frames[2]
            );
            body!(&mut b, commit_delivery(now))?;
            assert_eq!(
                body!(&mut b, prepare(ChannelId(1), now, 8))?,
                Prepared::Idle
            );
            assert_eq!(
                body!(&mut b, prepare(ChannelId(0), now, 8))?,
                Prepared::Idle
            );
            let now = Duration::from_millis(300);
            let len = a
                .poll_data_independent(now, &mut out, &mut budget())?
                .ok_or("old source retry")?;
            a.confirm_output_at(now, now, a.pending_data_output().ok_or("retry token")?)?;
            b.receive(now, &out[..len])?;
            assert_eq!(a.statistics().retry_packets, 1);
            for expected in &frames[..2] {
                assert_eq!(
                    body!(&mut b, prepare(ChannelId(0), now, 8))?,
                    Prepared::Ready
                );
                assert_eq!(
                    body!(&b, pending()).ok_or("ordered native frame")?.bytes,
                    expected
                );
                body!(&mut b, commit_delivery(now))?;
            }
            b.receive(now, &packets[0])?;
            for ch in [0, 1] {
                assert_eq!(
                    body!(&mut b, prepare(ChannelId(ch), now, 8))?,
                    Prepared::Idle
                );
            }
        }
    }
    Ok(())
}

#[test]
fn kcp_like_rejects_each_nonzero_reserved_strategy_byte() -> TestResult {
    let config = selected(NativePolicy::RawEthernet, true)?;
    let mut bytes = [0; packed::COMPACT_CONFIG_BYTES];
    config.encode_into(&mut bytes)?;
    let mut prefix = vec![4];
    prefix.extend(KCP.encode()?);
    let mut matches = bytes
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, slice)| *slice == prefix.as_slice());
    let (start, _) = matches
        .next()
        .ok_or("KCP-like strategy missing from encoding")?;
    assert!(matches.next().is_none(), "ambiguous strategy offset");
    let reserved = start + prefix.len();
    assert_eq!(&bytes[reserved..reserved + 8], &[0; 8]);
    for offset in reserved..reserved + 8 {
        let mut malformed = bytes;
        malformed[offset] = 1;
        assert!(
            matches!(
                packed::CompactConfig::decode(&malformed),
                Err(Error::Configuration)
            ),
            "accepted nonzero reserved byte at {offset}"
        );
    }
    Ok(())
}

#[test]
fn packed_preview_runs_once_per_accepted_source_and_retries_window_pressure() -> TestResult {
    let mut config = selected(NativePolicy::RawEthernet, true)?;
    // Record 3 cannot enter while record 0 is missing. Keep source 2 absent
    // after closing 0 so that 3 must make progress through preview again.
    config.base.receiver.record_window = 2;
    let plan = compact_storage::Plan::for_packed_duplex(config, config)?;
    let limits = storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let mut a = packed::Endpoint::new_compact_reserved(
        config,
        tests::context(EndpointRole::Initiator),
        limits,
    )?;
    let mut b = Endpoint::assemble_compact(plan, tests::context(EndpointRole::Responder), limits)?;
    a.enable_compact_wire(49)?;
    b.enable_compact_wire(49)?;
    let usage = b.storage_usage().ok_or("reserved receiver missing")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    let prefix = b.receive_config.packed_preview_bytes();
    assert_eq!(prefix, 1); // Eight live ARQ source slots.
    assert_eq!(
        b.packed_symbols.capacity(),
        prefix + usize::from(config.max_units) * config.base.receiver.body.symbol_bytes
    );

    let frames = [[0x34; 63], [0x35; 63], [0x36; 63], [0x37; 63]];
    let mut packets = Vec::new();
    for frame in &frames {
        let now = Duration::ZERO;
        a.enqueue_admitted(ChannelId(0), frame, now)?;
        a.flush(now)?;
        let mut packet = vec![0; a.max_packet_bytes()];
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 10_000,
        };
        let length = a
            .poll_data_independent(now, &mut packet, &mut budget)?
            .ok_or("missing packed original")?;
        a.confirm_output_at(
            now,
            now,
            a.pending_data_output().ok_or("missing physical token")?,
        )?;
        packet.truncate(length);
        packets.push(packet);
    }
    let mut now = Duration::from_millis(1);
    b.receive_authenticated_at(&packets[1], now, now)?;
    assert_eq!(b.packed_symbols[0], 1 << 1);
    // Every real decode clears and fills this existing workspace. A retained
    // original, an identical duplicate and idle/native polls must all skip it.
    b.packed_symbols[prefix..].fill(0xa5);
    b.receive_authenticated_at(&packets[1], now, now)?;
    b.tick(now)?;
    assert_eq!(b.prepare(ChannelId(0), now, 8)?, Prepared::Ready);
    assert_eq!(b.pending().ok_or("early frame 1")?.bytes, &frames[1]);
    b.commit_delivery(now)?;
    assert!(b.packed_symbols[prefix..].iter().all(|&byte| byte == 0xa5));

    now += Duration::from_millis(1);
    b.receive_authenticated_at(&packets[3], now, now)?;
    assert_eq!(b.packed_symbols[0], 1 << 1);
    assert!(
        !b.receiver
            .source_observed(b.receive_scope, receiver::SourceId(3))?
    );
    b.receive_authenticated_at(&packets[0], now, now)?;
    assert_eq!(b.packed_symbols[0], 0);
    assert_eq!(b.prepare(ChannelId(0), now, 8)?, Prepared::Ready);
    assert_eq!(b.pending().ok_or("oldest frame 0")?.bytes, &frames[0]);
    b.commit_delivery(now)?;
    assert_eq!(b.packed_symbols[0], 1 << 3);
    assert_eq!(b.prepare(ChannelId(0), now, 8)?, Prepared::Ready);
    assert_eq!(b.pending().ok_or("early frame 3")?.bytes, &frames[3]);
    b.commit_delivery(now)?;

    b.receive_authenticated_at(&packets[2], now, now)?;
    assert_eq!(b.packed_symbols[0], 0);
    assert_eq!(b.prepare(ChannelId(0), now, 8)?, Prepared::Ready);
    assert_eq!(b.pending().ok_or("old frame 2")?.bytes, &frames[2]);
    b.commit_delivery(now)?;
    assert_eq!(b.prepare(ChannelId(0), now, 8)?, Prepared::Idle);
    assert_eq!(b.storage_usage(), Some(usage));
    Ok(())
}

#[test]
fn packed_stateless_later_source_before_native_poll_can_coexist_with_ordered_handoff() -> TestResult
{
    for native in stateless_profiles() {
        for unit_window in [2, 32] {
            let mut config = selected(native, true)?;
            config.base.receiver.source_window = unit_window;
            let mut a = Body::construct(config, config, EndpointRole::Initiator, true, usize::MAX)?;
            let mut b = Body::construct(config, config, EndpointRole::Responder, true, usize::MAX)?;
            body!(&mut a, enable_compact_wire(49))?;
            body!(&mut b, enable_compact_wire(49))?;
            let frames = [[0x31; 60], [0x32; 60], [0x33; 60]];
            let mut packets = Vec::new();
            for (index, frame) in frames.iter().enumerate() {
                let now = Duration::from_millis(index as u64 * 3);
                body!(&mut a, enqueue_admitted(ChannelId(0), frame, now))?;
                let mut out = vec![0; a.maximum()];
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: 4096,
                };
                let paid = now + Duration::from_millis(1);
                let len = a
                    .poll(paid, false, &mut out, &mut budget)?
                    .ok_or("missing separate source")?;
                a.confirm(paid, a.token(false).ok_or("missing token")?)?;
                out.truncate(len);
                packets.push(out);
            }
            let now = Duration::from_millis(45);
            b.receive(now, &packets[2])?;
            assert_eq!(
                b.status().receiver.retained_records,
                usize::from(unit_window > 2)
            );
            b.receive(now, &packets[0]).map_err(|e| {
                format!(
                    "{native:?} receive source 0 before polling source 2, with 1 missing: {e:?}"
                )
            })?;
            let mut received = Vec::new();
            b.collect(now, &mut received)?;
            b.receive(now, &packets[1])?;
            b.collect(now, &mut received)?;
            assert_eq!(received, [frames[0], frames[2], frames[1]]);
        }
    }
    Ok(())
}

#[test]
fn packed_tcp_header_delta_waits_for_lost_context_and_recovers_exact_ethernet() -> TestResult {
    let config = selected(NativePolicy::EthernetHeaders, true)?;
    let mut a = Body::construct(config, config, EndpointRole::Initiator, true, usize::MAX)?;
    let mut b = Body::construct(config, config, EndpointRole::Responder, true, usize::MAX)?;
    body!(&mut a, enable_compact_wire(49))?;
    body!(&mut b, enable_compact_wire(49))?;
    let frames = tests::native_frames()?;
    assert_eq!(frames.len(), 2);
    let mut admitted = 0;
    let mut delivered = Vec::new();
    let mut dropped = false;
    let mut keep_feedback = true;
    for tick in 0..500 {
        let now = Duration::from_millis(tick);
        if admitted < frames.len() && (admitted == 0 || tick >= 3) {
            match body!(
                &mut a,
                enqueue_observed(ChannelId(0), &frames[admitted], now)
            ) {
                Ok((_, encoding)) => {
                    assert_eq!(encoding.kind, BodyKind::Delta);
                    assert_eq!(encoding.context_bytes != 0, admitted == 0);
                    assert!(encoding.encoded_body_bytes < frames[admitted].len());
                    admitted += 1;
                }
                Err(Error::Busy) => {}
                Err(error) => return Err(error.into()),
            }
        }
        transfer(&mut a, &mut b, now, false, &mut dropped, true)?;
        b.collect(now, &mut delivered)?;
        if tick == 30 {
            assert_eq!(admitted, 2);
            assert!(a.statistics().source_packets >= 2);
            assert!(delivered.is_empty());
        }
        if tick >= 30 {
            transfer(&mut b, &mut a, now, true, &mut keep_feedback, false)?;
        }
        if delivered.len() == 2 && a.drained() && b.drained() {
            break;
        }
    }
    assert!(dropped);
    assert_eq!(delivered, frames);
    assert!(a.statistics().retry_packets > 0);
    assert!(b.statistics().feedback_packets > 0);
    assert!(a.drained() && b.drained());
    Ok(())
}

#[test]
fn kcp_like_complete_fragmented_ethernet_bypasses_gap_and_old_record_recovers_once() -> TestResult {
    for native in stateless_profiles() {
        for packed in [false, true] {
            let config = selected(native, packed)?;
            let mut a =
                Body::construct(config, config, EndpointRole::Initiator, packed, usize::MAX)?;
            let mut b =
                Body::construct(config, config, EndpointRole::Responder, packed, usize::MAX)?;
            body!(&mut a, enable_compact_wire(49))?;
            body!(&mut b, enable_compact_wire(49))?;
            // The second frame requires multiple actual codec fragments even with LZ4.
            let mut random = 0x1ab4_508fu32;
            let frames = [
                vec![0x31; 63],
                (0..300)
                    .map(|_| {
                        random ^= random << 13;
                        random ^= random >> 17;
                        random ^= random << 5;
                        random as u8
                    })
                    .collect::<Vec<_>>(),
            ];
            let mut admitted = 0;
            let mut lost = None;
            let mut received = Vec::new();
            let mut never_drop = true;
            let mut replayed = false;
            for tick in 0..1000 {
                let now = Duration::from_millis(tick);
                if admitted < frames.len() && (admitted == 0 || tick >= 3) {
                    match body!(
                        &mut a,
                        enqueue_admitted(ChannelId(0), &frames[admitted], now)
                    ) {
                        Ok(()) => admitted += 1,
                        Err(Error::Busy) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut output = vec![0; a.maximum()];
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: 100_000,
                };
                if let Some(length) = a.poll(now, false, &mut output, &mut budget)? {
                    let token = a.token(false).ok_or("physical output")?;
                    a.confirm(now, token)?;
                    output.truncate(length);
                    if lost.is_none() {
                        lost = Some(output);
                    } else {
                        b.receive(now, &output)?;
                    }
                }
                b.collect(now, &mut received)?;
                if tick == 50 {
                    assert_eq!(
                        received,
                        vec![frames[1].clone()],
                        "complete later frame must not await the missing prefix: {native:?}, packed={packed}"
                    );
                }
                // Withhold feedback initially to prove delivery is independent of recovery.
                if tick >= 50 {
                    transfer(&mut b, &mut a, now, true, &mut never_drop, false)?;
                }
                if received.len() == 2 && a.drained() && b.drained() {
                    if replayed {
                        break;
                    }
                    let old = lost.as_ref().ok_or("lost original")?;
                    b.receive(now, old)?;
                    b.collect(now, &mut received)?;
                    replayed = true;
                }
            }
            assert_eq!(received, vec![frames[1].clone(), frames[0].clone()]);
            assert!(
                a.drained() && b.drained(),
                "{native:?}, packed={packed}: A={:?}, B={:?}",
                a.status(),
                b.status()
            );
            assert!(a.statistics().retry_packets > 0);
            assert_eq!(a.statistics().repair_packets, 0);
            assert_eq!(b.status().recovery.fec_reserved_bytes, 0);
        }
    }
    Ok(())
}
