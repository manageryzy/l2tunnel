use super::*;
use crate::{
    codec::{aligned_body, aligned_sender, packed},
    fec::{mixed_datagram::Profile, striped_group::schedule::RecoveryTiming},
};

type Test = Result<(), Box<dyn std::error::Error>>;

fn direction() -> Direction {
    let body = aligned_body::Config {
        max_frame_bytes: 1024,
        symbol_bytes: 192,
        elide_payload_length: false,
        predictive: false,
        timestamp_pair_dictionary: false,
        independent_short_frame_bytes: 64,
    };
    let first_record = r::RecordId(0);
    let first_unit = r::SourceId(13);
    Direction {
        native_policy: NativePolicy::RawIp,
        receiver: r::Limits {
            body,
            channels: 2,
            first_record,
            first_source: first_unit,
            record_window: 32,
            source_window: 32,
            lookahead_records: 4,
            lookahead_bytes: 4 * 65535,
            lookahead_fragments: 64,
            max_fragments_per_record: 8,
            lifetime_ticks: 5_000_000,
        },
        packing: packed_sender::Config {
            sender: aligned_sender::Config {
                body,
                channels: 2,
                first_record,
            },
            packing: packed::Config {
                symbol_bytes: 192,
                hold_micros: 20,
            },
            max_units: 4,
            first_unit,
            work_limit: 4,
        },
        profile: Profile {
            data_cells: 4,
            parity_cells: 1,
            max_wire_bytes: 1400,
            max_body_bytes: 1400,
        },
        first: GenerationId(40),
        source_limit: 32,
        expanded_limit: 256 * 1024,
        hold_micros: 10,
        timing: RecoveryTiming {
            gap_delay: 2,
            gap_repeat: 8,
            ack_delay: 2,
            quiet: 80,
        },
        overhead_bytes: 49,
        stream: 3,
        codec_stage_micros: 1000,
        native_stall_micros: 200,
    }
}
fn scope() -> r::Scope {
    r::Scope {
        session: [3; 16],
        epoch: crate::core::Epoch(2),
        direction: r::Direction::InitiatorToResponder,
    }
}
fn frame(n: u8, len: usize) -> Vec<u8> {
    let mut data = vec![n; len];
    data[..40].fill(0);
    data[0] = 0x45;
    data[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    data[8] = 64;
    data[9] = 6;
    data[12..16].copy_from_slice(&[10, 0, 0, 1]);
    data[16..20].copy_from_slice(&[10, 0, 0, 2]);
    data[20..22].copy_from_slice(&1000u16.to_be_bytes());
    data[22..24].copy_from_slice(&443u16.to_be_bytes());
    data[24..28].copy_from_slice(&(u32::from(n) * 100).to_be_bytes());
    data[32] = 0x50;
    data[33] = 0x10;
    data
}
fn seal(sender: &mut NativeSender, now: u64) -> Result<Vec<u8>, NativeError> {
    sender.packing.flush(now).map_err(NativeError::Sender)?;
    let n = sender
        .packing
        .write_pending_compact(&mut sender.scratch)
        .map_err(NativeError::Sender)?;
    let wire = sender.scratch[..n].to_vec();
    sender
        .packing
        .commit_source()
        .map_err(NativeError::Sender)?;
    Ok(wire)
}
fn prepare(receiver: &mut NativeReceiver, now: u64) -> Result<r::Prepared, NativeError> {
    receiver.prepare(now, 4, |_| true, |_, _, _| r::EarlyDecision::Allow)
}

#[test]
fn multi_record_source_waits_for_every_real_device_write_and_preserves_original_deadline() -> Test {
    let d = direction();
    let mut sender = NativeSender::new(d, scope())?;
    let mut receiver = NativeReceiver::new(d, scope())?;
    let first = frame(5, 48);
    let second = frame(6, 48);
    sender.stage(1, r::ChannelId(0), &first)?;
    sender.stage(1, r::ChannelId(1), &second)?;
    let wire = seal(&mut sender, 2)?;
    let view =
        packed_envelope::decode_compact(d.packing.envelope(), scope(), r::SourceId(40), &wire)?;
    assert_eq!(view.len(), 2);
    receiver.admit(3, d.first, &wire)?;
    assert_eq!(prepare(&mut receiver, 4)?, r::Prepared::Ready);
    assert_eq!(receiver.pending().ok_or("first")?.bytes, &first);
    assert_eq!(receiver.committable_source(), None);
    assert_eq!(prepare(&mut receiver, 6)?, r::Prepared::Ready);
    assert_eq!(receiver.pending_deadline(), Some(204));
    assert_eq!(receiver.pending().ok_or("retry")?.bytes, &first);
    receiver.commit_native(7)?;
    assert_eq!(receiver.committable_source(), None);
    assert_eq!(prepare(&mut receiver, 8)?, r::Prepared::Ready);
    assert_eq!(receiver.pending().ok_or("second")?.bytes, &second);
    receiver.commit_native(9)?;
    assert_eq!(receiver.committable_source(), Some(d.first));
    assert_eq!(receiver.committable_source(), Some(d.first));
    assert!(!receiver.drained());
    receiver.confirm_source(d.first)?;
    receiver.admit(10, d.first, &wire)?;
    assert_eq!(receiver.committable_source(), None);
    assert!(receiver.drained());
    Ok(())
}

#[test]
fn fixed_anchor_policy_applies_callers_order_guard_and_keeps_old_hole() -> Test {
    let d = Direction {
        native_policy: NativePolicy::FixedAnchorIpHeaders,
        ..direction()
    };
    // Use stateless RAW records, a legal fallback within the fixed-anchor policy.
    let mut sender = NativeSender::new(direction(), scope())?;
    let mut receiver = NativeReceiver::new(d, scope())?;
    let old = frame(5, 48);
    let ahead = frame(6, 48);
    sender.stage(1, r::ChannelId(0), &old)?;
    let first = seal(&mut sender, 1)?;
    sender.stage(2, r::ChannelId(0), &ahead)?;
    let next = seal(&mut sender, 2)?;
    receiver.admit(3, GenerationId(41), &next)?;
    assert_ne!(
        receiver.prepare(3, 4, |_| true, |_, _, _| r::EarlyDecision::Wait(7))?,
        r::Prepared::Ready
    );
    assert!(receiver.pending().is_none());
    for _ in 0..4 {
        if prepare(&mut receiver, 4)? == r::Prepared::Ready {
            break;
        }
    }
    let ready = receiver.pending().ok_or("independent ahead")?;
    assert!(ready.early);
    assert_eq!(ready.bytes, &ahead);
    let mut conflict = next.clone();
    *conflict.last_mut().ok_or("empty")? ^= 1;
    assert_eq!(
        receiver.admit(4, GenerationId(41), &conflict),
        Err(NativeError::Identity)
    );
    receiver.commit_native(5)?;
    assert_eq!(receiver.committable_source(), Some(GenerationId(41)));
    receiver.confirm_source(GenerationId(41))?;
    assert!(!receiver.drained());
    receiver.admit(6, d.first, &first)?;
    assert_eq!(prepare(&mut receiver, 6)?, r::Prepared::Ready);
    assert_eq!(receiver.pending().ok_or("old hole")?.bytes, &old);
    receiver.commit_native(6)?;
    assert_eq!(receiver.committable_source(), Some(d.first));
    receiver.confirm_source(d.first)?;
    for _ in 0..4 {
        assert_ne!(prepare(&mut receiver, 6)?, r::Prepared::Ready);
    }
    assert!(receiver.drained());
    Ok(())
}

#[test]
fn refused_fec_admission_preserves_the_identical_compact_source_and_stage_expiry() -> Test {
    let d = direction();
    let mut sender = NativeSender::new(d, scope())?;
    let mut scheduler = ScheduledSender::new(
        d.profile,
        d.context(scope()),
        d.first,
        d.hold_micros,
        0,
        1,
        d.timing,
    )?;
    assert_eq!(scheduler.submit(0, &[1, 2, 3])?, d.first);
    sender.stage(1, r::ChannelId(0), &frame(5, 48))?;
    assert_eq!(sender.pump(2, &mut scheduler)?, None);
    for now in [21, 22] {
        assert_eq!(
            sender.pump(now, &mut scheduler),
            Err(NativeError::Fec(fec::Error::Capacity))
        );
        assert!(sender.packing.has_pending_source());
        assert_eq!(sender.stage_deadline(), Some(1001));
        assert_eq!(sender.next_wake(), Some(1001));
    }
    let mut free = ScheduledSender::new(
        d.profile,
        d.context(scope()),
        d.first,
        d.hold_micros,
        0,
        d.source_limit,
        d.timing,
    )?;
    let wrong_scope = r::Scope {
        direction: r::Direction::ResponderToInitiator,
        ..scope()
    };
    let mut wrong = ScheduledSender::new(
        d.profile,
        d.context(wrong_scope),
        d.first,
        d.hold_micros,
        0,
        d.source_limit,
        d.timing,
    )?;
    let mismatch = sender
        .pump(23, &mut wrong)
        .err()
        .ok_or("accepted wrong coding direction")?;
    assert_eq!(mismatch, NativeError::Fec(fec::Error::ContextMismatch));
    assert!(!mismatch.is_backpressure());
    assert_eq!(wrong.retained(), 0);
    assert_eq!(sender.pump(23, &mut free)?, Some(d.first));
    assert!(sender.is_idle());
    Ok(())
}

#[test]
fn second_record_window_refusal_rolls_back_first_unit_and_admission_clock() -> Test {
    let d = direction();
    let mut s = NativeSender::new(d, scope())?;
    let mut rx = NativeReceiver::new(d, scope())?;
    s.stage(1, r::ChannelId(0), &frame(5, 48))?;
    s.stage(1, r::ChannelId(1), &frame(6, 48))?;
    let original = seal(&mut s, 2)?;
    let view =
        packed_envelope::decode_compact(d.packing.envelope(), scope(), r::SourceId(40), &original)?;
    let units = view.units()?.collect::<Vec<_>>();
    assert_eq!(units.len(), 2);
    let mut invalid = original.clone();
    // One-byte absolute IDs 0,0 follow the count, flags and first-unit varint.
    assert_eq!(&invalid[..5], &[2, 1, 13, 0, 0]);
    invalid[4] = 100;
    let offset = original
        .windows(units[1].bytes.len())
        .position(|w| w == units[1].bytes)
        .ok_or("second unit")?;
    invalid[offset + 2] = 100;
    let refusal = rx
        .admit(30, d.first, &invalid)
        .err()
        .ok_or("accepted future record")?;
    assert_eq!(refusal, NativeError::Receiver(r::Error::RecordWindow));
    assert!(refusal.is_backpressure());
    assert!(rx.drained());
    rx.admit(3, d.first, &original)?;
    assert_eq!(rx.retained_sources(), 1);
    assert_eq!(prepare(&mut rx, 3)?, r::Prepared::Ready);
    assert_eq!(
        rx.pending().ok_or("rolled back head")?.channel,
        r::ChannelId(0)
    );
    Ok(())
}

#[test]
fn actual_anchor_and_delta_retire_independently_while_a_native_predecessor_is_missing() -> Test {
    let mut d = Direction {
        native_policy: NativePolicy::FixedAnchorIpHeaders,
        ..direction()
    };
    d.packing.max_units = 1;
    d.receiver.body.independent_short_frame_bytes = 0;
    d.packing.sender.body = d.receiver.body;
    let mut s = NativeSender::new(d, scope())?;
    let mut rx = NativeReceiver::new(d, scope())?;
    // Captured IPv4/TCP fixture with valid IP and TCP checksums from tcp_header::ip_tests.
    let literal = "45000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff000000070102f0";
    let bytes = (0..literal.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&literal[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    s.stage(1, r::ChannelId(0), &bytes)?;
    let anchor = seal(&mut s, 1)?;
    let old = seal(&mut s, 1)?;
    s.stage(2, r::ChannelId(0), &bytes)?;
    let ahead = seal(&mut s, 2)?;
    let tag = |wire: &[u8]| -> Result<u8, NativeError> {
        let envelope =
            packed_envelope::decode_compact(d.packing.envelope(), scope(), r::SourceId(0), wire)
                .map_err(NativeError::Envelope)?;
        let unit = envelope
            .units()
            .map_err(NativeError::Envelope)?
            .next()
            .ok_or(NativeError::Identity)?;
        Ok(unit.bytes[3])
    };
    assert_eq!((tag(&anchor)?, tag(&old)?, tag(&ahead)?), (8, 11, 11));
    rx.admit(3, GenerationId(42), &ahead)?;
    assert_ne!(prepare(&mut rx, 3)?, r::Prepared::Ready);
    rx.admit(4, d.first, &anchor)?;
    for _ in 0..4 {
        if prepare(&mut rx, 4)? == r::Prepared::Ready {
            break;
        }
    }
    let ready = rx
        .pending()
        .ok_or("delta did not cross missing predecessor")?;
    assert!(ready.early);
    assert_eq!(ready.record, r::RecordId(2));
    assert_eq!(ready.bytes, &bytes);
    assert_eq!(rx.committable_source(), Some(d.first));
    rx.confirm_source(d.first)?;
    rx.commit_native(4)?;
    assert_eq!(rx.committable_source(), Some(GenerationId(42)));
    rx.confirm_source(GenerationId(42))?;
    rx.admit(5, GenerationId(41), &old)?;
    assert_eq!(prepare(&mut rx, 5)?, r::Prepared::Ready);
    let ready = rx.pending().ok_or("old native hole")?;
    assert!(!ready.early);
    assert_eq!(ready.record, r::RecordId(1));
    assert_eq!(ready.bytes, &bytes);
    rx.commit_native(5)?;
    assert_eq!(rx.committable_source(), Some(GenerationId(41)));
    rx.confirm_source(GenerationId(41))?;
    for _ in 0..4 {
        assert_ne!(prepare(&mut rx, 5)?, r::Prepared::Ready);
    }
    assert!(rx.drained());
    Ok(())
}

#[test]
fn ranges_leave_space_for_old_holes_and_last_unit_is_not_source_exhaustion() -> Test {
    let mut c = Custody::new(GenerationId(40), 13, 8, 2)?;
    let hash = [3; 32];
    let impossible = Span {
        first: 18,
        last: 18,
    };
    assert_eq!(
        c.preflight(GenerationId(42), impossible, hash),
        Err(NativeError::Identity)
    );
    let later = Span {
        first: 17,
        last: 17,
    };
    assert_eq!(c.preflight(GenerationId(42), later, hash), Ok(true));
    c.admit(GenerationId(42), later, hash, &[])?;
    assert_eq!(
        c.preflight(
            GenerationId(40),
            Span {
                first: 13,
                last: 13
            },
            hash
        ),
        Err(NativeError::Identity)
    );
    assert_eq!(
        c.preflight(
            GenerationId(40),
            Span {
                first: 13,
                last: 14
            },
            hash
        ),
        Ok(true)
    );
    let mut tail = Custody::new(GenerationId(40), u64::MAX, 2, 2)?;
    let last = Span {
        first: u64::MAX,
        last: u64::MAX,
    };
    assert_eq!(tail.preflight(GenerationId(40), last, hash), Ok(true));
    tail.admit(GenerationId(40), last, hash, &[])?;
    assert_eq!(
        tail.preflight(GenerationId(41), last, hash),
        Err(NativeError::Identity)
    );
    Ok(())
}
