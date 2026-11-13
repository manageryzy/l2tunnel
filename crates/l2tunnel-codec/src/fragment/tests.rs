use super::*;
use crate::{CodecConfig, Compression, FrameCodec, FrameLayer};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn context() -> FragmentContext {
    FragmentContext {
        session: SessionId(41),
        epoch: Epoch(7),
    }
}

fn sender_config() -> FragmentConfig {
    FragmentConfig {
        path_mtu: 256,
        outer_overhead_bytes: 56,
        max_message_bytes: 4096,
        max_fragments: 128,
    }
}

fn receiver_config() -> ReassemblyConfig {
    ReassemblyConfig {
        max_message_bytes: 4096,
        max_messages: 8,
        max_fragment_payload_bytes: 256,
        max_fragments_per_message: 128,
        max_total_fragments: 512,
        max_reserved_bytes: 16384,
        max_lifetime_ticks: 10,
        replay_window: 64,
    }
}

fn fragments(id: u64, length: usize) -> Result<FragmentBatch, FragmentError> {
    Fragmenter::new(context(), sender_config(), MessageId(id))?.fragment(&vec![7; length])
}

#[test]
fn roundtrip_mtu_and_chunk_boundaries_in_reverse_order() -> TestResult {
    let mut sender = Fragmenter::new(context(), sender_config(), MessageId(0))?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    assert_eq!(sender.chunk_bytes(), 160);
    for length in [1_usize, 159, 160, 161, 319, 320, 321, 4096] {
        let original: Vec<_> = (0..length).map(|value| (value % 251) as u8).collect();
        let batch = sender.fragment(&original)?;
        let mut output = vec![0xa5; length + 8];
        for (index, fragment) in batch.fragments.iter().rev().enumerate() {
            assert!(
                fragment.len() + sender_config().outer_overhead_bytes <= sender_config().path_mtu
            );
            let status = receiver.accept(fragment, 0, &mut output)?;
            if index + 1 == batch.fragments.len() {
                assert_eq!(
                    status,
                    ReassemblyStatus::Complete {
                        message: batch.message,
                        length
                    }
                );
            } else {
                assert!(matches!(status, ReassemblyStatus::Pending { .. }));
                assert!(output.iter().all(|value| *value == 0xa5));
            }
        }
        assert_eq!(output.get(..length), Some(original.as_slice()));
        assert_eq!(output.get(length..), Some([0xa5; 8].as_slice()));
        assert_eq!(receiver.reserved_bytes(), 0);
        assert_eq!(receiver.reserved_fragments(), 0);
        assert_eq!(receiver.pending_messages(), 0);
        assert_eq!(
            receiver.accept(&batch.fragments[0], 0, &mut [])?,
            ReassemblyStatus::Duplicate {
                message: batch.message
            }
        );
    }
    Ok(())
}

#[test]
fn minimum_mtu_and_u16_chunk_ceiling_are_exact() -> TestResult {
    let mut cfg = sender_config();
    cfg.path_mtu = cfg.outer_overhead_bytes + FRAGMENT_HEADER_BYTES;
    assert!(matches!(
        Fragmenter::new(context(), cfg, MessageId(0)),
        Err(FragmentError::MtuTooSmall)
    ));
    cfg.path_mtu += 1;
    let mut tiny = Fragmenter::new(context(), cfg, MessageId(0))?;
    assert_eq!(tiny.chunk_bytes(), 1);
    assert_eq!(tiny.fragment(&[1, 2, 3])?.fragments.len(), 3);
    cfg.path_mtu = usize::MAX;
    cfg.outer_overhead_bytes = usize::MAX;
    assert!(matches!(
        Fragmenter::new(context(), cfg, MessageId(0)),
        Err(FragmentError::Arithmetic)
    ));
    cfg.path_mtu = 100_000;
    cfg.outer_overhead_bytes = 56;
    cfg.max_message_bytes = 65_536;
    let mut large = Fragmenter::new(context(), cfg, MessageId(0))?;
    assert_eq!(large.chunk_bytes(), usize::from(u16::MAX));
    let batch = large.fragment(&vec![2; 65_536])?;
    assert_eq!(batch.fragments.len(), 2);
    assert_eq!(
        batch.fragments[0].len(),
        FRAGMENT_HEADER_BYTES + usize::from(u16::MAX)
    );
    assert_eq!(batch.fragments[1].len(), FRAGMENT_HEADER_BYTES + 1);
    Ok(())
}

#[test]
fn invalid_limits_and_sender_failure_do_not_consume_ids() -> TestResult {
    let mut cfg = sender_config();
    cfg.max_message_bytes = 0;
    assert!(matches!(
        Fragmenter::new(context(), cfg, MessageId(0)),
        Err(FragmentError::InvalidConfig)
    ));
    cfg = sender_config();
    cfg.max_fragments = 0;
    assert!(matches!(
        Fragmenter::new(context(), cfg, MessageId(0)),
        Err(FragmentError::InvalidConfig)
    ));
    cfg = sender_config();
    cfg.max_message_bytes = MAX_RECORD_BYTES + 1;
    assert!(matches!(
        Fragmenter::new(context(), cfg, MessageId(0)),
        Err(FragmentError::InvalidConfig)
    ));
    cfg = sender_config();
    cfg.max_fragments = 1;
    let mut sender = Fragmenter::new(context(), cfg, MessageId(19))?;
    assert_eq!(sender.fragment(&[]), Err(FragmentError::EmptyMessage));
    assert_eq!(
        sender.fragment(&vec![1; 4097]),
        Err(FragmentError::MessageTooLarge)
    );
    assert_eq!(
        sender.fragment(&[1; 161]),
        Err(FragmentError::TooManyFragments)
    );
    assert_eq!(sender.fragment(&[1])?.message, MessageId(19));
    let mut last = Fragmenter::new(context(), cfg, MessageId(u64::MAX))?;
    assert_eq!(last.fragment(&[1])?.message, MessageId(u64::MAX));
    assert_eq!(last.fragment(&[1]), Err(FragmentError::Exhausted));
    Ok(())
}

#[test]
fn receiver_rejects_each_invalid_limit() {
    let good = receiver_config();
    let mut cases = vec![good; 10];
    cases[0].max_message_bytes = 0;
    cases[1].max_message_bytes = MAX_RECORD_BYTES + 1;
    cases[2].max_messages = 0;
    cases[3].max_fragment_payload_bytes = 0;
    cases[4].max_fragments_per_message = 0;
    cases[5].max_total_fragments = 1;
    cases[6].max_reserved_bytes = 1;
    cases[7].max_lifetime_ticks = 0;
    cases[8].replay_window = 0;
    cases[9].replay_window = 65_537;
    for bad in cases {
        assert!(matches!(
            Reassembler::new(context(), bad),
            Err(FragmentError::InvalidConfig)
        ));
    }
    let mut bad = good;
    bad.max_messages = bad.replay_window + 1;
    assert!(matches!(
        Reassembler::new(context(), bad),
        Err(FragmentError::InvalidConfig)
    ));
}

#[test]
fn truncation_and_malformed_dimensions_leave_output_and_reservations_unchanged() -> TestResult {
    let batch = fragments(1, 320)?;
    let fragment = &batch.fragments[0];
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    for length in 0..fragment.len() {
        let mut output = vec![0xa5; 320];
        assert!(
            receiver
                .accept(&fragment[..length], 0, &mut output)
                .is_err()
        );
        assert!(output.iter().all(|value| *value == 0xa5));
        assert_eq!(receiver.reserved_bytes(), 0);
    }
    let mut invalids = Vec::new();
    for (offset, value) in [(0, 0), (2, 2), (3, 1), (4, 1), (12, 1)] {
        let mut bad = fragment.clone();
        bad[offset] = value;
        invalids.push(bad);
    }
    for (offset, value) in [(32, 2_u16), (34, 0), (34, 3), (36, 0), (36, 257), (38, 159)] {
        let mut bad = fragment.clone();
        bad[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        invalids.push(bad);
    }
    for value in [0_u32, u32::MAX] {
        let mut bad = fragment.clone();
        bad[28..32].copy_from_slice(&value.to_be_bytes());
        invalids.push(bad);
    }
    let mut trailing = fragment.clone();
    trailing.push(0);
    invalids.push(trailing);
    for bad in invalids {
        let mut output = vec![0xa5; 320];
        assert!(receiver.accept(&bad, 0, &mut output).is_err());
        assert!(output.iter().all(|value| *value == 0xa5));
        assert_eq!(receiver.reserved_bytes(), 0);
        assert_eq!(receiver.pending_messages(), 0);
    }
    Ok(())
}

#[test]
fn duplicate_conflict_and_geometry_mismatch_preserve_original_message() -> TestResult {
    let batch = fragments(1, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    let mut output = vec![0xa5; 320];
    assert!(matches!(
        receiver.accept(&batch.fragments[0], 0, &mut output)?,
        ReassemblyStatus::Pending { received: 1, .. }
    ));
    assert_eq!(receiver.reserved_bytes(), 320);
    assert_eq!(receiver.reserved_fragments(), 2);
    assert_eq!(
        receiver.accept(&batch.fragments[0], 1, &mut output)?,
        ReassemblyStatus::Duplicate {
            message: MessageId(1)
        }
    );
    let mut conflict = batch.fragments[0].clone();
    conflict[FRAGMENT_HEADER_BYTES] ^= 1;
    assert_eq!(
        receiver.accept(&conflict, 2, &mut output),
        Err(FragmentError::Conflict)
    );
    let mut changed = sender_config();
    changed.path_mtu -= 10;
    let changed_batch = Fragmenter::new(context(), changed, MessageId(1))?.fragment(&[7; 320])?;
    assert_eq!(
        receiver.accept(&changed_batch.fragments[0], 3, &mut output),
        Err(FragmentError::Conflict)
    );
    assert!(output.iter().all(|value| *value == 0xa5));
    assert!(matches!(
        receiver.accept(&batch.fragments[1], 4, &mut output)?,
        ReassemblyStatus::Complete { .. }
    ));
    assert_eq!(output, vec![7; 320]);
    assert_eq!(receiver.reserved_bytes(), 0);
    assert_eq!(receiver.reserved_fragments(), 0);
    Ok(())
}

#[test]
fn completion_destination_failure_is_retryable_without_retaining_final_fragment() -> TestResult {
    let batch = fragments(1, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    receiver.accept(&batch.fragments[0], 0, &mut [])?;
    let mut short = [0xa5; 319];
    assert_eq!(
        receiver.accept(&batch.fragments[1], 1, &mut short),
        Err(FragmentError::OutputTooSmall)
    );
    assert_eq!(short, [0xa5; 319]);
    assert_eq!(receiver.pending_messages(), 1);
    let mut output = [0xa5; 320];
    assert!(matches!(
        receiver.accept(&batch.fragments[1], 2, &mut output)?,
        ReassemblyStatus::Complete { .. }
    ));
    assert_eq!(output, [7; 320]);
    Ok(())
}

#[test]
fn tail_first_reserves_entire_declared_message_and_all_slots() -> TestResult {
    let batch = fragments(1, 321)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    let tail = batch.fragments.last().ok_or("tail fragment")?;
    assert_eq!(tail.len(), FRAGMENT_HEADER_BYTES + 1);
    receiver.accept(tail, 0, &mut [])?;
    assert_eq!(receiver.reserved_bytes(), 321);
    assert_eq!(receiver.reserved_fragments(), 3);
    Ok(())
}

#[test]
fn message_byte_and_fragment_reservation_caps_are_independent() -> TestResult {
    let first = fragments(1, 200)?;
    let second = fragments(2, 200)?;
    for reason in [
        FragmentError::MessageBudget,
        FragmentError::ByteBudget,
        FragmentError::FragmentBudget,
    ] {
        let mut cfg = receiver_config();
        cfg.max_message_bytes = 256;
        cfg.max_fragments_per_message = 2;
        match reason {
            FragmentError::MessageBudget => cfg.max_messages = 1,
            FragmentError::ByteBudget => cfg.max_reserved_bytes = 300,
            FragmentError::FragmentBudget => cfg.max_total_fragments = 3,
            _ => return Err("unexpected test reason".into()),
        }
        let mut receiver = Reassembler::new(context(), cfg)?;
        receiver.accept(&first.fragments[0], 0, &mut [])?;
        assert_eq!(
            receiver.accept(&second.fragments[0], 1, &mut []),
            Err(reason)
        );
        assert_eq!(receiver.pending_messages(), 1);
        assert_eq!(receiver.reserved_bytes(), 200);
        assert_eq!(receiver.reserved_fragments(), 2);
        receiver.expire(10)?;
        assert!(matches!(
            receiver.accept(&second.fragments[0], 10, &mut [])?,
            ReassemblyStatus::Pending { .. }
        ));
    }
    Ok(())
}

#[test]
fn exact_deadline_expiry_tombstones_and_time_validation() -> TestResult {
    let batch = fragments(1, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    receiver.accept(&batch.fragments[0], 1, &mut [])?;
    assert_eq!(
        receiver.accept(&batch.fragments[0], 10, &mut [])?,
        ReassemblyStatus::Duplicate {
            message: MessageId(1)
        }
    );
    assert!(receiver.expire(10)?.is_empty());
    assert_eq!(receiver.expire(11)?, vec![MessageId(1)]);
    assert_eq!(receiver.pending_messages(), 0);
    assert_eq!(receiver.reserved_bytes(), 0);
    assert_eq!(receiver.reserved_fragments(), 0);
    let mut output = [0xa5; 320];
    assert_eq!(
        receiver.accept(&batch.fragments[1], 11, &mut output)?,
        ReassemblyStatus::Duplicate {
            message: MessageId(1)
        }
    );
    assert_eq!(output, [0xa5; 320]);
    assert_eq!(receiver.expire(10), Err(FragmentError::TimeWentBackwards));
    let mut overflow = Reassembler::new(context(), receiver_config())?;
    assert_eq!(
        overflow.accept(&batch.fragments[0], u64::MAX - 5, &mut []),
        Err(FragmentError::DeadlineOverflow)
    );
    assert_eq!(overflow.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn next_expiry_tracks_pending_custody_without_renewing_on_duplicates() -> TestResult {
    let first = fragments(1, 320)?;
    let second = fragments(2, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    let mut output = [0; 320];
    assert_eq!(receiver.deadline(), None);
    receiver.accept(&first.fragments[0], 3, &mut output)?;
    receiver.accept(&second.fragments[0], 7, &mut output)?;
    assert_eq!(receiver.deadline(), Some(13));
    receiver.accept(&first.fragments[0], 9, &mut output)?;
    assert_eq!(receiver.deadline(), Some(13));
    receiver.accept(&first.fragments[1], 12, &mut output)?;
    assert_eq!(receiver.deadline(), Some(17));
    assert!(receiver.expire(16)?.is_empty());
    assert_eq!(receiver.deadline(), Some(17));
    assert_eq!(receiver.expire(17)?, vec![MessageId(2)]);
    assert_eq!(receiver.deadline(), None);
    Ok(())
}

#[test]
fn valid_input_cleans_expired_state_without_explicit_timer_poll() -> TestResult {
    let first = fragments(1, 320)?;
    let second = fragments(2, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    receiver.accept(&first.fragments[0], 0, &mut [])?;
    receiver.accept(&second.fragments[0], 10, &mut [])?;
    assert_eq!(receiver.pending_messages(), 1);
    assert_eq!(receiver.reserved_bytes(), 320);
    assert_eq!(receiver.retired_messages(), 1);
    assert_eq!(
        receiver.accept(&first.fragments[1], 10, &mut [])?,
        ReassemblyStatus::Duplicate {
            message: MessageId(1)
        }
    );
    Ok(())
}

#[test]
fn replay_window_cannot_evict_live_messages_and_terminal_history_stays_bounded() -> TestResult {
    let mut cfg = receiver_config();
    cfg.replay_window = 2;
    cfg.max_messages = 2;
    let mut receiver = Reassembler::new(context(), cfg)?;
    let old = fragments(1, 320)?;
    receiver.accept(&old.fragments[0], 0, &mut [])?;
    let newer = fragments(3, 1)?;
    let mut output = [0xa5; 1];
    assert_eq!(
        receiver.accept(&newer.fragments[0], 1, &mut output),
        Err(FragmentError::ReplayWindowBlocked)
    );
    assert_eq!(output, [0xa5]);
    receiver.expire(10)?;
    assert!(matches!(
        receiver.accept(&newer.fragments[0], 10, &mut output)?,
        ReassemblyStatus::Complete { .. }
    ));
    assert_eq!(
        receiver.accept(&old.fragments[1], 10, &mut []),
        Err(FragmentError::StaleMessage)
    );
    for id in 4..100 {
        let next = fragments(id, 1)?;
        receiver.accept(&next.fragments[0], 10, &mut output)?;
        assert!(receiver.retired_messages() <= 2);
    }
    Ok(())
}

#[test]
fn rejected_single_fragment_does_not_advance_replay_window() -> TestResult {
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    let high = fragments(u64::MAX, 1)?;
    assert_eq!(
        receiver.accept(&high.fragments[0], 0, &mut []),
        Err(FragmentError::OutputTooSmall)
    );
    assert_eq!(receiver.retired_messages(), 0);
    let low = fragments(0, 1)?;
    let mut output = [0];
    assert!(matches!(
        receiver.accept(&low.fragments[0], 0, &mut output)?,
        ReassemblyStatus::Complete {
            message: MessageId(0),
            ..
        }
    ));
    Ok(())
}

#[test]
fn context_mismatch_cannot_expire_or_change_active_state() -> TestResult {
    let batch = fragments(1, 320)?;
    let mut receiver = Reassembler::new(context(), receiver_config())?;
    receiver.accept(&batch.fragments[0], 0, &mut [])?;
    for offset in [4, 12] {
        let mut foreign = batch.fragments[1].clone();
        foreign[offset] ^= 1;
        let mut output = [0xa5; 320];
        assert_eq!(
            receiver.accept(&foreign, 100, &mut output),
            Err(FragmentError::WrongContext)
        );
        assert_eq!(receiver.pending_messages(), 1);
        assert_eq!(output, [0xa5; 320]);
    }
    let mut output = [0; 320];
    assert!(matches!(
        receiver.accept(&batch.fragments[1], 1, &mut output)?,
        ReassemblyStatus::Complete { .. }
    ));
    Ok(())
}

#[test]
fn complete_frame_pipeline_preserves_tap_and_tun_bytes() -> TestResult {
    for layer in [FrameLayer::Ethernet, FrameLayer::Ip] {
        let codec = FrameCodec::new(CodecConfig {
            layer,
            max_frame_bytes: 4000,
            compression: Compression::None,
        })?;
        let input: Vec<_> = (0..4000).map(|value| (value % 251) as u8).collect();
        let record = codec.encode_vec(&input)?;
        let mut sender = Fragmenter::new(context(), sender_config(), MessageId(0))?;
        let fragments = sender.fragment(&record)?;
        let mut receiver = Reassembler::new(context(), receiver_config())?;
        let mut assembled = vec![0; 4096];
        let mut complete_length = None;
        for fragment in fragments.fragments.iter().rev() {
            if let ReassemblyStatus::Complete { length, .. } =
                receiver.accept(fragment, 0, &mut assembled)?
            {
                complete_length = Some(length);
            }
        }
        let length = complete_length.ok_or("completed frame record")?;
        assert_eq!(codec.decode_vec(&assembled[..length])?, input);
    }
    Ok(())
}
