use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> FragmentContext {
    FragmentContext {
        session: SessionId(0x1122334455667788),
        epoch: Epoch(9),
    }
}
fn send_config() -> FragmentConfig {
    FragmentConfig {
        path_mtu: 56,
        outer_overhead_bytes: 0,
        max_message_bytes: 128,
        max_fragments: 8,
    }
}
fn config() -> ReassemblyConfig {
    ReassemblyConfig {
        max_message_bytes: 128,
        max_messages: 3,
        max_fragment_payload_bytes: 16,
        max_fragments_per_message: 8,
        max_total_fragments: 24,
        max_reserved_bytes: 384,
        max_lifetime_ticks: 10_000,
        replay_window: 65_536,
    }
}
fn reserved(config: ReassemblyConfig) -> Result<Reassembler> {
    Ok(Reassembler::new_reserved(
        context(),
        config,
        storage::Limits {
            capacity_bytes: storage::Plan::for_reassembly(config)?.capacity_bytes(),
        },
    )?)
}
fn inventory(owner: &Reassembler) -> Result<Vec<(usize, usize)>> {
    let PendingStore::Reserved(slots) = &owner.pending else {
        return Err("missing actual pending slots".into());
    };
    let RetiredStore::Reserved { tags, .. } = &owner.retired else {
        return Err("missing actual replay tags".into());
    };
    let mut values = vec![(slots.as_ptr() as usize, slots.capacity())];
    for slot in slots {
        values.push((
            slot.pending.present.as_ptr() as usize,
            slot.pending.present.capacity(),
        ));
        values.push((
            slot.pending.buffer.as_ptr() as usize,
            slot.pending.buffer.capacity(),
        ));
    }
    values.push((tags.as_ptr() as usize, tags.capacity()));
    values.push((
        owner.expired_scratch.as_ptr() as usize,
        owner.expired_scratch.capacity(),
    ));
    Ok(values)
}
#[test]
fn flat_batch_is_byte_exact_at_full_message_and_short_output_consumes_no_id() -> Result {
    let config = FragmentConfig {
        path_mtu: 184,
        max_message_bytes: 65_536,
        max_fragments: u16::MAX,
        ..send_config()
    };
    let record: Vec<_> = (0..65_536).map(|index| (index % 251) as u8).collect();
    let mut owned = Fragmenter::new(context(), config, MessageId(7))?;
    let mut flat = Fragmenter::new(context(), config, MessageId(7))?;
    let expected = owned.fragment(&record)?;
    let length: usize = expected.fragments.iter().map(Vec::len).sum();
    let mut short = vec![0xa5; length - 1];
    assert!(matches!(
        flat.fragment_into(&record, &mut short),
        Err(FragmentError::OutputTooSmall)
    ));
    assert!(short.iter().all(|byte| *byte == 0xa5));
    assert_eq!(flat.next_message, Some(MessageId(7)));
    let mut output = vec![0xa5; length + 17];
    let view = flat.fragment_into(&record, &mut output)?;
    assert_eq!(view.message(), MessageId(7));
    assert!(!view.is_empty());
    assert_eq!(view.len(), expected.fragments.len());
    for (index, fragment) in expected.fragments.iter().enumerate() {
        assert_eq!(view.fragment(index), Some(fragment.as_slice()));
    }
    assert_eq!(view.fragment(view.len()), None);
    assert_eq!(view.layout().fragment_range(usize::MAX), None);
    assert_eq!(view.encoded().len(), length);
    assert!(output[length..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(flat.next_message, owned.next_message);
    let mut receiver = reserved(ReassemblyConfig {
        max_message_bytes: 65_536,
        max_messages: 1,
        max_fragment_payload_bytes: 144,
        max_fragments_per_message: u16::MAX,
        max_total_fragments: usize::from(u16::MAX),
        max_reserved_bytes: 65_536,
        max_lifetime_ticks: 10_000,
        replay_window: 65_536,
    })?;
    let pointers = inventory(&receiver)?;
    let mut complete = vec![0; 65_536];
    for (index, fragment) in expected.fragments.iter().enumerate() {
        let status = receiver.accept(fragment, 0, &mut complete)?;
        if index + 1 == expected.fragments.len() {
            assert_eq!(
                status,
                ReassemblyStatus::Complete {
                    message: MessageId(7),
                    length: 65_536
                }
            );
        } else {
            assert!(matches!(status, ReassemblyStatus::Pending { .. }));
        }
    }
    assert_eq!(complete, record);
    assert_eq!(inventory(&receiver)?, pointers);
    let mut last = Fragmenter::new(context(), config, MessageId(u64::MAX))?;
    assert_eq!(
        last.fragment_into(b"x", &mut output)?.message(),
        MessageId(u64::MAX)
    );
    assert!(matches!(
        last.fragment_into(b"x", &mut output),
        Err(FragmentError::Exhausted)
    ));
    Ok(())
}
#[test]
fn reassembly_plan_exact_budget_all_local_failpoints_and_maxima() -> Result {
    let config = config();
    let plan = storage::Plan::for_reassembly(config)?;
    assert_eq!(plan.config(), config);
    assert_eq!(
        plan.capacity_bytes(),
        storage::array_bytes::<backing::PendingSlot>(3)?
            + 3 * (128 + 8)
            + storage::array_bytes::<Option<MessageId>>(65_536)?
            + storage::array_bytes::<MessageId>(3)?
    );
    assert!(matches!(
        Reassembler::new_reserved(
            context(),
            config,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    for point in 1..=9 {
        let mut allocation = storage::Allocation::failing(plan.capacity_bytes(), point);
        assert!(matches!(
            Reassembler::build_reserved(context(), config, &mut allocation),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(allocation.usage().allocations, point - 1);
        let bytes = allocation.usage().capacity_bytes;
        let expected = if bytes == 0 {
            Vec::new()
        } else {
            vec![
                storage::DropEvent::Before(bytes),
                storage::DropEvent::After(bytes),
            ]
        };
        assert_eq!(
            *allocation.trace.borrow(),
            expected,
            "every provisioned partial inventory was actually dropped at failpoint {point}"
        );
    }
    let mut allocation = storage::Allocation::new(plan.capacity_bytes());
    let transferred = Reassembler::build_reserved(context(), config, &mut allocation)?;
    assert!(
        allocation.trace.borrow().is_empty(),
        "successful transfer must not release live backing"
    );
    assert_eq!(
        transferred
            .storage_usage()
            .ok_or("missing transfer observation")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    let owner = reserved(config)?;
    let usage = owner.storage_usage().ok_or("missing storage observation")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(usage.allocations, 9);
    assert_eq!(inventory(&owner)?.len(), usage.allocations);
    assert_eq!(Reassembler::new(context(), config)?.storage_usage(), None);
    let maximum = ReassemblyConfig {
        max_message_bytes: 65_536,
        max_fragments_per_message: u16::MAX,
        max_total_fragments: 3 * usize::from(u16::MAX),
        max_reserved_bytes: 3 * 65_536,
        ..config
    };
    assert_eq!(storage::Plan::for_reassembly(maximum)?.config(), maximum);
    assert!(matches!(
        Reassembler::new_reserved(context(), maximum, storage::Limits { capacity_bytes: 0 }),
        Err(storage::Error::Limit { .. })
    ));
    assert!(matches!(
        storage::Plan::for_reassembly(ReassemblyConfig {
            replay_window: 0,
            ..config
        }),
        Err(storage::Error::Fragment(FragmentError::InvalidConfig))
    ));
    assert!(matches!(
        storage::array_bytes::<u64>(usize::MAX),
        Err(storage::Error::Layout)
    ));
    Ok(())
}
#[test]
fn complete_reassembly_slots_recycle_130_full_windows_with_exact_bytes() -> Result {
    let mut sender = Fragmenter::new(context(), send_config(), MessageId(1))?;
    let mut owner = reserved(config())?;
    let pointers = inventory(&owner)?;
    let usage = owner.storage_usage();
    let mut output = [0xa5; 128];
    for round in 0..130_u64 {
        let mut batches = Vec::new();
        for slot in 0..3_u8 {
            batches.push(sender.fragment(&[round as u8, slot].repeat(30))?);
        }
        for batch in &batches {
            for fragment in batch.fragments.iter().take(3) {
                assert!(matches!(
                    owner.accept(fragment, round, &mut output)?,
                    ReassemblyStatus::Pending { .. }
                ));
            }
        }
        assert_eq!(owner.pending_messages(), 3);
        assert_eq!(owner.reserved_bytes(), 180);
        assert_eq!(inventory(&owner)?, pointers);
        for index in [2, 0, 1] {
            let batch = &batches[index];
            assert_eq!(
                owner.accept(&batch.fragments[3], round, &mut output)?,
                ReassemblyStatus::Complete {
                    message: batch.message,
                    length: 60
                }
            );
            assert_eq!(&output[..60], &[round as u8, index as u8].repeat(30));
            let before = output;
            assert_eq!(
                owner.accept(&batch.fragments[0], round, &mut output)?,
                ReassemblyStatus::Duplicate {
                    message: batch.message
                }
            );
            assert_eq!(output, before);
        }
        assert_eq!(owner.pending_messages(), 0);
        assert_eq!(owner.reserved_fragments(), 0);
        assert_eq!(owner.storage_usage(), usage);
        assert_eq!(inventory(&owner)?, pointers);
    }
    Ok(())
}
#[test]
fn bounded_expiry_is_sorted_atomic_and_reuses_actual_slots() -> Result {
    let config = ReassemblyConfig {
        max_lifetime_ticks: 5,
        ..config()
    };
    let mut owner = reserved(config)?;
    let pointers = inventory(&owner)?;
    let mut sender = Fragmenter::new(context(), send_config(), MessageId(1))?;
    let batches: Vec<_> = (0..3)
        .map(|_| sender.fragment(&[0x44; 60]))
        .collect::<std::result::Result<_, _>>()?;
    let mut output = [0xa5; 128];
    for index in [2, 0, 1] {
        owner.accept(&batches[index].fragments[0], 10, &mut output)?;
    }
    owner.accept(&batches[0].fragments[0], 14, &mut output)?;
    let before = (
        owner.pending_messages(),
        owner.reserved_bytes(),
        owner.last_time,
        owner.deadline(),
    );
    let mut short = [MessageId(0x9999); 2];
    assert_eq!(
        owner.expire_into(15, &mut short),
        Err(FragmentError::OutputTooSmall)
    );
    assert_eq!(short, [MessageId(0x9999); 2]);
    assert_eq!(
        (
            owner.pending_messages(),
            owner.reserved_bytes(),
            owner.last_time,
            owner.deadline()
        ),
        before
    );
    let mut ids = [MessageId(0); 3];
    assert_eq!(owner.expire_into(15, &mut ids)?, 3);
    assert_eq!(ids, [MessageId(1), MessageId(2), MessageId(3)]);
    assert_eq!(owner.pending_messages(), 0);
    assert_eq!(
        owner.expire_count(14),
        Err(FragmentError::TimeWentBackwards)
    );
    assert_eq!(
        owner.accept(&batches[0].fragments[0], 15, &mut output)?,
        ReassemblyStatus::Duplicate {
            message: MessageId(1)
        }
    );
    assert_eq!(inventory(&owner)?, pointers);
    Ok(())
}
#[test]
fn full_65536_replay_window_uses_full_ids_and_rejects_stale_aliases() -> Result {
    let mut owner = reserved(config())?;
    let pointers = inventory(&owner)?;
    let mut sender = Fragmenter::new(context(), send_config(), MessageId(1))?;
    let mut encoded = [0; 41];
    let mut output = [0; 128];
    let mut first = [0; 41];
    for id in 1..=65_537_u64 {
        let view = sender.fragment_into(&[id as u8], &mut encoded)?;
        if id == 1 {
            first.copy_from_slice(view.encoded());
        }
        assert_eq!(
            owner.accept(view.encoded(), id, &mut output)?,
            ReassemblyStatus::Complete {
                message: MessageId(id),
                length: 1
            }
        );
    }
    assert_eq!(owner.retired_messages(), 65_536);
    assert_eq!(
        owner.accept(&first, 65_538, &mut output),
        Err(FragmentError::StaleMessage)
    );
    let mut near_max = reserved(config())?;
    let mut last = Fragmenter::new(context(), send_config(), MessageId(u64::MAX - 1))?;
    for id in [u64::MAX - 1, u64::MAX] {
        let view = last.fragment_into(b"z", &mut encoded)?;
        assert_eq!(
            near_max.accept(view.encoded(), 0, &mut output)?,
            ReassemblyStatus::Complete {
                message: MessageId(id),
                length: 1
            }
        );
        assert_eq!(
            near_max.accept(view.encoded(), 0, &mut output)?,
            ReassemblyStatus::Duplicate {
                message: MessageId(id)
            }
        );
    }
    assert_eq!(inventory(&owner)?, pointers);
    Ok(())
}

struct Mirror {
    legacy: Reassembler,
    reserved: Reassembler,
    pointers: Vec<(usize, usize)>,
}
impl Mirror {
    fn new(config: ReassemblyConfig) -> Result<Self> {
        let reserved = reserved(config)?;
        let pointers = inventory(&reserved)?;
        Ok(Self {
            legacy: Reassembler::new(context(), config)?,
            reserved,
            pointers,
        })
    }
    fn accept(
        &mut self,
        bytes: &[u8],
        now: u64,
        output_bytes: usize,
    ) -> Result<std::result::Result<ReassemblyStatus, FragmentError>> {
        let mut left = vec![0xA5; output_bytes];
        let mut right = left.clone();
        let actual = self.legacy.accept(bytes, now, &mut left);
        assert_eq!(actual, self.reserved.accept(bytes, now, &mut right));
        assert_eq!(left, right);
        if !matches!(actual, Ok(ReassemblyStatus::Complete { .. })) {
            assert!(left.iter().all(|byte| *byte == 0xA5));
        }
        assert_eq!(
            (
                self.legacy.pending_messages(),
                self.legacy.retired_messages(),
                self.legacy.reserved_bytes(),
                self.legacy.reserved_fragments(),
                self.legacy.deadline(),
                self.legacy.highest,
                self.legacy.last_time
            ),
            (
                self.reserved.pending_messages(),
                self.reserved.retired_messages(),
                self.reserved.reserved_bytes(),
                self.reserved.reserved_fragments(),
                self.reserved.deadline(),
                self.reserved.highest,
                self.reserved.last_time
            )
        );
        assert_eq!(inventory(&self.reserved)?, self.pointers);
        Ok(actual)
    }
}

#[test]
fn reserved_and_legacy_match_parser_context_conflict_output_and_original_clock_errors() -> Result {
    let mut sender = Fragmenter::new(context(), send_config(), MessageId(1))?;
    let batch = sender.fragment(&[0x63; 60])?;
    let mut mirror = Mirror::new(config())?;
    assert_eq!(
        mirror.accept(&batch.fragments[0][..39], 0, 128)?,
        Err(FragmentError::Truncated)
    );
    for (offset, error) in [
        (0, FragmentError::InvalidHeader),
        (4, FragmentError::WrongContext),
    ] {
        let mut bad = batch.fragments[0].clone();
        bad[offset] ^= 0x01;
        assert_eq!(mirror.accept(&bad, 0, 128)?, Err(error));
    }
    let mut geometry = batch.fragments[0].clone();
    geometry[32..34].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        mirror.accept(&geometry, 0, 128)?,
        Err(FragmentError::InvalidGeometry)
    );
    assert!(matches!(
        mirror.accept(&batch.fragments[0], 10, 128)?,
        Ok(ReassemblyStatus::Pending { received: 1, .. })
    ));
    let mut conflict = batch.fragments[0].clone();
    *conflict.last_mut().ok_or("missing real body")? ^= 1;
    assert_eq!(
        mirror.accept(&conflict, 10, 128)?,
        Err(FragmentError::Conflict)
    );
    assert_eq!(
        mirror.accept(&batch.fragments[0], 10, 128)?,
        Ok(ReassemblyStatus::Duplicate {
            message: MessageId(1)
        })
    );
    for fragment in &batch.fragments[1..3] {
        assert!(matches!(
            mirror.accept(fragment, 10, 128)?,
            Ok(ReassemblyStatus::Pending { .. })
        ));
    }
    assert_eq!(
        mirror.accept(&batch.fragments[3], 10, 59)?,
        Err(FragmentError::OutputTooSmall)
    );
    assert_eq!(
        mirror
            .reserved
            .pending
            .get(&MessageId(1))
            .ok_or("missing unchanged pending slot")?
            .received,
        3
    );
    assert_eq!(
        mirror.accept(&batch.fragments[3], 10, 128)?,
        Ok(ReassemblyStatus::Complete {
            message: MessageId(1),
            length: 60
        })
    );
    assert_eq!(
        mirror.accept(&batch.fragments[3], 9, 128)?,
        Err(FragmentError::TimeWentBackwards)
    );
    assert_eq!(
        mirror.accept(&batch.fragments[0], 11, 128)?,
        Ok(ReassemblyStatus::Duplicate {
            message: MessageId(1)
        })
    );
    let mut expiry = Mirror::new(ReassemblyConfig {
        max_lifetime_ticks: 5,
        ..config()
    })?;
    expiry.accept(&batch.fragments[0], 10, 128)??;
    assert_eq!(
        expiry.accept(&batch.fragments[0][..39], 15, 128)?,
        Err(FragmentError::Truncated)
    );
    assert_eq!(
        expiry.reserved.pending_messages(),
        1,
        "malformed input does not run expiry"
    );
    assert_eq!(
        expiry.accept(&batch.fragments[1], 15, 128)?,
        Ok(ReassemblyStatus::Duplicate {
            message: MessageId(1)
        })
    );
    assert_eq!(expiry.reserved.pending_messages(), 0);
    let mut overflow = Mirror::new(config())?;
    assert_eq!(
        overflow.accept(&batch.fragments[0], u64::MAX, 128)?,
        Err(FragmentError::DeadlineOverflow)
    );
    Ok(())
}

#[test]
fn reserved_and_legacy_match_independent_message_byte_fragment_and_replay_pressure() -> Result {
    for (receiver, bytes, expected) in [
        (
            ReassemblyConfig {
                max_messages: 1,
                ..config()
            },
            60,
            FragmentError::MessageBudget,
        ),
        (
            ReassemblyConfig {
                max_reserved_bytes: 128,
                ..config()
            },
            100,
            FragmentError::ByteBudget,
        ),
        (
            ReassemblyConfig {
                max_total_fragments: 8,
                ..config()
            },
            128,
            FragmentError::FragmentBudget,
        ),
    ] {
        let mut sender = Fragmenter::new(context(), send_config(), MessageId(1))?;
        let first = sender.fragment(&vec![0x11; bytes])?;
        let second = sender.fragment(&vec![0x22; bytes])?;
        let mut mirror = Mirror::new(receiver)?;
        mirror.accept(&first.fragments[0], 0, 128)??;
        assert_eq!(mirror.accept(&second.fragments[0], 0, 128)?, Err(expected));
        for fragment in first.fragments.iter().skip(1) {
            mirror.accept(fragment, 0, 128)??;
        }
        assert!(matches!(
            mirror.accept(&second.fragments[0], 0, 128)?,
            Ok(ReassemblyStatus::Pending { .. })
        ));
    }
    let mut mirror = Mirror::new(ReassemblyConfig {
        replay_window: 3,
        ..config()
    })?;
    let mut low = Fragmenter::new(context(), send_config(), MessageId(1))?;
    let mut high = Fragmenter::new(context(), send_config(), MessageId(4))?;
    let first = low.fragment(&[0x11; 32])?;
    let later = high.fragment(&[0x44; 32])?;
    mirror.accept(&first.fragments[0], 0, 128)??;
    assert_eq!(
        mirror.accept(&later.fragments[0], 0, 128)?,
        Err(FragmentError::ReplayWindowBlocked)
    );
    mirror.accept(&first.fragments[1], 0, 128)??;
    mirror.accept(&later.fragments[0], 0, 128)??;
    assert_eq!(
        mirror.accept(&first.fragments[0], 0, 128)?,
        Err(FragmentError::StaleMessage)
    );
    Ok(())
}

#[test]
fn exact_65535_fragment_wire_boundary_and_every_flat_error_preserve_id_and_output() -> Result {
    let config = FragmentConfig {
        path_mtu: 41,
        outer_overhead_bytes: 0,
        max_message_bytes: 65_536,
        max_fragments: u16::MAX,
    };
    let mut sender = Fragmenter::new(context(), config, MessageId(3))?;
    let mut output = vec![0xA5; 41 * usize::from(u16::MAX)];
    assert!(matches!(
        sender.fragment_into(&[], &mut output),
        Err(FragmentError::EmptyMessage)
    ));
    assert!(matches!(
        sender.fragment_into(&vec![0; 65_537], &mut output),
        Err(FragmentError::MessageTooLarge)
    ));
    assert!(matches!(
        sender.fragment_into(&vec![0; 65_536], &mut output),
        Err(FragmentError::TooManyFragments)
    ));
    assert_eq!(sender.next_message, Some(MessageId(3)));
    assert!(output.iter().all(|byte| *byte == 0xA5));
    let body = vec![0x5A; usize::from(u16::MAX)];
    let output_length = output.len();
    let batch = sender.fragment_into(&body, &mut output)?;
    assert_eq!(batch.len(), usize::from(u16::MAX));
    assert_eq!(batch.encoded().len(), output_length);
    let first = batch.fragment(0).ok_or("first fragment absent")?;
    let last = batch
        .fragment(usize::from(u16::MAX) - 1)
        .ok_or("last fragment absent")?;
    assert_eq!(&first[32..36], &[0, 0, 0xFF, 0xFF]);
    assert_eq!(&last[32..36], &[0xFF, 0xFE, 0xFF, 0xFF]);
    assert_eq!(last[40], 0x5A);
    assert_eq!(sender.next_message, Some(MessageId(4)));
    let mut receiver = reserved(ReassemblyConfig {
        max_message_bytes: 65_536,
        max_messages: 1,
        max_fragment_payload_bytes: 1,
        max_fragments_per_message: u16::MAX,
        max_total_fragments: usize::from(u16::MAX),
        max_reserved_bytes: 65_536,
        max_lifetime_ticks: 10_000,
        replay_window: 65_536,
    })?;
    let pointers = inventory(&receiver)?;
    let mut complete = vec![0; 65_536];
    for index in 0..batch.len() {
        let status = receiver.accept(
            batch.fragment(index).ok_or("canonical fragment missing")?,
            0,
            &mut complete,
        )?;
        if index + 1 == batch.len() {
            assert_eq!(
                status,
                ReassemblyStatus::Complete {
                    message: MessageId(3),
                    length: usize::from(u16::MAX)
                }
            );
        } else {
            assert!(matches!(status, ReassemblyStatus::Pending { .. }));
        }
    }
    assert_eq!(&complete[..body.len()], body);
    assert_eq!(inventory(&receiver)?, pointers);
    Ok(())
}

#[path = "timing_tests.rs"]
mod original_time;

#[path = "geometry_tests.rs"]
mod geometry;
