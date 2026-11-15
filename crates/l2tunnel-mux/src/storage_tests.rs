use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type BackingState = ([usize; 4], [*const u8; 4]);

fn limits(plan: storage::Plan) -> storage::Limits {
    storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    }
}
fn fixed(
    channels: u16,
    bytes: usize,
    frames: usize,
    maximum: usize,
) -> Result<Mux, storage::Error> {
    let plan = storage::Plan::for_queue(channels, bytes, frames, maximum)?;
    Mux::with_plan(plan, limits(plan))
}
fn backing(mux: &Mux) -> Result<BackingState, &'static str> {
    let Backing::Reserved(backing) = &mux.backing else {
        return Err("expected actual slabs");
    };
    Ok((
        [
            backing.lanes.capacity(),
            backing.slots.capacity(),
            backing.free.capacity(),
            backing.bytes.capacity(),
        ],
        [
            backing.lanes.as_ptr().cast(),
            backing.slots.as_ptr().cast(),
            backing.free.as_ptr().cast(),
            backing.bytes.as_ptr(),
        ],
    ))
}
fn trace() -> DropTrace {
    std::rc::Rc::default()
}
fn observed(trace: DropTrace) -> Provisioned {
    Provisioned {
        lanes: Vec::new(),
        slots: Vec::new(),
        free: Vec::new(),
        bytes: Vec::new(),
        trace: Some(trace),
    }
}

#[test]
fn exact_capacity_and_local_partial_reservation_failure_drop_actual_buffers() -> TestResult {
    let plan = storage::Plan::for_queue(3, 17, 5, 9)?;
    let expected = 3 * std::mem::size_of::<Lane>()
        + 5 * std::mem::size_of::<Slot>()
        + 5 * std::mem::size_of::<usize>()
        + 45;
    assert_eq!(plan.capacity_bytes(), expected);
    let mut allocation = storage::Allocation::failing(1);
    let drops = trace();
    let guard = observed(drops.clone());
    assert!(
        matches!(Mux::with_allocation(plan, storage::Limits { capacity_bytes: expected - 1 }, &mut allocation, guard), Err(storage::Error::Limit { required, limit }) if required == expected && limit == expected - 1)
    );
    assert_eq!(allocation.attempts, 0);
    assert_eq!(&*drops.borrow(), &[[0; 4]]);
    for attempt in 1..=4 {
        let drops = trace();
        let guard = observed(drops.clone());
        let mut allocation = storage::Allocation::failing(attempt);
        assert!(matches!(
            Mux::with_allocation(plan, limits(plan), &mut allocation, guard),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(allocation.attempts, attempt);
        let mut actual_before_drop = [0; 4];
        for (index, count) in [3, 5, 5, 45].into_iter().enumerate().take(attempt - 1) {
            actual_before_drop[index] = count;
        }
        // Observation runs only after these same actual guard-owned Vecs were dropped.
        assert_eq!(&*drops.borrow(), &[actual_before_drop]);
    }
    for extra in [0, 1] {
        let drops = trace();
        let guard = observed(drops.clone());
        let mut allocation = storage::Allocation::default();
        let mux = Mux::with_allocation(
            plan,
            storage::Limits {
                capacity_bytes: expected + extra,
            },
            &mut allocation,
            guard,
        )?;
        assert_eq!(backing(&mux)?.0, [3, 5, 5, 45]);
        assert_eq!(allocation.attempts, 4);
        assert_eq!(
            mux.storage_usage(),
            Some(storage::Usage {
                limit_bytes: expected + extra,
                capacity_bytes: expected,
                allocations: 4
            })
        );
        assert_eq!(&*drops.borrow(), &[[0; 4]]);
    }
    assert_eq!(Mux::new(3, 17, 5)?.storage_usage(), None);
    Ok(())
}

#[test]
fn checked_layouts_retain_full_width_and_distinct_logical_and_physical_limits() -> TestResult {
    let plan = storage::Plan::for_queue(256, 1, 2, 33)?;
    assert_eq!(
        (
            plan.channels(),
            plan.byte_limit(),
            plan.frame_limit(),
            plan.max_frame_bytes()
        ),
        (256, 1, 2, Some(33))
    );
    let mut mux = Mux::with_plan(plan, limits(plan))?;
    mux.push_borrowed(255, &[7])
        .map_err(|_| "full channel width")?;
    assert_eq!(
        mux.push_borrowed(256, &[]),
        Err(BorrowedAdmissionError::Channel)
    );
    assert_eq!(
        mux.push_borrowed(0, &[8]),
        Err(BorrowedAdmissionError::Budget)
    );
    assert_eq!(
        mux.offer_front_borrowed(|channel, bytes| {
            assert_eq!((channel, bytes), (255, &[7][..]));
            Ok::<_, ()>(Some(()))
        }),
        Ok(Some((255, ())))
    );
    assert_eq!(mux.next, 0);
    for (channels, bytes, frames, maximum) in [
        (0, 1, 1, 1),
        (257, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
    ] {
        assert_eq!(
            storage::Plan::for_queue(channels, bytes, frames, maximum),
            Err(storage::Error::Configuration)
        );
    }
    assert_eq!(
        storage::Plan::for_queue(1, 1, usize::MAX, 2),
        Err(storage::Error::Layout)
    );
    assert_eq!(
        storage::Plan::for_queue(1, 1, 1, usize::MAX),
        Err(storage::Error::Layout)
    );
    Ok(())
}

#[test]
fn globally_shared_slots_refuse_without_changing_custody_and_recycle_in_place() -> TestResult {
    let mut mux = fixed(4, 12, 3, 4)?;
    let original = backing(&mux)?;
    for round in 0..32u8 {
        // Every global slot can belong to the same lane; no per-lane quota exists.
        for value in [round, round + 1, round + 2] {
            mux.push_borrowed(3, &[value, value])
                .map_err(|_| "global slot")?;
        }
        assert_eq!(
            mux.push_borrowed(0, &[9]),
            Err(BorrowedAdmissionError::Budget)
        );
        let (_, release) = mux.front(3).map_err(|()| "actual front")?.ok_or("head")?;
        let release = release.ok_or("actual slot")?;
        let pointer = match &mux.backing {
            Backing::Reserved(backing) => backing.bytes[release.start..release.end].as_ptr(),
            _ => return Err("actual slab".into()),
        };
        let before = (mux.next, mux.queued_bytes, mux.queued_frames);
        let mut refused_copy = storage::Allocation::failing(1);
        assert_eq!(
            mux.offer_inner::<(), &str, Owned>(
                |_, _| Err("must not enter after allocation refusal"),
                &mut refused_copy
            ),
            Err(OfferError::Allocation)
        );
        assert_eq!(refused_copy.attempts, 1);
        assert_eq!((mux.next, mux.queued_bytes, mux.queued_frames), before);
        assert_eq!(
            mux.offer_front(|_, bytes| {
                assert_eq!(bytes.as_ptr(), pointer);
                Ok::<Option<()>, &str>(None)
            }),
            Ok(None)
        );
        assert_eq!(
            mux.offer_front(|_, bytes| {
                assert_eq!(bytes.as_ptr(), pointer);
                Err::<Option<()>, _>("owned full")
            }),
            Err(OfferError::Downstream("owned full"))
        );
        assert_eq!((mux.next, mux.queued_bytes, mux.queued_frames), before);
        for _ in 0..2 {
            assert_eq!(
                mux.offer_front_borrowed(|channel, bytes| {
                    assert_eq!(channel, 3);
                    assert_eq!(bytes, &[round, round]);
                    assert_eq!(bytes.as_ptr(), pointer);
                    Ok::<Option<()>, &str>(None)
                }),
                Ok(None)
            );
            assert_eq!(
                mux.offer_front_borrowed(|_, bytes| {
                    assert_eq!(bytes.as_ptr(), pointer);
                    Err::<Option<()>, _>("full")
                }),
                Err(OfferError::Downstream("full"))
            );
            assert_eq!((mux.next, mux.queued_bytes, mux.queued_frames), before);
        }
        for value in [round, round + 1, round + 2] {
            assert_eq!(
                mux.offer_front_borrowed(|channel, bytes| {
                    assert_eq!(channel, 3);
                    assert_eq!(bytes, &[value, value]);
                    Ok::<_, ()>(Some(value))
                }),
                Ok(Some((3, value)))
            );
        }
        assert_eq!(
            mux.offer_front_borrowed(|_, _| Err::<Option<()>, _>("empty callback")),
            Ok(None)
        );
        assert_eq!((mux.queued_bytes, mux.queued_frames), (0, 0));
        assert_eq!(backing(&mux)?, original);
        let Backing::Reserved(backing) = &mux.backing else {
            return Err("actual slab".into());
        };
        assert_eq!(backing.free.len(), 3);
        assert!(
            backing
                .slots
                .iter()
                .all(|slot| slot.length == 0 && slot.next.is_none())
        );
    }
    let mut small = fixed(2, 5, 4, 3)?;
    small.push_borrowed(0, &[1, 2, 3]).map_err(|_| "first")?;
    small.push_borrowed(1, &[4, 5]).map_err(|_| "second")?;
    assert_eq!(
        small.push_borrowed(0, &[6]),
        Err(BorrowedAdmissionError::Budget)
    );
    let Backing::Reserved(backing) = &small.backing else {
        return Err("actual slab".into());
    };
    assert_eq!(backing.free.len(), 2);
    assert_eq!(small.pop(), Some((0, vec![1, 2, 3])));
    assert_eq!(small.pop(), Some((1, vec![4, 5])));
    assert_eq!(
        small.push_borrowed(0, &[0; 4]),
        Err(BorrowedAdmissionError::Budget)
    );
    assert_eq!((small.queued_bytes, small.queued_frames), (0, 0));
    Ok(())
}

#[test]
fn mixed_owned_and_borrowed_paths_match_real_legacy_fifo_and_round_robin() -> TestResult {
    let mut legacy = Mux::new(256, 64, 8)?;
    let mut fixed = fixed(256, 64, 8, 8)?;
    let original = backing(&fixed)?;
    for mux in [&mut legacy, &mut fixed] {
        mux.next = 254;
        for (channel, bytes) in [
            (0, vec![1, 2]),
            (255, vec![3]),
            (254, vec![4, 5]),
            (255, vec![6, 7]),
            (0, vec![8]),
        ] {
            mux.push(channel, bytes).map_err(|_| "owned ingress")?;
        }
    }
    let mut borrowed = true;
    while let Some(expected) = legacy.pop() {
        if borrowed {
            let actual = fixed
                .offer_front_borrowed(|channel, bytes| Ok::<_, ()>(Some((channel, bytes.to_vec()))))
                .map_err(|_| "borrowed handoff")?
                .ok_or("actual packet")?;
            assert_eq!(actual.0, expected.0);
            assert_eq!(actual.1, expected);
        } else {
            let (channel, bytes, token) = fixed
                .offer_front(|channel, bytes| Ok::<_, ()>(Some((channel, bytes.as_ptr()))))
                .map_err(|_| "owned convenience")?
                .ok_or("actual packet")?;
            assert_eq!((channel, bytes.clone()), expected);
            assert_eq!(token.0, channel);
            // A reserved owned convenience copies; callback still sees the actual slab.
            assert_ne!(bytes.as_ptr(), token.1);
        }
        assert_eq!(
            (fixed.next, fixed.queued_bytes, fixed.queued_frames),
            (legacy.next, legacy.queued_bytes, legacy.queued_frames)
        );
        borrowed = !borrowed;
    }
    assert_eq!(backing(&fixed)?, original);
    Ok(())
}

#[test]
fn inline_handoff_has_zero_heap_full_logical_domain_and_original_cursor_semantics() -> TestResult {
    let plan = storage::Plan::for_handoff(256, usize::MAX, usize::MAX)?;
    assert!(plan.is_handoff());
    assert_eq!(plan.capacity_bytes(), 0);
    assert_eq!(plan.max_frame_bytes(), None);
    let mut allocation = storage::Allocation::failing(1);
    let mut mux =
        Mux::with_allocation(plan, limits(plan), &mut allocation, Provisioned::default())?;
    assert_eq!(allocation.attempts, 0);
    assert!(matches!(mux.backing, Backing::Handoff));
    assert_eq!(
        mux.storage_usage(),
        Some(storage::Usage {
            limit_bytes: 0,
            capacity_bytes: 0,
            allocations: 0
        })
    );
    assert_eq!(
        mux.push_borrowed(255, &[1]),
        Err(BorrowedAdmissionError::Unavailable)
    );
    assert_eq!(
        mux.push_borrowed(256, &[]),
        Err(BorrowedAdmissionError::Channel)
    );
    assert_eq!(mux.push(255, vec![1]), Err(AdmissionError::Budget(vec![1])));
    assert_eq!(
        mux.offer_front_borrowed(|_, _| Err::<Option<()>, _>("empty callback")),
        Ok(None)
    );
    for channel in [255, 0, 254] {
        let before = mux.next;
        assert_eq!(
            mux.offer_selected(channel, &[1], |_, _| Ok::<Option<()>, ()>(None)),
            Ok(None)
        );
        assert_eq!(mux.next, before);
        assert_eq!(
            mux.offer_selected(channel, &[1], |_, _| Err::<Option<()>, _>("full")),
            Err(OfferError::Downstream("full"))
        );
        assert_eq!(mux.next, before);
        assert_eq!(
            mux.offer_selected(channel, &[1], |observed, bytes| {
                assert_eq!((observed, bytes), (channel, &[1][..]));
                Ok::<_, ()>(Some(7))
            }),
            Ok(Some(7))
        );
        assert_eq!(mux.next, (usize::from(channel) + 1) % 256);
        assert_eq!((mux.queued_bytes, mux.queued_frames), (0, 0));
    }
    Ok(())
}

#[test]
fn reserved_link_and_accounting_refusals_precede_downstream_callback() -> TestResult {
    let mut mux = fixed(2, 8, 2, 4)?;
    mux.push_borrowed(1, &[4, 5])
        .map_err(|_| "actual ingress")?;
    let original = backing(&mux)?;
    for (bytes, frames) in [(0, 1), (2, 0), (3, 1), (2, 2)] {
        mux.queued_bytes = bytes;
        mux.queued_frames = frames;
        assert_eq!(
            mux.offer_front_borrowed(|_, _| Err::<Option<()>, _>("must not enter")),
            Err(OfferError::Invariant)
        );
        assert_eq!(backing(&mux)?, original);
    }
    mux.queued_bytes = 2;
    mux.queued_frames = 1;
    let Backing::Reserved(reserved) = &mut mux.backing else {
        return Err("actual slab".into());
    };
    let head = reserved.lanes[1].head.ok_or("head")?;
    reserved.slots[head].next = Some(head);
    assert_eq!(
        mux.offer_front_borrowed(|_, _| Err::<Option<()>, _>("must not enter")),
        Err(OfferError::Invariant)
    );
    let Backing::Reserved(reserved) = &mut mux.backing else {
        return Err("actual slab".into());
    };
    reserved.slots[head].next = None;
    assert_eq!(
        mux.offer_front_borrowed(|_, bytes| {
            assert_eq!(bytes, &[4, 5]);
            Ok::<_, ()>(Some(()))
        }),
        Ok(Some((1, ())))
    );
    assert_eq!(backing(&mux)?, original);
    Ok(())
}
