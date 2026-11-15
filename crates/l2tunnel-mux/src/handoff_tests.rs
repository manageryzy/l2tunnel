use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn queued_refusal_preserves_original_allocation_fifo_and_round_robin() -> TestResult {
    let mut offered = Mux::new(4, 64, 8)?;
    let mut legacy = Mux::new(4, 64, 8)?;
    for mux in [&mut offered, &mut legacy] {
        mux.next = 1;
        for (channel, bytes) in [
            (2, vec![21, 22]),
            (2, vec![23]),
            (0, vec![1]),
            (3, vec![31]),
        ] {
            mux.push(channel, bytes).map_err(|_| "admission")?;
        }
    }
    let pointer = offered.legacy_lanes()[2].front().ok_or("head")?.as_ptr();
    let before = (offered.next, offered.queued_bytes, offered.queued_frames);
    for _ in 0..3 {
        assert_eq!(
            offered.offer_front(|channel, bytes| {
                assert_eq!(channel, 2);
                assert_eq!(bytes, &[21, 22]);
                assert_eq!(bytes.as_ptr(), pointer);
                Ok::<Option<usize>, &str>(None)
            }),
            Ok(None)
        );
        assert_eq!(
            offered.offer_front(|_, bytes| {
                assert_eq!(bytes.as_ptr(), pointer);
                Err::<Option<usize>, _>("downstream")
            }),
            Err(OfferError::Downstream("downstream"))
        );
        assert_eq!(
            (offered.next, offered.queued_bytes, offered.queued_frames),
            before
        );
    }
    let (channel, bytes, token) = offered
        .offer_front(|_, _| Ok::<_, &str>(Some(17)))
        .map_err(|_| "offer")?
        .ok_or("packet")?;
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(token, 17);
    assert_eq!(Some((channel, bytes)), legacy.pop());
    while let Some(expected) = legacy.pop() {
        let (channel, bytes, ()) = offered
            .offer_front(|_, _| Ok::<_, &str>(Some(())))
            .map_err(|_| "offer")?
            .ok_or("packet")?;
        assert_eq!((channel, bytes), expected);
        assert_eq!(offered.next, legacy.next);
    }
    assert_eq!(
        offered.offer_front(|_, _| -> Result<Option<()>, &str> { Err("empty callback") }),
        Ok(None)
    );
    assert_eq!((offered.queued_bytes, offered.queued_frames), (0, 0));
    Ok(())
}

#[test]
fn borrowed_selected_transit_enforces_real_policy_without_retaining_or_copying_bytes() -> TestResult
{
    let mut mux = Mux::new(3, 4, 2)?;
    let bytes = vec![7, 8, 9];
    let pointer = bytes.as_ptr();
    assert_eq!(
        mux.offer_selected(3, &bytes, |_, _| -> Result<Option<()>, &str> {
            Err("channel callback")
        }),
        Err(OfferError::Channel)
    );
    assert_eq!(
        mux.offer_selected(1, &[], |_, _| -> Result<Option<()>, &str> {
            Err("empty callback")
        }),
        Err(OfferError::Budget)
    );
    assert_eq!(
        mux.offer_selected(1, &[0; 5], |_, _| -> Result<Option<()>, &str> {
            Err("budget callback")
        }),
        Err(OfferError::Budget)
    );
    mux.push(0, vec![1]).map_err(|_| "queued frame")?;
    assert_eq!(
        mux.offer_selected(1, &bytes, |_, _| -> Result<Option<()>, &str> {
            Err("busy callback")
        }),
        Err(OfferError::Busy)
    );
    assert_eq!(mux.pop(), Some((0, vec![1])));
    let before = mux.next;
    for _ in 0..3 {
        assert_eq!(
            mux.offer_selected(1, &bytes, |channel, actual| {
                assert_eq!(channel, 1);
                assert_eq!(actual.as_ptr(), pointer);
                Ok::<Option<()>, &str>(None)
            }),
            Ok(None)
        );
        assert_eq!(
            mux.offer_selected(1, &bytes, |_, _| Err::<Option<()>, _>("full")),
            Err(OfferError::Downstream("full"))
        );
        assert_eq!(mux.next, before);
        assert_eq!((mux.queued_bytes, mux.queued_frames), (0, 0));
    }
    assert_eq!(
        mux.offer_selected(1, &bytes, |channel, actual| {
            assert_eq!((channel, actual.as_ptr()), (1, pointer));
            Ok::<_, &str>(Some(99))
        }),
        Ok(Some(99))
    );
    let mut legacy = Mux::new(3, 4, 2)?;
    legacy.push(1, bytes.clone()).map_err(|_| "same policy")?;
    assert_eq!(legacy.pop(), Some((1, bytes)));
    assert_eq!(mux.next, legacy.next);
    assert!(mux.legacy_lanes().iter().all(VecDeque::is_empty));
    assert_eq!((mux.queued_bytes, mux.queued_frames), (0, 0));
    mux.next = 3;
    assert_eq!(
        mux.offer_selected(1, &[1], |_, _| -> Result<Option<()>, &str> {
            Err("invariant callback")
        }),
        Err(OfferError::Invariant)
    );
    Ok(())
}

#[test]
fn corrupt_queued_accounting_refuses_before_downstream_and_preserves_custody() -> TestResult {
    let mut mux = Mux::new(2, 8, 2)?;
    mux.push(1, vec![4, 5]).map_err(|_| "admission")?;
    let pointer = mux.legacy_lanes()[1].front().ok_or("head")?.as_ptr();
    for (bytes, frames) in [(0, 1), (2, 0), (3, 1), (2, 2)] {
        mux.queued_bytes = bytes;
        mux.queued_frames = frames;
        assert_eq!(
            mux.offer_front(|_, _| -> Result<Option<()>, &str> { Err("invariant callback") }),
            Err(OfferError::Invariant)
        );
        assert_eq!(
            mux.legacy_lanes()[1].front().ok_or("retained")?.as_ptr(),
            pointer
        );
        assert_eq!(mux.next, 0);
    }
    mux.queued_bytes = 2;
    mux.queued_frames = 1;
    let (_, bytes, ()) = mux
        .offer_front(|_, _| Ok::<_, &str>(Some(())))
        .map_err(|_| "offer")?
        .ok_or("packet")?;
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(bytes, [4, 5]);
    Ok(())
}
