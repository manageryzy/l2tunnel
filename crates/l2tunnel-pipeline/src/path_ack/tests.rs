use super::*;

fn prepared(owner: &mut AckReceiver, now: u64, why: Opportunity) -> Result<(u64, AckBatch), Error> {
    let ready = owner.prepare(now, why)?.ok_or(Error::Stale)?;
    Ok((ready.token(), ready.batch().clone()))
}

#[test]
fn wire_golden_multiple_paths_and_reserved_group() -> Result<(), Error> {
    // path 0 confirms [0,2), [3,4), [5,7); path 2 confirms [128,129);
    // the logical owner confirms [0,9000) without advancing its floor.
    let bytes = [
        0xa1, 3, 0, 0, 2, 2, 1, 1, 1, 2, 2, 128, 1, 129, 1, 0, 255, 0, 168, 70, 0,
    ];
    let batch = AckBatch::decode(&bytes)?;
    assert_eq!(batch.blocks()[0].ranges(), &[3..4, 5..7]);
    assert_eq!(batch.blocks()[1].floor(), 128);
    assert_eq!(batch.blocks()[2].next(), 9000);
    assert_eq!(batch.wire_len(), bytes.len());
    let mut output = [93; 32];
    assert_eq!(batch.encode(&mut output[..3]), Err(Error::ShortBuffer));
    assert!(output.iter().all(|v| *v == 93));
    let length = batch.encode(&mut output)?;
    assert_eq!(output[..length], bytes);
    for end in 0..bytes.len() {
        assert_eq!(AckBatch::decode(&bytes[..end]), Err(Error::Invalid));
    }
    Ok(())
}

#[test]
fn noncanonical_overflow_retire_and_hostile_counts_are_rejected() -> Result<(), Error> {
    for example in [
        &[0xa2, 1, 0, 0, 1, 0][..],
        &[0xa1, 0],
        &[0xa1, 9],
        &[0xa1, 1, 0, 0, 0, 9],
        &[0xa1, 1, 0, 1, 0, 0],
        &[0xa1, 1, 0, 128, 0, 0, 0],
        &[0xa1, 1, 0, 0, 0, 0, 0],
        &[0xa1, 1, 0, 0, 0, 1, 0, 1],
        &[0xa1, 1, 0, 0, 0, 1, 1, 0],
        &[0xa1, 1, 255, 1, 1, 0],
        &[0xa1, 2, 3, 0, 0, 0, 3, 0, 0, 0],
        &[0xa1, 2, 5, 0, 0, 0, 2, 0, 0, 0],
        &[0xa1, 1, 0, 0, 129, 64, 0],
        &[0xa1, 1, 0, 0, 0, 1, 128, 64, 1],
        &[
            0xa1, 1, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2, 0,
        ],
        &[
            0xa1, 1, 255, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1, 1, 1, 1,
        ],
    ] {
        assert_eq!(
            AckBatch::decode(example),
            Err(Error::Invalid),
            "{example:x?}"
        );
    }
    let top = AckBlock::new(7, u64::MAX - 2, u64::MAX, Vec::new())?;
    assert!(top.acknowledges(u64::MAX - 1));
    assert!(!top.acknowledges(u64::MAX));
    assert!(AckBlock::new(255, 0, u64::MAX, Vec::new()).is_ok());
    Ok(())
}

#[test]
fn piggyback_would_block_and_delayed_payment_keep_intervening_work() -> Result<(), Error> {
    let mut r = AckReceiver::new(&[0, 3], 32, 3, 10)?;
    assert_eq!(r.next_deadline(), None);
    assert_eq!(r.observe_data(0, 1, 10)?, Observation::New);
    assert_eq!(r.next_deadline(), Some(20));
    assert!(r.prepare(11, Opportunity::Standalone)?.is_none());
    let (first, original) = prepared(&mut r, 12, Opportunity::Piggyback)?;
    assert!(original.blocks()[0].acknowledges(1));
    assert!(!original.blocks()[0].acknowledges(0));
    assert_eq!(r.observe_data(0, 0, 13)?, Observation::New);
    r.observe_data(3, 0, 14)?;
    assert_eq!(r.next_deadline(), Some(14));
    assert_eq!(
        prepared(&mut r, 15, Opportunity::Standalone)?,
        (first, original)
    );
    assert_eq!(r.confirm_paid(first, 11, 15), Err(Error::Time));
    assert_eq!(r.confirm_paid(first + 1, 12, 15), Err(Error::Stale));
    // The callback can arrive after new DATA on another path.
    r.confirm_paid(first, 12, 16)?;
    assert_eq!(r.confirm_paid(first, 12, 16), Err(Error::Stale));
    assert_eq!(r.next_deadline(), Some(23));
    let (second, batch) = prepared(&mut r, 23, Opportunity::Standalone)?;
    assert_eq!(
        batch
            .blocks()
            .iter()
            .map(|b| (b.path(), b.next()))
            .collect::<Vec<_>>(),
        [(0, 2), (3, 1)]
    );
    r.confirm_paid(second, 23, 23)?;
    assert_eq!(r.next_deadline(), None);
    // A pure ACK is a stateless parse and creates no obligation at the peer.
    let mut buf = [0; 64];
    let n = batch.encode(&mut buf)?;
    assert_eq!(AckBatch::decode(&buf[..n])?, batch);
    assert!(r.prepare(50, Opportunity::Standalone)?.is_none());
    // A duplicate authenticated DATA after that pure ACK was erased does.
    assert_eq!(r.observe_data(0, 1, 51)?, Observation::Duplicate);
    let (_, again) = prepared(&mut r, 61, Opportunity::Standalone)?;
    assert!(again.blocks()[0].acknowledges(1));
    Ok(())
}

#[test]
fn logical_ack_never_generated_and_physical_retirement_never_confirms_old_holes()
-> Result<(), Error> {
    assert!(AckReceiver::new(&[255], 8, 1, 10).is_err());
    assert!(AckReceiver::new(&[1, 1], 8, 1, 10).is_err());
    assert!(AckReceiver::new(&[0], 0, 1, 10).is_err());
    let mut r = AckReceiver::new(&[0], 4, 1, 5)?;
    assert_eq!(r.observe_data(0, 1, 2)?, Observation::New);
    let (first, _) = prepared(&mut r, 2, Opportunity::Standalone)?;
    r.observe_data(0, 6, 3)?;
    r.confirm_paid(first, 3, 3)?;
    let (second, batch) = prepared(&mut r, 3, Opportunity::Standalone)?;
    let block = &batch.blocks()[0];
    assert_eq!((block.floor(), block.next()), (3, 3));
    assert!(!block.acknowledges(0));
    assert!(!block.acknowledges(1));
    assert!(block.acknowledges(6));
    r.confirm_paid(second, 3, 3)?;
    assert_eq!(r.observe_data(0, 0, 4)?, Observation::Retired);
    assert_eq!(r.observe_data(0, u64::MAX, 4), Err(Error::Configuration));
    assert_eq!(r.observe_data(255, 0, 4), Err(Error::Configuration));
    assert_eq!(r.observe_data(0, 1, 3), Err(Error::Time));
    r.observe_data(0, u64::MAX - 1, 5)?;
    let (_, top) = prepared(&mut r, 5, Opportunity::Standalone)?;
    assert!(top.blocks()[0].acknowledges(u64::MAX - 1));
    assert_eq!(top.blocks()[0].floor(), u64::MAX - 4);
    Ok(())
}

#[test]
fn dirty_range_and_path_paging_make_progress_under_duplicates() -> Result<(), Error> {
    let ids = (0..13).collect::<Vec<_>>();
    let mut r = AckReceiver::new(&ids, 128, 1, 20)?;
    for &id in &ids {
        r.observe_data(id, 1, 1)?;
    }
    for seq in (3..41).step_by(2) {
        r.observe_data(0, seq, 1)?;
    }
    let (token, batch) = prepared(&mut r, 1, Opportunity::Standalone)?;
    assert_eq!(batch.blocks().len(), 8);
    assert_eq!(batch.blocks()[0].ranges().len(), 8);
    let mut confirmed = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    let mut keep = |batch: &AckBatch| {
        for block in batch.blocks() {
            paths.insert(block.path());
            if block.path() == 0 {
                for range in block.ranges() {
                    confirmed.extend(range.clone());
                }
            }
        }
    };
    keep(&batch);
    r.confirm_paid(token, 1, 1)?;
    for tick in 2..=4 {
        // The same low slots become eligible again while a later range page is outstanding.
        for seq in (1..17).step_by(2) {
            r.observe_data(0, seq, tick)?;
        }
        let (token, batch) = prepared(&mut r, tick, Opportunity::Standalone)?;
        keep(&batch);
        r.confirm_paid(token, tick, tick)?;
    }
    assert_eq!(paths.into_iter().collect::<Vec<_>>(), ids);
    assert_eq!(
        confirmed.into_iter().collect::<Vec<_>>(),
        (1..41).step_by(2).collect::<Vec<_>>()
    );
    Ok(())
}
#[test]
fn paid_selective_page_repeats_once_and_sleeps_even_if_original_data_never_reappears()
-> Result<(), Error> {
    let mut r = AckReceiver::with_selective_repeat(&[0], 32, 16, 1_000, 8_000)?;
    r.observe_data(0, 3, 1)?;
    let (first, page) = prepared(&mut r, 2, Opportunity::Piggyback)?;
    assert!(page.blocks()[0].acknowledges(3));
    assert_eq!(
        prepared(&mut r, 20_002, Opportunity::Standalone)?,
        (first, page.clone())
    );
    // Erase the first paid ACK. The long blocked interval did not start its repeat clock.
    r.confirm_paid(first, 20_005, 20_010)?;
    assert_eq!(r.next_deadline(), Some(28_005));
    assert!(r.prepare(28_004, Opportunity::Piggyback)?.is_none());
    let (second, page2) = prepared(&mut r, 28_005, Opportunity::Standalone)?;
    assert_eq!(page2, page);
    assert_eq!(
        prepared(&mut r, 48_000, Opportunity::Standalone)?,
        (second, page2)
    );
    r.confirm_paid(second, 48_000, 48_000)?;
    assert_eq!(r.next_deadline(), None);
    assert!(r.prepare(80_000, Opportunity::Standalone)?.is_none());
    Ok(())
}

#[test]
fn cumulative_advance_can_complete_the_overdue_repeat_without_resurrecting_old_slots()
-> Result<(), Error> {
    let mut r = AckReceiver::with_selective_repeat(&[0], 4, 16, 1, 8)?;
    r.observe_data(0, 1, 0)?;
    let (one, _) = prepared(&mut r, 0, Opportunity::Piggyback)?;
    r.confirm_paid(one, 0, 0)?;
    r.observe_data(0, 0, 2)?;
    let (early, p) = prepared(&mut r, 3, Opportunity::Standalone)?;
    assert_eq!(p.blocks()[0].next(), 2);
    r.confirm_paid(early, 3, 3)?;
    assert_eq!(r.next_deadline(), Some(8));
    let (repeat, p) = prepared(&mut r, 8, Opportunity::Standalone)?;
    assert_eq!((p.blocks()[0].next(), p.blocks()[0].ranges().len()), (2, 0));
    r.confirm_paid(repeat, 8, 8)?;
    assert_eq!(r.next_deadline(), None);
    r.observe_data(0, 3, 9)?;
    let (old, _) = prepared(&mut r, 10, Opportunity::Standalone)?;
    // The frozen old receipt pays after an entire ring replacement.
    r.observe_data(0, 10, 11)?;
    r.confirm_paid(old, 12, 12)?;
    let (new, b) = prepared(&mut r, 12, Opportunity::Standalone)?;
    assert_eq!(b.blocks()[0].floor(), 7);
    assert!(!b.blocks()[0].acknowledges(3));
    r.confirm_paid(new, 12, 12)?;
    assert_eq!(r.next_deadline(), Some(20));
    let (last, b) = prepared(&mut r, 20, Opportunity::Standalone)?;
    assert!(b.blocks()[0].acknowledges(10));
    assert!(!b.blocks()[0].acknowledges(3));
    r.confirm_paid(last, 20, 20)?;
    assert_eq!(r.next_deadline(), None);
    Ok(())
}

#[test]
fn bounded_selective_repeat_pages_cover_disjoint_positives_once_on_a_quiet_path()
-> Result<(), Error> {
    let ids = (0..12).collect::<Vec<_>>();
    let mut r = AckReceiver::with_selective_repeat(&ids, 64, 16, 1, 8)?;
    for &p in &ids {
        for n in (1..33).step_by(2) {
            r.observe_data(p, n, 0)?;
        }
    }
    for at in [1, 9] {
        let mut observed = std::collections::BTreeSet::new();
        let mut pages = 0;
        while r.next_deadline().is_some_and(|d| d <= at) {
            let (token, batch) = prepared(&mut r, at, Opportunity::Standalone)?;
            assert!(batch.blocks().len() <= MAX_BLOCKS);
            for block in batch.blocks() {
                assert_eq!(block.floor(), 0);
                for span in block.ranges() {
                    for n in span.clone() {
                        assert!(observed.insert((block.path(), n)));
                    }
                }
            }
            r.confirm_paid(token, at, at)?;
            pages += 1;
            assert!(pages <= ids.len() * 2);
        }
        assert_eq!(observed.len(), 12 * 16);
    }
    assert_eq!(r.next_deadline(), None);
    Ok(())
}
