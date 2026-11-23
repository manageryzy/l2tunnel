use super::*;

const ACK: &[u8] = &[0xa1, 1, 2, 0, 1, 0];
const ACK_OTHER: &[u8] = &[0xa1, 1, 2, 0, 2, 0];
const V1: &[u8] = &[
    0x01, 0x02, 0x81, 0x01, 0x02, 0xac, 0x02, 0x06, b'a', b'b', b'c', 0x09, 0x03, 0x01, b'Z',
];

fn us(n: u64) -> Duration {
    Duration::from_micros(n)
}
fn cfg(plaintext: usize, hold: u64, max_entries: u8) -> PathConfig {
    PathConfig {
        mtu: plaintext + 48,
        outer_bytes: 48,
        max_hold: us(hold),
        max_entries,
    }
}
fn s(generation: u64, ordinal: u8, bytes: &[u8]) -> Shard<'_> {
    Shard {
        generation,
        ordinal,
        bytes,
    }
}

#[test]
fn overdue_shards_share_one_assembly_turn_without_extending_the_deadline() -> Result<(), Error> {
    let path = PathId::new(0)?;
    let config = cfg(100, 10, 8);
    let mut tx = PathBatcher::new(&[config])?;
    for generation in 0..3 {
        tx.enqueue(path, us(100), Some(us(5)), s(generation, 0, b"body"))?;
    }
    assert_eq!(tx.next_wake(path)?, Some(us(5)));
    let ready = tx
        .prepare(path, us(100), None)?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(ready.deadline, us(5));
    assert_eq!(config.decode(path, ready.bytes)?.count, 3);
    let id = ready.id;
    tx.confirm(id)?;

    tx.enqueue(path, us(101), Some(us(5)), s(3, 0, b"body"))?;
    tx.enqueue(path, us(102), Some(us(5)), s(4, 0, b"body"))?;
    let ready = tx
        .prepare(path, us(102), None)?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(config.decode(path, ready.bytes)?.count, 1);
    assert_eq!(ready.deadline, us(5));
    let id = ready.id;
    tx.confirm(id)?;
    let next = tx
        .prepare(path, us(102), None)?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(config.decode(path, next.bytes)?.count, 1);
    Ok(())
}

#[test]
fn golden_generation_ordinal_and_data_sequence_match() -> Result<(), Error> {
    let p = PathId::new(2)?;
    let config = cfg(32, 300, 2);
    let shards = [s(300, 2, b"abc"), s(9, 1, b"Z")];
    let batch = config.decode(p, V1)?;
    assert_eq!(batch.sequence, 129);
    assert_eq!(batch.ack, None);
    assert_eq!(batch.entries().collect::<Vec<_>>(), shards);
    let mut tx = PathBatcher::new(&[config; 3])?;
    tx.lanes[2].next = 129;
    for v in shards {
        tx.enqueue(p, us(1), None, v)?;
    }
    let emitted = tx.prepare(p, us(2), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(emitted.bytes, V1);
    assert_eq!(emitted.deadline, us(301));
    assert_eq!(emitted.id.sequence(), 129);
    Ok(())
}

#[test]
fn unrelated_path_sends_while_full_path_retains_bytes_deadline_and_receipt() -> Result<(), Error> {
    let (a, b) = (PathId::new(0)?, PathId::new(1)?);
    let configs = [cfg(24, 9, 2), cfg(16, 2, 1)];
    let mut tx = PathBatcher::new(&configs)?;
    let backing = tx.capacity_bytes();
    tx.enqueue(a, us(1), None, s(10, 0, b"first"))?;
    assert_eq!(tx.next_wake(a)?, Some(us(10)));
    assert!(tx.prepare(a, us(7), None)?.is_none());
    tx.enqueue(a, us(8), Some(us(9)), s(11, 0, b"second"))?;
    let h = tx.prepare(a, us(8), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(h.deadline, us(9));
    let bytes = h.bytes.to_vec();
    let token = h.id;
    tx.enqueue(a, us(9), None, s(12, 0, b"third"))?;
    tx.enqueue(a, us(9), None, s(13, 0, b"fourth"))?;
    assert_eq!(
        tx.enqueue(a, us(9), None, s(14, 0, b"fifth")),
        Err(Error::Backpressure)
    );
    assert_eq!(tx.next_wake(a)?, None);
    tx.enqueue(b, us(0), None, s(20, 1, b"peer"))?;
    let other = tx.prepare(b, us(0), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(other.id.sequence(), 0);
    let btoken = other.id;
    tx.confirm(btoken)?;
    assert_eq!(tx.confirm(btoken), Err(Error::StaleReceipt));
    assert_eq!(tx.prepared_bytes(btoken), Err(Error::StaleReceipt));
    assert_eq!(tx.prepared_bytes(token)?, bytes);
    let retry = tx
        .prepare(a, us(20), Some(ACK))?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(
        (retry.id, retry.bytes, retry.deadline, retry.attached_ack),
        (token, bytes.as_slice(), us(9), None)
    );
    tx.confirm(token)?;
    let following = tx.prepare(a, us(20), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(following.id.sequence(), 1);
    assert_eq!(
        configs[0]
            .decode(a, following.bytes)?
            .entries()
            .collect::<Vec<_>>(),
        [s(12, 0, b"third"), s(13, 0, b"fourth")]
    );
    assert_eq!(following.deadline, us(18));
    let f = following.id;
    assert_eq!(tx.confirm(token), Err(Error::StaleReceipt));
    assert_eq!(tx.prepared_bytes(token), Err(Error::StaleReceipt));
    assert!(tx.prepared_bytes(f).is_ok());
    tx.confirm(f)?;
    tx.enqueue(a, us(20), None, s(14, 0, b"fifth"))?;
    assert_eq!(tx.capacity_bytes(), backing);
    Ok(())
}

#[test]
fn ack_attachment_is_transactional_and_full_data_wins() -> Result<(), Error> {
    let p = PathId::new(0)?;
    let config = cfg(15, 40, 3);
    let mut tx = PathBatcher::new(&[config])?;
    assert!(tx.prepare(p, us(0), Some(ACK))?.is_none());
    tx.enqueue(p, us(0), None, s(0, 0, b"abc"))?;
    let first = tx
        .prepare(p, us(1), Some(ACK))?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(first.bytes.len(), 15);
    assert_eq!(first.remaining_bytes, 0);
    assert_eq!(first.bytes[0], wire::DATA_ACK);
    assert_eq!(first.attached_ack, Some(ACK));
    assert_eq!(config.decode(p, first.bytes)?.ack, Some(ACK));
    let token = first.id;
    assert_eq!(
        tx.prepare(p, us(2), Some(ACK_OTHER))?
            .ok_or(Error::StaleReceipt)?
            .attached_ack,
        Some(ACK)
    );
    tx.confirm(token)?;
    tx.enqueue(p, us(3), None, s(1, 0, b"123456789"))?;
    let full = tx
        .prepare(p, us(3), Some(ACK_OTHER))?
        .ok_or(Error::StaleReceipt)?;
    assert_eq!(full.id.sequence(), 1);
    assert_eq!(full.bytes[0], 1);
    assert_eq!(full.attached_ack, None);
    assert_eq!(
        config.decode(p, full.bytes)?.entries().next(),
        Some(s(1, 0, b"123456789"))
    );
    Ok(())
}

#[test]
fn absolute_deadline_mtu_split_and_sequence_growth_preserve_fifo() -> Result<(), Error> {
    let p = PathId::new(0)?;
    let config = cfg(12, 10, 8);
    let mut tx = PathBatcher::new(&[config])?;
    tx.lanes[0].next = 127;
    // At 127 the first body consumes 11 bytes. At 128 the header grows.
    tx.enqueue(p, us(5), None, s(1, 0, b"12345"))?;
    tx.enqueue(p, us(5), Some(us(6)), s(2, 0, b"ABCD"))?;
    let one = tx.prepare(p, us(5), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!((one.id.sequence(), one.deadline), (127, us(15)));
    let id = one.id;
    tx.confirm(id)?;
    assert_eq!(tx.oldest_deadline(p)?, Some(us(6)));
    assert_eq!(tx.next_wake(p)?, Some(us(5))); // only one byte remains
    let two = tx.prepare(p, us(5), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(two.id.sequence(), 128);
    assert_eq!(two.bytes.len(), 11);
    let id = two.id;
    tx.confirm(id)?;
    assert_eq!(
        tx.enqueue(p, us(5), None, s(3, 0, b"012345")),
        Err(Error::TooLarge)
    );
    assert_eq!(
        tx.enqueue(p, us(4), None, s(3, 0, b"x")),
        Err(Error::TimeBackwards)
    );
    let mut last = PathBatcher::new(&[cfg(25, 0, 1)])?;
    last.lanes[0].next = u64::MAX - 1;
    last.enqueue(p, us(0), None, s(u64::MAX - 1, 0, b"x"))?;
    let last_id = last.prepare(p, us(0), None)?.ok_or(Error::StaleReceipt)?.id;
    assert_eq!(
        last.enqueue(p, us(0), None, s(2, 0, b"x")),
        Err(Error::Exhausted)
    );
    last.confirm(last_id)?;
    assert_eq!(
        last.enqueue(p, us(1), None, s(3, 0, b"x")),
        Err(Error::Exhausted)
    );
    Ok(())
}

#[test]
fn later_fragments_and_ack_never_extend_the_oldest_path_deadline() -> Result<(), Error> {
    let a = PathId::new(0)?;
    let b = PathId::new(1)?;
    let configs = [cfg(48, 9, 8), cfg(28, 3, 4)];
    let mut tx = PathBatcher::new(&configs)?;
    // Two already-encoded multi-frame shards. Their fragment directories and data
    // remain opaque on wire; the batch layer only interprets group and member IDs.
    let fragments = [
        s(3, 0, &[2, 14, 1, 0x41, 15, 1, 0x42]),
        s(4, 0, &[2, 16, 1, 0x43, 17, 1, 0x44]),
    ];
    tx.enqueue(a, us(1), None, fragments[0])?;
    tx.enqueue(a, us(5), Some(us(20)), fragments[1])?;
    tx.enqueue(b, us(1), None, s(9, 1, b"single"))?;
    assert_eq!(tx.ack_space(a)?, Some(26));
    assert_eq!(tx.next_wake(a)?, Some(us(10)));
    assert_eq!(tx.next_wake(b)?, Some(us(4)));
    assert!(tx.prepare(a, us(9), None)?.is_none());
    let b_id = tx.prepare(b, us(4), None)?.ok_or(Error::StaleReceipt)?.id;
    tx.confirm(b_id)?;
    let prepared = tx.prepare(a, us(10), None)?.ok_or(Error::StaleReceipt)?;
    assert_eq!(
        configs[0]
            .decode(a, prepared.bytes)?
            .entries()
            .collect::<Vec<_>>(),
        fragments
    );
    assert_eq!(prepared.deadline, us(10));
    assert_eq!(tx.ack_space(a)?, None);
    Ok(())
}

#[test]
fn malformed_truncation_noncanonical_identity_and_ack_rejected() -> Result<(), Error> {
    let p = PathId::new(2)?;
    for end in 0..V1.len() {
        assert!(Decoded::parse(p, 1500, &V1[..end]).is_err());
    }
    for invalid in [
        vec![1, 2, 0, 0],
        vec![1, 2, 128, 0, 1, 0, 2, 1],
        vec![1, 2, 0, 1, 128, 0, 2, 1],
        vec![1, 2, 0, 1, 1, 0],
        vec![1, 2, 0, 1, 1, 3, 2, 99],
        vec![1, 2, 0, 1, 1, 2, 99, 0],
        vec![2, 2, 0, 1, 1, 2, 99],
        vec![2, 2, 0, 1, 1, 2, 99, 0xa1, 0],
        [&[1, 2][..], &[0xff; 9], &[1, 1, 0, 2, 1]].concat(),
        [&[1, 2, 0, 1][..], &[0xff; 9], &[1, 2, 1]].concat(),
    ] {
        assert!(Decoded::parse(p, 1500, &invalid).is_err());
    }
    assert!(Decoded::parse(PathId::new(1)?, 1500, V1).is_err());
    assert!(Decoded::parse(p, V1.len() - 1, V1).is_err());
    assert!(cfg(64, 5, 1).decode(p, V1).is_err());
    assert!(PathId::new(255).is_err());
    assert!(PathBatcher::new(&[]).is_err());
    assert!(PathBatcher::new(&[cfg(6, 1, 1)]).is_err());
    Ok(())
}
