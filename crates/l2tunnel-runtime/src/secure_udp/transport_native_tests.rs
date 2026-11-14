//! Fixed native FIFO capacity, ownership and deterministic allocation failures.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Metadata {
    session: [u8; 16],
    scope: u64,
    channel: u8,
    record: u64,
}

fn metadata(record: u64) -> Metadata {
    Metadata {
        session: [17; 16],
        scope: 91,
        channel: 3,
        record,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Storage {
    ready: (usize, usize),
    free: (usize, usize),
    payloads: Vec<(usize, usize)>,
    capacity_bytes: usize,
}

fn storage<T>(queue: &Queue<T>) -> Storage {
    let mut payloads: Vec<_> = queue
        .free
        .iter()
        .chain(queue.ready.iter().map(|packet| &packet.payload))
        .map(|payload| (payload.as_ptr() as usize, payload.capacity()))
        .collect();
    payloads.sort_unstable();
    Storage {
        // A deque's head moves as the FIFO wraps. Exact retained capacity is
        // stable; its first slice pointer is deliberately not an identity.
        ready: (queue.ready.capacity(), queue.packets),
        free: (queue.free.as_ptr() as usize, queue.free.capacity()),
        payloads,
        capacity_bytes: queue.capacity_bytes(),
    }
}

fn enqueue<T>(queue: &mut Queue<T>, metadata: T, since: u64, input: &[u8]) -> io::Result<()> {
    queue
        .acquire()
        .ok_or(io::ErrorKind::WouldBlock)?
        .copy(metadata, since, input)
}

#[test]
fn exact_requested_layout_includes_all_empty_pool_buffers() -> TestResult {
    let queue = Queue::<Metadata>::new(3, 40, 17)?;
    let expected = 3 * size_of::<Packet<Metadata>>() + 3 * size_of::<Vec<u8>>() + 3 * 17;
    assert_eq!(queue.capacity_bytes(), expected);
    assert!(queue.is_empty());
    assert_eq!(queue.bytes(), 0);
    assert_eq!(queue.ready.capacity(), 3);
    assert_eq!(queue.free.capacity(), 3);
    assert_eq!(queue.free.len(), 3);
    assert!(
        queue
            .free
            .iter()
            .all(|buffer| buffer.is_empty() && buffer.capacity() == 17)
    );
    assert!(queue.can_acquire());
    // Logical payload admission and provisioned maximum-sized storage differ.
    assert!(3 * 17 > queue.limit);
    Ok(())
}

#[test]
fn every_real_allocation_failure_position_refuses_partial_publication() -> TestResult {
    let packets = 4;
    let attempts = packets + 2;
    for fail_at in 1..=attempts {
        let mut allocation = Allocation {
            attempts: 0,
            fail_at: Some(fail_at),
        };
        let error = Queue::<Metadata>::allocate(packets, 50, 11, &mut allocation)
            .err()
            .ok_or("injected allocation unexpectedly succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(allocation.attempts, fail_at);
    }
    let mut allocation = Allocation {
        attempts: 0,
        fail_at: Some(attempts + 1),
    };
    let queue = Queue::<Metadata>::allocate(packets, 50, 11, &mut allocation)?;
    assert_eq!(allocation.attempts, attempts);
    assert_eq!(queue.free.len(), packets);
    assert_eq!(queue.ready.len(), 0);
    Ok(())
}

#[test]
fn invalid_and_overflowing_layouts_fail_before_any_allocation() -> TestResult {
    for (packets, bytes, maximum) in [
        (0, 10, 1),
        (1, 0, 1),
        (1, 10, 0),
        (1, 9, 10),
        (usize::MAX, usize::MAX, 1),
        (2, usize::MAX, usize::MAX),
    ] {
        let mut allocation = Allocation::default();
        let error = Queue::<Metadata>::allocate(packets, bytes, maximum, &mut allocation)
            .err()
            .ok_or("invalid geometry unexpectedly succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(allocation.attempts, 0);
    }
    // Empty user metadata is legal: packet headers still have nonzero layout.
    let queue = Queue::<()>::new(1, 1, 1)?;
    assert!(queue.can_acquire());
    Ok(())
}

#[test]
fn packet_and_conservative_byte_ceilings_remain_independent() -> TestResult {
    let mut queue = Queue::<Metadata>::new(3, 10, 6)?;
    enqueue(&mut queue, metadata(0), 10, &[1; 4])?;
    assert!(queue.can_acquire());
    enqueue(&mut queue, metadata(1), 20, &[2; 5])?;
    assert_eq!(queue.bytes(), 9);
    assert_eq!(queue.len(), 2);
    // A one-byte packet could fit, but old admission reserves a full maximum.
    assert!(!queue.can_acquire());
    assert!(queue.acquire().is_none());
    queue.complete_front()?;
    assert_eq!(queue.bytes(), 5);
    assert!(!queue.can_acquire());
    queue.complete_front()?;
    assert!(queue.can_acquire());
    let mut packets = Queue::<Metadata>::new(2, 100, 5)?;
    enqueue(&mut packets, metadata(0), 1, &[1])?;
    enqueue(&mut packets, metadata(1), 2, &[2])?;
    assert_eq!(packets.bytes(), 2);
    assert!(!packets.can_acquire());
    assert!(packets.acquire().is_none());
    Ok(())
}

#[test]
fn empty_or_oversized_copy_refuses_atomically_and_returns_buffer() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 20, 8)?;
    let original = storage(&queue);
    for input in [&[][..], &[9; 9][..]] {
        let lease = queue.acquire().ok_or("lease unavailable")?;
        let error = lease
            .copy(metadata(99), 999, input)
            .err()
            .ok_or("bad copy succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert_eq!(storage(&queue), original);
    }
    enqueue(&mut queue, metadata(0), 1, &[4; 8])?;
    assert_eq!(queue.len(), 1);
    Ok(())
}

fn extraction(queue: &mut Queue<Metadata>, result: io::Result<Option<&[u8]>>) -> io::Result<()> {
    let lease = queue.acquire().ok_or(io::ErrorKind::WouldBlock)?;
    let Some(input) = result? else {
        return Ok(());
    };
    lease.copy(metadata(0), 42, input)
}

#[test]
fn lease_drop_none_and_extraction_error_all_restore_the_same_pool() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 32, 16)?;
    let original = storage(&queue);
    drop(queue.acquire().ok_or("lease unavailable")?);
    assert_eq!(storage(&queue), original);
    extraction(&mut queue, Ok(None))?;
    assert_eq!(storage(&queue), original);
    let error = extraction(&mut queue, Err(io::ErrorKind::InvalidData.into()))
        .err()
        .ok_or("extraction error disappeared")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(storage(&queue), original);
    assert_eq!(queue.bytes(), 0);
    extraction(&mut queue, Ok(Some(&[1, 2, 3])))?;
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.bytes(), 3);
    Ok(())
}

#[test]
fn fifo_owns_exact_metadata_bytes_and_original_age_until_completion() -> TestResult {
    let mut queue = Queue::<Metadata>::new(3, 48, 16)?;
    let mut source = [1, 2, 3, 4];
    enqueue(&mut queue, metadata(7), 11, &source)?;
    source.fill(9);
    let mut other = metadata(8);
    other.scope = 92;
    other.channel = 5;
    enqueue(&mut queue, other, 22, &[5, 6])?;
    for _ in 0..3 {
        // Simulated no-completion/EAGAIN: observing the front changes nothing.
        let front = queue.front().ok_or("missing front")?;
        assert_eq!(front.metadata(), &metadata(7));
        assert_eq!(front.since(), 11);
        assert_eq!(front.bytes(), &[1, 2, 3, 4]);
        assert_eq!(queue.bytes(), 6);
    }
    queue.complete_front()?;
    let front = queue.front().ok_or("missing second packet")?;
    assert_eq!(front.metadata(), &other);
    assert_eq!(front.since(), 22);
    assert_eq!(front.bytes(), &[5, 6]);
    assert_eq!(queue.bytes(), 2);
    queue.complete_front()?;
    assert!(queue.front().is_none());
    assert!(queue.is_empty());
    assert_eq!(queue.bytes(), 0);
    Ok(())
}

#[test]
fn repeated_fifo_wrap_and_recycling_preserve_every_payload_allocation() -> TestResult {
    let mut queue = Queue::<Metadata>::new(4, 68, 17)?;
    let original = storage(&queue);
    let mut record = 0;
    for round in 0..128u64 {
        for length in [1, 17, 8, 13] {
            enqueue(
                &mut queue,
                metadata(record),
                round * 10,
                &vec![record as u8; length],
            )?;
            record += 1;
            assert_eq!(storage(&queue), original);
        }
        assert!(!queue.can_acquire());
        for expected in record - 4..record {
            let front = queue.front().ok_or("FIFO lost packet")?;
            assert_eq!(front.metadata().record, expected);
            assert_eq!(front.since(), round * 10);
            queue.complete_front()?;
            assert_eq!(storage(&queue), original);
        }
        assert_eq!(queue.bytes(), 0);
    }
    Ok(())
}

#[test]
fn completion_accounting_refusal_precedes_any_fifo_or_pool_mutation() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 16, 8)?;
    let empty = storage(&queue);
    assert_eq!(
        queue.complete_front().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(storage(&queue), empty);
    enqueue(&mut queue, metadata(0), 77, &[4; 8])?;
    let occupied = storage(&queue);
    // Trusted-local corruption seam, never an authenticated peer packet.
    queue.bytes = 7;
    assert_eq!(
        queue.complete_front().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.bytes(), 7);
    let front = queue.front().ok_or("refusal removed packet")?;
    assert_eq!(front.metadata(), &metadata(0));
    assert_eq!(front.since(), 77);
    assert_eq!(front.bytes(), &[4; 8]);
    assert_eq!(storage(&queue), occupied);
    queue.bytes = 8;
    queue.complete_front()?;
    assert_eq!(storage(&queue), empty);
    assert_eq!(queue.bytes(), 0);
    Ok(())
}
