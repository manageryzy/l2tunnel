//! Actual native FIFO capacity, ownership and deterministic allocation failures.

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

fn enqueue<T>(queue: &mut Queue<T>, metadata: T, since: u64, input: &[u8]) -> Result<(), Error> {
    queue
        .acquire()
        .ok_or(Error::Invariant)?
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
        assert_eq!(error, Error::Allocation);
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
        assert!(matches!(error, Error::Configuration | Error::Layout));
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
        assert_eq!(error, Error::Configuration);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert_eq!(storage(&queue), original);
    }
    enqueue(&mut queue, metadata(0), 1, &[4; 8])?;
    assert_eq!(queue.len(), 1);
    Ok(())
}

fn extraction(
    queue: &mut Queue<Metadata>,
    result: Result<Option<&[u8]>, Error>,
) -> Result<(), Error> {
    let lease = queue.acquire().ok_or(Error::Invariant)?;
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
    let error = extraction(&mut queue, Err(Error::Invariant))
        .err()
        .ok_or("extraction error disappeared")?;
    assert_eq!(error, Error::Invariant);
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
    let plan = Queue::<Metadata>::plan(4, 68, 17)?;
    let expected_capacity = plan.capacity_bytes();
    let mut queue = Queue::<Metadata>::with_plan(plan)?;
    assert_eq!(queue.capacity_bytes(), expected_capacity);
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
fn typed_plan_provisions_real_metadata_owners_and_drops_each_exactly_once() -> TestResult {
    use std::{cell::Cell, rc::Rc};
    struct OwnedMetadata(Rc<Cell<usize>>);
    impl Drop for OwnedMetadata {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let plan = Queue::<OwnedMetadata>::plan(2, 8, 4)?;
    let planned = plan.capacity_bytes();
    let mut queue = Queue::with_plan(plan)?;
    let original = storage(&queue);
    assert_eq!(queue.capacity_bytes(), planned);
    let actual_layout = queue.ready.capacity() * size_of::<Packet<OwnedMetadata>>()
        + queue.free.capacity() * size_of::<Vec<u8>>()
        + queue.free.iter().map(Vec::capacity).sum::<usize>();
    assert_eq!(planned, actual_layout);
    enqueue(&mut queue, OwnedMetadata(drops.clone()), 1, &[1; 4])?;
    enqueue(&mut queue, OwnedMetadata(drops.clone()), 2, &[2; 4])?;
    assert_eq!(drops.get(), 0);
    queue.complete_front()?;
    assert_eq!(drops.get(), 1);
    assert_eq!(
        queue
            .acquire()
            .ok_or("missing returned actual slot")?
            .copy(OwnedMetadata(drops.clone()), 3, &[3; 5])
            .err(),
        Some(Error::Configuration)
    );
    assert_eq!(drops.get(), 2);
    assert_eq!(storage(&queue), original);
    assert_eq!(
        queue.front().ok_or("refusal lost earlier packet")?.bytes(),
        &[2; 4]
    );
    drop(queue);
    assert_eq!(drops.get(), 3);
    Ok(())
}

#[test]
fn completion_accounting_refusal_precedes_any_fifo_or_pool_mutation() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 16, 8)?;
    let empty = storage(&queue);
    assert_eq!(queue.complete_front().err(), Some(Error::Invariant));
    assert_eq!(storage(&queue), empty);
    enqueue(&mut queue, metadata(0), 77, &[4; 8])?;
    let occupied = storage(&queue);
    // Trusted-local corruption seam, never an authenticated peer packet.
    queue.bytes = 7;
    assert_eq!(queue.complete_front().err(), Some(Error::Invariant));
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

#[test]
fn complete_plan_limit_precedes_every_real_reservation_and_usage_is_observed() -> TestResult {
    let config = Config {
        packets: 3,
        bytes: 19,
        max_native: 11,
    };
    let plan = Plan::<Metadata>::for_queue(config)?;
    assert_eq!(plan.config(), config);
    let required = plan.capacity_bytes();
    let mut allocation = Allocation::default();
    assert_eq!(
        Queue::<Metadata>::allocate_plan(
            plan,
            Limits {
                capacity_bytes: required - 1
            },
            &mut allocation
        )
        .err(),
        Some(Error::Limit {
            required,
            limit: required - 1
        })
    );
    assert_eq!(allocation.attempts, 0);
    let plan = Plan::<Metadata>::for_queue(config)?;
    let queue = Queue::allocate_plan(
        plan,
        Limits {
            capacity_bytes: required + 7,
        },
        &mut allocation,
    )?;
    assert_eq!(
        queue.storage_usage(),
        Usage {
            limit_bytes: required + 7,
            capacity_bytes: required,
            allocations: config.packets + 2,
        }
    );
    assert_eq!(allocation.attempts, config.packets + 2);
    let original = storage(&queue);
    assert_eq!(original.capacity_bytes, required);
    assert_eq!(original.payloads.len(), config.packets);
    Ok(())
}

#[test]
fn initialized_output_publishes_same_actual_buffer_and_exact_prefix() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 32, 16)?;
    let original = storage(&queue);
    let mut lease = queue.acquire().ok_or("lease unavailable")?;
    let pointer = {
        let output = lease.output()?;
        assert_eq!(output, &[0; 16]);
        output[..7].copy_from_slice(&[3, 1, 4, 1, 5, 9, 2]);
        output.as_ptr()
    };
    lease.publish(metadata(37), 61, 7)?;
    let packet = queue.front().ok_or("publication missing")?;
    assert_eq!(packet.bytes(), &[3, 1, 4, 1, 5, 9, 2]);
    assert_eq!(packet.bytes().as_ptr(), pointer);
    assert_eq!(packet.metadata(), &metadata(37));
    assert_eq!(packet.since(), 61);
    assert_eq!(queue.bytes(), 7);
    assert_eq!(queue.len(), 1);
    assert_eq!(storage(&queue), original);
    let observed: Vec<_> = queue
        .iter()
        .map(|packet| (packet.metadata().record, packet.since(), packet.bytes()))
        .collect();
    assert_eq!(observed, [(37, 61, &[3, 1, 4, 1, 5, 9, 2][..])]);
    queue.complete_front()?;
    assert_eq!(storage(&queue), original);
    // Recycling clears initialized length and the next lease initializes all M.
    let mut lease = queue.acquire().ok_or("returned buffer unavailable")?;
    assert_eq!(lease.output()?, &[0; 16]);
    Ok(())
}

#[test]
fn invalid_publication_without_initialization_or_beyond_prefix_recycles_exact_pool() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 16, 8)?;
    let original = storage(&queue);
    for length in [0, 1, 9] {
        assert_eq!(
            queue
                .acquire()
                .ok_or("lease unavailable")?
                .publish(metadata(0), 1, length),
            Err(Error::Configuration)
        );
        assert_eq!(storage(&queue), original);
        assert!(queue.is_empty());
    }
    for length in [0, 9] {
        let mut lease = queue.acquire().ok_or("lease unavailable")?;
        lease.output()?.fill(7);
        assert_eq!(
            lease.publish(metadata(0), 1, length),
            Err(Error::Configuration)
        );
        assert_eq!(storage(&queue), original);
        assert_eq!(queue.bytes(), 0);
    }
    let mut lease = queue.acquire().ok_or("lease unavailable")?;
    lease.output()?.fill(8);
    drop(lease);
    assert_eq!(storage(&queue), original);
    assert_eq!(queue.bytes(), 0);
    // The compatibility copy path cannot accidentally publish initialized zeros.
    let mut lease = queue.acquire().ok_or("lease unavailable")?;
    lease.output()?;
    assert_eq!(lease.copy(metadata(0), 1, &[1]), Err(Error::Invariant));
    assert_eq!(storage(&queue), original);
    Ok(())
}

#[test]
fn publication_preflight_refusal_retains_existing_fifo_and_drops_new_metadata_once() -> TestResult {
    use std::{cell::Cell, rc::Rc};
    struct OwnedMetadata(Rc<Cell<usize>>);
    impl Drop for OwnedMetadata {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut queue = Queue::<OwnedMetadata>::new(2, 16, 8)?;
    let original = storage(&queue);
    enqueue(&mut queue, OwnedMetadata(drops.clone()), 11, &[1; 4])?;
    let mut lease = queue.acquire().ok_or("lease unavailable")?;
    lease.output()?.fill(2);
    // Internal accounting corruption exercises the real publication preflight.
    lease.queue.bytes = 15;
    assert_eq!(
        lease.publish(OwnedMetadata(drops.clone()), 22, 2),
        Err(Error::Invariant)
    );
    assert_eq!(drops.get(), 1);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.front().ok_or("prior packet lost")?.bytes(), &[1; 4]);
    assert_eq!(queue.front().ok_or("prior age lost")?.since(), 11);
    assert_eq!(storage(&queue), original);
    queue.bytes = 4;
    queue.complete_front()?;
    assert_eq!(drops.get(), 2);
    assert_eq!(storage(&queue), original);
    Ok(())
}
