//! Observable runtime compatibility over the single pure native-buffer owner.
//!
//! Original internal layout/failpoint/drop regressions now live beside that
//! actual owner in l2tunnel::native_storage::tests, without a second queue.

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
fn enqueue<T>(queue: &mut Queue<T>, metadata: T, since: u64, bytes: &[u8]) -> io::Result<()> {
    queue
        .acquire()
        .ok_or(io::ErrorKind::WouldBlock)?
        .copy(metadata, since, bytes)
}

#[test]
fn adapter_plans_same_actual_packet_storage_and_constructor_categories() -> TestResult {
    let plan = Queue::<Metadata>::plan(3, 40, 17)?;
    let required =
        3 * std::mem::size_of::<Packet<Metadata>>() + 3 * std::mem::size_of::<Vec<u8>>() + 3 * 17;
    assert_eq!(plan.capacity_bytes(), required);
    let queue = Queue::with_plan(plan)?;
    assert_eq!(queue.capacity_bytes(), required);
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.bytes(), 0);
    assert!(queue.can_acquire());
    for (packets, bytes, maximum) in [
        (0, 10, 1),
        (1, 0, 1),
        (1, 10, 0),
        (1, 9, 10),
        (usize::MAX, usize::MAX, 1),
        (2, usize::MAX, usize::MAX),
    ] {
        let error = Queue::<Metadata>::new(packets, bytes, maximum)
            .err()
            .ok_or("invalid geometry unexpectedly succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    assert!(Queue::<()>::new(1, 1, 1)?.can_acquire());
    Ok(())
}

#[test]
fn adapter_preserves_conservative_byte_packet_and_fifo_boundaries() -> TestResult {
    let mut queue = Queue::<Metadata>::new(3, 10, 6)?;
    let capacity = queue.capacity_bytes();
    enqueue(&mut queue, metadata(0), 11, &[1; 4])?;
    enqueue(&mut queue, metadata(1), 22, &[2; 5])?;
    assert_eq!(queue.bytes(), 9);
    assert_eq!(queue.len(), 2);
    assert!(!queue.can_acquire());
    assert!(queue.acquire().is_none());
    let observed: Vec<_> = queue
        .iter()
        .map(|packet| (packet.metadata().record, packet.since()))
        .collect();
    assert_eq!(observed, [(0, 11), (1, 22)]);
    queue.complete_front()?;
    assert_eq!(queue.bytes(), 5);
    assert!(!queue.can_acquire());
    assert_eq!(
        queue.front().ok_or("second packet missing")?.metadata(),
        &metadata(1)
    );
    queue.complete_front()?;
    assert!(queue.can_acquire());
    assert_eq!(queue.capacity_bytes(), capacity);
    let mut queue = Queue::<Metadata>::new(2, 100, 5)?;
    enqueue(&mut queue, metadata(0), 1, &[1])?;
    enqueue(&mut queue, metadata(1), 2, &[2])?;
    assert_eq!(queue.bytes(), 2);
    assert!(queue.acquire().is_none());
    Ok(())
}

#[test]
fn adapter_observation_without_completion_retains_original_bytes_identity_and_age() -> TestResult {
    let mut queue = Queue::<Metadata>::new(2, 16, 8)?;
    let mut input = [1, 2, 3, 4];
    enqueue(&mut queue, metadata(7), 11, &input)?;
    input.fill(9);
    enqueue(&mut queue, metadata(8), 22, &[5, 6])?;
    let pointer = queue.front().ok_or("front missing")?.bytes().as_ptr();
    for _ in 0..3 {
        let front = queue.front().ok_or("front missing")?;
        assert_eq!(front.metadata(), &metadata(7));
        assert_eq!(front.since(), 11);
        assert_eq!(front.bytes(), &[1, 2, 3, 4]);
        assert_eq!(front.bytes().as_ptr(), pointer);
        assert_eq!(queue.bytes(), 6);
    }
    queue.complete_front()?;
    let front = queue.front().ok_or("second packet missing")?;
    assert_eq!(front.metadata(), &metadata(8));
    assert_eq!(front.since(), 22);
    assert_eq!(front.bytes(), &[5, 6]);
    queue.complete_front()?;
    assert!(queue.is_empty());
    assert_eq!(queue.bytes(), 0);
    Ok(())
}

#[test]
fn adapter_drop_and_copy_refusal_preserve_real_noncopy_metadata_ownership() -> TestResult {
    use std::{cell::Cell, rc::Rc};
    struct OwnedMetadata(Rc<Cell<usize>>);
    impl Drop for OwnedMetadata {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut queue = Queue::<OwnedMetadata>::new(2, 16, 8)?;
    let capacity = queue.capacity_bytes();
    drop(queue.acquire().ok_or("lease missing")?);
    for input in [&[][..], &[9; 9][..]] {
        let error = queue
            .acquire()
            .ok_or("lease missing")?
            .copy(OwnedMetadata(drops.clone()), 99, input)
            .err()
            .ok_or("invalid copy succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert_eq!(queue.capacity_bytes(), capacity);
    }
    assert_eq!(drops.get(), 2);
    enqueue(&mut queue, OwnedMetadata(drops.clone()), 1, &[1; 8])?;
    enqueue(&mut queue, OwnedMetadata(drops.clone()), 2, &[2; 8])?;
    queue.complete_front()?;
    assert_eq!(drops.get(), 3);
    drop(queue);
    assert_eq!(drops.get(), 4);
    Ok(())
}

#[test]
fn adapter_preserves_constructor_allocator_and_packet_error_categories() -> TestResult {
    for error in [
        storage::Error::Configuration,
        storage::Error::Layout,
        storage::Error::Invariant,
    ] {
        assert_eq!(
            construction_error(error).kind(),
            io::ErrorKind::InvalidInput
        );
    }
    // These test conversion only. Every real allocation-failure position and
    // accounting corruption is exercised privately beside the actual owner.
    assert_eq!(
        construction_error(storage::Error::Allocation).kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        packet_error(storage::Error::Allocation).kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        packet_error(storage::Error::Invariant).kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        packet_error(storage::Error::Configuration).kind(),
        io::ErrorKind::InvalidInput
    );
    let mut queue = Queue::<Metadata>::new(1, 8, 8)?;
    assert_eq!(
        queue.complete_front().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert!(queue.is_empty());
    assert_eq!(queue.bytes(), 0);
    assert!(queue.can_acquire());
    Ok(())
}
