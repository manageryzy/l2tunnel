//! Exact prefix-transfer checks for contiguous and physically wrapped queues.

use super::append_prefix;
use std::collections::VecDeque;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wrapped(bytes: &[u8], first: usize) -> VecDeque<u8> {
    assert!(first > 0 && first < bytes.len());
    let mut queue = VecDeque::with_capacity(bytes.len() + 8);
    let capacity = queue.capacity();
    queue.resize(capacity - first, 0xEE);
    queue.extend(&bytes[..first]);
    drop(queue.drain(..capacity - first));
    queue.extend(&bytes[first..]);
    assert_eq!(queue.as_slices().0.len(), first);
    assert!(!queue.as_slices().1.is_empty());
    assert_eq!(queue.iter().copied().collect::<Vec<_>>(), bytes);
    queue
}

#[test]
fn every_physical_prefix_preserves_destination_and_exact_queue_suffix() -> TestResult {
    let bytes = [0, 1, 2, 0, 4, 5, 6, 7, 0, 9];
    for first in [1, 4, bytes.len() - 1] {
        for count in 0..=bytes.len() {
            let mut queue = wrapped(&bytes, first);
            let mut output = vec![0xA5, 0x5A];
            append_prefix(&mut queue, count, &mut output)?;
            assert_eq!(&output[..2], &[0xA5, 0x5A]);
            assert_eq!(&output[2..], &bytes[..count]);
            assert_eq!(queue.iter().copied().collect::<Vec<_>>(), &bytes[count..]);
        }
    }
    for count in 0..=bytes.len() {
        let mut queue: VecDeque<_> = bytes.into_iter().collect();
        assert!(queue.as_slices().1.is_empty());
        let mut output = vec![0xA5, 0x5A];
        append_prefix(&mut queue, count, &mut output)?;
        assert_eq!(&output[..2], &[0xA5, 0x5A]);
        assert_eq!(&output[2..], &bytes[..count]);
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), &bytes[count..]);
    }
    let mut queue = VecDeque::new();
    let mut output = vec![0xA5];
    append_prefix(&mut queue, 0, &mut output)?;
    assert!(queue.is_empty());
    assert_eq!(output, [0xA5]);
    Ok(())
}

#[test]
fn oversized_prefix_is_atomic_even_with_reused_destination() -> TestResult {
    let bytes = [3, 1, 4, 1, 5, 9, 0];
    let mut queue = wrapped(&bytes, 3);
    let mut output = Vec::with_capacity(64);
    output.extend_from_slice(&[7, 8]);
    for count in [bytes.len() + 1, usize::MAX] {
        assert!(append_prefix(&mut queue, count, &mut output).is_err());
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), bytes);
        assert_eq!(queue.as_slices().0.len(), 3);
        assert!(!queue.as_slices().1.is_empty());
        assert_eq!(output, [7, 8]);
    }
    append_prefix(&mut queue, 4, &mut output)?;
    append_prefix(&mut queue, bytes.len() - 4, &mut output)?;
    assert_eq!(&output[..2], &[7, 8]);
    assert_eq!(&output[2..], &bytes);
    assert!(queue.is_empty());
    output.clear();
    queue.extend([10, 11]);
    append_prefix(&mut queue, 2, &mut output)?;
    assert_eq!(output, [10, 11]);
    Ok(())
}
