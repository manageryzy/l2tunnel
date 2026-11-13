//! Bounded byte-prefix transfer from the deque's existing physical slices.

use crate::Error;
use std::collections::VecDeque;

/// Append exactly `count` bytes and retain the remaining queue in order.
/// Validate before mutation; neither make the queue contiguous nor copy history.
#[inline]
pub(crate) fn append_prefix(
    queue: &mut VecDeque<u8>,
    count: usize,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if count > queue.len() {
        return Err(Error::Malformed);
    }
    // Reserve the admitted prefix once, even when it spans both slices.
    output.reserve(count);
    let (front, back) = queue.as_slices();
    let first = count.min(front.len());
    output.extend_from_slice(&front[..first]);
    output.extend_from_slice(&back[..count - first]);
    drop(queue.drain(..count));
    Ok(())
}

#[cfg(test)]
#[path = "byte_queue_tests.rs"]
mod tests;
