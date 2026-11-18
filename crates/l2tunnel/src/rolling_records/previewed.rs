//! Sources whose aligned units the targeted receiver has already admitted.
use super::*;

#[derive(Clone, Copy, Default)]
struct Block {
    number: u32,
    seen: u64,
}

pub(super) struct Previewed(Vec<Block>);

impl Previewed {
    fn count<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        if direction.scheduler.targeted() {
            direction.scheduler.recovery().window.div_ceil(64)
        } else {
            0
        }
    }

    pub(super) fn planned_bytes<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        Self::count(direction) * std::mem::size_of::<Block>()
    }

    pub(super) fn new<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> Result<Self, Error> {
        let count = Self::count(direction);
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        blocks.resize(count, Block::default());
        Ok(Self(blocks))
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.0.capacity() * std::mem::size_of::<Block>()
    }

    // An absolute block tag prevents aliases when an older hole and a newer
    // partial block share a slot. Replacement can only cause another scan.
    pub(super) fn mark(&mut self, source: u32) {
        let len = self.0.len();
        if len == 0 {
            return;
        }
        let number = source / 64;
        let block = &mut self.0[number as usize % len];
        if block.number != number {
            *block = Block { number, seen: 0 };
        }
        block.seen |= 1 << (source % 64);
    }

    pub(super) fn skip(&self, start: u32, end: u32) -> u32 {
        if self.0.is_empty() {
            return start;
        }
        let number = start / 64;
        let block = self.0[number as usize % self.0.len()];
        if block.number != number {
            return start;
        }
        let known = (block.seen >> (start % 64)).trailing_ones();
        start + known.min(end - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_skip_preserves_holes_and_absolute_ids_across_wrap() {
        let mut cache = Previewed(vec![Block::default(); 2]);
        for id in [1, 2, 4, 5, 62, 63, 64, 65] {
            cache.mark(id);
        }
        assert_eq!(cache.skip(0, 200), 0);
        assert_eq!(cache.skip(1, 200), 3);
        assert_eq!(cache.skip(4, 5), 5);
        assert_eq!(cache.skip(62, 200), 64);
        assert_eq!(cache.skip(64, 200), 66);
        assert_eq!(cache.skip(129, 200), 129);
        cache.mark(129);
        assert_eq!(cache.skip(1, 200), 1);
        assert_eq!(cache.skip(129, 200), 130);
        cache.mark(u32::MAX - 1);
        assert_eq!(cache.skip(u32::MAX - 1, u32::MAX), u32::MAX);
    }
}
