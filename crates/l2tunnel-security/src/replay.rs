use crate::REPLAY_PACKETS;

pub(crate) struct Replay {
    pub(crate) highest: Option<u64>,
    bits: [u64; (REPLAY_PACKETS / 64) as usize],
}

impl Replay {
    pub(crate) fn new() -> Self {
        Self {
            highest: None,
            bits: [0; (REPLAY_PACKETS / 64) as usize],
        }
    }
    fn slot(number: u64) -> (usize, u64) {
        let bit = number % REPLAY_PACKETS;
        ((bit / 64) as usize, 1 << (bit % 64))
    }
    pub(crate) fn fresh(&self, number: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if number > highest {
            return true;
        }
        if highest - number >= REPLAY_PACKETS {
            return false;
        }
        let (word, mask) = Self::slot(number);
        self.bits[word] & mask == 0
    }
    pub(crate) fn commit(&mut self, number: u64) {
        if self.highest.is_none_or(|highest| number > highest) {
            let first = self.highest.map_or(0, |highest| highest.saturating_add(1));
            if number - first >= REPLAY_PACKETS {
                self.bits.fill(0);
            } else {
                for skipped in first..number {
                    let (word, mask) = Self::slot(skipped);
                    self.bits[word] &= !mask;
                }
            }
            let (word, mask) = Self::slot(number);
            self.bits[word] &= !mask;
            self.highest = Some(number);
        }
        let (word, mask) = Self::slot(number);
        self.bits[word] |= mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_tracks_reordering_and_large_jumps() {
        let mut replay = Replay::new();
        assert!(replay.fresh(5));
        replay.commit(5);
        assert!(!replay.fresh(5));
        assert!(replay.fresh(3));
        replay.commit(3);
        assert!(!replay.fresh(3));
        replay.commit(5 + REPLAY_PACKETS);
        assert!(!replay.fresh(5), "number left the window");
        assert!(replay.fresh(6));
        assert!(!replay.fresh(5 + REPLAY_PACKETS));
        replay.commit(1 << 40);
        assert!(replay.fresh((1 << 40) - 1));
        assert!(!replay.fresh((1 << 40) - REPLAY_PACKETS));
        replay.commit(u64::MAX);
        assert!(!replay.fresh(u64::MAX));
        assert!(replay.fresh(u64::MAX - 1));
    }
}
