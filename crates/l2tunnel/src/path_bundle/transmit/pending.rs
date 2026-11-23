//! Bounded local custody shared by natural first flights and recovery producers.
use super::Error;

/// Usually one path owns a member. Explicit replicas can add other path owners.
#[derive(Default)]
pub(super) struct Pending {
    first: Option<(u8, u16)>,
    extra: Vec<(u8, u16)>,
}

impl Pending {
    /// Reserve bookkeeping before accepting bytes into a batch.
    pub(super) fn reserve(&mut self, path: u8) -> Result<(), Error> {
        if let Some((_, count)) = self
            .first
            .iter()
            .chain(&self.extra)
            .find(|(slot, _)| *slot == path)
        {
            count.checked_add(1).ok_or(Error::Exhausted)?;
        } else if self.first.is_some() {
            self.extra.try_reserve(1).map_err(|_| Error::Allocation)?;
        }
        Ok(())
    }

    pub(super) fn add_reserved(&mut self, path: u8) {
        if let Some((_, count)) = self
            .first
            .iter_mut()
            .chain(&mut self.extra)
            .find(|(slot, _)| *slot == path)
        {
            *count += 1;
        } else if self.first.is_none() {
            self.first = Some((path, 1));
        } else {
            self.extra.push((path, 1));
        }
    }

    pub(super) fn remove(&mut self, path: u8) {
        if let Some((slot, count)) = &mut self.first
            && *slot == path
        {
            *count -= 1;
            if *count == 0 {
                self.first = self.extra.pop();
            }
        } else if let Some(index) = self.extra.iter().position(|(slot, _)| *slot == path) {
            self.extra[index].1 -= 1;
            if self.extra[index].1 == 0 {
                self.extra.swap_remove(index);
            }
        }
    }

    pub(super) fn paths(&self) -> Option<[u64; 4]> {
        self.first?;
        let mut paths = [0; 4];
        for &(path, _) in self.first.iter().chain(&self.extra) {
            paths[usize::from(path / 64)] |= 1 << (path % 64);
        }
        Some(paths)
    }
}
