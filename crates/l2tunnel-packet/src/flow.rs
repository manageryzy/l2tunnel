use std::collections::BTreeMap;
use std::time::Duration;

use crate::{FlowKey, Mapping};

/// Local nonreusable flow identifier; unrelated to channel and recovery IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowId(pub u64);

/// Assigned local flow identifier and negotiated MUX channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Increasing identifier, never reused by a table.
    pub id: FlowId,
    /// Zero-based channel within the configured count.
    pub channel: u16,
}

/// Bounded flow-table parameters, fixed for one session/epoch/tenant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowTableConfig {
    /// Maximum retained identities, from one through 65536.
    pub capacity: usize,
    /// Negotiated channel count, from one through 256.
    pub channels: u16,
    /// Deterministic CRC affinity or learned connection-round-robin.
    pub mapping: Mapping,
    /// Nonzero inactivity period before an entry becomes a retirement candidate.
    pub idle_timeout: Duration,
}

/// Explicit table lifecycle and binding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowError {
    /// Invalid capacity, channel count or idle timeout.
    InvalidConfig,
    /// Retained entries fill the configured capacity; none was silently evicted.
    Capacity,
    /// The monotonic identifier space has been consumed.
    IdExhausted,
    /// Injected time moved backwards relative to the last accepted table event.
    TimeRegression,
    /// A received channel lies outside the negotiated range.
    InvalidChannel,
    /// A learned channel conflicts with existing or deterministic affinity.
    BindingConflict {
        /// Existing or CRC-selected channel.
        expected: u16,
        /// Received authenticated channel.
        received: u16,
    },
    /// The requested identity does not exist.
    UnknownFlow,
    /// The entry is not yet idle; no state was removed.
    NotIdle,
    /// Sequence inheritance requires empty tables and a never-used destination.
    NotFreshOrDrained,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "flow assignment failed: {self:?}")
    }
}

impl std::error::Error for FlowError {}

#[derive(Clone, Copy, Debug)]
struct Entry {
    binding: Binding,
    last_seen: Duration,
}

/// Count-bounded flow identities with explicit, caller-drained retirement.
///
/// This table does not know whether downstream recovery/credit/codec queues are
/// drained. The caller must establish that before any removal. `learn` requires
/// an already-authenticated peer channel; packet contents grant no authority.
#[derive(Debug)]
pub struct FlowTable {
    config: FlowTableConfig,
    entries: BTreeMap<FlowKey, Entry>,
    next_id: Option<u64>,
    next_channel: u16,
    last_now: Duration,
}

/// Exclusively borrowed assignment transaction; dropping it changes nothing.
///
/// Perform other component admission first, then commit this table infallibly.
/// The borrow prevents another assignment from invalidating the preview.
pub struct PreparedAssignment<'a> {
    table: &'a mut FlowTable,
    key: FlowKey,
    binding: Binding,
    now: Duration,
    existed: bool,
    learned: bool,
}

impl PreparedAssignment<'_> {
    /// Exact binding that commit will install or refresh.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Commit after other component admission, without another fallible check.
    pub fn commit(self) -> Binding {
        self.table.entries.insert(
            self.key,
            Entry {
                binding: self.binding,
                last_seen: self.now,
            },
        );
        if !self.existed {
            self.table.next_id = self.binding.id.0.checked_add(1);
            if !self.learned && self.table.config.mapping == Mapping::ConnectionRoundRobin {
                self.table.next_channel =
                    (self.table.next_channel + 1) % self.table.config.channels;
            }
        }
        self.table.last_now = self.now;
        self.binding
    }
}

impl FlowTable {
    /// Create an empty table; local identifiers begin at one.
    pub fn new(config: FlowTableConfig) -> Result<Self, FlowError> {
        if !(1..=65536).contains(&config.capacity)
            || !(1..=256).contains(&config.channels)
            || config.idle_timeout.is_zero()
        {
            return Err(FlowError::InvalidConfig);
        }
        Ok(Self {
            config,
            entries: BTreeMap::new(),
            next_id: Some(1),
            next_channel: 0,
            last_now: Duration::ZERO,
        })
    }

    /// Predict an assignment without consuming IDs, channel turns or timer state.
    ///
    /// A subsequent `assign` returns this binding if no mutation intervenes.
    /// This preview is not a reservation or permission for concurrent mutation.
    pub fn preview_assign(&self, key: FlowKey, now: Duration) -> Result<Binding, FlowError> {
        self.check_time(now)?;
        if let Some(entry) = self.entries.get(&key) {
            return Ok(entry.binding);
        }
        let channel = match self.config.mapping {
            Mapping::Crc32 => self.crc_channel(key),
            Mapping::ConnectionRoundRobin => self.next_channel,
        };
        self.preview_insert(channel)
    }

    /// Predict authenticated learned affinity without changing any table state.
    ///
    /// A subsequent `learn` returns this binding if no mutation intervenes.
    pub fn preview_learn(
        &self,
        key: FlowKey,
        channel: u16,
        now: Duration,
    ) -> Result<Binding, FlowError> {
        self.check_time(now)?;
        if channel >= self.config.channels {
            return Err(FlowError::InvalidChannel);
        }
        let expected = self
            .entries
            .get(&key)
            .map(|entry| entry.binding.channel)
            .or_else(|| (self.config.mapping == Mapping::Crc32).then(|| self.crc_channel(key)));
        if let Some(expected) = expected
            && channel != expected
        {
            return Err(FlowError::BindingConflict {
                expected,
                received: channel,
            });
        }
        match self.entries.get(&key) {
            Some(entry) => Ok(entry.binding),
            None => self.preview_insert(channel),
        }
    }

    /// Prepare an assignment transaction; dropping it consumes no state.
    pub fn prepare_assign(
        &mut self,
        key: FlowKey,
        now: Duration,
    ) -> Result<PreparedAssignment<'_>, FlowError> {
        let binding = self.preview_assign(key, now)?;
        let existed = self.entries.contains_key(&key);
        Ok(PreparedAssignment {
            table: self,
            key,
            binding,
            now,
            existed,
            learned: false,
        })
    }

    /// Prepare authenticated learned affinity; dropping it consumes no state.
    pub fn prepare_learn(
        &mut self,
        key: FlowKey,
        channel: u16,
        now: Duration,
    ) -> Result<PreparedAssignment<'_>, FlowError> {
        let binding = self.preview_learn(key, channel, now)?;
        let existed = self.entries.contains_key(&key);
        Ok(PreparedAssignment {
            table: self,
            key,
            binding,
            now,
            existed,
            learned: true,
        })
    }

    /// Assign or refresh local flow affinity without evicting any existing entry.
    pub fn assign(&mut self, key: FlowKey, now: Duration) -> Result<Binding, FlowError> {
        Ok(self.prepare_assign(key, now)?.commit())
    }

    /// Learn authenticated reverse affinity, rejecting simultaneous-open conflicts.
    ///
    /// Learning a new RR entry does not advance the local assignment cursor.
    pub fn learn(
        &mut self,
        key: FlowKey,
        channel: u16,
        now: Duration,
    ) -> Result<Binding, FlowError> {
        Ok(self.prepare_learn(key, channel, now)?.commit())
    }

    /// Read affinity without refreshing its idle timer.
    pub fn lookup(&self, key: &FlowKey) -> Option<Binding> {
        self.entries.get(key).map(|entry| entry.binding)
    }

    /// Number of retained flow identities, bounded by configured capacity.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no identities remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find an idle candidate without removal; downstream drain is still required.
    ///
    /// Work is one bounded scan of retained entries. Ties use canonical key order.
    pub fn oldest_idle(&self, now: Duration) -> Result<Option<(FlowKey, Binding)>, FlowError> {
        self.check_time(now)?;
        Ok(self
            .entries
            .iter()
            .filter(|(_, entry)| now - entry.last_seen >= self.config.idle_timeout)
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(key, entry)| (*key, entry.binding)))
    }

    /// Remove an idle flow only after the caller establishes all downstream drain.
    pub fn retire_idle(&mut self, key: &FlowKey, now: Duration) -> Result<Binding, FlowError> {
        self.check_time(now)?;
        let entry = self.entries.get(key).ok_or(FlowError::UnknownFlow)?;
        if now - entry.last_seen < self.config.idle_timeout {
            return Err(FlowError::NotIdle);
        }
        let binding = entry.binding;
        self.entries.remove(key);
        self.last_now = now;
        Ok(binding)
    }

    /// Explicitly remove a flow whose complete downstream state is already drained.
    pub fn remove_drained(&mut self, key: &FlowKey) -> Option<Binding> {
        self.entries.remove(key).map(|entry| entry.binding)
    }

    /// Continue a drained table's nonreusable IDs in a fresh empty table.
    ///
    /// The caller owns all downstream drain and epoch authorization. Exhaustion
    /// is inherited rather than reset; rejection leaves both tables unchanged.
    pub fn continue_ids_from(&mut self, previous: &Self) -> Result<(), FlowError> {
        if !self.entries.is_empty() || !previous.entries.is_empty() || self.next_id != Some(1) {
            return Err(FlowError::NotFreshOrDrained);
        }
        self.next_id = previous.next_id;
        self.next_channel = previous.next_channel % self.config.channels;
        self.last_now = self.last_now.max(previous.last_now);
        Ok(())
    }

    fn check_time(&self, now: Duration) -> Result<(), FlowError> {
        if now < self.last_now {
            Err(FlowError::TimeRegression)
        } else {
            Ok(())
        }
    }

    fn crc_channel(&self, key: FlowKey) -> u16 {
        (key.crc32() % u32::from(self.config.channels)) as u16
    }

    fn preview_insert(&self, channel: u16) -> Result<Binding, FlowError> {
        if self.entries.len() == self.config.capacity {
            return Err(FlowError::Capacity);
        }
        Ok(Binding {
            id: FlowId(self.next_id.ok_or(FlowError::IdExhausted)?),
            channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Domain, Tuple};

    #[test]
    fn sequence_inheritance_requires_fresh_drained_tables_and_preserves_exhaustion()
    -> Result<(), FlowError> {
        let config = FlowTableConfig {
            capacity: 2,
            channels: 3,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        };
        let key = FlowKey {
            domain: Domain::default(),
            tuple: Tuple::Ethernet(0x1234, [0; 6], [1; 6]),
        };
        let mut old = FlowTable::new(config)?;
        let mut new = FlowTable::new(FlowTableConfig {
            channels: 1,
            ..config
        })?;
        old.assign(key, Duration::from_secs(2))?;
        assert_eq!(
            new.continue_ids_from(&old),
            Err(FlowError::NotFreshOrDrained)
        );
        assert_eq!(new.preview_assign(key, Duration::ZERO)?.id, FlowId(1));
        old.remove_drained(&key);
        new.continue_ids_from(&old)?;
        assert_eq!(
            new.preview_assign(key, Duration::ZERO),
            Err(FlowError::TimeRegression)
        );
        assert_eq!(
            new.assign(key, Duration::from_secs(2))?,
            Binding {
                id: FlowId(2),
                channel: 0
            }
        );
        new.remove_drained(&key);
        assert_eq!(
            new.continue_ids_from(&old),
            Err(FlowError::NotFreshOrDrained)
        );
        assert_eq!(
            new.preview_assign(key, Duration::from_secs(2))?.id,
            FlowId(3)
        );
        old.next_id = None;
        let mut exhausted = FlowTable::new(config)?;
        exhausted.continue_ids_from(&old)?;
        assert_eq!(
            exhausted.assign(key, Duration::from_secs(2)),
            Err(FlowError::IdExhausted)
        );
        Ok(())
    }

    #[test]
    fn identifiers_never_wrap_or_reuse_after_final_id_retirement() -> Result<(), FlowError> {
        let mut table = FlowTable::new(FlowTableConfig {
            capacity: 2,
            channels: 2,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        })?;
        table.next_id = Some(u64::MAX);
        let key = FlowKey {
            domain: Domain::default(),
            tuple: Tuple::Ethernet(0x1234, [0; 6], [1; 6]),
        };
        assert_eq!(table.assign(key, Duration::ZERO)?.id, FlowId(u64::MAX));
        assert!(table.remove_drained(&key).is_some());
        assert_eq!(
            table.assign(key, Duration::ZERO),
            Err(FlowError::IdExhausted)
        );
        assert!(table.is_empty());
        Ok(())
    }

    #[test]
    fn previews_are_nonmutating_and_match_serialized_commit() -> Result<(), FlowError> {
        let mut table = FlowTable::new(FlowTableConfig {
            capacity: 1,
            channels: 3,
            mapping: Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        })?;
        let key = FlowKey {
            domain: Domain::default(),
            tuple: Tuple::Ethernet(0x1234, [0; 6], [1; 6]),
        };
        let local = table.preview_assign(key, Duration::from_secs(100))?;
        assert_eq!(
            local,
            Binding {
                id: FlowId(1),
                channel: 0
            }
        );
        assert!(table.is_empty());
        {
            let abandoned = table.prepare_assign(key, Duration::from_secs(100))?;
            assert_eq!(abandoned.binding(), local);
        }
        assert!(table.is_empty());
        let learned = table.preview_learn(key, 2, Duration::ZERO)?;
        assert_eq!(
            learned,
            Binding {
                id: FlowId(1),
                channel: 2
            }
        );
        assert_eq!(table.learn(key, 2, Duration::ZERO)?, learned);
        assert_eq!(table.preview_assign(key, Duration::ZERO)?, learned);
        assert_eq!(
            table.preview_learn(key, 1, Duration::ZERO),
            Err(FlowError::BindingConflict {
                expected: 2,
                received: 1
            })
        );
        assert_eq!(table.remove_drained(&key), Some(learned));
        assert_eq!(
            table.assign(key, Duration::ZERO)?,
            Binding {
                id: FlowId(2),
                channel: 0
            }
        );
        assert_eq!(
            table.preview_learn(key, 3, Duration::ZERO),
            Err(FlowError::InvalidChannel)
        );
        let other = FlowKey {
            domain: Domain::default(),
            tuple: Tuple::Ethernet(0x1235, [0; 6], [1; 6]),
        };
        assert_eq!(
            table.preview_assign(other, Duration::ZERO),
            Err(FlowError::Capacity)
        );
        table.remove_drained(&key);
        table.next_id = None;
        assert_eq!(
            table.preview_assign(key, Duration::ZERO),
            Err(FlowError::IdExhausted)
        );
        assert_eq!(
            table.preview_learn(key, 0, Duration::ZERO),
            Err(FlowError::IdExhausted)
        );
        assert!(table.is_empty());
        Ok(())
    }
}
