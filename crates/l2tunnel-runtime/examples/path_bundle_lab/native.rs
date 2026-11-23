use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

use super::{Receiver, Result};

mod ack;
#[cfg(test)]
mod ack_tests;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Independent,
    Ordered,
    OrderedTcpData,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Handoff {
    Empty,
    WaitingForPrefix,
    WaitingForPathReady,
    WouldBlock,
    Written {
        group: u64,
        ready_us: u64,
        len: usize,
    },
}

/// The receiver retains packet bytes and reports readiness once within its group window.
pub(super) enum Queue {
    Independent(VecDeque<(u64, u64)>),
    Ordered {
        ready: BTreeMap<u64, u64>,
        acks: Option<BTreeSet<u64>>,
    },
}

impl Queue {
    pub(super) fn new(mode: Mode) -> Self {
        match mode {
            Mode::Independent => Self::Independent(VecDeque::new()),
            Mode::Ordered | Mode::OrderedTcpData => Self::Ordered {
                ready: BTreeMap::new(),
                acks: (mode == Mode::OrderedTcpData).then(BTreeSet::new),
            },
        }
    }

    pub(super) fn mode(&self) -> Mode {
        match self {
            Self::Independent(_) => Mode::Independent,
            Self::Ordered { acks: None, .. } => Mode::Ordered,
            Self::Ordered { acks: Some(_), .. } => Mode::OrderedTcpData,
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Independent(queue) => queue.len(),
            Self::Ordered { ready, .. } => ready.len(),
        }
    }

    pub(super) fn push(&mut self, group: u64, ready_us: u64, rx: &Receiver) -> Result<()> {
        match self {
            Self::Independent(queue) => queue.push_back((group, ready_us)),
            Self::Ordered { ready, acks } => {
                if let Some(acks) = acks {
                    let bytes = rx
                        .ready(group)
                        .ok_or("missing ready group for ACK inspection")?;
                    if ack::eligible(bytes) {
                        acks.insert(group);
                    }
                }
                ready.entry(group).or_insert(ready_us);
            }
        }
        Ok(())
    }

    pub(super) fn next(&self, prefix: u64) -> Option<(u64, u64)> {
        match self {
            Self::Independent(queue) => queue.front().copied(),
            Self::Ordered { ready, acks } => {
                let group = if ready.contains_key(&prefix) {
                    prefix
                } else {
                    *acks.as_ref()?.first()?
                };
                ready.get(&group).map(|&at| (group, at))
            }
        }
    }

    pub(super) fn write_after_setup(
        &mut self,
        setup: Option<&super::readiness::State>,
        rx: &mut Receiver,
        write: impl FnOnce(u64, &[u8]) -> io::Result<()>,
    ) -> Result<Handoff> {
        if setup.is_some_and(|state| !state.ready()) {
            return Ok(Handoff::WaitingForPathReady);
        }
        self.write_next(rx, write)
    }

    pub(super) fn write_next(
        &mut self,
        rx: &mut Receiver,
        write: impl FnOnce(u64, &[u8]) -> io::Result<()>,
    ) -> Result<Handoff> {
        let Some((group, ready_us)) = self.next(rx.confirmed_prefix()) else {
            return Ok(if self.len() == 0 {
                Handoff::Empty
            } else {
                Handoff::WaitingForPrefix
            });
        };
        let packet = rx.ready(group).ok_or("ready native disappeared")?;
        let len = packet.len();
        match write(group, packet) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(Handoff::WouldBlock);
            }
            Err(error) => return Err(error.into()),
        }
        if !rx.commit(group)? {
            return Err("native packet was already committed".into());
        }
        match self {
            Self::Independent(queue) => {
                let removed = queue.pop_front();
                debug_assert_eq!(removed.map(|(id, _)| id), Some(group));
            }
            Self::Ordered { ready, acks } => {
                let removed = ready.remove(&group);
                debug_assert!(removed.is_some());
                if let Some(acks) = acks {
                    acks.remove(&group);
                }
            }
        }
        Ok(Handoff::Written {
            group,
            ready_us,
            len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_fec::path_shards::Profile;
    use l2tunnel_fec::{ChannelId, Direction, Epoch, FecContext, SessionId};
    use l2tunnel_pipeline::path_batch::Shard;

    const DOMAIN: FecContext = FecContext {
        session: SessionId([7; 16]),
        epoch: Epoch(42),
        channel: ChannelId(0),
        direction: Direction::ClientToServer,
    };

    fn receive(group: u64, now: u64, rx: &mut Receiver, queue: &mut Queue) -> Result<()> {
        let shards = Profile::new(3, 2, 1500, 1000)?.encode(&group.to_be_bytes())?;
        for index in [2, 0, 0] {
            let shard = Shard {
                generation: group,
                ordinal: index,
                bytes: &shards[usize::from(index)],
            };
            if rx.accept(DOMAIN, shard)? {
                queue.push(group, now, rx)?;
            }
        }
        Ok(())
    }

    #[test]
    fn authenticated_early_data_keeps_native_custody_until_every_path_proof_and_actual_write()
    -> Result<()> {
        use crate::endpoint::readiness::{ECHO, State};
        let mut rx = Receiver::new(DOMAIN, 3, 2, 1500, 1000, 8)?;
        let mut queue = Queue::new(Mode::Ordered);
        let mut setup = State::new(vec![[1; 16], [2; 16], [3; 16]], 0)?;
        receive(0, 3, &mut rx, &mut queue)?;
        for slot in 0..3 {
            assert_eq!(
                queue.write_after_setup(Some(&setup), &mut rx, |_, _| {
                    Err(io::Error::other("unverified native write"))
                })?,
                Handoff::WaitingForPathReady
            );
            assert_eq!(rx.confirmed_prefix(), 0);
            assert_eq!(rx.ready(0), Some(&0_u64.to_be_bytes()[..]));
            let t = 10 + 3 * u64::from(slot);
            let msg = setup.due(slot, t)?.ok_or("missing initial path request")?;
            setup.paid(slot, msg, t)?;
            let mut echo = msg.encode();
            echo[0] = ECHO;
            setup.receive_authenticated(slot, &echo, t + 1)?;
        }
        assert_eq!(
            queue.write_after_setup(Some(&setup), &mut rx, |_, _| Err(
                io::ErrorKind::WouldBlock.into()
            ))?,
            Handoff::WouldBlock
        );
        assert_eq!(rx.confirmed_prefix(), 0);
        let receipt = queue.write_after_setup(Some(&setup), &mut rx, |gid, bytes| {
            assert_eq!((gid, bytes), (0, &0_u64.to_be_bytes()[..]));
            Ok(())
        })?;
        assert!(matches!(receipt, Handoff::Written { group: 0, .. }));
        assert_eq!(rx.confirmed_prefix(), 1);
        assert_eq!(queue.len(), 0);
        Ok(())
    }

    #[test]
    fn ordered_late_gap_and_blocked_write_keep_logical_custody() -> Result<()> {
        let mut rx = Receiver::new(DOMAIN, 3, 2, 1500, 1000, 8)?;
        let mut queue = Queue::new(Mode::Ordered);
        receive(2, 10, &mut rx, &mut queue)?;
        receive(1, 15, &mut rx, &mut queue)?;
        assert!(queue.next(rx.confirmed_prefix()).is_none());
        assert_eq!(
            queue.write_next(&mut rx, |_, _| panic!("cannot write past the gap"))?,
            Handoff::WaitingForPrefix
        );
        receive(0, 90, &mut rx, &mut queue)?;
        assert_eq!(
            queue.write_next(&mut rx, |_, _| Err(io::ErrorKind::WouldBlock.into()))?,
            Handoff::WouldBlock
        );
        assert_eq!(queue.len(), 3);
        assert_eq!(rx.confirmed_prefix(), 0);
        assert_eq!(rx.ready(0), Some(&0_u64.to_be_bytes()[..]));
        for (expected, at) in [(0_u64, 90), (1, 15), (2, 10)] {
            let written = queue.write_next(&mut rx, |group, packet| {
                assert_eq!(group, expected);
                assert_eq!(packet, expected.to_be_bytes());
                Ok(())
            })?;
            assert_eq!(
                written,
                Handoff::Written {
                    group: expected,
                    ready_us: at,
                    len: 8
                }
            );
            assert_eq!(rx.confirmed_prefix(), expected + 1);
        }
        assert_eq!(queue.len(), 0);
        Ok(())
    }

    #[test]
    fn independent_handoff_keeps_a_completed_later_group_eligible() -> Result<()> {
        let mut rx = Receiver::new(DOMAIN, 3, 2, 1500, 1000, 8)?;
        let mut queue = Queue::new(Mode::Independent);
        receive(1, 5, &mut rx, &mut queue)?;
        assert_eq!(queue.next(0), Some((1, 5)));
        assert!(matches!(
            queue.write_next(&mut rx, |_, _| Ok(()))?,
            Handoff::Written { group: 1, .. }
        ));
        assert_eq!(rx.confirmed_prefix(), 0);
        receive(0, 20, &mut rx, &mut queue)?;
        assert!(matches!(
            queue.write_next(&mut rx, |_, _| Ok(()))?,
            Handoff::Written { group: 0, .. }
        ));
        assert_eq!(rx.confirmed_prefix(), 2);
        Ok(())
    }
}
