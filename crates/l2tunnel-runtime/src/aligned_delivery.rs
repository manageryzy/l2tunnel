//! Exact sender-owned native identities, separate from local packet queues.
use super::*;
use l2tunnel_flow_control::{delivery_window, target::Micros};
use std::mem::size_of;
use tokio::{io::AsyncWrite, time::timeout};

#[derive(Clone, Copy)]
struct Native {
    identity: protocol::RecordIdentity,
    ordinal: u64,
    admitted_at: Micros,
    parts: usize,
    sent: usize,
    latest_send: Micros,
}
/// Metadata includes the complete retained ordinal span and every original
/// fragment bit. Neither an early ACK nor a later completion reclaims a hole.
fn metadata(
    config: delivery_window::Config,
    channels: usize,
    fragments: usize,
) -> io::Result<usize> {
    let words = fragments.div_ceil(64);
    config
        .metadata_bytes()
        .map_err(io::Error::other)?
        .checked_add(
            config
                .max_records
                .checked_mul(
                    size_of::<Option<Native>>()
                        .checked_add(
                            words
                                .checked_mul(8)
                                .ok_or_else(|| invalid("aligned fragment metadata"))?,
                        )
                        .ok_or_else(|| invalid("aligned native metadata"))?,
                )
                .ok_or_else(|| invalid("aligned native metadata"))?,
        )
        .and_then(|n| n.checked_add(channels.checked_mul(size_of::<Option<u64>>())?))
        .ok_or_else(|| invalid("aligned delivery metadata overflow"))
}
pub(super) fn validate(config: Config) -> io::Result<()> {
    for policy in [config.delivery.forward, config.delivery.reverse] {
        if metadata(
            policy,
            usize::from(config.pipeline.flows.channels),
            config.protocol.receiver.max_fragments_per_record,
        )? > policy.metadata_limit_bytes
        {
            return Err(invalid(
                "aligned delivery metadata excludes native identities or fragments",
            ));
        }
    }
    Ok(())
}
pub(super) fn since(origin: Instant, at: Instant) -> io::Result<Duration> {
    at.checked_duration_since(origin)
        .ok_or_else(|| invalid("aligned event precedes actor origin"))
}
pub(super) fn micros(at: Duration) -> io::Result<Micros> {
    Ok(Micros(
        u64::try_from(at.as_micros()).map_err(io::Error::other)?,
    ))
}
pub(super) struct Flight {
    pub controller: delivery_window::Controller,
    entries: Vec<Option<Native>>,
    bits: Vec<u64>,
    words: usize,
    fragments: usize,
    retired: Vec<Option<u64>>,
    retired_ordinal: u64,
}
impl Flight {
    pub fn new(
        policy: delivery_window::Config,
        channels: usize,
        fragments: usize,
    ) -> io::Result<Self> {
        if metadata(policy, channels, fragments)? > policy.metadata_limit_bytes {
            return Err(invalid("aligned native metadata capacity"));
        }
        let words = fragments.div_ceil(64);
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(policy.max_records)
            .map_err(io::Error::other)?;
        entries.resize(policy.max_records, None);
        let count = policy
            .max_records
            .checked_mul(words)
            .ok_or_else(|| invalid("aligned bitmap capacity"))?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(count).map_err(io::Error::other)?;
        bits.resize(count, 0);
        Ok(Self {
            controller: delivery_window::Controller::new(policy, Micros(0))
                .map_err(io::Error::other)?,
            entries,
            bits,
            words,
            fragments,
            retired: vec![None; channels],
            retired_ordinal: 0,
        })
    }
    pub fn preview(&mut self, bytes: usize, now: Duration) -> io::Result<bool> {
        match self.controller.preview_admit(bytes as u64, micros(now)?) {
            Ok(()) => Ok(true),
            Err(delivery_window::Error::Blocked) => Ok(false),
            Err(error) => Err(io::Error::other(error)),
        }
    }
    pub fn admit(
        &mut self,
        identity: protocol::RecordIdentity,
        bytes: usize,
        now: Duration,
    ) -> io::Result<()> {
        let channel = usize::from(identity.channel.0);
        let retired = self
            .retired
            .get(channel)
            .ok_or_else(|| invalid("aligned admission channel"))?;
        if retired.is_some_and(|old| identity.record.0 <= old)
            || self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.identity == identity)
        {
            return Err(invalid("aligned native identity reused"));
        }
        let end = self
            .controller
            .admit(bytes as u64, micros(now)?)
            .map_err(io::Error::other)?;
        let slot = ((end.records - 1) % self.entries.len() as u64) as usize;
        if self.entries[slot].is_some() || usize::from(identity.channel.0) >= self.retired.len() {
            return Err(invalid("aligned native identity ownership"));
        }
        self.bits[slot * self.words..(slot + 1) * self.words].fill(0);
        self.entries[slot] = Some(Native {
            identity,
            ordinal: end.records,
            admitted_at: micros(now)?,
            parts: 0,
            sent: 0,
            latest_send: Micros(0),
        });
        Ok(())
    }
    pub fn tick(&mut self, now: Duration) -> io::Result<()> {
        self.controller.tick(micros(now)?).map_err(io::Error::other)
    }
    pub fn delivered(
        &mut self,
        identity: protocol::RecordIdentity,
        actual: Duration,
        observed: Duration,
    ) -> io::Result<()> {
        self.tick(observed)?;
        let channel = usize::from(identity.channel.0);
        let retired = self
            .retired
            .get(channel)
            .ok_or_else(|| invalid("aligned native receipt channel"))?;
        let Some(native) = self
            .entries
            .iter()
            .flatten()
            .find(|n| n.identity == identity)
        else {
            if retired.is_some_and(|record| identity.record.0 <= record) {
                return Ok(());
            }
            return Err(invalid("aligned receipt is not an admitted native body"));
        };
        self.controller
            .delivered_record_at(native.ordinal, micros(actual)?, micros(observed)?)
            .map_err(io::Error::other)?;
        self.prune(observed)
    }
    pub fn sent(
        &mut self,
        units: &[protocol::UnitWitness],
        actual: Duration,
        observed: Duration,
    ) -> io::Result<()> {
        self.tick(observed)?;
        let actual = micros(actual)?;
        if actual > micros(observed)? {
            return Err(invalid("aligned send callback from future"));
        }
        for unit in units {
            let Some(slot) = self
                .entries
                .iter()
                .position(|n| n.is_some_and(|n| n.identity == unit.identity))
            else {
                // Codec context units and already retired original-ID retries
                // have no native debt. Only the admission ledger creates it.
                continue;
            };
            if unit.count == 0 || unit.count > self.fragments || unit.index >= unit.count {
                return Err(invalid("aligned original fragment witness"));
            }
            let native = self.entries[slot]
                .as_mut()
                .ok_or_else(|| invalid("aligned witness identity"))?;
            if actual < native.admitted_at {
                return Err(invalid("aligned send before native admission"));
            }
            if native.parts != 0 && native.parts != unit.count {
                return Err(invalid("aligned fragment count changed"));
            }
            native.parts = unit.count;
            let bit = slot * self.words + unit.index / 64;
            let mask = 1u64 << (unit.index % 64);
            if self.bits[bit] & mask != 0 {
                continue;
            }
            self.bits[bit] |= mask;
            native.sent += 1;
            native.latest_send = native.latest_send.max(actual);
            if native.sent == native.parts {
                self.controller
                    .confirm_record_flushed_at(
                        native.ordinal,
                        native.latest_send,
                        micros(observed)?,
                    )
                    .map_err(io::Error::other)?;
            }
        }
        self.prune(observed)
    }
    fn prune(&mut self, now: Duration) -> io::Result<()> {
        let status = self
            .controller
            .status(micros(now)?)
            .map_err(io::Error::other)?;
        let floor = status.admitted.records - status.retained_records as u64;
        while self.retired_ordinal < floor {
            let slot = (self.retired_ordinal % self.entries.len() as u64) as usize;
            let native = self.entries[slot]
                .take()
                .ok_or_else(|| invalid("aligned native retirement"))?;
            let retired = &mut self.retired[usize::from(native.identity.channel.0)];
            *retired = Some(retired.map_or(native.identity.record.0, |old| {
                old.max(native.identity.record.0)
            }));
            self.retired_ordinal += 1;
        }
        Ok(())
    }
}
pub(super) struct Outbound {
    pub bytes: Vec<u8>,
    pub units: Vec<protocol::UnitWitness>,
}
pub(super) struct Sent {
    pub lane: usize,
    pub units: Vec<protocol::UnitWitness>,
    pub at: Instant,
}
pub(super) async fn write_datagrams<S: DatagramSend>(
    mut sender: S,
    mut packets: mpsc::Receiver<Outbound>,
    lane: usize,
    sent: mpsc::Sender<Sent>,
) -> io::Result<()> {
    while let Some(packet) = packets.recv().await {
        let permit = if packet.units.is_empty() {
            None
        } else {
            Some(
                sent.reserve()
                    .await
                    .map_err(|_| invalid("aligned send observer closed"))?,
            )
        };
        sender.send(&packet.bytes).await?;
        let at = Instant::now();
        if let Some(permit) = permit {
            permit.send(Sent {
                lane,
                units: packet.units,
                at,
            });
        }
    }
    Err(invalid("aligned datagram owner closed"))
}
pub(super) async fn write_control(
    mut writer: impl AsyncWrite + Unpin,
    mut changes: watch::Receiver<udp::Feedback>,
    mut native: mpsc::Receiver<protocol::RecordIdentity>,
    config: DatagramPolicy,
    budget: udp::SharedBudget,
) -> io::Result<()> {
    let mut heartbeat = interval(config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_ack = None;
    loop {
        let receipt = tokio::select! {
            changed = changes.changed() => { changed.map_err(|_| invalid("aligned recovery owner closed"))?; None },
            identity = native.recv() => Some(identity.ok_or_else(|| invalid("aligned native receipt owner closed"))?),
            _ = heartbeat.tick() => None,
        };
        let latest = changes.borrow_and_update().clone();
        timeout(config.control_timeout, async {
            if latest.ack != previous_ack
                && let Some(ack) = &latest.ack
            {
                udp::write_control_frame_bound(&mut writer, 2, ack, config.control_magic).await?;
            }
            if let Some(identity) = receipt {
                let mut body = [0; 9];
                body[0] = identity.channel.0;
                body[1..].copy_from_slice(&identity.record.0.to_be_bytes());
                budget.control(body.len()).await?;
                udp::write_control_frame_bound(&mut writer, 3, &body, config.control_magic).await?;
            }
            budget.control(0).await?;
            udp::write_control_frame_bound(&mut writer, 1, &[], config.control_magic).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "aligned control write deadline"))??;
        previous_ack = latest.ack;
    }
}

#[cfg(test)]
#[path = "aligned_delivery_tests.rs"]
mod tests;
