//! Authenticated directional byte windows; local queue sizes remain independent.
use super::*;
use l2tunnel_flow_control::{delivery_window, target::Micros};

/// Canonical original-native-byte policies, identical on both authenticated peers.
/// Forward means originator to acceptor; reverse means acceptor to originator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryConfig {
    /// Originator-to-acceptor delivery policy.
    pub forward: delivery_window::Config,
    /// Acceptor-to-originator delivery policy.
    pub reverse: delivery_window::Config,
}
impl DeliveryConfig {
    pub(crate) fn validate(self, runtime: RuntimeConfig) -> io::Result<()> {
        for config in [self.forward, self.reverse] {
            config.validate().map_err(io::Error::other)?;
            if config.max_packet_bytes != runtime.max_packet as u64 {
                return Err(invalid("delivery maximum packet differs from native bound"));
            }
        }
        Ok(())
    }
    pub(crate) fn outgoing(self, role: Role) -> delivery_window::Config {
        if role == Role::Client {
            self.forward
        } else {
            self.reverse
        }
    }
    pub(crate) fn incoming(self, role: Role) -> delivery_window::Config {
        if role == Role::Client {
            self.reverse
        } else {
            self.forward
        }
    }
    pub(crate) fn canonical(self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(192);
        for config in [self.forward, self.reverse] {
            for value in [
                config.target_bandwidth_bps,
                config.bootstrap_rtt_micros,
                config.min_rtt_micros,
                config.max_rtt_micros,
                u64::from(config.headroom_percent),
                config.minimum_bytes,
                config.max_inflight_bytes,
                u64::try_from(config.max_records).map_err(io::Error::other)?,
                config.max_packet_bytes,
                u64::try_from(config.metadata_limit_bytes).map_err(io::Error::other)?,
                config.sample_ttl_micros,
                config.flush_timeout_micros,
            ] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        Ok(bytes)
    }
}
/// Validate directional delivery limits while retaining the original local mode queues.
pub fn mode_config_with_delivery(
    runtime: RuntimeConfig,
    duplex: Duplex,
    delivery: DeliveryConfig,
) -> io::Result<ModeConfig> {
    delivery.validate(runtime)?;
    mode_config(runtime, duplex)
}
/// Authenticate both directional byte policies separately from local queue budgets.
/// The legacy fixed-record session digest is intentionally incompatible.
pub fn session_config_with_delivery(
    runtime: RuntimeConfig,
    mode: &ModeConfig,
    delivery: DeliveryConfig,
) -> io::Result<SessionConfig> {
    delivery.validate(runtime)?;
    let legacy = session_config(runtime, mode)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/managed-runtime/delivery-window/v1\0");
    hash.update(&legacy.digest.0);
    hash.update(&delivery.canonical()?);
    Ok(SessionConfig {
        layer: legacy.layer,
        digest: ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("delivery digest size"))?,
        ),
    })
}

/// One original writer completion; never reconstructed from a coalesced ordinal.
pub(super) struct FlushEvent {
    pub ordinal: u64,
    pub at: Instant,
}
pub(super) fn micros(origin: Instant, at: Instant) -> io::Result<Micros> {
    Ok(Micros(
        u64::try_from(
            at.checked_duration_since(origin)
                .ok_or_else(|| invalid("delivery clock regression"))?
                .as_micros(),
        )
        .map_err(io::Error::other)?,
    ))
}

pub(super) struct Window {
    pub sender: delivery_window::Controller,
    pub incoming: delivery_window::Config,
    pub pending_bytes: u64,
    pub staged: Option<Vec<u8>>,
    pub origin: Instant,
}
impl Window {
    pub fn new(config: DeliveryConfig, role: Role, origin: Instant) -> io::Result<Self> {
        Ok(Self {
            sender: delivery_window::Controller::new(config.outgoing(role), Micros(0))
                .map_err(io::Error::other)?,
            incoming: config.incoming(role),
            pending_bytes: 0,
            staged: None,
            origin,
        })
    }
    pub fn now(&self) -> io::Result<Micros> {
        micros(self.origin, Instant::now())
    }
    pub fn flush(&mut self, event: FlushEvent) -> io::Result<()> {
        self.sender
            .confirm_flushed_at(event.ordinal, micros(self.origin, event.at)?, self.now()?)
            .map_err(io::Error::other)?;
        Ok(())
    }
    pub fn feedback(&mut self, ordinal: u64, at: Instant) -> io::Result<()> {
        let end = self
            .sender
            .credit_at_record(ordinal)
            .map_err(io::Error::other)?;
        self.sender
            .delivered_at(end, micros(self.origin, at)?, self.now()?)
            .map_err(io::Error::other)?;
        Ok(())
    }
    pub fn admit(&mut self, bytes: usize) -> io::Result<bool> {
        match self.sender.admit(bytes as u64, self.now()?) {
            Ok(_) => Ok(true),
            Err(delivery_window::Error::Blocked) => Ok(false),
            Err(error) => Err(io::Error::other(error)),
        }
    }
    pub fn receive(&mut self, size: usize, pending_records: usize) -> io::Result<()> {
        let total = self
            .pending_bytes
            .checked_add(size as u64)
            .ok_or_else(|| invalid("delivery receive byte overflow"))?;
        if pending_records >= self.incoming.max_records || total > self.incoming.max_inflight_bytes
        {
            return Err(invalid(
                "negotiated native receive delivery capacity exceeded",
            ));
        }
        self.pending_bytes = total;
        Ok(())
    }
    pub fn publish(&mut self, profile: Option<&ProfileSink>) -> io::Result<()> {
        let now = self.now()?;
        self.sender.tick(now).map_err(io::Error::other)?;
        let status = self.sender.status(now).map_err(io::Error::other)?;
        if let Some(profile) = profile {
            use profiling::Value as V;
            profile.value(V::Enabled, 1);
            profile.value(V::Target, status.target_bytes);
            profile.value(V::OutstandingBytes, status.outstanding.bytes);
            profile.value(V::OutstandingRecords, status.outstanding.records);
            // A=admitted, F=local TLS-full-flushed, D=remote native-device delivered.
            // F and D may cross: remote delivery can precede local callback observation.
            // These partitions are ownership observations, not physical wire counters.
            profile.value(V::ReservedBytes, status.outstanding.bytes);
            profile.value(V::ReservedRecords, status.outstanding.records);
            profile.value(
                V::UnflushedBytes,
                status.admitted.bytes - status.flushed.bytes,
            );
            profile.value(
                V::UnflushedRecords,
                status.admitted.records - status.flushed.records,
            );
            profile.value(
                V::FlushedUnacknowledgedBytes,
                status.flushed.bytes.saturating_sub(status.delivered.bytes),
            );
            profile.value(
                V::FlushedUnacknowledgedRecords,
                status
                    .flushed
                    .records
                    .saturating_sub(status.delivered.records),
            );
            profile.value(
                V::DeliveredAwaitingCallbackBytes,
                status.delivered.bytes.saturating_sub(status.flushed.bytes),
            );
            profile.value(
                V::DeliveredAwaitingCallbackRecords,
                status
                    .delivered
                    .records
                    .saturating_sub(status.flushed.records),
            );

            profile.value(V::RetainedRecords, status.retained_records as u64);
            profile.value(V::Rtt, status.sample.map_or(0, |s| s.smoothed_micros));
            profile.value(V::RttFresh, u64::from(status.sample_fresh));
            profile.value(V::PendingBytes, self.pending_bytes);
            profile.value(
                V::StagedBytes,
                self.staged.as_ref().map_or(0, |p| p.len() as u64),
            );
        }
        Ok(())
    }
}
