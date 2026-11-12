use super::*;

/// Immutable explicit rolling source/frame, common MUX and service policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Required canonical native delivery policies, independent of local queues.
    pub delivery: super::super::managed::DeliveryConfig,
    /// Actual pure causal byte-recovery scheduling and total owner limits.
    pub scheduler: scheduler::Policy,
    /// The one common native admission/MUX policy, including all user probes.
    pub pipeline: PipelineConfig,
    /// First logical coding stream; a second physical lane uses checked stream+1.
    pub stream: u32,
    /// Nonzero startup-bound epoch; hot reload requires a new authenticated session.
    pub epoch: u64,
    /// Per-owner/per-pass GF/copy/metadata work, each in 1..=65536.
    pub work: protocol::WorkBudget,
    /// Finite service passes per actor turn, in 1..=64.
    pub passes_per_turn: usize,
}
impl Config {
    /// Derive an explicitly selected rolling policy from ordinary protected UDP geometry.
    pub fn for_udp(
        runtime: RuntimeConfig,
        transport: udp::Config,
        channels: u16,
        delivery: super::super::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        udp::base_session_config(runtime, transport)?;
        Self::derive(runtime, transport.policy()?, channels, delivery)
    }
    /// Derive an explicitly selected rolling policy from genuine QUIC datagram geometry.
    pub fn for_quic(
        runtime: RuntimeConfig,
        transport: quic::Config,
        channels: u16,
        delivery: super::super::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        quic::base_session_config(runtime, transport)?;
        Self::derive(runtime, transport.policy()?, channels, delivery)
    }
    fn derive(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
        delivery: super::super::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        let max_payload = policy
            .payload_bytes
            .checked_sub(protocol::wire::HEADER_BYTES + 2)
            .ok_or_else(|| invalid("rolling source wire MTU"))?
            .min(protocol::MAX_PAYLOAD);
        let bytes = runtime
            .max_packet
            .checked_mul(runtime.queue_packets)
            .ok_or_else(|| invalid("rolling queue overflow"))?;
        let queue = pipeline::QueueLimits {
            bytes,
            packets: runtime.queue_packets,
        };
        let value = Self {
            delivery,
            scheduler: scheduler::Policy {
                recovery: protocol::Config {
                    window: 32,
                    local_window: 8,
                    global_every: 16,
                    max_payload,
                    max_rows: 32,
                    repair_history: 64,
                    handoff_sources: 8,
                    job_ticks: 5000,
                    debt_ticks: 20000,
                    handoff_ticks: 5000,
                    memory_bytes: 32 << 20,
                },
                repair_numerator: 1,
                repair_denominator: 4,
                tail_ticks: 20,
                feedback_ticks: 5,
                feedback_packets: 4,
                memory_bytes: 32 << 20,
            },
            pipeline: PipelineConfig {
                profile: match runtime.layer {
                    PacketLayer::Ethernet => pipeline::Profile::TapSystem,
                    PacketLayer::Ip => pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                        base_quantum_bytes: runtime.max_packet as u32,
                        max_weight: 1,
                        per_flow: queue,
                    }),
                },
                flows: pipeline::FlowTableConfig {
                    capacity: 1024,
                    channels,
                    mapping: pipeline::Mapping::Crc32,
                    idle_timeout: Duration::from_secs(60),
                },
                parse: pipeline::ParseLimits {
                    max_packet_bytes: runtime.max_packet,
                    ..pipeline::ParseLimits::default()
                },
                queue,
            },
            stream: 1,
            epoch: 1,
            work: protocol::WorkBudget {
                field: 4096,
                copies: 4096,
                metadata: 4096,
            },
            passes_per_turn: 8,
        };
        value.validate(runtime, policy)?;
        Ok(value)
    }
    pub(super) fn validate(self, runtime: RuntimeConfig, policy: DatagramPolicy) -> io::Result<()> {
        runtime.validate()?;
        self.delivery.validate(runtime)?;
        for delivery in [self.delivery.forward, self.delivery.reverse] {
            let markers = delivery
                .max_records
                .checked_mul(std::mem::size_of::<(protocol::SourceId, u64)>())
                .ok_or_else(|| invalid("rolling native marker reservation overflow"))?;
            let total = delivery
                .metadata_bytes()
                .map_err(io::Error::other)?
                .checked_add(markers)
                .ok_or_else(|| invalid("rolling native metadata reservation overflow"))?;
            if total > delivery.metadata_limit_bytes {
                return Err(invalid(
                    "rolling delivery metadata budget excludes fragment markers",
                ));
            }
        }

        self.scheduler.validate().map_err(io::Error::other)?;
        let c = self.scheduler.recovery;
        let profile = matches!(
            (runtime.layer, self.pipeline.profile),
            (PacketLayer::Ethernet, pipeline::Profile::TapSystem)
                | (PacketLayer::Ip, pipeline::Profile::TunDrr(_))
        );
        if policy.reliable.is_some()
            || c.window > 128
            || c.max_payload <= FRAGMENT_HEADER_BYTES + 2
            || c.width().map_err(io::Error::other)? + protocol::wire::HEADER_BYTES
                > policy.payload_bytes
            || [c.job_ticks, c.debt_ticks, c.handoff_ticks]
                .into_iter()
                .any(|v| v > 120000)
            || self.epoch == 0
            || (policy.duplex == Duplex::Half && self.stream == u32::MAX)
            || !profile
            || !(1..=256).contains(&self.pipeline.flows.channels)
            || self.pipeline.flows.mapping != pipeline::Mapping::Crc32
            || self.pipeline.parse.max_packet_bytes != runtime.max_packet
            || self.pipeline.queue.packets > runtime.queue_packets
            || self.pipeline.queue.bytes > runtime.queue_packets * runtime.max_packet
            || [self.work.field, self.work.copies, self.work.metadata]
                .into_iter()
                .any(|v| !(1..=protocol::MAX_STEP_WORK).contains(&v))
            || !(1..=64).contains(&self.passes_per_turn)
        {
            return Err(invalid(
                "rolling profile, geometry or bounded service mismatch",
            ));
        }
        if let pipeline::Profile::TunDrr(qos) = self.pipeline.profile
            && (qos.per_flow.bytes > self.pipeline.queue.bytes
                || qos.per_flow.packets > self.pipeline.queue.packets)
        {
            return Err(invalid("rolling TUN per-flow queue exceeds common queue"));
        }
        Pipeline::new(self.pipeline).map_err(io::Error::other)?;
        for bound in [
            protocol::Encoder::memory_bound(c),
            protocol::Decoder::memory_bound(c),
        ] {
            if bound.map_err(io::Error::other)? > c.memory_bytes {
                return Err(invalid("rolling primitive reservation"));
            }
        }
        for bound in [
            scheduler::Sender::memory_bound(self.scheduler),
            scheduler::Receiver::memory_bound(self.scheduler),
        ] {
            if bound.map_err(io::Error::other)? > self.scheduler.memory_bytes {
                return Err(invalid("rolling total scheduler reservation"));
            }
        }
        // Validate the new exact feedback reservation before any link/device ownership.
        udp::SharedBudget::from_policy_feedback(policy, Instant::now(), scheduler::FEEDBACK_BYTES)?;
        Ok(())
    }
    pub(super) fn bind(self, base: SessionConfig) -> io::Result<SessionConfig> {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(
            b"l2tunnel/rolling-frame-policy/v2/millisecond-ticks/l2rw1/l2rf1/lx1/channel-u16\0",
        );
        hash.update(&self.delivery.canonical()?);
        let c = self.scheduler.recovery;
        for value in [
            c.window as u64,
            c.local_window as u64,
            u64::from(c.global_every),
            c.max_payload as u64,
            c.max_rows as u64,
            c.repair_history as u64,
            c.handoff_sources as u64,
            c.job_ticks,
            c.debt_ticks,
            c.handoff_ticks,
            c.memory_bytes as u64,
            u64::from(self.scheduler.repair_numerator),
            u64::from(self.scheduler.repair_denominator),
            self.scheduler.tail_ticks,
            self.scheduler.feedback_ticks,
            u64::from(self.scheduler.feedback_packets),
            self.scheduler.memory_bytes as u64,
            u64::from(self.stream),
            self.epoch,
            self.work.field as u64,
            self.work.copies as u64,
            self.work.metadata as u64,
            self.passes_per_turn as u64,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let digest = ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("rolling digest width"))?,
        );
        Ok(super::super::aligned::bind_policy(
            base,
            digest,
            self.pipeline,
            b"l2tunnel/rolling-frame-runtime/v2\0",
        ))
    }
}

#[cfg(test)]
pub(super) fn test_delivery(runtime: RuntimeConfig) -> super::super::managed::DeliveryConfig {
    let config = l2tunnel_flow_control::delivery_window::Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2000,
        max_rtt_micros: 1_000_000,
        headroom_percent: 125,
        minimum_bytes: runtime.max_packet as u64,
        max_inflight_bytes: 4 * 1024 * 1024,
        // Existing small fixtures explicitly reserve two native records.
        max_records: 2,
        max_packet_bytes: runtime.max_packet as u64,
        metadata_limit_bytes: 1_000_000,
        sample_ttl_micros: 4_000_000,
        flush_timeout_micros: 120_000_000,
    };
    super::super::managed::DeliveryConfig {
        forward: config,
        reverse: config,
    }
}
