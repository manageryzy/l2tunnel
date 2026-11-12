use super::*;
/// Fixed authenticated native, common-admission and maintained-recovery policy.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Complete original TLS/pair/packet policy; no fallback occurs after attachment.
    pub transport: PacketPhaseConfig,
    /// Native packet/codec/queue policy shared by CLI and service callers.
    pub runtime: RuntimeConfig,
    /// Explicit physical one/full or ordered two/half policy.
    pub duplex: Duplex,
    /// Existing common MUX and TAP-system or transparent-TUN DRR policy.
    pub pipeline: PipelineConfig,
    /// Real selective-repeat retention, source identity and retry bounds.
    pub arq: ArqConfig,
    /// Existing SelectiveRepeat or Reliable/Cauchy engine; no simulator mode claim.
    pub recovery: udp::RecoveryMode,
    /// Periodic protected cumulative native-confirmation resend interval.
    pub credit_interval: Duration,
    /// Original first-fragment lifetime; feedback does not renew it.
    pub reassembly_timeout: Duration,
}
impl Config {
    /// Derive finite direct selective-repeat and common-MUX defaults at the real MTU.
    pub fn new(
        runtime: RuntimeConfig,
        transport: PacketPhaseConfig,
        duplex: Duplex,
        channels: u16,
    ) -> io::Result<Self> {
        runtime.validate()?;
        let maximum = transport
            .packet
            .max_record_bytes()
            .map_err(carrier_error)?
            .checked_sub(HEADER + DATA_HEADER_BYTES)
            .ok_or_else(|| invalid("raw recovery MTU"))?;
        let queue_bytes = runtime
            .queue_packets
            .checked_mul(runtime.max_packet)
            .ok_or_else(|| invalid("raw pipeline byte bound"))?;
        let value = Self {
            transport,
            runtime,
            duplex,
            pipeline: PipelineConfig {
                profile: match runtime.layer {
                    PacketLayer::Ethernet => pipeline::Profile::TapSystem,
                    PacketLayer::Ip => pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                        base_quantum_bytes: u32::try_from(runtime.max_packet)
                            .map_err(|_| invalid("raw DRR quantum"))?,
                        max_weight: 1,
                        per_flow: pipeline::QueueLimits {
                            bytes: queue_bytes,
                            packets: runtime.queue_packets,
                        },
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
                queue: pipeline::QueueLimits {
                    bytes: queue_bytes,
                    packets: runtime.queue_packets,
                },
            },
            arq: ArqConfig {
                max_source_bytes: maximum,
                send_bytes: maximum * 64,
                receive_bytes: maximum * 64,
                ..ArqConfig::default()
            },
            recovery: udp::RecoveryMode::SelectiveRepeat,
            credit_interval: Duration::from_millis(20),
            reassembly_timeout: Duration::from_secs(10),
        };
        value.validate()?;
        Ok(value)
    }
    /// Recompute actual source/fragment budgets for the maintained Cauchy engine.
    pub fn with_recovery(mut self, recovery: udp::RecoveryMode) -> io::Result<Self> {
        let overhead = match recovery {
            udp::RecoveryMode::SelectiveRepeat => DATA_HEADER_BYTES,
            udp::RecoveryMode::Cauchy {
                sources, repairs, ..
            } => {
                if !(1..=16).contains(&sources) || !(1..=16).contains(&repairs) {
                    return Err(invalid("raw Cauchy dimensions"));
                }
                reliable::ENVELOPE_BYTES
                    + l2tunnel_fec::HEADER_BYTES
                    + sources
                    + 2
                    + DATA_HEADER_BYTES
            }
        };
        self.arq.max_source_bytes = self
            .recovery_bytes()?
            .checked_sub(overhead)
            .ok_or_else(|| invalid("raw reliable MTU"))?;
        self.arq.send_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.send_records)
            .ok_or_else(|| invalid("raw send bytes"))?;
        self.arq.receive_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.receive_records)
            .ok_or_else(|| invalid("raw receive bytes"))?;
        self.recovery = recovery;
        self.validate()?;
        Ok(self)
    }
    pub(super) fn recovery_bytes(self) -> io::Result<usize> {
        self.transport
            .packet
            .max_record_bytes()
            .map_err(carrier_error)?
            .checked_sub(HEADER)
            .ok_or_else(|| invalid("raw runtime header MTU"))
    }
    pub(super) fn policy(self) -> io::Result<udp::DatagramPolicy> {
        let bytes = self.recovery_bytes()?;
        Ok(udp::DatagramPolicy {
            duplex: self.duplex,
            arq: self.arq,
            reliable: udp::reliable_config(self.arq, self.recovery, bytes)?,
            payload_bytes: bytes,
            data_overhead: usize::from(self.transport.packet.mtu) - bytes,
            control_overhead: usize::from(self.transport.packet.mtu) - bytes,
            control_magic: *MAGIC,
            wire_budget: udp::WireBudget {
                interval: Duration::from_millis(1),
                packets: 32,
                wire_bytes: 32 * usize::from(self.transport.packet.mtu),
            },
            control_timeout: self.reassembly_timeout,
            heartbeat_interval: self.credit_interval,
            reassembly_timeout: self.reassembly_timeout,
        })
    }
    /// Validate all local native/queue/recovery limits without opening I/O or devices.
    pub fn validate(self) -> io::Result<()> {
        self.runtime.validate()?;
        let qbytes = self
            .runtime
            .max_packet
            .checked_mul(self.runtime.queue_packets)
            .ok_or_else(|| invalid("raw queue byte overflow"))?;
        if self.transport.pair.session.layer != self.runtime.layer
            || self.arq.max_source_bytes <= FRAGMENT_HEADER_BYTES
            || self
                .arq
                .max_source_bytes
                .checked_add(DATA_HEADER_BYTES)
                .is_none_or(|n| n > self.recovery_bytes().unwrap_or(0))
            || self.arq.send_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.arq.receive_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.arq.maximum_rto > Duration::from_secs(30)
            || self.arq.max_retries > 64
            || self.credit_interval < Duration::from_millis(1)
            || self.credit_interval > Duration::from_secs(1)
            || self.reassembly_timeout < self.credit_interval * 3
            || self.reassembly_timeout > Duration::from_secs(120)
            || self.pipeline.flows.mapping != pipeline::Mapping::Crc32
            || self.pipeline.flows.capacity > 4096
            || self.pipeline.parse.max_packet_bytes != self.runtime.max_packet
            || self.pipeline.queue.packets > self.runtime.queue_packets
            || self.pipeline.queue.bytes > qbytes
            || qbytes > 64 * 1024 * 1024
            || !matches!(
                (self.runtime.layer, self.pipeline.profile),
                (PacketLayer::Ethernet, pipeline::Profile::TapSystem)
                    | (PacketLayer::Ip, pipeline::Profile::TunDrr(_))
            )
        {
            return Err(invalid("raw runtime native/MUX/recovery configuration"));
        }
        let maximum = self
            .runtime
            .codec()?
            .max_encoded_len()
            .checked_add(4)
            .ok_or_else(|| invalid("raw native envelope overflow"))?;
        let chunk = self.arq.max_source_bytes - FRAGMENT_HEADER_BYTES;
        u16::try_from(maximum.div_ceil(chunk))
            .map_err(|_| invalid("raw fragment count exceeds wire field"))?;
        Pipeline::new(self.pipeline).map_err(io::Error::other)?;
        udp::Engine::from_policy(
            self.policy()?,
            RecoveryContext {
                session: 0,
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )?;
        for duration in [
            self.credit_interval,
            self.reassembly_timeout,
            self.runtime.poll_interval,
            self.arq.initial_rto,
            self.arq.maximum_rto,
            self.arq.ack_delay,
            self.pipeline.flows.idle_timeout,
        ] {
            ticks(duration)?;
        }
        Ok(())
    }
    /// Canonical native/MUX/recovery/credit binding used before original authentication.
    pub fn session_config(self) -> io::Result<SessionConfig> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/raw-packet-runtime/v1/frame-v1/fragment-v1/arq-v1/reliable-v1/native-credit-v1\0");
        hash.update(&self.transport.pair.session.digest.0);
        hash.update(&[
            match self.runtime.layer {
                PacketLayer::Ethernet => 1,
                PacketLayer::Ip => 2,
            },
            match self.runtime.compression {
                Compression::None => 0,
                Compression::Lz4IfSmaller => 1,
            },
            if self.duplex == Duplex::Full { 1 } else { 2 },
        ]);
        for n in [
            self.runtime.max_packet,
            self.runtime.queue_packets,
            self.arq.max_source_bytes,
            self.arq.send_bytes,
            self.arq.receive_bytes,
            self.arq.send_records,
            self.arq.receive_records,
        ] {
            hash.update(&(n as u64).to_be_bytes());
        }
        for duration in [
            self.runtime.poll_interval,
            self.arq.initial_rto,
            self.arq.maximum_rto,
            self.arq.ack_delay,
            self.credit_interval,
            self.reassembly_timeout,
        ] {
            hash.update(&ticks(duration)?.to_be_bytes());
        }
        hash.update(&self.arq.max_retries.to_be_bytes());
        match self.recovery {
            udp::RecoveryMode::SelectiveRepeat => hash.update(&[0]),
            udp::RecoveryMode::Cauchy {
                sources,
                repairs,
                flush_after,
            } => {
                hash.update(&[1]);
                hash.update(&(sources as u64).to_be_bytes());
                hash.update(&(repairs as u64).to_be_bytes());
                hash.update(&ticks(flush_after)?.to_be_bytes());
            }
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(hash.finish().as_ref());
        Ok(super::super::aligned::bind_policy(
            self.transport.pair.session,
            ConfigDigest(digest),
            self.pipeline,
            b"l2tunnel/raw-packet-runtime/v1/common-mux-crc32\0",
        ))
    }
}
