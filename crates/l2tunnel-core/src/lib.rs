//! Runtime-independent policy contracts. Algorithm variants are roadmap entries.

/// Planned device-layer, TCP ownership and QoS selection.
pub mod traffic;

/// Configuration generation; unrelated to TCP or TLS sequence numbers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Epoch(pub u64);

/// Digest of canonical negotiated configuration bytes, computed by the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigDigest(pub [u8; 32]);

/// Bulk-data direction policy. Reverse control traffic is always permitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Duplex {
    /// One bulk direction per carrier; pair carrier sets for a bidirectional tunnel.
    #[default]
    Half,
    /// Both bulk directions per carrier, with independent counters and budgets.
    Full,
}

/// Connection-to-channel assignment, separate from record release order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mapping {
    /// Symmetric endpoint CRC32, matching the simulator's IPv4/TCP profile.
    Crc32,
    /// Assign new connections locally to successive channels.
    #[default]
    ConnectionRoundRobin,
    /// Explicit decoded-channel reply affinity over the same local RR flow owner.
    ConnectionRoundRobinLearned,
}

/// Planned recovery engines; enum presence does not indicate implementation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Recovery {
    /// Rely on a reliable carrier without custom retransmission.
    #[default]
    CarrierOnly,
    /// Cumulative/selective receipt feedback and timed retries.
    SelectiveArq,
    /// Expedite first retry using later receipt evidence.
    FirstFlightArq,
    /// Receive-gap feedback plus guarded retry.
    BoundedGapArq,
    /// Bounded systematic GF(256) generations.
    BlockFec,
    /// Sliding-window random linear repair plus ARQ.
    SlidingFec,
    /// Short/long-window repair plus ARQ.
    HybridFec,
    /// Elastic GF(256) coding window.
    ElasticRlnc,
    /// Bounded generations with rank-deficit feedback.
    RankBlockFec,
}

/// Planned source packing policies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecordLayout {
    /// Complete frame fragments with bounded reassembly.
    #[default]
    Frame,
    /// Records cross coding-source boundaries.
    CrossFrame,
    /// Shared coding sources across channel record streams.
    Shared,
    /// Aligned record starts and independent short records.
    Aligned,
    /// Short sources aggregate before coding with a finite flush timer.
    Packed,
}

/// Frame delivery policy, independent of MUX mapping.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Delivery {
    /// In-order release within a channel.
    #[default]
    Ordered,
    /// Release explicitly independent short records without waiting for gaps.
    IndependentShort,
}

/// Header profiles; unsupported traffic must fall back to complete frames.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HeaderProfile {
    /// No header compression.
    #[default]
    FullL2,
    /// Reversible Ethernet/IPv4/TCP timestamp profile.
    TcpTimestamp,
    /// Reliable context plus changed fields.
    TcpDelta,
    /// Experimental prediction and explicit context recovery.
    PredictiveTcp,
}

/// Payload compression is new work beyond the Python header-codec experiments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PayloadCompression {
    /// Preserve payload bytes.
    #[default]
    Off,
    /// Bounded independent LZ4 blocks; planned.
    Lz4,
    /// Bounded independent Zstandard blocks; planned.
    Zstd,
}

/// Initial orthogonal mode contract. Detailed knobs are specified in the roadmap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeConfig {
    /// Carrier bulk direction policy.
    pub duplex: Duplex,
    /// Shared traffic-channel count, including probes.
    pub channels: u16,
    /// Connection placement.
    pub mapping: Mapping,
    /// Recovery engine.
    pub recovery: Recovery,
    /// Source layout.
    pub records: RecordLayout,
    /// Release policy.
    pub delivery: Delivery,
    /// Lossless header transform.
    pub headers: HeaderProfile,
    /// Payload transform.
    pub compression: PayloadCompression,
    /// Queued payload budget per direction in bytes.
    pub queue_bytes: usize,
    /// Shared queued-frame count limit per direction.
    pub queue_frames: usize,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            duplex: Duplex::Half,
            channels: 16,
            mapping: Mapping::ConnectionRoundRobin,
            recovery: Recovery::CarrierOnly,
            records: RecordLayout::Frame,
            delivery: Delivery::Ordered,
            headers: HeaderProfile::FullL2,
            compression: PayloadCompression::Off,
            queue_bytes: 4 * 1024 * 1024,
            queue_frames: 4096,
        }
    }
}

impl ModeConfig {
    /// Validate structural constraints without claiming algorithms are implemented.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=256).contains(&self.channels) {
            return Err("channels must be in 1..=256");
        }
        if !(65_535..=256 * 1024 * 1024).contains(&self.queue_bytes) {
            return Err("queue_bytes must be in 65535..=268435456");
        }
        if !(1..=262_144).contains(&self.queue_frames) {
            return Err("queue_frames must be in 1..=262144");
        }
        if self.delivery == Delivery::IndependentShort
            && !matches!(self.records, RecordLayout::Aligned | RecordLayout::Packed)
        {
            return Err("independent short delivery requires aligned or packed records");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validate_limits_and_delivery_dependencies() {
        let base = ModeConfig::default();
        assert_eq!(base.duplex, Duplex::Half);
        assert!(base.validate().is_ok());
        assert!(
            ModeConfig {
                channels: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ModeConfig {
                queue_frames: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ModeConfig {
                queue_bytes: usize::MAX,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ModeConfig {
                delivery: Delivery::IndependentShort,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ModeConfig {
                delivery: Delivery::IndependentShort,
                records: RecordLayout::Packed,
                ..base
            }
            .validate()
            .is_ok()
        );
    }
}
