//! Explicit Common PackedCompact TAP profiles with KCP-like recovery.
use l2tunnel::{aligned, codec, record_configuration as records, reliable};
use l2tunnel_recovery::{CompactArqConfig, CompactRecovery};
use serde_json::{Value, json};
use std::io;
use std::time::Duration;

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

/// Maximum Packed unit capacity for the chosen physical allowance and canonical identities.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    mtu: usize,
    overhead: usize,
    packing: codec::packed_envelope::Config,
    source: usize,
}

impl Geometry {
    /// Charge the actual carrier's selected allowance, the Compact union and both maximum serials.
    pub fn new(mtu: usize, overhead: usize, channels: u16, max_units: u8) -> io::Result<Self> {
        let source = mtu
            .checked_sub(overhead)
            .and_then(|v| v.checked_sub(1 + l2tunnel_recovery::COMPACT_BODY_DATA_MAX_HEADER_BYTES))
            .ok_or_else(|| invalid("path MTU cannot contain Compact DATA"))?;
        let mut packing = codec::packed_envelope::Config {
            symbol_bytes: 9,
            channels,
            max_units,
        };
        let minimum = packing.max_source_bytes().map_err(invalid)?;
        packing.symbol_bytes = source
            .checked_sub(minimum)
            .and_then(|v| v.checked_add(9))
            .ok_or_else(|| invalid("path MTU cannot contain a Packed unit"))?;
        if packing.max_source_bytes().map_err(invalid)? != source {
            return Err(invalid("inconsistent Packed source geometry"));
        }
        Ok(Self {
            mtu,
            overhead,
            packing,
            source,
        })
    }

    /// Exact source limit to pass to CompactArqConfig.
    pub fn max_source_bytes(self) -> usize {
        self.source
    }

    /// Exact unit capacity to pass to the aligned sender and receiver.
    pub fn symbol_bytes(self) -> usize {
        self.packing.symbol_bytes
    }

    /// Build one direction using explicit budgets and timing. No FEC or repeat copies are enabled.
    pub fn direction(
        self,
        native: aligned::NativePolicy,
        receiver: codec::aligned_receiver::Limits,
        arq: CompactArqConfig,
        hold_micros: u64,
        work_limit: usize,
    ) -> io::Result<aligned::packed::CompactConfig> {
        self.direction_with_delivery(
            native,
            aligned::NativeDelivery::ProfileDefault,
            receiver,
            arq,
            hold_micros,
            work_limit,
        )
    }

    /// Select native device ordering without changing Packed preview or Compact source feedback.
    pub fn direction_with_delivery(
        self,
        native: aligned::NativePolicy,
        native_delivery: aligned::NativeDelivery,
        receiver: codec::aligned_receiver::Limits,
        arq: CompactArqConfig,
        hold_micros: u64,
        work_limit: usize,
    ) -> io::Result<aligned::packed::CompactConfig> {
        if !matches!(
            native,
            aligned::NativePolicy::RawEthernet
                | aligned::NativePolicy::EthernetHeaders
                | aligned::NativePolicy::Lz4Ethernet
        ) || !matches!(arq.recovery(), CompactRecovery::KcpLike(_))
            || receiver.channels != self.packing.channels
            || receiver.body.symbol_bytes != self.symbol_bytes()
            || arq.bounds().max_source_bytes != self.source
        {
            return Err(invalid(
                "expected matching TAP, Packed and KCP-like settings",
            ));
        }
        let recovery = reliable::CompactReliableConfig::new(arq, self.overhead).map_err(invalid)?;
        let maximum = recovery
            .compact_wire_maximum_packet_bytes()
            .map_err(invalid)?;
        if maximum
            .checked_add(self.overhead)
            .is_none_or(|n| n > self.mtu)
        {
            return Err(invalid("DATA or ACK exceeds the selected carrier MTU"));
        }
        let direction = aligned::packed::CompactConfig {
            base: aligned::CompactConfig {
                native_policy: native,
                native_delivery,
                receiver,
                recovery,
                max_recovery_packet_bytes: self.source
                    + l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES
                    + reliable::ENVELOPE_BYTES,
                copies: codec::source_copy::Policy::ONE,
            },
            hold_micros,
            max_units: self.packing.max_units,
            work_limit,
        };
        direction.validate().map_err(invalid)?;
        Ok(direction)
    }
}

fn report_duration(output: &mut Value, micros: &str, exact: &str, value: Duration) {
    let whole = u64::try_from(value.as_micros()).ok();
    output[micros] = json!(whole);
    if whole.is_none() || !value.subsec_nanos().is_multiple_of(1000) {
        output[exact] = json!({"seconds":value.as_secs(),"subsec_nanos":value.subsec_nanos()});
    }
}

fn facts(base: aligned::CompactConfig, packing: Option<(u8, u64, usize)>) -> Option<Value> {
    let arq = base.recovery.arq();
    let CompactRecovery::KcpLike(kcp) = arq.recovery() else {
        return None;
    };
    let native = match base.native_policy {
        aligned::NativePolicy::RawEthernet => "raw_ethernet",
        aligned::NativePolicy::EthernetHeaders => "ethernet_headers",
        aligned::NativePolicy::Lz4Ethernet => "lz4_ethernet",
        _ => return None,
    };
    let bounds = arq.bounds();
    let rx = base.receiver;
    let body = rx.body;
    let (delivery_policy, delivery) = match base.native_delivery {
        aligned::NativeDelivery::ChannelOrdered => ("channel_ordered", "per_channel_ordered"),
        aligned::NativeDelivery::ProfileDefault if base.native_policy.is_stateless() => {
            ("profile_default", "complete_independent_frames")
        }
        aligned::NativeDelivery::ProfileDefault => ("profile_default", "header_context_ordered"),
    };
    let mut output = json!({
        "native_encoding":native, "native_delivery":delivery, "native_delivery_policy":delivery_policy,
        "fast_resend":kcp.fast_resend, "interval_ms":kcp.interval_ms, "minimum_rto_ms":kcp.minimum_rto_ms,
        "maximum_rto_ms":kcp.maximum_rto_ms, "ack_packets":arq.timing().feedback_packets,
        "max_feedback_bytes":arq.maximum_feedback_bytes(), "history_entries":arq.history_entries(),
        "maximum_attempts":arq.maximum_attempts(), "send_records":bounds.send_records, "receive_records":bounds.receive_records,
        "send_bytes":bounds.send_bytes, "receive_bytes":bounds.receive_bytes, "max_source_bytes":bounds.max_source_bytes,
        "max_packed_units":packing.map(|p|p.0), "hold_micros":packing.map(|p|p.1), "work_limit":packing.map(|p|p.2),
        "source_copies":base.copies.copies,"source_copy_max_unit_bytes":base.copies.max_unit_bytes,
        "channels":rx.channels, "max_frame_bytes":body.max_frame_bytes, "symbol_bytes":body.symbol_bytes,
        "record_window":rx.record_window, "source_window":rx.source_window, "lookahead_records":rx.lookahead_records,
        "lookahead_bytes":rx.lookahead_bytes, "lookahead_fragments":rx.lookahead_fragments,
        "max_fragments_per_record":rx.max_fragments_per_record,"lifetime_ticks":rx.lifetime_ticks,
        "elide_payload_length":body.elide_payload_length, "predictive":body.predictive,
        "timestamp_pair_dictionary":body.timestamp_pair_dictionary,"independent_short_frame_bytes":body.independent_short_frame_bytes,
        "compact_data_max_bytes":base.recovery.compact_wire_maximum_data_bytes().ok()?,
        "compact_feedback_max_bytes":base.recovery.compact_wire_maximum_feedback_bytes().ok()?,
        "outer_allowance_bytes":base.recovery.outer_overhead_bytes(), "repair_symbols":0
    });
    let timing = arq.timing();
    report_duration(
        &mut output,
        "ack_interval_us",
        "ack_interval_exact",
        timing.feedback_interval,
    );
    report_duration(
        &mut output,
        "nominal_rtt_us",
        "nominal_rtt_exact",
        timing.nominal_rtt,
    );
    Some(output)
}

/// Report the actual negotiated profile fields, independent of the CLI row name.
pub fn selected(descriptor: &records::Descriptor) -> Option<Value> {
    let (owner, forward, reverse) = match descriptor.profile() {
        records::Profile::AlignedCompact { forward, reverse } => (
            "aligned_compact",
            facts(*forward, None)?,
            facts(*reverse, None)?,
        ),
        records::Profile::PackedCompact { forward, reverse } => {
            let packed = |config: &aligned::packed::CompactConfig| {
                facts(
                    config.base,
                    Some((config.max_units, config.hold_micros, config.work_limit)),
                )
            };
            ("packed_compact", packed(forward)?, packed(reverse)?)
        }
        _ => return None,
    };
    Some(
        json!({"recovery":"kcp_like","owner":owner,"native_layer":"tap","path_mtu":descriptor.path_mtu(),
        "forward":forward, "reverse":reverse}),
    )
}
