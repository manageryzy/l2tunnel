//! Strict bounded runtime resources shared by the current Common CLI plan.
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::transport::TransactionSettings as Parameters;
use l2tunnel_runtime::secure_udp::{control, transport};
use l2tunnel_security as security;
use l2tunnel_swift::policy;
use serde::{Deserialize, Deserializer, de};
use std::{fmt, io, io::Read, path::Path, time::Duration};
const MAX_PLAN_BYTES: usize = 256 * 1024;

/// Read the same finite regular-file plan input without following symlinks.
pub(crate) fn read_document(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the final reparse point itself so the handle metadata can reject it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), "cannot open transaction plan"))?;
    let metadata = file
        .metadata()
        .map_err(|error| io::Error::new(error.kind(), "cannot inspect transaction plan"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("transaction plan must not be a reparse point"));
        }
    }
    if !metadata.is_file() {
        return Err(invalid("transaction plan must be a regular file"));
    }
    if metadata.len() > 256 * 1024 {
        return Err(invalid("transaction plan exceeds file bound"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_PLAN_BYTES + 1)
        .map_err(|_| invalid("transaction plan buffer allocation failed"))?;
    file.take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io::Error::new(error.kind(), "cannot read transaction plan"))?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug)]
struct Size(usize);
impl<'de> Deserialize<'de> for Size {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        usize::try_from(u64::deserialize(deserializer)?)
            .map(Self)
            .map_err(|_| de::Error::custom("integer exceeds platform capacity"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransactionDto {
    retry_ms: u64,
    phase_timeout_ms: u64,
    reconcile_timeout_ms: u64,
    max_operation_ms: u64,
    retained_bytes: Size,
}
impl TransactionDto {
    pub(crate) fn build(self) -> Parameters {
        Parameters {
            protocol: transaction::Settings {
                retry_ms: self.retry_ms,
                phase_timeout_ms: self.phase_timeout_ms,
                reconcile_timeout_ms: self.reconcile_timeout_ms,
            },
            max_operation_ms: self.max_operation_ms,
            retained_bytes: self.retained_bytes.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeDto {
    control_epoch: u64,
    data_epoch: u64,
    legacy_policy: LegacyPolicyDto,
    security: SecurityDto,
    control: DeliveryDto,
    streams: StreamsDto,
    wire: WireDto,
    work: WorkDto,
    native: NativeDto,
    lifetime: LifetimeDto,
    credit: CreditDto,
    report_interval_micros: RequiredReport,
}
impl RuntimeDto {
    pub(crate) fn report_interval(self) -> Option<Duration> {
        self.report_interval_micros.0.map(Duration::from_micros)
    }
    pub(crate) fn templates_for(
        self,
        path_mtu: usize,
        send: policy::Direction,
        receive: policy::Direction,
        maximum_body: usize,
        wire_overhead: usize,
    ) -> io::Result<[transport::Config; 2]> {
        let control = self.control.build(wire_overhead);
        let wrapped = delivery::Settings {
            wire_overhead: wire_overhead
                .checked_add(control_streams::HEADER_BYTES)
                .ok_or_else(|| invalid("transaction stream overhead overflow"))?,
            ..control
        };
        let entry = |value: MessageDto| value.build(wrapped, path_mtu);
        let initiator = transport::Config {
            path_mtu,
            send,
            receive,
            policy: policy::Settings {
                transaction_micros: self.legacy_policy.transaction_micros,
                max_outbound: self.legacy_policy.max_outbound.0,
            },
            security: security::Limits {
                max_body_bytes: maximum_body,
                packets_per_key: self.security.packets_per_key,
                max_body_bytes_per_key: self.security.max_body_bytes_per_key,
            },
            control,
            streams: Some(control::Settings {
                streams: [
                    entry(self.streams.transaction),
                    entry(self.streams.liveness),
                    entry(self.streams.data_feedback),
                ],
            }),
            control_epoch: security::Epoch(self.control_epoch),
            data_epoch: security::Epoch(self.data_epoch),
            wire: transport::WireBudget {
                burst_bytes: self.wire.initiator_burst_bytes.0,
            },
            work: transport::WorkBudget {
                receive_interval: Duration::from_micros(self.work.receive_interval_micros),
                receive_packets: u32::try_from(self.work.receive_packets)
                    .map_err(|_| invalid("transaction receive packet count exceeds u32"))?,
                send_batch: self.work.send_batch.0,
                native_read_batch: self.work.native_read_batch.0,
                native_write_batch: self.work.native_write_batch.0,
            },
            native: transport::NativeBudget {
                pending_packets: self.native.pending_packets.0,
                pending_bytes: self.native.pending_bytes.0,
                stall_timeout: Duration::from_micros(self.native.stall_timeout_micros),
            },
            lifetime: transport::Lifetime {
                lease: Duration::from_micros(self.lifetime.lease_micros),
                ping_interval: Duration::from_micros(self.lifetime.ping_interval_micros),
                pong_timeout: Duration::from_micros(self.lifetime.pong_timeout_micros),
            },
            rolling_work: None,
            ack_coalescing: None,
            connection_ingress: None,
            rolling_fragments: None,
            rolling_ingress: None,
            credit: Some(self.credit.build()),
            report_interval: self.report_interval_micros.0.map(Duration::from_micros),
        };
        Ok([
            initiator,
            transport::Config {
                send: initiator.receive,
                receive: initiator.send,
                wire: transport::WireBudget {
                    burst_bytes: self.wire.responder_burst_bytes.0,
                },
                ..initiator
            },
        ])
    }
}

#[derive(Clone, Copy, Debug)]
struct RequiredReport(Option<u64>);
impl<'de> Deserialize<'de> for RequiredReport {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReportVisitor;
        impl<'de> de::Visitor<'de> for ReportVisitor {
            type Value = RequiredReport;
            fn expecting(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                output.write_str("an explicit null or unsigned report interval")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequiredReport(None))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(RequiredReport(Some(value)))
            }
        }
        // Missing-field deserializers reject deserialize_any. Delegating to
        // Option::deserialize here would incorrectly turn omission into null.
        deserializer.deserialize_any(ReportVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPolicyDto {
    transaction_micros: u64,
    max_outbound: Size,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDto {
    packets_per_key: u64,
    max_body_bytes_per_key: u64,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryDto {
    recovery: RecoveryDto,
    interval_micros: u64,
    packets_per_interval: u32,
    bytes_per_interval: Size,
}
impl DeliveryDto {
    fn build(self, wire_overhead: usize) -> delivery::Settings {
        delivery::Settings {
            recovery: self.recovery.build(),
            interval: Duration::from_micros(self.interval_micros),
            packets_per_interval: self.packets_per_interval,
            bytes_per_interval: self.bytes_per_interval.0,
            wire_overhead,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDto {
    max_source_bytes: Size,
    send_bytes: Size,
    receive_bytes: Size,
    send_records: Size,
    receive_records: Size,
    initial_rto_micros: u64,
    maximum_rto_micros: u64,
    ack_delay_micros: u64,
    max_retries: u16,
}
impl RecoveryDto {
    pub(crate) fn build(self) -> l2tunnel_recovery::ArqConfig {
        l2tunnel_recovery::ArqConfig {
            max_source_bytes: self.max_source_bytes.0,
            send_bytes: self.send_bytes.0,
            receive_bytes: self.receive_bytes.0,
            send_records: self.send_records.0,
            receive_records: self.receive_records.0,
            initial_rto: Duration::from_micros(self.initial_rto_micros),
            maximum_rto: Duration::from_micros(self.maximum_rto_micros),
            ack_delay: Duration::from_micros(self.ack_delay_micros),
            max_retries: self.max_retries,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamsDto {
    transaction: MessageDto,
    liveness: MessageDto,
    data_feedback: MessageDto,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageDto {
    max_message_bytes: Size,
    max_outbound_messages: Size,
    max_outbound_bytes: Size,
    max_fragments: u16,
    max_reassembly_bytes: Size,
    max_incomplete_messages: Size,
    message_lifetime_micros: u64,
    work_per_call: Size,
}
impl MessageDto {
    fn build(self, delivery: delivery::Settings, path_mtu: usize) -> messages::Settings {
        messages::Settings {
            delivery,
            path_mtu,
            max_message_bytes: self.max_message_bytes.0,
            max_outbound_messages: self.max_outbound_messages.0,
            max_outbound_bytes: self.max_outbound_bytes.0,
            max_fragments: self.max_fragments,
            max_reassembly_bytes: self.max_reassembly_bytes.0,
            max_incomplete_messages: self.max_incomplete_messages.0,
            message_lifetime: Duration::from_micros(self.message_lifetime_micros),
            work_per_call: self.work_per_call.0,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDto {
    initiator_burst_bytes: Size,
    responder_burst_bytes: Size,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkDto {
    receive_interval_micros: u64,
    receive_packets: u64,
    send_batch: Size,
    native_read_batch: Size,
    native_write_batch: Size,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeDto {
    pending_packets: Size,
    pending_bytes: Size,
    stall_timeout_micros: u64,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifetimeDto {
    lease_micros: u64,
    ping_interval_micros: u64,
    pong_timeout_micros: u64,
}

/// Session receiver credit (`docs/modules/receiver-credit.md`); required.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreditDto {
    floor_datagrams: u64,
    ceiling_datagrams: u64,
    floor_bytes: u64,
    ceiling_bytes: u64,
    period_micros: u64,
    idle_period_micros: u64,
}
impl CreditDto {
    fn build(self) -> l2tunnel_flow_control::session_credit::Config {
        l2tunnel_flow_control::session_credit::Config {
            floor_datagrams: self.floor_datagrams,
            ceiling_datagrams: self.ceiling_datagrams,
            floor_bytes: self.floor_bytes,
            ceiling_bytes: self.ceiling_bytes,
            period: Duration::from_micros(self.period_micros),
            idle_period: Duration::from_micros(self.idle_period_micros),
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
