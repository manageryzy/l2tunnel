//! Strict, bounded private CLI input for the actual complete transaction Profile.
//!
//! File validation grants no authentication, allocation admission or readiness.

use crate::{ConnectionConfig, secure_udp};
use l2tunnel::swift_configuration::{Catalog, Descriptor};
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::{control, establish, transport};
use l2tunnel_security as security;
use l2tunnel_swift::{policy, records};
use secure_udp::transaction_profile::{self, Parameters};
use serde::{Deserialize, Deserializer, de};
use std::{fmt, io, io::Read, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

const MAX_PLAN_BYTES: usize = 256 * 1024;
const MAX_CATALOG: usize = 64;

/// Complete input retained independently of the file after its bounded read.
#[derive(Clone, Debug)]
pub(super) struct Plan {
    catalog: Catalog,
    parameters: Parameters,
    runtime: RuntimeDto,
}

impl Plan {
    pub(super) fn read(path: &Path) -> io::Result<Self> {
        Self::decode(&read_document(path)?)
    }

    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(invalid("transaction plan outside file bound"));
        }
        let document: PlanDto = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid complete transaction plan JSON"))?;
        if document.version != 1 {
            return Err(invalid("unsupported transaction plan version"));
        }
        let Backend::GenericSwiftV1 = document.backend;
        let initial = document
            .catalog
            .0
            .get(document.initial_index.0)
            .copied()
            .ok_or_else(|| invalid("transaction plan initial index outside catalog"))?;
        let catalog = Catalog::new(initial, &document.catalog.0)
            .map_err(|_| invalid("invalid complete transaction catalog"))?;
        Ok(Self {
            catalog,
            parameters: document.transaction.build(),
            runtime: document.runtime,
        })
    }

    pub(super) fn initial(&self) -> Descriptor {
        self.catalog.initial()
    }

    pub(super) fn report_interval(&self) -> Option<Duration> {
        self.runtime
            .report_interval_micros
            .0
            .map(Duration::from_micros)
    }

    pub(super) fn build(
        &self,
        connection: ConnectionConfig,
        raw: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        wire_overhead: usize,
    ) -> io::Result<transaction_profile::Profile> {
        let initial = self.initial();
        if raw.gate.path_mtu != initial.path_mtu() {
            return Err(invalid(
                "raw bootstrap MTU differs from transaction initial",
            ));
        }
        let [initiator, responder] =
            self.runtime
                .templates(initial, maximum_body, wire_overhead)?;
        transaction_profile::Profile::new(
            connection,
            raw,
            peers,
            initiator,
            responder,
            self.catalog.clone(),
            self.parameters,
        )
        .map_err(|_| invalid("transaction plan does not match runtime or trust contract"))
    }
}

/// Read the same finite regular-file plan input without following symlinks.
pub(super) fn read_document(path: &Path) -> io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), "cannot open transaction plan"))?;
    let metadata = file
        .metadata()
        .map_err(|error| io::Error::new(error.kind(), "cannot inspect transaction plan"))?;
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
struct PlanDto {
    version: u64,
    backend: Backend,
    initial_index: Size,
    catalog: BoundedCatalog,
    transaction: TransactionDto,
    runtime: RuntimeDto,
}
#[derive(Deserialize)]
enum Backend {
    #[serde(rename = "generic_swift_v1")]
    GenericSwiftV1,
}

struct BoundedCatalog(Vec<Descriptor>);
impl<'de> Deserialize<'de> for BoundedCatalog {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CatalogVisitor;
        impl<'de> de::Visitor<'de> for CatalogVisitor {
            type Value = BoundedCatalog;
            fn expecting(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                output.write_str("one to64 complete Swift descriptors")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(MAX_CATALOG)
                    .map_err(|_| de::Error::custom("catalog allocation failed"))?;
                for _ in 0..MAX_CATALOG {
                    let Some(value) = sequence.next_element::<DescriptorDto>()? else {
                        return Ok(BoundedCatalog(values));
                    };
                    values.push(
                        value
                            .build()
                            .map_err(|_| de::Error::custom("invalid Swift descriptor"))?,
                    );
                }
                // SeqAccess tests for the array end before invoking this seed.
                // A65th entry is refused without constructing or traversing it.
                let _: Option<()> = sequence.next_element_seed(RejectExtra)?;
                Ok(BoundedCatalog(values))
            }
        }
        deserializer.deserialize_seq(CatalogVisitor)
    }
}
struct RejectExtra;
impl<'de> de::DeserializeSeed<'de> for RejectExtra {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        Err(de::Error::custom("transaction catalog exceeds64 members"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorDto {
    path_mtu: Size,
    forward: DirectionDto,
    reverse: DirectionDto,
}
impl DescriptorDto {
    fn build(self) -> io::Result<Descriptor> {
        Descriptor::new(self.path_mtu.0, self.forward.build(), self.reverse.build())
            .map_err(|_| invalid("invalid complete Swift descriptor"))
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LayerDto {
    Ethernet,
    Ip,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectionDto {
    channels: Size,
    layer: LayerDto,
    max_native: Size,
    bytes_per_second: u64,
    datagram_bytes: Size,
    window: Size,
    repair_numerator: u32,
    repair_denominator: u32,
    flow_sources: Size,
    queue_bytes: Size,
    max_packet: Size,
    flush_micros: u64,
    feedback_micros: u64,
    tail_micros: u64,
    min_rto_micros: u64,
    max_rto_micros: u64,
}
impl DirectionDto {
    fn build(self) -> policy::Direction {
        policy::Direction {
            records: records::Config {
                channels: self.channels.0,
                layer: match self.layer {
                    LayerDto::Ethernet => records::Layer::Ethernet,
                    LayerDto::Ip => records::Layer::Ip,
                },
                max_native: self.max_native.0,
                codec: l2tunnel_swift::Config {
                    datagram_bytes: self.datagram_bytes.0,
                    window: self.window.0,
                    repair_numerator: self.repair_numerator,
                    repair_denominator: self.repair_denominator,
                    flow_sources: self.flow_sources.0,
                    queue_bytes: self.queue_bytes.0,
                    max_packet: self.max_packet.0,
                    flush_micros: self.flush_micros,
                    feedback_micros: self.feedback_micros,
                    tail_micros: self.tail_micros,
                    min_rto_micros: self.min_rto_micros,
                    max_rto_micros: self.max_rto_micros,
                },
            },
            bytes_per_second: self.bytes_per_second,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionDto {
    retry_ms: u64,
    phase_timeout_ms: u64,
    reconcile_timeout_ms: u64,
    max_operation_ms: u64,
    retained_bytes: Size,
}
impl TransactionDto {
    pub(super) fn build(self) -> Parameters {
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
pub(super) struct RuntimeDto {
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
    report_interval_micros: RequiredReport,
}
impl RuntimeDto {
    fn templates(
        self,
        initial: Descriptor,
        maximum_body: usize,
        wire_overhead: usize,
    ) -> io::Result<[transport::Config; 2]> {
        self.templates_for(
            initial.path_mtu(),
            initial.forward(),
            initial.reverse(),
            maximum_body,
            wire_overhead,
        )
    }
    pub(super) fn report_interval(self) -> Option<Duration> {
        self.report_interval_micros.0.map(Duration::from_micros)
    }
    pub(super) fn templates_for(
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
pub(super) struct RecoveryDto {
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
    pub(super) fn build(self) -> l2tunnel_recovery::ArqConfig {
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
pub(super) fn test_plan_value() -> serde_json::Value {
    tests::plan_value()
}

#[cfg(test)]
#[path = "transaction_cli_tests.rs"]
mod tests;
