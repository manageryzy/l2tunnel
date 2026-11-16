//! Complete Common CLI plans reuse resource parsing, without inventing Swift policies.
use super::transaction_cli::{RecoveryDto, RuntimeDto, TransactionDto, read_document};
use crate::{ConnectionConfig, secure_udp};
use l2tunnel::record_configuration::{Catalog, DESCRIPTOR_BYTES, Descriptor};
use l2tunnel_runtime::secure_udp::{establish, transport};
use serde::{Deserialize, Deserializer, de};
use std::{fmt, io, path::Path, time::Duration};

#[derive(Clone, Debug)]
pub(super) struct Plan {
    catalog: Catalog,
    parameters: transport::TransactionSettings,
    runtime: RuntimeDto,
    rolling_work: Option<l2tunnel_fec::rolling::WorkBudget>,
    outer_carrier: Option<OuterCarrierDto>,
    ack_coalescing: Option<crate::secure_udp::common_status::AckPolicies>,
    rolling_ingress: Option<crate::secure_udp::common_status::RollingIngressPolicies>,
    connection_ingress: Option<crate::secure_udp::common_status::ConnectionIngressPolicies>,
    rolling_fragments: Option<crate::secure_udp::common_status::RollingFragments>,
    compact_wire: Option<crate::secure_udp::common_status::CompactWireSelection>,
}
impl Plan {
    pub(super) fn read(path: &Path) -> io::Result<Self> {
        Self::decode(&read_document(path)?)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > 256 * 1024 {
            return Err(invalid("Common plan outside file bound"));
        }
        let dto: PlanDto = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid complete Common plan JSON"))?;
        if dto.version != 1 || dto.backend != "common_records_v2" {
            return Err(invalid("unsupported Common plan version/backend"));
        }
        let initial = dto
            .catalog
            .0
            .get(usize::from(dto.initial_index))
            .copied()
            .ok_or_else(|| invalid("initial index outside catalog"))?;
        if let Some(value) = dto.compact_wire {
            value.build()?;
            if dto.outer_carrier.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "compact v3 currently requires the original UDP carrier",
                ));
            }
        }
        Ok(Self {
            catalog: Catalog::new(initial, &dto.catalog.0).map_err(io::Error::other)?,
            parameters: dto.transaction.build(),
            runtime: dto.runtime,
            rolling_work: dto.rolling_work.0.map(|value| value.build()).transpose()?,
            outer_carrier: dto.outer_carrier,
            ack_coalescing: dto.ack_coalescing,
            rolling_ingress: dto.rolling_ingress,
            connection_ingress: dto.connection_ingress,
            rolling_fragments: dto.rolling_fragments,
            compact_wire: dto.compact_wire,
        })
    }
    pub(super) fn initial(&self) -> Descriptor {
        self.catalog.initial()
    }
    pub(super) fn report_interval(&self) -> Option<Duration> {
        self.runtime.report_interval()
    }
    pub(super) fn validate_carrier(&self, selected: bool) -> io::Result<()> {
        match (selected, &self.outer_carrier) {
            (false, None) => Ok(()),
            (true, Some(value)) if value.version == 1 && value.backend == "openvpn_wire_common" => {
                Ok(())
            }
            _ => Err(invalid(
                "outer_carrier must be complete version1/openvpn_wire_common only for explicit OpenVPN Common selection",
            )),
        }
    }
    pub(super) fn outer_capacity(&self) -> io::Result<usize> {
        self.validate_carrier(true)?;
        usize::try_from(
            self.outer_carrier
                .as_ref()
                .ok_or_else(|| invalid("outer carrier absent"))?
                .max_record_bytes,
        )
        .map_err(|_| invalid("outer record capacity exceeds platform width"))
    }
    pub(super) fn outer_config(
        &self,
        profile: &secure_udp::common_transaction_profile::Profile,
    ) -> io::Result<l2tunnel_openvpn::wire_carrier::common::Config> {
        self.validate_carrier(true)?;
        let value = self
            .outer_carrier
            .as_ref()
            .ok_or_else(|| invalid("outer carrier absent"))?;
        let size = |value| {
            usize::try_from(value)
                .map_err(|_| invalid("outer carrier capacity exceeds platform width"))
        };
        let mut base = profile.connection().session()?;
        base.digest = l2tunnel_core::ConfigDigest(profile.requested_configuration()?.0);
        let settings = profile.settings();
        let config = l2tunnel_openvpn::wire_carrier::common::Config {
            base,
            path_mtu: self.initial().path_mtu(),
            outer_overhead_bytes: if settings.gate.path.client.is_ipv6() {
                49
            } else {
                29
            },
            max_record_bytes: size(value.max_record_bytes)?,
            control_arq: value.control_arq.build(),
            handshake_timeout: Duration::from_micros(value.handshake_timeout_micros),
            lifetime: Duration::from_micros(value.lifetime_micros),
            packet_slots: size(value.packet_slots)?,
            stream_bytes: size(value.stream_bytes)?,
            poll_interval: Duration::from_micros(value.poll_interval_micros),
            work_limit: size(value.work_limit)?,
            wire_budget: l2tunnel_openvpn::WireBudget {
                interval: Duration::from_micros(value.wire_budget.interval_micros),
                packets: size(value.wire_budget.packets)?,
                ip_bytes: size(value.wire_budget.ip_bytes)?,
                reserved_control_packets: size(value.wire_budget.reserved_control_packets)?,
                reserved_control_bytes: size(value.wire_budget.reserved_control_bytes)?,
                maximum_control_packets: size(value.wire_budget.maximum_control_packets)?,
            },
        };
        config.validate().map_err(io::Error::other)?;
        if config.handshake_timeout > profile.connection().handshake_timeout {
            return Err(invalid("outer handshake exceeds original setup cap"));
        }
        Ok(config)
    }
    pub(super) fn build(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
        self.build_selected(
            connection,
            settings,
            peers,
            maximum_body,
            overhead,
            None,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_raw(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
        policy: l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
        self.build_selected(
            connection,
            settings,
            peers,
            maximum_body,
            overhead,
            Some(policy),
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_proxy(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
        proxy: l2tunnel_runtime::proxy::Config,
        retained: bool,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
        self.validate_carrier(false)?;
        self.build_selected(
            connection,
            settings,
            peers,
            maximum_body,
            overhead,
            None,
            Some((proxy, retained)),
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_proxy_measured(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
        proxy: l2tunnel_runtime::proxy::measured::Config,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
        self.validate_carrier(false)?;
        self.build_selected(
            connection,
            settings,
            peers,
            maximum_body,
            overhead,
            None,
            None,
            Some(proxy),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn build_selected(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
        raw: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        proxy: Option<(l2tunnel_runtime::proxy::Config, bool)>,
        measured: Option<l2tunnel_runtime::proxy::measured::Config>,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
        if self.compact_wire.is_some() && (raw.is_some() || proxy.is_some() || measured.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compact v3 currently requires the native Common original UDP backend",
            ));
        }
        // Config shares a legacy-shaped resource container. These explicit inert
        // fields are not selected, hashed or resolved by CommonTransactionContract.
        let inert = l2tunnel_swift::policy::Direction {
            bytes_per_second: 8_000,
            records: l2tunnel_swift::records::Config {
                channels: 1,
                layer: l2tunnel_swift::records::Layer::Ip,
                max_native: 1,
                codec: l2tunnel_swift::Config {
                    datagram_bytes: 64,
                    window: 1,
                    repair_numerator: 0,
                    repair_denominator: 1,
                    flow_sources: 1,
                    queue_bytes: 16,
                    max_packet: 1,
                    flush_micros: 0,
                    feedback_micros: 1,
                    tail_micros: 1,
                    min_rto_micros: 1,
                    max_rto_micros: 1,
                },
            },
        };
        let overhead = if self.compact_wire.is_some() {
            let physical: usize = if settings.gate.path.client.is_ipv6() {
                48
            } else {
                28
            };
            physical
                .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
                .ok_or_else(|| invalid("compact control wire geometry overflow"))?
        } else {
            overhead
        };
        let mut configs = self.runtime.templates_for(
            self.initial().path_mtu(),
            inert,
            inert,
            maximum_body,
            overhead,
        )?;
        let ack = self
            .ack_coalescing
            .map(|policy| policy.build())
            .transpose()?
            .unwrap_or([None, None]);
        let rolling = self
            .rolling_ingress
            .map(|policy| policy.build())
            .transpose()?
            .unwrap_or([None, None]);
        let fragments = self
            .rolling_fragments
            .map(|policy| policy.build())
            .transpose()?;
        let connections = self
            .connection_ingress
            .map(|policy| policy.build())
            .transpose()?
            .unwrap_or([None, None]);
        for (((config, ack), rolling), connections) in
            configs.iter_mut().zip(ack).zip(rolling).zip(connections)
        {
            config.connection_ingress = connections;
            config.rolling_fragments = fragments;
            config.rolling_work = self.rolling_work;
            config.ack_coalescing = ack;
            config.rolling_ingress = rolling;
        }
        if let Some(selection) = self.compact_wire {
            return secure_udp::common_transaction_profile::Profile::new_compact(
                connection,
                settings,
                peers,
                configs[0],
                configs[1],
                self.catalog.clone(),
                self.parameters,
                selection.build()?,
            );
        }
        if let Some(policy) = raw {
            return secure_udp::common_transaction_profile::Profile::new_raw(
                connection,
                settings,
                peers,
                configs[0],
                configs[1],
                self.catalog.clone(),
                self.parameters,
                policy,
            );
        }
        if let Some(proxy) = measured {
            return secure_udp::common_transaction_profile::Profile::new_proxy_measured_retained(
                connection,
                settings,
                peers,
                configs[0],
                configs[1],
                self.catalog.clone(),
                self.parameters,
                proxy,
            );
        }
        if let Some((proxy, retained)) = proxy {
            let construct = if retained {
                secure_udp::common_transaction_profile::Profile::new_proxy_retained
            } else {
                secure_udp::common_transaction_profile::Profile::new_proxy
            };
            return construct(
                connection,
                settings,
                peers,
                configs[0],
                configs[1],
                self.catalog.clone(),
                self.parameters,
                proxy,
            );
        }
        secure_udp::common_transaction_profile::Profile::new(
            connection,
            settings,
            peers,
            configs[0],
            configs[1],
            self.catalog.clone(),
            self.parameters,
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDto {
    version: u64,
    backend: String,
    initial_index: u16,
    catalog: BoundedCatalog,
    transaction: TransactionDto,
    runtime: RuntimeDto,
    rolling_work: RequiredWork,
    #[serde(default, deserialize_with = "selected_compact_wire")]
    compact_wire: Option<crate::secure_udp::common_status::CompactWireSelection>,
    #[serde(default)]
    outer_carrier: Option<OuterCarrierDto>,
    #[serde(default, deserialize_with = "selected_ack")]
    ack_coalescing: Option<crate::secure_udp::common_status::AckPolicies>,
    #[serde(default, deserialize_with = "selected_rolling_ingress")]
    rolling_ingress: Option<crate::secure_udp::common_status::RollingIngressPolicies>,
    #[serde(default, deserialize_with = "selected_connection_ingress")]
    connection_ingress: Option<crate::secure_udp::common_status::ConnectionIngressPolicies>,
    #[serde(default, deserialize_with = "selected_fragments")]
    rolling_fragments: Option<crate::secure_udp::common_status::RollingFragments>,
}
fn selected_compact_wire<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::CompactWireSelection>, D::Error> {
    crate::secure_udp::common_status::CompactWireSelection::deserialize(deserializer).map(Some)
}
fn selected_fragments<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::RollingFragments>, D::Error> {
    crate::secure_udp::common_status::RollingFragments::deserialize(deserializer).map(Some)
}
fn selected_connection_ingress<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::ConnectionIngressPolicies>, D::Error> {
    crate::secure_udp::common_status::ConnectionIngressPolicies::deserialize(deserializer).map(Some)
}
fn selected_rolling_ingress<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::RollingIngressPolicies>, D::Error> {
    crate::secure_udp::common_status::RollingIngressPolicies::deserialize(deserializer).map(Some)
}
fn selected_ack<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::AckPolicies>, D::Error> {
    crate::secure_udp::common_status::AckPolicies::deserialize(deserializer).map(Some)
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OuterCarrierDto {
    version: u64,
    backend: String,
    max_record_bytes: u64,
    control_arq: RecoveryDto,
    handshake_timeout_micros: u64,
    lifetime_micros: u64,
    packet_slots: u64,
    stream_bytes: u64,
    poll_interval_micros: u64,
    work_limit: u64,
    wire_budget: OuterWireBudgetDto,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OuterWireBudgetDto {
    interval_micros: u64,
    packets: u64,
    ip_bytes: u64,
    reserved_control_packets: u64,
    reserved_control_bytes: u64,
    maximum_control_packets: u64,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work {
    field: u64,
    copies: u64,
    metadata: u64,
}
impl Work {
    fn build(self) -> io::Result<l2tunnel_fec::rolling::WorkBudget> {
        let convert = |value| {
            usize::try_from(value).map_err(|_| invalid("rolling work exceeds platform capacity"))
        };
        Ok(l2tunnel_fec::rolling::WorkBudget {
            field: convert(self.field)?,
            copies: convert(self.copies)?,
            metadata: convert(self.metadata)?,
        })
    }
}
struct RequiredWork(Option<Work>);
impl<'de> Deserialize<'de> for RequiredWork {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = RequiredWork;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("explicit null or complete rolling work caps")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequiredWork(None))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                Work::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(|value| RequiredWork(Some(value)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
struct DescriptorHex(Descriptor);
impl<'de> Deserialize<'de> for DescriptorHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = DescriptorHex;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("exact2544 lowercase canonical descriptor hex")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() != 2 * DESCRIPTOR_BYTES
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(E::custom("invalid descriptor hex"));
                }
                let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                let mut bytes = [0; DESCRIPTOR_BYTES];
                for (byte, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
                    *byte = nibble(pair[0]) * 16 + nibble(pair[1]);
                }
                let descriptor = Descriptor::decode(&bytes).map_err(E::custom)?;
                let mut canonical = [0; DESCRIPTOR_BYTES];
                descriptor.encode_into(&mut canonical).map_err(E::custom)?;
                if canonical != bytes {
                    return Err(E::custom("noncanonical descriptor"));
                }
                Ok(DescriptorHex(descriptor))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
struct BoundedCatalog(Vec<Descriptor>);
impl<'de> Deserialize<'de> for BoundedCatalog {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = BoundedCatalog;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("one through64 complete descriptors")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(64)
                    .map_err(|_| de::Error::custom("catalog allocation failed"))?;
                for _ in 0..64 {
                    let Some(value) = sequence.next_element::<DescriptorHex>()? else {
                        return Ok(BoundedCatalog(values));
                    };
                    values.push(value.0);
                }
                struct Extra;
                impl<'de> de::DeserializeSeed<'de> for Extra {
                    type Value = ();
                    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
                        Err(de::Error::custom("catalog exceeds64"))
                    }
                }
                let _: Option<()> = sequence.next_element_seed(Extra)?;
                Ok(BoundedCatalog(values))
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "common_cli_tests.rs"]
mod tests;
