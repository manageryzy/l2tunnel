//! Complete Common CLI plans reuse resource parsing, without inventing Swift policies.
use super::transaction_cli::{RuntimeDto, TransactionDto, read_document};
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
        Ok(Self {
            catalog: Catalog::new(initial, &dto.catalog.0).map_err(io::Error::other)?,
            parameters: dto.transaction.build(),
            runtime: dto.runtime,
            rolling_work: dto.rolling_work.0.map(|value| value.build()).transpose()?,
        })
    }
    pub(super) fn initial(&self) -> Descriptor {
        self.catalog.initial()
    }
    pub(super) fn report_interval(&self) -> Option<Duration> {
        self.runtime.report_interval()
    }
    pub(super) fn build(
        &self,
        connection: ConnectionConfig,
        settings: secure_udp::Settings,
        peers: establish::Peers,
        maximum_body: usize,
        overhead: usize,
    ) -> io::Result<secure_udp::common_transaction_profile::Profile> {
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
        let mut configs = self.runtime.templates_for(
            self.initial().path_mtu(),
            inert,
            inert,
            maximum_body,
            overhead,
        )?;
        for config in &mut configs {
            config.rolling_work = self.rolling_work;
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
