//! File/schema and actual Profile evidence, without authentication or runtime I/O.

use super::*;
use crate::{Compression, cli::secure_udp_frontend::Selection};
use l2tunnel_core::{ConfigDigest, Duplex};
use l2tunnel_device::PacketLayer;
use l2tunnel_handshake as hs;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-transaction-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.0.join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?
            .write_all(bytes)?;
        Ok(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn direction(forward: bool) -> Value {
    json!({
        "channels": if forward { 2 } else { 3 },
        "layer": "ip", "max_native": 1500,
        "bytes_per_second": if forward { 1_250_001 } else { 625_013 },
        "datagram_bytes": if forward { 1200 } else { 1024 },
        "window": if forward { 7 } else { 11 },
        "repair_numerator": if forward { 1 } else { 2 },
        "repair_denominator": if forward { 3 } else { 7 },
        "flow_sources": 64, "queue_bytes": 8192,
        "max_packet": 1500 + l2tunnel_swift::header::MAX_EXPANSION,
        "flush_micros": if forward { 123 } else { 321 },
        "feedback_micros": if forward { 5003 } else { 5007 },
        "tail_micros": if forward { 10001 } else { 10009 },
        "min_rto_micros": if forward { 20003 } else { 20011 },
        "max_rto_micros": if forward { 1_000_007 } else { 1_000_009 },
    })
}

/// Complete test witness only; this is not a product default or sample fallback.
pub(super) fn plan_value() -> Value {
    let initial = json!({"path_mtu":1500,"forward":direction(true),"reverse":direction(false)});
    let mut target = initial.clone();
    target["path_mtu"] = json!(1600);
    target["forward"]["channels"] = json!(4);
    target["reverse"]["channels"] = json!(1);
    target["forward"]["bytes_per_second"] = json!(1_375_007);
    target["reverse"]["bytes_per_second"] = json!(575_011);
    target["forward"]["datagram_bytes"] = json!(1280);
    target["reverse"]["datagram_bytes"] = json!(1100);
    let message = json!({
        "max_message_bytes":4096,"max_outbound_messages":4,
        "max_outbound_bytes":131072,"max_fragments":32,
        "max_reassembly_bytes":16384,"max_incomplete_messages":2,
        "message_lifetime_micros":5_000_000,"work_per_call":8,
    });
    json!({
        "version":1,"backend":"generic_swift_v1","initial_index":0,
        "catalog":[initial,target],
        "transaction":{"retry_ms":10,"phase_timeout_ms":500,"reconcile_timeout_ms":1000,
            "max_operation_ms":1500,"retained_bytes":64*1024*1024},
        "runtime":{
            "control_epoch":1,"data_epoch":1,
            "legacy_policy":{"transaction_micros":10_000_000,"max_outbound":32},
            "security":{"packets_per_key":security::MAX_PACKETS_PER_KEY,
                "max_body_bytes_per_key":security::MAX_BODY_BYTES_PER_KEY},
            "control":{
                "recovery":{"max_source_bytes":256,"send_bytes":2048,"receive_bytes":2048,
                    "send_records":8,"receive_records":8,"initial_rto_micros":10000,
                    "maximum_rto_micros":100000,"ack_delay_micros":1000,"max_retries":32},
                "interval_micros":10000,"packets_per_interval":4,"bytes_per_interval":4096},
            "streams":{"transaction":message.clone(),"liveness":message.clone(),"data_feedback":message},
            "wire":{"initiator_burst_bytes":8192,"responder_burst_bytes":6144},
            "work":{"receive_interval_micros":1000,"receive_packets":256,
                "send_batch":64,"native_read_batch":64,"native_write_batch":64},
            "native":{"pending_packets":64,"pending_bytes":96000,"stall_timeout_micros":10_000_000},
            "lifetime":{"lease_micros":60_000_000,"ping_interval_micros":1_000_000,
                "pong_timeout_micros":5_000_000},
            "report_interval_micros":null,
        },
    })
}

struct Inputs {
    connection: ConnectionConfig,
    raw: secure_udp::Settings,
    peers: establish::Peers,
    maximum_body: usize,
    overhead: usize,
}
impl Inputs {
    fn new(kind: l2tunnel_cover::Appearance) -> Result<Self> {
        let peers = establish::Peers {
            initiator: hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
            responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
        };
        let connection = ConnectionConfig {
            layer: PacketLayer::Ip,
            duplex: Duplex::Full,
            max_packet: 1500,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(3),
        };
        // Reuse the established public geometry fixture, then replace its derived
        // application value with an independent original seed before generic build.
        let legacy = Selection {
            appearance: kind,
            role: security::Role::Initiator,
            local: "127.0.0.1:41921".parse()?,
            peer: "127.0.0.1:41922".parse()?,
            policy: l2tunnel_swift::control::Policy {
                path_mtu: 1500,
                forward_kbit: 10000,
                reverse_kbit: 5000,
                channels: 4,
                window: 32,
                repair_permille: 0,
            },
            maximum_mtu: 2000,
            profile: hs::Profile::Ik,
            report: None,
        }
        .build(
            connection,
            peers,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let runtime = legacy.runtime(security::Role::Initiator);
        let mut raw = legacy.settings();
        raw.application = ConfigDigest([0x31; 32]);
        Ok(Self {
            connection,
            raw,
            peers,
            maximum_body: runtime.security.max_body_bytes,
            overhead: runtime.control.wire_overhead,
        })
    }
    fn build(&self, value: &Value) -> io::Result<transaction_profile::Profile> {
        Plan::decode(&serde_json::to_vec(value).map_err(io::Error::other)?)?.build(
            self.connection,
            self.raw,
            self.peers,
            self.maximum_body,
            self.overhead,
        )
    }
}

fn decode(value: &Value) -> io::Result<Plan> {
    Plan::decode(&serde_json::to_vec(value).map_err(io::Error::other)?)
}
fn objects(value: &Value, path: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(entries) => {
            output.push(path.to_owned());
            for (key, value) in entries {
                objects(value, &format!("{path}/{key}"), output);
            }
        }
        Value::Array(entries) => {
            for (index, value) in entries.iter().enumerate() {
                objects(value, &format!("{path}/{index}"), output);
            }
        }
        _ => {}
    }
}
fn numbers(value: &Value, path: &str, output: &mut Vec<String>) {
    match value {
        Value::Number(_) => output.push(path.to_owned()),
        Value::Object(entries) => {
            for (key, value) in entries {
                numbers(value, &format!("{path}/{key}"), output);
            }
        }
        Value::Array(entries) => {
            for (index, value) in entries.iter().enumerate() {
                numbers(value, &format!("{path}/{index}"), output);
            }
        }
        _ => {}
    }
}

#[test]
fn regular_reader_is_bounded_and_refuses_special_files_before_reading() -> Result {
    let temp = Temp::new()?;
    let encoded = serde_json::to_vec(&plan_value())?;
    let path = temp.write("plan", &encoded)?;
    assert_eq!(Plan::read(&path)?.initial().path_mtu(), 1500);
    let mut exact = encoded.clone();
    exact.resize(MAX_PLAN_BYTES, b' ');
    std::fs::write(&path, &exact)?;
    assert!(Plan::read(&path).is_ok());
    exact.push(b' ');
    std::fs::write(&path, &exact)?;
    assert!(Plan::read(&path).is_err());
    for bad in [
        Vec::new(),
        vec![0xff],
        encoded[..encoded.len() - 1].to_vec(),
        [encoded.as_slice(), b"{}"].concat(),
    ] {
        std::fs::write(&path, bad)?;
        assert!(Plan::read(&path).is_err());
    }
    let link = temp.0.join("link");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(Plan::read(&link).is_err());
    assert!(Plan::read(&temp.0).is_err());
    assert!(Plan::read(Path::new("/dev/null")).is_err());
    let fifo = temp.0.join("fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    assert!(Plan::read(&fifo).is_err());
    Ok(())
}

#[test]
fn every_object_requires_all_fields_and_rejects_unknown_fields() -> Result {
    let original = plan_value();
    let mut paths = Vec::new();
    objects(&original, "", &mut paths);
    for path in paths {
        let keys: Vec<_> = original
            .pointer(&path)
            .and_then(Value::as_object)
            .ok_or("fixture object")?
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut value = original.clone();
            value
                .pointer_mut(&path)
                .and_then(Value::as_object_mut)
                .ok_or("fixture object")?
                .remove(&key);
            assert!(decode(&value).is_err(), "missing {path}/{key}");
        }
        let mut value = original.clone();
        value
            .pointer_mut(&path)
            .and_then(Value::as_object_mut)
            .ok_or("fixture object")?
            .insert(
                "unknown_secret_path".into(),
                json!("must-not-appear-in-error"),
            );
        let error = match decode(&value) {
            Err(error) => error,
            Ok(_) => return Err("unknown field accepted".into()),
        };
        assert!(!error.to_string().contains("must-not-appear"));
        assert!(!error.to_string().contains("unknown_secret_path"));
    }
    Ok(())
}

#[test]
fn every_object_rejects_duplicate_fields() -> Result {
    let original = plan_value();
    let mut paths = Vec::new();
    objects(&original, "", &mut paths);
    let complete = serde_json::to_string(&original)?;
    for path in paths {
        let value = original.pointer(&path).ok_or("fixture pointer")?;
        let object = value.as_object().ok_or("fixture object")?;
        let (key, field) = object.iter().next().ok_or("fixture field")?;
        let normal = serde_json::to_string(value)?;
        let duplicate = format!(
            "{{{}:{},{}",
            serde_json::to_string(key)?,
            serde_json::to_string(field)?,
            normal.strip_prefix('{').ok_or("fixture object encoding")?
        );
        let bytes = complete.replacen(&normal, &duplicate, 1);
        assert!(
            Plan::decode(bytes.as_bytes()).is_err(),
            "duplicate in {path}"
        );
    }
    Ok(())
}

#[test]
fn numeric_schema_never_coerces_or_saturates() -> Result {
    let original = plan_value();
    let mut paths = Vec::new();
    numbers(&original, "", &mut paths);
    for path in paths {
        for bad in [json!(-1), json!(1.0), json!("1"), Value::Null, json!(true)] {
            let mut value = original.clone();
            *value.pointer_mut(&path).ok_or("fixture number")? = bad;
            assert!(
                decode(&value).is_err(),
                "invalid numeric representation {path}"
            );
        }
        let mut value = original.clone();
        *value.pointer_mut(&path).ok_or("fixture number")? = json!("overflow-witness");
        let encoded = serde_json::to_string(&value)?.replacen(
            "\"overflow-witness\"",
            "18446744073709551616",
            1,
        );
        assert!(
            Plan::decode(encoded.as_bytes()).is_err(),
            "u64 overflow {path}"
        );
    }
    let parsed = serde_json::from_str::<Size>("18446744073709551615");
    assert_eq!(parsed.is_ok(), usize::try_from(u64::MAX).is_ok());
    for path in [
        "/catalog/0/forward/repair_numerator",
        "/catalog/0/reverse/repair_denominator",
        "/runtime/control/packets_per_interval",
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).ok_or("u32 fixture")? = json!(u64::from(u32::MAX) + 1);
        assert!(decode(&value).is_err());
    }
    for path in [
        "/runtime/control/recovery/max_retries",
        "/runtime/streams/liveness/max_fragments",
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).ok_or("u16 fixture")? = json!(u32::from(u16::MAX) + 1);
        assert!(decode(&value).is_err());
    }
    let mut value = original;
    value["runtime"]["work"]["receive_packets"] = json!(u64::from(u32::MAX) + 1);
    assert!(
        Inputs::new(l2tunnel_cover::Appearance::QuicLike)?
            .build(&value)
            .is_err()
    );
    Ok(())
}

#[test]
fn report_is_required_nullable_and_retained_without_a_default() -> Result {
    let value = plan_value();
    assert_eq!(decode(&value)?.report_interval(), None);
    let mut changed = value.clone();
    changed["runtime"]["report_interval_micros"] = json!(12345);
    assert_eq!(
        decode(&changed)?.report_interval(),
        Some(Duration::from_micros(12345))
    );
    changed["runtime"]
        .as_object_mut()
        .ok_or("runtime object")?
        .remove("report_interval_micros");
    assert!(decode(&changed).is_err());
    for bad in [
        json!(-1),
        json!(1.0),
        json!("1"),
        json!(false),
        json!([]),
        json!({}),
    ] {
        changed["runtime"]["report_interval_micros"] = bad;
        assert!(decode(&changed).is_err());
    }
    Ok(())
}

#[test]
fn version_backend_layer_and_top_level_are_explicit() -> Result {
    for bad in [json!([]), json!(null), json!(true), json!("plan")] {
        assert!(decode(&bad).is_err());
    }
    for (path, bad) in [
        ("/version", json!(0)),
        ("/version", json!(2)),
        ("/backend", json!("legacy")),
        ("/catalog/0/forward/layer", json!("tun")),
    ] {
        let mut value = plan_value();
        *value.pointer_mut(path).ok_or("fixture value")? = bad;
        assert!(decode(&value).is_err());
    }
    Ok(())
}

fn catalog64() -> Value {
    let mut value = plan_value();
    let source = value["catalog"][0].clone();
    let values: Vec<_> = (0..64_u64)
        .map(|index| {
            let mut member = source.clone();
            member["forward"]["bytes_per_second"] = json!(1_250_001 + index);
            member["reverse"]["bytes_per_second"] = json!(625_013 + 3 * index);
            member
        })
        .collect();
    value["catalog"] = json!(values);
    value["initial_index"] = json!(37);
    value["catalog"][63]["forward"]["channels"] = json!(l2tunnel_swift::MAX_CHANNELS);
    value["catalog"][63]["reverse"]["channels"] = json!(l2tunnel_swift::MAX_CHANNELS);
    value
}

#[test]
fn complete_catalog_limits_initial_index_and_duplicates_are_not_pruned() -> Result {
    let value = catalog64();
    let encoded = serde_json::to_vec_pretty(&value)?;
    assert!(encoded.len() < MAX_PLAN_BYTES);
    let plan = Plan::decode(&encoded)?;
    let temp = Temp::new()?;
    let path = temp.write("all64", &encoded)?;
    assert_eq!(Plan::read(&path)?.catalog, plan.catalog);
    assert_eq!(plan.catalog.descriptors().len(), 64);
    assert_eq!(plan.initial().forward().bytes_per_second, 1_250_038);
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let profile = Inputs::new(kind)?.build(&value)?;
        assert_eq!(profile.catalog().descriptors().len(), 64);
        assert_eq!(
            profile.catalog().configurations(profile.envelope()).len(),
            64
        );
        for member in profile.catalog().configurations(profile.envelope()) {
            for role in [security::Role::Initiator, security::Role::Responder] {
                profile.runtime_for(member, role)?;
            }
        }
    }
    for (catalog, index) in [
        (json!([]), 0),
        (json!([value["catalog"][0].clone()]), 1),
        (
            json!([value["catalog"][0].clone(), value["catalog"][0].clone()]),
            0,
        ),
    ] {
        let mut bad = value.clone();
        bad["catalog"] = catalog;
        bad["initial_index"] = json!(index);
        assert!(decode(&bad).is_err());
    }
    let mut excess = value["catalog"].as_array().ok_or("catalog")?.clone();
    excess.push(json!("must-not-deserialize-a-65th-descriptor"));
    let error = match serde_json::from_value::<BoundedCatalog>(json!(excess)) {
        Err(error) => error,
        Ok(_) => return Err("65th entry accepted".into()),
    };
    assert!(error.to_string().contains("exceeds64"));
    Ok(())
}

#[test]
fn noninitial_maximum_width_requires_complete_fence_capacity_in_both_directions() -> Result {
    let input = Inputs::new(l2tunnel_cover::Appearance::QuicLike)?;
    let mut narrow = plan_value();
    narrow["runtime"]["streams"]["transaction"]["max_message_bytes"] = json!(600);
    assert!(input.build(&narrow).is_ok());
    let mut complete = catalog64();
    assert!(input.build(&complete).is_ok());
    complete["runtime"]["streams"]["transaction"]["max_message_bytes"] = json!(600);
    assert!(input.build(&complete).is_err());
    Ok(())
}

#[test]
fn canonical_catalog_and_graph_ignore_file_order_and_whitespace() -> Result {
    let value = plan_value();
    let mut reordered = value.clone();
    reordered["catalog"]
        .as_array_mut()
        .ok_or("catalog")?
        .reverse();
    reordered["initial_index"] = json!(1);
    let original = decode(&value)?;
    let changed = decode(&reordered)?;
    assert_eq!(original.catalog, changed.catalog);
    let explicit = format!(
        "{{\n\"runtime\":{},\"transaction\":{},\"catalog\":{},\"initial_index\":0,\"backend\":\"generic_swift_v1\",\"version\":1\n}}",
        value["runtime"], value["transaction"], value["catalog"]
    );
    assert_eq!(Plan::decode(explicit.as_bytes())?.catalog, original.catalog);
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let input = Inputs::new(kind)?;
        let first = input.build(&value)?;
        let second = input.build(&reordered)?;
        assert_eq!(first.envelope(), second.envelope());
        assert_eq!(first.initial(), second.initial());
        assert_eq!(first.data_digest(), second.data_digest());
        assert_eq!(first.configuration()?, second.configuration()?);
    }
    Ok(())
}

#[test]
fn exact_asymmetric_templates_and_resources_resolve_under_both_covers_and_roles() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let input = Inputs::new(kind)?;
        let value = plan_value();
        let profile = input.build(&value)?;
        let a = profile.runtime_for(profile.initial(), security::Role::Initiator)?;
        let b = profile.runtime_for(profile.initial(), security::Role::Responder)?;
        assert_eq!(a.send, b.receive);
        assert_eq!(a.receive, b.send);
        assert_eq!(a.send.bytes_per_second, 1_250_001);
        assert_eq!(a.receive.bytes_per_second, 625_013);
        assert_eq!(a.send.records.channels, 2);
        assert_eq!(a.receive.records.channels, 3);
        assert_eq!(a.send.records.codec.repair_numerator, 1);
        assert_eq!(a.send.records.codec.repair_denominator, 3);
        assert_eq!(a.receive.records.codec.repair_numerator, 2);
        assert_eq!(a.receive.records.codec.repair_denominator, 7);
        assert_eq!(a.send.records.codec.window, 7);
        assert_eq!(a.receive.records.codec.window, 11);
        assert_eq!(a.send.records.codec.flow_sources, 64);
        assert_eq!(a.send.records.codec.queue_bytes, 8192);
        assert_eq!(
            a.send.records.codec.max_packet,
            1500 + l2tunnel_swift::header::MAX_EXPANSION
        );
        assert_eq!(a.send.records.codec.datagram_bytes, 1200);
        assert_eq!(a.receive.records.codec.datagram_bytes, 1024);
        assert_eq!(a.send.records.codec.flush_micros, 123);
        assert_eq!(a.receive.records.codec.flush_micros, 321);
        assert_eq!(a.send.records.codec.feedback_micros, 5003);
        assert_eq!(a.receive.records.codec.feedback_micros, 5007);
        assert_eq!(a.send.records.codec.tail_micros, 10001);
        assert_eq!(a.receive.records.codec.tail_micros, 10009);
        assert_eq!(a.send.records.codec.min_rto_micros, 20003);
        assert_eq!(a.receive.records.codec.min_rto_micros, 20011);
        assert_eq!(a.send.records.codec.max_rto_micros, 1_000_007);
        assert_eq!(a.receive.records.codec.max_rto_micros, 1_000_009);
        assert_eq!(a.send.records.layer, records::Layer::Ip);
        assert_eq!(a.send.records.max_native, 1500);
        assert_eq!(
            a.policy,
            policy::Settings {
                transaction_micros: 10_000_000,
                max_outbound: 32
            }
        );
        assert_eq!(a.security.max_body_bytes, input.maximum_body);
        assert_eq!(a.security.packets_per_key, security::MAX_PACKETS_PER_KEY);
        assert_eq!(
            a.security.max_body_bytes_per_key,
            security::MAX_BODY_BYTES_PER_KEY
        );
        assert_eq!(
            a.control.recovery,
            l2tunnel_recovery::ArqConfig {
                max_source_bytes: 256,
                send_bytes: 2048,
                receive_bytes: 2048,
                send_records: 8,
                receive_records: 8,
                initial_rto: Duration::from_micros(10000),
                maximum_rto: Duration::from_micros(100000),
                ack_delay: Duration::from_micros(1000),
                max_retries: 32
            }
        );
        assert_eq!(a.control.interval, Duration::from_micros(10000));
        assert_eq!(a.control.packets_per_interval, 4);
        assert_eq!(a.control.bytes_per_interval, 4096);
        assert_eq!(a.control.wire_overhead, input.overhead);
        let streams = a.streams.ok_or("actual streams")?;
        for stream in streams.streams {
            assert_eq!(
                stream.delivery,
                delivery::Settings {
                    wire_overhead: input.overhead + control_streams::HEADER_BYTES,
                    ..a.control
                }
            );
            assert_eq!(stream.path_mtu, 1500);
            assert_eq!(stream.max_message_bytes, 4096);
            assert_eq!(stream.max_outbound_messages, 4);
            assert_eq!(stream.max_outbound_bytes, 131072);
            assert_eq!(stream.max_fragments, 32);
            assert_eq!(stream.max_reassembly_bytes, 16384);
            assert_eq!(stream.max_incomplete_messages, 2);
            assert_eq!(stream.message_lifetime, Duration::from_secs(5));
            assert_eq!(stream.work_per_call, 8);
        }
        assert_eq!(a.control_epoch.0, 1);
        assert_eq!(a.data_epoch.0, 1);
        assert_eq!(a.wire.burst_bytes, 8192);
        assert_eq!(b.wire.burst_bytes, 6144);
        assert_eq!(
            a.work,
            transport::WorkBudget {
                receive_interval: Duration::from_micros(1000),
                receive_packets: 256,
                send_batch: 64,
                native_read_batch: 64,
                native_write_batch: 64
            }
        );
        assert_eq!(
            a.native,
            transport::NativeBudget {
                pending_packets: 64,
                pending_bytes: 96000,
                stall_timeout: Duration::from_secs(10)
            }
        );
        assert_eq!(
            a.lifetime,
            transport::Lifetime {
                lease: Duration::from_secs(60),
                ping_interval: Duration::from_secs(1),
                pong_timeout: Duration::from_secs(5)
            }
        );
        assert_eq!(a.report_interval, None);
        assert_eq!(b.report_interval, None);
        assert_eq!(
            profile.parameters(),
            Parameters {
                protocol: transaction::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 500,
                    reconcile_timeout_ms: 1000
                },
                max_operation_ms: 1500,
                retained_bytes: 64 * 1024 * 1024
            }
        );
        let direct = transaction_profile::Profile::new(
            input.connection,
            input.raw,
            input.peers,
            a,
            b,
            profile.catalog().clone(),
            profile.parameters(),
        )?;
        assert_eq!(direct.envelope(), profile.envelope());
        assert_eq!(direct.initial(), profile.initial());
        assert_eq!(direct.data_digest(), profile.data_digest());
        assert_eq!(direct.configuration()?, profile.configuration()?);
        for member in profile.catalog().configurations(profile.envelope()) {
            let client = profile.runtime_for(member, security::Role::Initiator)?;
            let server = profile.runtime_for(member, security::Role::Responder)?;
            assert_eq!(client.send, member.descriptor().forward());
            assert_eq!(server.send, member.descriptor().reverse());
            assert_eq!(client.send, server.receive);
            assert_eq!(client.receive, server.send);
        }
    }
    Ok(())
}

#[test]
fn report_only_changes_local_cadence_while_catalog_resources_and_raw_seed_bind_actual_graph()
-> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let input = Inputs::new(kind)?;
        let original = plan_value();
        let profile = input.build(&original)?;
        let mut report = original.clone();
        report["runtime"]["report_interval_micros"] = json!(12345);
        let local = input.build(&report)?;
        assert_eq!(profile.envelope(), local.envelope());
        assert_eq!(profile.data_digest(), local.data_digest());
        assert_eq!(profile.configuration()?, local.configuration()?);
        for role in [security::Role::Initiator, security::Role::Responder] {
            assert_eq!(
                local.runtime_for(local.initial(), role)?.report_interval,
                Some(Duration::from_micros(12345))
            );
        }
        for path in [
            "/transaction/max_operation_ms",
            "/runtime/native/pending_bytes",
            "/catalog/1/forward/bytes_per_second",
        ] {
            let mut changed = original.clone();
            let field = changed.pointer_mut(path).ok_or("graph field")?;
            *field = json!(field.as_u64().ok_or("graph integer")? + 1);
            let next = input.build(&changed)?;
            assert_ne!(next.envelope(), profile.envelope());
            assert_ne!(next.data_digest(), profile.data_digest());
            assert_ne!(next.configuration()?, profile.configuration()?);
        }
        let mut raw = input.raw;
        raw.application = ConfigDigest([0x32; 32]);
        let next = decode(&original)?.build(
            input.connection,
            raw,
            input.peers,
            input.maximum_body,
            input.overhead,
        )?;
        assert_eq!(next.catalog().root(), profile.catalog().root());
        assert_ne!(next.envelope(), profile.envelope());
        assert_ne!(next.configuration()?, profile.configuration()?);
        let mut peers = input.peers;
        peers.responder = hs::LocalSecret::new(Zeroizing::new([33; 32])).public_key();
        let next = decode(&original)?.build(
            input.connection,
            input.raw,
            peers,
            input.maximum_body,
            input.overhead,
        )?;
        assert_eq!(next.catalog().root(), profile.catalog().root());
        assert_ne!(next.envelope(), profile.envelope());
        assert_ne!(next.configuration()?, profile.configuration()?);
        let mut raw = input.raw;
        raw.member = l2tunnel_identity::MemberPublicKey([8; 32]);
        let next = decode(&original)?.build(
            input.connection,
            raw,
            input.peers,
            input.maximum_body,
            input.overhead,
        )?;
        assert_eq!(next.catalog().root(), profile.catalog().root());
        assert_ne!(next.envelope(), profile.envelope());
        assert_ne!(next.configuration()?, profile.configuration()?);
    }
    Ok(())
}

#[test]
fn actual_profile_refuses_incompatible_geometry_resources_and_partial_catalogs() -> Result {
    let input = Inputs::new(l2tunnel_cover::Appearance::QuicLike)?;
    let original = plan_value();
    for (path, bad) in [
        ("/runtime/control_epoch", json!(0)),
        ("/runtime/data_epoch", json!(0)),
        ("/transaction/retained_bytes", json!(0)),
        ("/transaction/phase_timeout_ms", json!(0)),
        ("/runtime/streams/transaction/max_message_bytes", json!(10)),
        ("/runtime/wire/initiator_burst_bytes", json!(0)),
        ("/runtime/report_interval_micros", json!(0)),
        ("/catalog/1/path_mtu", json!(9001)),
        ("/catalog/1/forward/datagram_bytes", json!(1900)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).ok_or("negative field")? = bad;
        assert!(
            input.build(&changed).is_err(),
            "invalid actual contract {path}"
        );
    }
    // The descriptor remains internally valid; only the actual fixed native
    // attachment makes this noninitial catalog member inadmissible.
    let mut changed = original.clone();
    for direction in ["forward", "reverse"] {
        changed["catalog"][1][direction]["max_native"] = json!(1499);
        changed["catalog"][1][direction]["max_packet"] =
            json!(1499 + l2tunnel_swift::header::MAX_EXPANSION);
    }
    assert!(decode(&changed).is_ok());
    assert!(input.build(&changed).is_err());
    let plan = decode(&original)?;
    let mut raw = input.raw;
    raw.gate.path_mtu += 1;
    assert!(
        plan.build(
            input.connection,
            raw,
            input.peers,
            input.maximum_body,
            input.overhead
        )
        .is_err()
    );
    assert!(
        plan.build(input.connection, input.raw, input.peers, 0, input.overhead)
            .is_err()
    );
    assert!(
        plan.build(
            input.connection,
            input.raw,
            input.peers,
            input.maximum_body,
            usize::MAX
        )
        .is_err()
    );
    let mut native = input.connection;
    native.max_packet = 1499;
    assert!(
        plan.build(
            native,
            input.raw,
            input.peers,
            input.maximum_body,
            input.overhead
        )
        .is_err()
    );
    let mut layer = input.connection;
    layer.layer = PacketLayer::Ethernet;
    assert!(
        plan.build(
            layer,
            input.raw,
            input.peers,
            input.maximum_body,
            input.overhead
        )
        .is_err()
    );
    let mut half = input.connection;
    half.duplex = Duplex::Half;
    assert!(
        plan.build(
            half,
            input.raw,
            input.peers,
            input.maximum_body,
            input.overhead
        )
        .is_err()
    );
    Ok(())
}
