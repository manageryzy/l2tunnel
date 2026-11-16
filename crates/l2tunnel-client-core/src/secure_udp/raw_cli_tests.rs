//! Actual frontend selection and Profile construction; no raw socket or authentication.
use super::*;
use l2tunnel::record_configuration as common;
use l2tunnel_raw_io::handoff::pairing::packet::{PacketPolicy, Protection};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct File(PathBuf);
impl File {
    fn new(value: &Value) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-raw-common-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
        Ok(Self(path))
    }
    fn text(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn descriptor(duplex: Duplex, rate: u64) -> io::Result<common::Descriptor> {
    let original = crate::secure_udp::common_status::tests::descriptor(rate)?;
    common::Descriptor::new(
        original.path_mtu(),
        duplex,
        *original
            .direction(l2tunnel_management::Role::Client)
            .common(),
        *original
            .direction(l2tunnel_management::Role::Server)
            .common(),
        *original.profile(),
    )
    .map_err(io::Error::other)
}
fn plan(duplex: Duplex) -> io::Result<Value> {
    let original = transaction_cli::test_plan_value();
    let catalog = [
        descriptor(duplex, 1_250_001)?,
        descriptor(duplex, 1_375_007)?,
    ]
    .into_iter()
    .map(|value| {
        let mut bytes = [0; common::DESCRIPTOR_BYTES];
        value.encode_into(&mut bytes).map_err(io::Error::other)?;
        Ok(bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>())
    })
    .collect::<io::Result<Vec<_>>>()?;
    Ok(
        json!({"version":1,"backend":"common_records_v2","initial_index":0,
        "catalog":catalog,"transaction":original["transaction"],"runtime":original["runtime"],"rolling_work":null}),
    )
}
fn policy(duplex: Duplex, role: &str, protection: Protection) -> Value {
    let policy = PacketPolicy {
        protection,
        ..PacketPolicy::new(1500)
    };
    let (local, peer, reverse_local, reverse_peer) = if role == "connect" {
        (
            "127.0.0.1:42351",
            "127.0.0.1:42352",
            "127.0.0.1:42353",
            "127.0.0.1:42354",
        )
    } else {
        (
            "127.0.0.1:42352",
            "127.0.0.1:42351",
            "127.0.0.1:42354",
            "127.0.0.1:42353",
        )
    };
    json!({"version":1,"profile":"raw-common-carrier-v1","forward":{"local":local,"peer":peer},
        "reverse":if duplex==Duplex::Half { json!({"local":reverse_local,"peer":reverse_peer}) } else { Value::Null },
        "packet":{"mtu":policy.mtu,"protection":if protection==Protection::ChaCha20Poly1305 {"aead"}else{"integrity"},
            "queue_packets":policy.queue_packets,"horizon_bytes":policy.horizon_bytes,
            "minimum_transfer_bytes":policy.minimum_transfer_bytes,"bytes_per_second":policy.bytes_per_second,
            "packets_per_second":policy.packets_per_second,"burst_bytes":policy.burst_bytes,
            "burst_packets":policy.burst_packets,"max_key_packets":policy.max_key_packets,"max_key_bytes":policy.max_key_bytes}})
}
fn options(
    role: &str,
    cover: &str,
    duplex: Duplex,
    plan: &File,
    raw: &File,
) -> BTreeMap<String, String> {
    let mut options = options_for(role, "raw-packet");
    for field in [
        "--udp-bind",
        "--udp-peer",
        "--swift-forward-kbit",
        "--swift-reverse-kbit",
    ] {
        options.remove(field);
    }
    for (field, value) in [
        ("--record-profile", "common"),
        ("--max-packet", "1500"),
        ("--udp-cover", cover),
        ("--raw-mark", "17"),
        (
            "--duplex",
            if duplex == Duplex::Half {
                "half"
            } else {
                "full"
            },
        ),
    ] {
        options.insert(field.into(), value.into());
    }
    options.insert("--common-transaction-plan".into(), plan.text());
    options.insert("--raw-policy".into(), raw.text());
    if role == "connect" {
        options.insert("--remote".into(), "127.0.0.1:42352".into());
        options.insert("--ca".into(), "not-opened-ca.der".into());
        options.insert("--server-name".into(), "own-server.test".into());
        options.insert("--sni".into(), "cover.example".into());
    } else {
        options.insert("--listen".into(), "127.0.0.1:42352".into());
        options.insert("--cert".into(), "not-opened-cert.der".into());
        options.insert("--key".into(), "not-opened-tls.pkcs8".into());
    }
    options
}
fn profile(
    selected: &Selected,
    options: &BTreeMap<String, String>,
) -> io::Result<Box<secure_udp::common_transaction_profile::Profile>> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    match selected.build(
        configuration(options)?,
        peers,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )? {
        Built::Records(value) => Ok(value),
        _ => Err(input("explicit raw complete plan selected another backend")),
    }
}

#[test]
fn raw_cli_full_and_half_build_actual_requested_profiles_without_effective_authority()
-> io::Result<()> {
    for (cover, duplex, protection) in [
        ("quic-like", Duplex::Full, Protection::ChaCha20Poly1305),
        ("media-like", Duplex::Half, Protection::HmacSha256),
    ] {
        let plan_file = File::new(&plan(duplex)?)?;
        let mut previous = None;
        for role in ["connect", "serve"] {
            let policy_file = File::new(&policy(duplex, role, protection))?;
            let options = options(role, cover, duplex, &plan_file, &policy_file);
            let selected = selection(role, &options, configuration(&options)?)?
                .ok_or_else(|| input("explicit raw Common selection absent"))?;
            assert!(selected.1 == Carrier::RawPacket && selected.transaction());
            let raw = selected
                .2
                .as_ref()
                .ok_or_else(|| input("selected raw policy absent"))?;
            assert_eq!(raw.mark, Some(17));
            let built = profile(&selected, &options)?;
            let actual_policy = built
                .raw_policy()
                .ok_or_else(|| input("Profile lost raw policy"))?;
            assert_eq!(actual_policy.protection, protection);
            assert_eq!(built.connection().duplex, duplex);
            assert!(built.raw_binding().is_none() && built.carrier_binding().is_none());
            assert_eq!(
                built.initial().descriptor(),
                &descriptor(duplex, 1_250_001)?
            );
            assert_eq!(built.catalog().descriptors().len(), 2);
            for side in [security::Role::Initiator, security::Role::Responder] {
                assert!(built.runtime_contract(side).is_err());
            }
            built.validate_raw_request()?;
            let identity = (built.configuration()?, built.envelope(), built.initial());
            if let Some(previous) = previous {
                assert_eq!(identity, previous);
            }
            previous = Some(identity);
            let mut offline = options.clone();
            for field in [
                "--device",
                "--session-admission-key-file",
                "--session-cookie-key-file",
                "--raw-mark",
                "--remote",
                "--listen",
            ] {
                offline.remove(field);
            }
            let inspected = selection_for(role, &offline, configuration(&offline)?, true)?
                .ok_or_else(|| input("offline raw selection absent"))?;
            let offline_profile = profile(&inspected, &offline)?;
            assert_eq!(offline_profile.configuration()?, built.configuration()?);
            let values = common_cli_output::raw_inspection(
                &offline_profile,
                inspected.common().role,
                &inspected
                    .2
                    .as_ref()
                    .ok_or_else(|| input("offline raw policy absent"))?
                    .settings,
            )?;
            let values =
                common_cli_output::requested_tls(values, tls_frontend::requested(&offline)?)?;
            let header = &values[0];
            assert_eq!(header["carrier"], "raw-packet");
            assert_eq!(header["authenticated"], false);
            assert_eq!(header["catalog_members"], 2);
            assert_eq!(values.len(), 2);
            for field in [
                "effective_configuration",
                "effective_envelope",
                "effective_catalog",
            ] {
                assert!(header[field].is_null());
            }
            assert_eq!(header["authenticated_outer_binding_required"], true);
            assert_eq!(
                header["outer_policy"]["duplex"],
                if duplex == Duplex::Half {
                    "half"
                } else {
                    "full"
                }
            );
            assert_eq!(header["outer_policy"]["ip_tcp_bytes"], 40);
            assert_eq!(
                header["outer_policy"]["record_overhead_bytes"],
                if protection == Protection::ChaCha20Poly1305 {
                    112
                } else {
                    128
                }
            );
            if role == "connect" {
                assert_eq!(
                    header["tls_name_policy"]["requested"]["sni"],
                    "cover.example"
                );
                assert_eq!(
                    header["tls_name_policy"]["requested"]["verification_name"],
                    "own-server.test"
                );
                tls_frontend::preflight("inspect-common-transaction-plan", &{
                    let mut v = offline.clone();
                    v.insert("--role".into(), "connect".into());
                    v
                })?;
            }
        }
    }
    Ok(())
}

#[test]
fn raw_cli_rejects_shape_mark_tuple_and_legacy_policy_before_any_runtime_open() -> io::Result<()> {
    let plan_file = File::new(&plan(Duplex::Half)?)?;
    let policy_file = File::new(&policy(
        Duplex::Half,
        "connect",
        Protection::ChaCha20Poly1305,
    ))?;
    let options = options(
        "connect",
        "quic-like",
        Duplex::Half,
        &plan_file,
        &policy_file,
    );
    for (field, value) in [
        ("--raw-mark", Some("0")),
        ("--raw-mark", None),
        ("--udp-cover", None),
        ("--duplex", Some("full")),
        ("--remote", Some("127.0.0.1:49999")),
        ("--udp-bind", Some("127.0.0.1:42351")),
        ("--admission-key-file", Some("must-not-be-opened")),
    ] {
        let mut changed = options.clone();
        if let Some(value) = value {
            changed.insert(field.into(), value.into());
        } else {
            changed.remove(field);
        }
        let error = selection("connect", &changed, configuration(&changed)?)
            .err()
            .ok_or_else(|| input(format!("accepted invalid raw input {field}")))?;
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "{field}: {error}"
        );
    }
    let mut offline = options.clone();
    for field in [
        "--device",
        "--session-admission-key-file",
        "--raw-mark",
        "--remote",
    ] {
        offline.remove(field);
    }
    offline.insert("--raw-mark".into(), "17".into());
    assert!(selection_for("connect", &offline, configuration(&offline)?, true).is_err());
    let mut legacy = policy(Duplex::Half, "connect", Protection::ChaCha20Poly1305);
    legacy["recovery"] = json!({"kind":"none"});
    let invalid = File::new(&legacy)?;
    let mut changed = options;
    changed.insert("--raw-policy".into(), invalid.text());
    assert!(selection("connect", &changed, configuration(&changed)?).is_err());
    let old = BTreeMap::from([("--carrier".into(), "raw-packet".into())]);
    let configuration = ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1500,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    assert!(selection("connect", &old, configuration)?.is_none());
    Ok(())
}
