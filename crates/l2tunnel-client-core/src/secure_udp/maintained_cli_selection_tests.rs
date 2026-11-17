//! Maintained CLI selects a complete requested profile without I/O authority.
use super::*;
use l2tunnel::record_configuration as common;
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
            "l2tunnel-maintained-common-cli-{}-{}",
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
    let original = common_plan_fixture::template();
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

#[test]
fn maintained_cli_binds_complete_tls_quic_catalog_and_refuses_incompatible_selection()
-> io::Result<()> {
    for carrier in ["tcp", "quic"] {
        let mut document = plan(Duplex::Full)?;
        document["compact_wire"] = json!({"version":3,"data_protection":"aes-ccm-4","max_forward_packets":8192,"max_failed_checks":64});
        let plan_file = File::new(&document)?;
        let quic = carrier == "quic";
        let policy = json!({"version":1,"first":{"client":"127.0.0.1:42351","server":"127.0.0.1:42352"},"second":null,
            "geometry":{"path_mtu":1500,"max_record_bytes":if quic{1344}else{1430},"max_bootstrap_bytes":if quic{1296}else{1430},
            "charged_overhead_bytes":if quic{156}else{70},"bootstrap_overhead_bytes":if quic{204}else{70},"framing_bytes":if quic{0}else{5}},
            "transport":if quic {json!({"kind":"quic","application_id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"queued_datagrams":8,"control_window_bytes":16384,"idle_timeout_micros":30000000,"io_timeout_micros":2000000})}
                else {json!({"kind":"tls","record_timeout_micros":2000000})}});
        let policy_file = File::new(&policy)?;
        let mut previous = None;
        for role in ["connect", "serve"] {
            let mut options = options_for(role, carrier);
            for key in [
                "--udp-bind",
                "--udp-peer",
                "--swift-forward-kbit",
                "--swift-reverse-kbit",
            ] {
                options.remove(key);
            }
            options.insert("--record-profile".into(), "common".into());
            options.insert("--max-packet".into(), "1500".into());
            options.insert("--udp-cover".into(), "quic-like".into());
            options.insert("--common-transaction-plan".into(), plan_file.text());
            options.insert("--maintained-policy".into(), policy_file.text());
            if role == "connect" {
                options.insert("--remote".into(), "127.0.0.1:42352".into());
                options.insert("--ca".into(), "absent-root".into());
                options.insert("--server-name".into(), "own-server.test".into());
                if !quic {
                    options.insert("--sni".into(), "cover.example".into());
                }
            } else {
                options.insert("--listen".into(), "127.0.0.1:42352".into());
                options.insert("--cert".into(), "absent-cert".into());
                options.insert("--key".into(), "absent-key".into());
            }
            let connection = configuration(&options)?;
            let selected = selection(role, &options, connection)?
                .ok_or_else(|| input("maintained selection absent"))?;
            let peers = establish::Peers {
                initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
                responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
            };
            let Built::Records(profile) = selected.build(
                connection,
                peers,
                l2tunnel_identity::MemberPublicKey([7; 32]),
            )?
            else {
                return Err(input("maintained backend lost"));
            };
            assert_eq!(profile.catalog().descriptors().len(), 2);
            if quic {
                assert_eq!(profile.settings().cover.max_packet_bytes, 1344);
                assert_eq!(
                    profile
                        .maintained_settings()
                        .ok_or_else(|| input("missing maintained request"))?
                        .geometry
                        .max_bootstrap_bytes,
                    1296
                );
                assert!(profile.settings().cover.max_protected_bytes < 1296);
            }
            assert!(profile.maintained_binding().is_none());
            assert!(profile.runtime_contract(security::Role::Initiator).is_err());
            let digest = profile.requested_configuration()?;
            if let Some(previous) = previous {
                assert_eq!(digest, previous);
            }
            previous = Some(digest);
            let lines = common_cli_output::inspection(&profile, selected.common().role)?;
            assert_eq!(lines[0]["carrier"], carrier);
            assert!(lines[0]["maintained_carrier"]["effective"].is_null());
            assert!(lines[0]["maintained_carrier"]["binding"].is_null());
            assert_eq!(
                lines[0]["maintained_carrier"]["outer_protection"],
                "mandatory-maintained-aead-additional-to-inner"
            );
            for (key, value) in [
                ("--udp-bind", "127.0.0.1:42351"),
                ("--traffic", "proxy"),
                ("--carrier", if quic { "tcp" } else { "quic" }),
            ] {
                let mut wrong = options.clone();
                wrong.insert(key.into(), value.into());
                assert!(
                    selection(role, &wrong, configuration(&wrong)?).is_err(),
                    "accepted {key}"
                );
            }
        }
    }
    Ok(())
}
