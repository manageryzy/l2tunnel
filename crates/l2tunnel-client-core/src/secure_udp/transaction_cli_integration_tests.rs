//! Selection and identity regressions across the actual frontend and plan builder.
use super::*;
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct PlanFile(PathBuf);
impl PlanFile {
    fn new(value: &serde_json::Value) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-plan-selection-{}-{}",
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
}
impl Drop for PlanFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn options_for(role: &str, carrier: &str, plan: &PlanFile) -> BTreeMap<String, String> {
    let (local, peer) = if role == "connect" {
        ("127.0.0.1:42301", "127.0.0.1:42302")
    } else {
        ("127.0.0.1:42302", "127.0.0.1:42301")
    };
    let mut options = BTreeMap::from([
        ("--carrier".into(), carrier.into()),
        ("--record-profile".into(), "swift".into()),
        ("--duplex".into(), "full".into()),
        ("--layer".into(), "tun".into()),
        ("--max-packet".into(), "1500".into()),
        ("--device".into(), "absent-device".into()),
        ("--noise-profile".into(), "ik".into()),
        ("--noise-private-key-file".into(), "absent-private".into()),
        ("--noise-peer-key-file".into(), "absent-peer".into()),
        (
            "--session-admission-key-file".into(),
            "absent-admission".into(),
        ),
        ("--udp-bind".into(), local.into()),
        ("--udp-peer".into(), peer.into()),
        (
            "--swift-transaction-plan".into(),
            plan.0.to_string_lossy().into_owned(),
        ),
    ]);
    if role == "connect" {
        options.insert("--identity".into(), "absent-member".into());
    } else {
        options.insert("--allow-key".into(), "absent-member-public".into());
        options.insert("--session-cookie-key-file".into(), "absent-cookie".into());
    }
    options
}
fn peers() -> establish::Peers {
    establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    }
}
fn selected(options: &BTreeMap<String, String>, role: &str) -> io::Result<Selected> {
    selection(role, options, configuration(options)?)?
        .ok_or_else(|| input("missing explicit selection"))
}
fn profile(
    options: &BTreeMap<String, String>,
    role: &str,
) -> io::Result<Box<secure_udp::transaction_profile::Profile>> {
    match selected(options, role)?.build(
        configuration(options)?,
        peers(),
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )? {
        Built::Transaction(value) => Ok(value),
        Built::Legacy(_) => Err(input("complete plan selected legacy backend")),
        Built::Records(_) => Err(input("Swift plan selected Common backend")),
    }
}

#[test]
fn both_covers_roles_preserve_complete_values_and_use_original_seed_once() -> io::Result<()> {
    let file = PlanFile::new(&transaction_cli::test_plan_value())?;
    for carrier in ["quic-like", "media-like"] {
        let options = options_for("connect", carrier, &file);
        let client = selected(&options, "connect")?;
        assert!(client.transaction());
        assert_eq!(client.report_interval(), None);
        let a = profile(&options, "connect")?;
        let b = profile(&options_for("serve", carrier, &file), "serve")?;
        assert_eq!(a.configuration()?, b.configuration()?);
        assert_eq!(a.envelope(), b.envelope());
        assert_eq!(a.initial(), b.initial());
        assert_eq!(a.catalog().descriptors().len(), 2);
        let c = a.initial();
        let forward = a.runtime_for(c, security::Role::Initiator)?;
        let reverse = b.runtime_for(c, security::Role::Responder)?;
        assert_eq!(forward.send, reverse.receive);
        assert_eq!(forward.receive, reverse.send);
        assert_eq!(forward.send.bytes_per_second, 1_250_001);
        assert_eq!(forward.receive.bytes_per_second, 625_013);
        assert_eq!(forward.send.records.channels, 2);
        assert_eq!(forward.receive.records.channels, 3);
        assert_eq!(forward.send.records.codec.repair_numerator, 1);
        assert_eq!(forward.send.records.codec.repair_denominator, 3);
        assert_eq!(forward.receive.records.codec.repair_numerator, 2);
        assert_eq!(forward.receive.records.codec.repair_denominator, 7);
        let common = client.common();
        let connection = configuration(&options)?;
        let (overhead, maximum_body) = common.geometry()?;
        let plan = transaction_cli::Plan::read(&file.0)?;
        let raw = common.raw(
            plan.initial().path_mtu(),
            connection.handshake_timeout,
            peers(),
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let independent = plan.build(connection, raw, peers(), maximum_body, overhead)?;
        assert_eq!(a.configuration()?, independent.configuration()?);
        assert_eq!(
            raw.application.0,
            public_digest(b"l2tunnel/service/application/v1\0", peers())
        );
        assert_ne!(a.settings().application, raw.application);
        let mut already_derived = raw;
        already_derived.application = a.settings().application;
        let double = plan.build(connection, already_derived, peers(), maximum_body, overhead)?;
        assert_ne!(
            a.envelope(),
            double.envelope(),
            "using an already-derived seed must be distinguishable"
        );
    }
    Ok(())
}

#[test]
fn plan_and_legacy_authorities_conflict_before_file_or_credential_access() -> io::Result<()> {
    let file = PlanFile::new(&transaction_cli::test_plan_value())?;
    let mut valid = options_for("connect", "quic-like", &file);
    valid.insert("--swift-transaction-plan".into(), "absent-plan".into());
    for key in [
        "--path-mtu",
        "--swift-forward-kbit",
        "--swift-reverse-kbit",
        "--swift-channels",
        "--swift-window",
        "--swift-repair-permille",
        "--swift-report-ms",
    ] {
        let mut options = valid.clone();
        options.insert(key.into(), "1".into());
        let error = selection("connect", &options, configuration(&options)?)
            .err()
            .ok_or_else(|| input("conflict accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{key}: {error}");
        assert!(error.to_string().contains("conflicts"), "{key}: {error}");
    }
    Ok(())
}

#[test]
fn offline_inspection_refuses_runtime_authority_and_invalid_role_before_credentials()
-> io::Result<()> {
    let file = PlanFile::new(&transaction_cli::test_plan_value())?;
    let mut options = options_for("connect", "media-like", &file);
    options.remove("--device");
    options.remove("--session-admission-key-file");
    options.insert("--role".into(), "connect".into());
    let config = configuration(&options)?;
    assert!(selection_for("connect", &options, config, true)?.is_some());
    for key in [
        "--device",
        "--control-socket",
        "--session-admission-key-file",
        "--session-cookie-key-file",
        "--runtime-model",
    ] {
        let mut changed = options.clone();
        changed.insert(key.into(), "absent".into());
        assert_eq!(
            inspect(&changed)
                .err()
                .ok_or_else(|| input("runtime inspection accepted"))?
                .kind(),
            io::ErrorKind::InvalidInput,
            "{key}"
        );
    }
    options.insert("--role".into(), "invalid".into());
    assert_eq!(
        inspect(&options)
            .err()
            .ok_or_else(|| input("invalid role accepted"))?
            .kind(),
        io::ErrorKind::InvalidInput
    );
    Ok(())
}

#[test]
fn generic_selection_does_not_prune_invalid_noninitial_member_or_fall_back() -> io::Result<()> {
    let mut value = transaction_cli::test_plan_value();
    value["catalog"][1]["forward"]["max_native"] = serde_json::json!(1499);
    let file = PlanFile::new(&value)?;
    for carrier in ["quic-like", "media-like"] {
        let options = options_for("connect", carrier, &file);
        assert!(profile(&options, "connect").is_err());
    }
    Ok(())
}
