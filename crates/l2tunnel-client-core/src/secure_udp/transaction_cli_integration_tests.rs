//! Selection and identity regressions across the actual frontend and plan builder.
use super::*;
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct PlanFile(pub(super) PathBuf);
impl PlanFile {
    pub(super) fn new(value: &serde_json::Value) -> io::Result<Self> {
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
pub(super) fn common_value() -> io::Result<serde_json::Value> {
    use l2tunnel::record_configuration as common;
    use l2tunnel_management::Role;
    let base = crate::secure_udp::common_status::tests::descriptor(1_250_001)?;
    let forward = *base.direction(Role::Client).common();
    let mut reverse_pipeline = forward.pipeline();
    reverse_pipeline.flows.channels = 3;
    let reverse = common::CommonDirection::new(
        forward.traffic(),
        reverse_pipeline,
        625_013,
        forward.burst_bytes(),
        forward.native_window(),
    )
    .map_err(io::Error::other)?;
    let common::Profile::Swift {
        forward: a,
        reverse: mut b,
    } = *base.profile()
    else {
        return Err(input("fixture is not Swift"));
    };
    b.channels = 3;
    b.codec.repair_numerator = 2;
    b.codec.repair_denominator = 7;
    let initial = common::Descriptor::new(
        1500,
        Duplex::Full,
        forward,
        reverse,
        common::Profile::Swift {
            forward: a,
            reverse: b,
        },
    )
    .map_err(io::Error::other)?;
    let changed = common::CommonDirection::new(
        forward.traffic(),
        forward.pipeline(),
        1_250_002,
        forward.burst_bytes(),
        forward.native_window(),
    )
    .map_err(io::Error::other)?;
    let target = common::Descriptor::new(1500, Duplex::Full, changed, reverse, *initial.profile())
        .map_err(io::Error::other)?;
    let encode = |descriptor: common::Descriptor| -> io::Result<String> {
        let mut bytes = [0; common::DESCRIPTOR_BYTES];
        descriptor
            .encode_into(&mut bytes)
            .map_err(io::Error::other)?;
        Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
    };
    let template = common_plan_fixture::template();
    Ok(
        serde_json::json!({"version":1,"backend":"common_records_v2","initial_index":0,
        "catalog":[encode(initial)?,encode(target)?],"rolling_work":null,
        "transaction":template["transaction"],"runtime":template["runtime"]}),
    )
}
fn options_for(role: &str, carrier: &str, plan: &PlanFile) -> BTreeMap<String, String> {
    let (local, peer) = if role == "connect" {
        ("127.0.0.1:42301", "127.0.0.1:42302")
    } else {
        ("127.0.0.1:42302", "127.0.0.1:42301")
    };
    let mut options = BTreeMap::from([
        ("--carrier".into(), carrier.into()),
        ("--record-profile".into(), "common".into()),
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
            "--common-transaction-plan".into(),
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
) -> io::Result<Box<secure_udp::common_transaction_profile::Profile>> {
    match selected(options, role)?.build(
        configuration(options)?,
        peers(),
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )? {
        Built::Records(value) => Ok(value),
        Built::Proxy(_) => Err(input("native Common plan selected proxy backend")),
    }
}

#[test]
fn both_covers_roles_preserve_complete_values_and_use_original_seed_once() -> io::Result<()> {
    let file = PlanFile::new(&common_value()?)?;
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
        let forward = c.descriptor().local(l2tunnel_management::Role::Client);
        let reverse = c.descriptor().local(l2tunnel_management::Role::Server);
        assert_eq!(forward.send(), reverse.receive());
        assert_eq!(forward.receive(), reverse.send());
        assert_eq!(forward.send().common().bytes_per_second(), 1_250_001);
        assert_eq!(forward.receive().common().bytes_per_second(), 625_013);
        assert_eq!(forward.send().channels(), 2);
        assert_eq!(forward.receive().channels(), 3);
        let l2tunnel::record_configuration::Profile::Swift { forward, reverse } =
            *c.descriptor().profile()
        else {
            return Err(input("fixture is not Swift"));
        };
        assert_eq!(
            (
                forward.codec.repair_numerator,
                forward.codec.repair_denominator
            ),
            (1, 3)
        );
        assert_eq!(
            (
                reverse.codec.repair_numerator,
                reverse.codec.repair_denominator
            ),
            (2, 7)
        );
        a.runtime_contract(security::Role::Initiator)?.resolve(c)?;
        b.runtime_contract(security::Role::Responder)?.resolve(c)?;
        let common = client.common();
        let connection = configuration(&options)?;
        let (overhead, maximum_body) = common.final_geometry()?;
        let plan = common_cli::Plan::read(&file.0)?;
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
    let file = PlanFile::new(&common_value()?)?;
    let mut valid = options_for("connect", "quic-like", &file);
    valid.insert("--common-transaction-plan".into(), "absent-plan".into());
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
    let file = PlanFile::new(&common_value()?)?;
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
    let mut value = common_value()?;
    let mut invalid = value["catalog"][1]
        .as_str()
        .ok_or_else(|| input("fixture catalog"))?
        .to_owned();
    let last = invalid.len() - 1;
    invalid.replace_range(last.., "1");
    value["catalog"][1] = serde_json::json!(invalid);
    let file = PlanFile::new(&value)?;
    for carrier in ["quic-like", "media-like"] {
        let options = options_for("connect", carrier, &file);
        assert!(profile(&options, "connect").is_err());
    }
    Ok(())
}
