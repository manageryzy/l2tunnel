//! Strict selection and bounded DTO projection; no network/device startup.
use super::*;
use crate::service::{ProxyCommonFrame, ProxyFrame, ProxyProfile};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Temporary(PathBuf);
impl Temporary {
    fn new(bytes: &[u8]) -> io::Result<Self> {
        use std::io::Write;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-common-proxy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let temporary = Self(path);
                    file.write_all(bytes)?;
                    return Ok(temporary);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("temporary fixture namespace exhausted"))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn options(plan: &Path, policy: &Path) -> BTreeMap<String, String> {
    [
        ("--carrier", "quic-like"),
        ("--record-profile", "common"),
        ("--traffic", "proxy"),
        ("--layer", "tun"),
        ("--duplex", "full"),
        ("--compression", "off"),
        ("--max-packet", "1280"),
        ("--udp-bind", "127.0.0.1:41921"),
        ("--udp-peer", "127.0.0.1:41922"),
        ("--noise-profile", "ik"),
        ("--noise-private-key-file", "/not-read/private"),
        ("--noise-peer-key-file", "/not-read/peer"),
        ("--identity", "/not-read/member"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .chain([
        (
            "--common-transaction-plan".into(),
            plan.to_string_lossy().into_owned(),
        ),
        (
            "--proxy-policy".into(),
            policy.to_string_lossy().into_owned(),
        ),
    ])
    .collect()
}
#[test]
fn fixed_common_proxy_selection_is_explicit_and_unsupported_shapes_refuse_before_file_reads()
-> io::Result<()> {
    let missing = Path::new("/not-read/common-proxy-policy");
    let base = options(missing, missing);
    let connection = configuration(&base)?;
    assert!(selection(&base, connection, true, Carrier::OriginalUdp)?);
    assert!(!retained(&base)?);
    let mut closing = base.clone();
    closing.insert("--proxy-close".into(), "retained".into());
    assert!(selection(&closing, connection, true, Carrier::OriginalUdp)? && retained(&closing)?);
    closing.insert("--proxy-close".into(), "unknown".into());
    assert_eq!(
        selection(&closing, connection, true, Carrier::OriginalUdp)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    for (key, value) in [
        ("--traffic", "proxy-measured"),
        ("--record-profile", "swift"),
    ] {
        let mut bad = base.clone();
        bad.insert(key.into(), value.into());
        assert_eq!(
            super::super::selection_for("connect", &bad, connection, true)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    for carrier in [Carrier::OpenVpn, Carrier::RawPacket] {
        assert_eq!(
            selection(&base, connection, true, carrier)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let mut half = connection;
    half.duplex = Duplex::Half;
    assert!(selection(&base, half, true, Carrier::OriginalUdp).is_err());
    let mut tap = connection;
    tap.layer = l2tunnel_device::PacketLayer::Ethernet;
    assert!(selection(&base, tap, true, Carrier::OriginalUdp).is_err());
    let mut unknown = base.clone();
    unknown.insert("--unused-proxy-mode".into(), "on".into());
    assert_eq!(
        super::super::selection_for("connect", &unknown, connection, true)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    let descriptor = crate::secure_udp::common_status::tests::descriptor(1_250_001)?;
    let mut encoded = [0; l2tunnel::record_configuration::DESCRIPTOR_BYTES];
    descriptor
        .encode_into(&mut encoded)
        .map_err(io::Error::other)?;
    let mut document = super::super::transaction_cli::test_plan_value();
    document["backend"] = json!("common_records_v2");
    document["catalog"] = json!([encoded
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()]);
    document["rolling_work"] = Value::Null;
    let plan = Temporary::new(&serde_json::to_vec(&document).map_err(io::Error::other)?)?;
    let policy = Temporary::new(
        br#"{"version":1,"channels":1,"time_wait_reset":"maintained","routes":[]}"#,
    )?;
    let mut selected_options = options(plan.path(), policy.path());
    selected_options.insert("--max-packet".into(), "1500".into());
    let connection = configuration(&selected_options)?;
    let selected = super::super::selection_for("connect", &selected_options, connection, true)?
        .ok_or_else(|| input("explicit proxy not selected"))?;
    assert!(matches!(&selected.0, Choice::Proxy(_, _, _, false)));
    let mut retained_options = selected_options.clone();
    retained_options.insert("--proxy-close".into(), "retained".into());
    let retained_selection =
        super::super::selection_for("connect", &retained_options, connection, true)?
            .ok_or_else(|| input("explicit retained proxy not selected"))?;
    assert!(matches!(
        &retained_selection.0,
        Choice::Proxy(_, _, _, true)
    ));
    // A valid native Common catalog is not silently converted to proxy ownership.
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(zeroize::Zeroizing::new([21; 32])).public_key(),
        responder: hs::LocalSecret::new(zeroize::Zeroizing::new([22; 32])).public_key(),
    };
    assert_eq!(
        selected
            .build(
                connection,
                peers,
                l2tunnel_identity::MemberPublicKey([7; 32])
            )
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    let wide = Temporary::new(
        br#"{"version":1,"channels":2,"time_wait_reset":"maintained","routes":[]}"#,
    )?;
    selected_options.insert(
        "--proxy-policy".into(),
        wide.path().to_string_lossy().into_owned(),
    );
    assert!(super::super::selection_for("connect", &selected_options, connection, true).is_err());
    Ok(())
}
fn frame() -> io::Result<ProxyFrame> {
    Ok(ProxyFrame {
        requested_profile: ProxyProfile::FixedCredit,
        effective_profile: ProxyProfile::FixedCredit,
        requested_digest: l2tunnel_core::ConfigDigest([1; 32]),
        effective_digest: l2tunnel_core::ConfigDigest([2; 32]),
        runtime: None,
        measured: None,
        drain_accepted: false,
        releasing: false,
        release_deadline: None,
        released: false,
        terminal: None,
        service_terminal: None,
        exact_tcp_rwnd_control: false,
        common_record_composition: false,
        common: Some(ProxyCommonFrame {
            requested_configuration: security::ConfigDigest([3; 32]),
            effective_configuration: security::ConfigDigest([4; 32]),
            requested_carrier: [5; 32],
            effective_carrier: [6; 32],
            requested_cover: l2tunnel_cover::Appearance::QuicLike,
            effective_cover: None,
            local_addr: "127.0.0.1:41921".parse().map_err(io::Error::other)?,
            peer_addr: "127.0.0.1:41922".parse().map_err(io::Error::other)?,
            installed: false,
            running: false,
            epoch: None,
            liveness: transport::Liveness {
                last_verified_micros: Some(u64::MAX),
                ..Default::default()
            },
            hot_switch: false,
            graceful_close: false,
        }),
    })
}
#[test]
fn proxy_common_projection_preserves_actual_distinctions_and_legacy_omission_bytes()
-> io::Result<()> {
    let mut frame = frame()?;
    let status = frame.status();
    let common = status
        .common
        .as_ref()
        .ok_or_else(|| input("Common facts absent"))?;
    assert_ne!(
        common.requested_configuration,
        common.effective_configuration
    );
    assert_ne!(common.requested_carrier, common.effective_carrier);
    assert_ne!(common.requested_proxy_digest, common.effective_proxy_digest);
    assert_eq!(common.last_verified_micros, Some(u64::MAX));
    assert!(
        !common.installed
            && !common.running
            && !common.hot_switch
            && !common.graceful_close
            && !common.exact_tcp_rwnd_control
    );
    let text = serde_json::to_string(&status).map_err(io::Error::other)?;
    assert!(text.len() < 4096);
    assert_eq!(
        serde_json::from_str::<crate::local::ProxySnapshot>(&text).map_err(io::Error::other)?,
        status
    );
    let mut unknown = serde_json::to_value(&status).map_err(io::Error::other)?;
    unknown["common"]["untrusted_authority"] = json!(true);
    assert!(serde_json::from_value::<crate::local::ProxySnapshot>(unknown).is_err());
    frame.common = None;
    let legacy = frame.status();
    let actual = serde_json::to_string(&legacy).map_err(io::Error::other)?;
    let expected = format!(
        r#"{{"digest":"{}","drain_accepted":false,"runtime":null,"terminal":null}}"#,
        "02".repeat(32)
    );
    assert_eq!(actual, expected);
    assert!(legacy.common.is_none());
    assert_eq!(
        serde_json::from_str::<crate::local::ProxySnapshot>(&actual).map_err(io::Error::other)?,
        legacy
    );
    Ok(())
}
