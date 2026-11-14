use super::{diagnostics as diag, establish, member};
use l2tunnel_cover as cover;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_udp_control as gate;
use std::time::Duration;
use tokio::{net::UdpSocket, time::Instant};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Entropy {
    byte: u8,
    fail: bool,
    calls: usize,
}
impl Entropy {
    fn new(byte: u8) -> Self {
        Self {
            byte,
            fail: false,
            calls: 0,
        }
    }
}
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        self.calls += 1;
        if self.fail {
            return Err(hs::EntropyError);
        }
        output.fill(self.byte);
        self.byte = self.byte.wrapping_add(1);
        Ok(())
    }
}
fn local(initiator: bool) -> hs::LocalSecret {
    hs::LocalSecret::new(Zeroizing::new([if initiator { 11 } else { 22 }; 32]))
}
fn identity(initiator: bool, psk: Option<u8>) -> establish::Identity {
    establish::Identity {
        local: local(initiator),
        peer: local(!initiator).public_key(),
        psk: psk.map(|byte| hs::Psk::new(Zeroizing::new([byte; 32]))),
    }
}
async fn sockets() -> Result<(UdpSocket, UdpSocket, gate::Path)> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let path = gate::Path {
        client: a.local_addr()?,
        server: b.local_addr()?,
    };
    a.connect(path.server).await?;
    b.connect(path.client).await?;
    Ok((a, b, path))
}
fn config(
    path: gate::Path,
    appearance: cover::Appearance,
    initiator: bool,
    psk: bool,
) -> Result<establish::Config> {
    let mut gate = gate::Config::new(path, [30; 32], 1)?;
    gate.outer_overhead = 29
        + if appearance == cover::Appearance::QuicLike {
            30
        } else {
            14
        };
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.arq.max_retries = 256;
    gate.cookie_ttl = Duration::from_millis(500);
    gate.handshake_timeout = Duration::from_secs(1);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    Ok(establish::Config {
        gate,
        cover: cover::Config::new(
            appearance,
            cover::ConnectionIds {
                local: cover::ConnectionId([if initiator { 1 } else { 2 }; 8]),
                peer: cover::ConnectionId([if initiator { 2 } else { 1 }; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(if initiator { 1 } else { 2 }),
                peer_ssrc: cover::Ssrc(if initiator { 2 } else { 1 }),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1200,
                max_protected_bytes: 512,
            },
        )?,
        profile: if psk {
            hs::Profile::IkPsk2
        } else {
            hs::Profile::Ik
        },
        binding: establish::Binding {
            configuration: [3; 32],
            carrier: [4; 32],
            outer: [5; 32],
            member: [6; 32],
        },
        receive_packets_per_interval: 64,
    })
}
fn peers() -> establish::Peers {
    establish::Peers {
        initiator: local(true).public_key(),
        responder: local(false).public_key(),
    }
}
fn admission(config: establish::Config) -> Result<establish::ServerAdmission> {
    Ok(establish::ServerAdmission::new(
        config,
        peers(),
        gate::Secret::new([44; 32]),
        gate::Secret::new([55; 32]),
        Instant::now(),
    )?)
}
async fn pair(
    appearance: cover::Appearance,
) -> Result<(establish::Established, establish::Established)> {
    pair_with_retry_limit(appearance, 256).await
}
async fn pair_with_retry_limit(
    appearance: cover::Appearance,
    retries: u16,
) -> Result<(establish::Established, establish::Established)> {
    let (a, b, path) = sockets().await?;
    let mut ca = config(path, appearance, true, false)?;
    let mut cb = config(path, appearance, false, false)?;
    for value in [&mut ca, &mut cb] {
        value.gate.arq.max_retries = retries;
        if retries == 0 {
            value.gate.arq.initial_rto = Duration::from_millis(100);
        }
    }
    let mut server = admission(cb)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut ea = Entropy::new(31);
    let mut eb = Entropy::new(61);
    let (a, b) = tokio::join!(
        establish::connect(
            a,
            ca,
            identity(true, None),
            gate::Secret::new([44; 32]),
            deadline,
            &mut ea
        ),
        establish::accept(b, identity(false, None), &mut server, deadline, &mut eb)
    );
    Ok((a?, b?))
}
fn member_key() -> Result<identity::IdentityKey> {
    // Published RFC8032 vector; never real provisioning material.
    let text = "3051020101300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60812100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn settings(value: &establish::Established, attempts: u32) -> member::Settings {
    member::Settings {
        context: identity::Context {
            session: value.binding.session,
            transcript: value.binding.transcript,
            configuration: value.authenticated.configuration,
            carrier: value.authenticated.carrier,
            outer: value.authenticated.outer,
            initiator_noise: identity::NoisePublicKey(value.peers.initiator.0),
            responder_noise: identity::NoisePublicKey(value.peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: attempts,
        receive_interval: Duration::from_millis(10),
        receive_packets_per_interval: 64,
    }
}

#[test]
fn typed_setup_reasons_do_not_infer_authentication_from_io_kind() {
    assert_eq!(
        diag::establishment_reason(&establish::Error::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        ))),
        diag::Reason::LocalIo
    );
    assert_eq!(
        diag::establishment_reason(&establish::Error::Gate(gate::Error::RetryExhausted)),
        diag::Reason::AdmissionAttempts
    );
    assert_eq!(
        diag::establishment_reason(&establish::Error::Gate(gate::Error::Recovery(
            l2tunnel_recovery::RecoveryError::RetryExhausted {
                source: l2tunnel_recovery::SourceId(3)
            }
        ))),
        diag::Reason::BootstrapAttempts
    );
    assert_eq!(
        diag::establishment_reason(&establish::Error::Noise(hs::Error::Authentication)),
        diag::Reason::Authentication
    );
    assert_eq!(
        diag::Observation::new(diag::Stage::Configuration).bootstrap,
        None
    );
}

#[tokio::test]
async fn observed_admission_failure_preserves_noop_wire_and_original_bound() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (a, b, path) = sockets().await?;
        let mut config = config(path, appearance, true, false)?;
        config.gate.gate_attempts = 1;
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut observations = Vec::new();
        let mut entropy = Entropy::new(31);
        let failed = establish::connect_observed(
            a,
            config,
            identity(true, None),
            gate::Secret::new([44; 32]),
            deadline,
            &mut entropy,
            &mut |value| observations.push(value),
        )
        .await;
        assert!(matches!(
            failed,
            Err(establish::Error::Gate(gate::Error::RetryExhausted))
        ));
        assert!(Instant::now() < deadline);
        let last = observations.last().ok_or("missing admission observation")?;
        assert_eq!(last.stage, diag::Stage::Admission);
        assert_eq!(last.reason, Some(diag::Reason::AdmissionAttempts));
        assert_eq!(
            last.bootstrap
                .ok_or("missing actual bootstrap counters")?
                .emitted_datagrams,
            1
        );
        assert!(last.control.is_none() && last.member_attempts.is_none());
        let mut original = [0; 1500];
        let length = tokio::time::timeout(Duration::from_secs(1), b.recv(&mut original)).await??;
        let a = UdpSocket::bind(path.client).await?;
        a.connect(path.server).await?;
        let mut entropy = Entropy::new(31);
        let legacy = establish::connect(
            a,
            config,
            identity(true, None),
            gate::Secret::new([44; 32]),
            Instant::now() + Duration::from_secs(1),
            &mut entropy,
        )
        .await;
        assert!(matches!(
            legacy,
            Err(establish::Error::Gate(gate::Error::RetryExhausted))
        ));
        let mut noop = [0; 1500];
        let noop_length = tokio::time::timeout(Duration::from_secs(1), b.recv(&mut noop)).await??;
        assert_eq!(&original[..length], &noop[..noop_length]);
    }
    Ok(())
}

#[tokio::test]
async fn observed_configuration_expiry_and_entropy_do_not_fabricate_admission() -> Result {
    let (a, _b, path) = sockets().await?;
    let mut entropy = Entropy::new(31);
    let mut observations = Vec::new();
    let result = establish::connect_observed(
        a,
        config(path, cover::Appearance::QuicLike, true, false)?,
        identity(true, None),
        gate::Secret::new([44; 32]),
        Instant::now(),
        &mut entropy,
        &mut |value| observations.push(value),
    )
    .await;
    assert!(matches!(result, Err(establish::Error::Deadline)));
    assert_eq!(entropy.calls, 0);
    let last = observations.last().ok_or("missing expiry observation")?;
    assert_eq!(last.stage, diag::Stage::Configuration);
    assert_eq!(last.reason, Some(diag::Reason::OriginalDeadline));
    assert!(last.bootstrap.is_none());
    let (a, _b, path) = sockets().await?;
    entropy.fail = true;
    observations.clear();
    let result = establish::connect_observed(
        a,
        config(path, cover::Appearance::QuicLike, true, false)?,
        identity(true, None),
        gate::Secret::new([44; 32]),
        Instant::now() + Duration::from_secs(1),
        &mut entropy,
        &mut |value| observations.push(value),
    )
    .await;
    assert!(matches!(result, Err(establish::Error::Entropy)));
    let last = observations.last().ok_or("missing entropy observation")?;
    assert_eq!(last.reason, Some(diag::Reason::Entropy));
    assert!(last.bootstrap.is_none());
    Ok(())
}

#[tokio::test]
async fn observed_noise_authentication_failure_retains_actual_stage_and_control() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (a, b, path) = sockets().await?;
        let mut server = admission(config(path, appearance, false, true)?)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut ea = Entropy::new(31);
        let mut eb = Entropy::new(61);
        let mut oa = Vec::new();
        let mut ob = Vec::new();
        let mut observe_a = |value| oa.push(value);
        let mut observe_b = |value| ob.push(value);
        let (a, b) = tokio::join!(
            establish::connect_observed(
                a,
                config(path, appearance, true, true)?,
                identity(true, Some(7)),
                gate::Secret::new([44; 32]),
                deadline,
                &mut ea,
                &mut observe_a
            ),
            establish::accept_observed(
                b,
                identity(false, Some(8)),
                &mut server,
                deadline,
                &mut eb,
                &mut observe_b
            )
        );
        assert!(a.is_err() && b.is_err());
        assert!(
            oa.iter()
                .chain(&ob)
                .any(|value| value.stage == diag::Stage::Noise
                    && value.reason == Some(diag::Reason::Authentication))
        );
        assert!(oa.iter().chain(&ob).any(|value| value.control.is_some()));
        assert!(
            ob.last()
                .ok_or("missing server diagnostic")?
                .server_gate
                .is_some()
        );
    }
    Ok(())
}

#[tokio::test]
async fn observed_joining_attempt_limit_is_not_original_deadline_or_auth_failure() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (a, _peer_root_and_original_socket) = pair(appearance).await?;
        let settings = settings(&a, 2);
        let deadline = a.deadline;
        let key = member_key()?;
        let mut observations = Vec::new();
        let result =
            member::connect_observed(a, &key, settings, &mut |value| observations.push(value))
                .await;
        assert_eq!(
            result
                .err()
                .ok_or("silent peer unexpectedly authenticated")?
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(Instant::now() < deadline);
        let last = observations.last().ok_or("missing member observation")?;
        assert_eq!(last.stage, diag::Stage::Membership);
        assert_eq!(last.reason, Some(diag::Reason::JoiningAttempts));
        assert_eq!(last.member_attempts, Some(2));
        assert!(last.bootstrap.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn observed_pending_bootstrap_failure_during_membership_keeps_typed_cause() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (a, _peer_root_and_original_socket) = pair_with_retry_limit(appearance, 0).await?;
        assert!(
            !a.tail.drained(),
            "actual final-flight debt is required for this regression"
        );
        let deadline = a.deadline;
        let policy = settings(&a, 128);
        let key = member_key()?;
        let mut observations = Vec::new();
        let result =
            member::connect_observed(a, &key, policy, &mut |value| observations.push(value)).await;
        assert_eq!(
            result
                .err()
                .ok_or("unconfirmed bootstrap unexpectedly released membership")?
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(Instant::now() < deadline);
        let last = observations
            .last()
            .ok_or("missing final bootstrap diagnostic")?;
        assert_eq!(last.stage, diag::Stage::Membership);
        assert_eq!(last.reason, Some(diag::Reason::BootstrapAttempts));
        assert!(
            last.control.is_none(),
            "terminal bootstrap custody retired its control owner"
        );
        assert!(
            last.bootstrap
                .ok_or("actual bootstrap accounting missing")?
                .noise_flights
                > 0
        );
    }
    Ok(())
}
