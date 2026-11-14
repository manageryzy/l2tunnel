//! Deterministic local admission/capture invariants, not authenticated runtime evidence.

use super::*;
use crate::secure_udp::{credentials, transaction_profile};
use l2tunnel::swift_configuration::{Catalog, Configuration, Descriptor};
use l2tunnel_handshake as hs;
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::{establish, member, transport};
use l2tunnel_security as security;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn member() -> Result<l2tunnel_identity::IdentityKey> {
    // Public RFC8032 section7.1 vector, used only for checked plan construction.
    let text = concat!(
        "3051020101300506032b657004220420",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "812100",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let mut bytes = Vec::new();
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(l2tunnel_identity::IdentityKey::from_pkcs8(&bytes)?)
}

struct Fixture {
    old: Prepared,
    generic: Prepared,
    old_backend: ObservedBackend,
    generic_backend: ObservedBackend,
    initial: Configuration,
    target: Configuration,
    opened: Arc<AtomicUsize>,
}
fn fixture() -> Result<Fixture> {
    let (legacy, peers) = crate::secure_udp::profile::tests::fixture(
        l2tunnel_udp_control::Path {
            client: "127.0.0.1:41321".parse()?,
            server: "127.0.0.1:41322".parse()?,
        },
        l2tunnel_cover::Appearance::QuicLike,
        member()?.public_key(),
    )?;
    let mut initiator = legacy.runtime(security::Role::Initiator);
    let mut responder = legacy.runtime(security::Role::Responder);
    for template in [&mut initiator, &mut responder] {
        let stream = messages::Settings {
            delivery: delivery::Settings {
                wire_overhead: template.control.wire_overhead + control_streams::HEADER_BYTES,
                ..template.control
            },
            path_mtu: template.path_mtu,
            max_message_bytes: 4096,
            max_outbound_messages: 4,
            max_outbound_bytes: 131_072,
            max_fragments: 32,
            max_reassembly_bytes: 16_384,
            max_incomplete_messages: 2,
            message_lifetime: Duration::from_secs(5),
            work_per_call: 8,
        };
        template.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
            streams: [stream; 3],
        });
    }
    let initial = Descriptor::new(1500, initiator.send, initiator.receive)?;
    let mut forward = initial.forward();
    forward.records.channels = 3;
    let target = Descriptor::new(1500, forward, initial.reverse())?;
    let profile = Arc::new(transaction_profile::Profile::new(
        legacy.connection(),
        legacy.settings(),
        peers,
        initiator,
        responder,
        Catalog::new(initial, &[initial, target])?,
        transaction_profile::Parameters {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 << 20,
        },
    )?);
    let initial = profile.initial();
    let target = Configuration::new(profile.envelope(), target)?;
    let opened = Arc::new(AtomicUsize::new(0));
    let attachment = || {
        let opened = opened.clone();
        Attachment::readable(l2tunnel_device::PacketLayer::Ip, move || {
            opened.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("unexpected local admission opener"))
        })
    };
    let credentials = || -> Result<credentials::Client> {
        Ok(credentials::Client::new(
            credentials::NoiseIdentity::new(
                Zeroizing::new([11; 32]),
                peers.responder,
                hs::Profile::Ik,
                None,
            )?,
            member()?,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
        )?)
    };
    let old = Prepared::secure_udp_client(legacy, credentials()?, attachment())?;
    let generic =
        Prepared::secure_udp_transaction_client((*profile).clone(), credentials()?, attachment())?;
    let settings = profile.settings();
    let authenticated = settings
        .runtime(security::Role::Initiator, peers)?
        .expected_binding(peers, security::SessionId([1; 16]))?;
    let info = |configuration: security::ConfigDigest| member::Info {
        // Logical service fixture only; paired service tests prove actual authentication.
        binding: security::SessionBinding {
            session: security::SessionId([1; 16]),
            transcript: [2; 32],
        },
        authenticated: hs::Binding {
            session: security::SessionId([1; 16]),
            configuration: configuration.0,
            carrier: authenticated.carrier,
            outer: authenticated.outer,
            member: authenticated.member,
        },
        member: settings.member,
        peers,
        role: security::Role::Initiator,
        local_addr: settings.gate.path.client,
        peer_addr: settings.gate.path.server,
        statistics: establish::Statistics::default(),
    };
    let (switcher, _requests) = transport::channel();
    let old_backend = ObservedBackend::SecureUdp(Arc::new(SecureUdpBackend {
        requested: legacy,
        info: info(legacy.configuration(peers)?),
        counters: Mutex::new(None),
        switcher,
        generation: 11,
    }));
    let (switcher, _requests) = transport::transaction_channel();
    let generic_backend =
        ObservedBackend::SecureUdpTransaction(Arc::new(SecureUdpTransactionBackend {
            requested: profile.clone(),
            info: info(profile.configuration()?),
            counters: Mutex::new(None),
            switcher,
            generation: 22,
        }));
    Ok(Fixture {
        old,
        generic,
        old_backend,
        generic_backend,
        initial,
        target,
        opened,
    })
}

fn install(handle: &Handle, plan: &Prepared, backend: &ObservedBackend, generation: u64) {
    let mut state = handle.0.lock();
    state.snapshot.phase = Phase::Connected;
    state.snapshot.generation = Some(OperationId(generation));
    state.snapshot.operation = None;
    state.snapshot.runtime = backend.observe();
    state.snapshot.terminal = None;
    state.backend = Some(backend.clone());
    state.plan = Some(plan.clone());
}
fn status_request(version: u16) -> local::Request {
    local::Request {
        version,
        action: local::Action::Status {},
    }
}
fn no_effects(
    handle: &Handle,
) -> (
    u64,
    usize,
    Option<OperationId>,
    bool,
    Option<OperationId>,
    Phase,
) {
    let state = handle.0.lock();
    (
        state.last_key,
        state.entries.len(),
        state.snapshot.operation,
        state.queued.is_some(),
        state.snapshot.generation,
        state.snapshot.phase,
    )
}
fn refused(
    result: std::result::Result<Accepted, LocalAdmissionError>,
    version: u16,
    code: &str,
) -> Result {
    let Err(LocalAdmissionError::Version(response)) = result else {
        return Err("wrong-version local lifecycle admission was not refused".into());
    };
    assert_eq!(response.version, version);
    assert_eq!(response.code, code);
    assert!(!response.ok && response.state.is_none());
    Ok(())
}

#[test]
fn stale_local_version_cannot_consume_key_or_mutate_the_replacement_owner() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    assert!(
        handle
            .api_version(&status_request(local::SECURE_UDP_VERSION))
            .is_none()
    );
    // Deterministic old-precheck/new-admission interleaving, without scheduling assumptions.
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    for reconnect in [false, true] {
        let before = no_effects(&handle);
        refused(
            handle.submit_local_lifecycle(local::SECURE_UDP_VERSION, reconnect),
            local::SECURE_UDP_VERSION,
            "requires_version_3",
        )?;
        assert_eq!(no_effects(&handle), before);
    }
    assert!(
        handle
            .api_version(&status_request(local::TRANSACTION_VERSION))
            .is_none()
    );
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    for reconnect in [false, true] {
        let before = no_effects(&handle);
        refused(
            handle.submit_local_lifecycle(local::TRANSACTION_VERSION, reconnect),
            local::TRANSACTION_VERSION,
            "unsupported_version",
        )?;
        assert_eq!(no_effects(&handle), before);
    }
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn validated_status_view_keeps_its_own_version_and_generation_after_replacement() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    let old = handle
        .local_view(local::SECURE_UDP_VERSION)
        .map_err(|_| "old view refused")?;
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    let reply =
        Handle::status_from_view(old, status_request(local::SECURE_UDP_VERSION), false).await;
    assert_eq!(reply.version, local::SECURE_UDP_VERSION);
    let state = reply.state.ok_or("old captured state")?;
    assert_eq!(
        state
            .secure_udp
            .as_ref()
            .ok_or("old captured frame")?
            .generation,
        11
    );
    assert!(state.transaction.is_none());
    assert!(handle.local_view(local::SECURE_UDP_VERSION).is_err());
    let generic = handle
        .local_view(local::TRANSACTION_VERSION)
        .map_err(|_| "generic view refused")?;
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    let reply =
        Handle::status_from_view(generic, status_request(local::TRANSACTION_VERSION), false).await;
    assert_eq!(reply.version, local::TRANSACTION_VERSION);
    let state = reply.state.ok_or("generic captured state")?;
    assert_eq!(
        state
            .transaction
            .as_ref()
            .ok_or("generic captured frame")?
            .generation,
        22
    );
    assert!(state.secure_udp.is_none());
    assert!(handle.local_view(local::TRANSACTION_VERSION).is_err());
    Ok(())
}

#[tokio::test]
async fn live_backend_precedes_retained_plan_and_released_view_does_not_mix_frames() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    handle.0.lock().plan = Some(fixture.generic.clone());
    assert!(handle.local_view(local::SECURE_UDP_VERSION).is_ok());
    assert!(handle.local_view(local::TRANSACTION_VERSION).is_err());
    // Retain the old frame after release, exactly as the service terminal path does.
    handle.0.lock().backend = None;
    let view = handle
        .local_view(local::TRANSACTION_VERSION)
        .map_err(|_| "retained plan view refused")?;
    let reply =
        Handle::status_from_view(view, status_request(local::TRANSACTION_VERSION), false).await;
    assert_eq!(reply.version, local::TRANSACTION_VERSION);
    let state = reply.state.ok_or("released state")?;
    assert!(state.secure_udp.is_none() && state.transaction.is_none());
    Ok(())
}

#[test]
fn local_reconnect_selects_exact_retained_plan_and_key_in_the_same_admission() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    handle.0.lock().plan = Some(fixture.generic.clone());
    let accepted = handle
        .submit_local_lifecycle(local::SECURE_UDP_VERSION, true)
        .map_err(|_| "matching old-version reconnect refused")?;
    assert_eq!(accepted.operation, OperationId(1));
    assert_eq!(handle.next_key().map_err(|_| "next key")?, RequestKey(2));
    let state = handle.0.lock();
    let job = state.queued.as_ref().ok_or("missing reconnect")?;
    let Command::Reconnect(plan) = &job.command else {
        return Err("wrong local lifecycle command".into());
    };
    assert!(Arc::ptr_eq(&plan.identity, &fixture.generic.identity));
    assert!(plan.secure_udp_transaction());
    assert_eq!(state.snapshot.generation, Some(OperationId(11)));
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn typed_retained_key_replay_still_precedes_fresh_backend_catalog_validation() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    let key = handle.next_key().map_err(|_| "next key")?;
    let accepted = handle
        .apply_transaction(fixture.target, key)
        .map_err(|_| "initial typed admission")?;
    // Logical retained-entry test only; it does not fabricate transaction completion.
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    assert_eq!(
        handle
            .apply_transaction(fixture.target, key)
            .map_err(|_| "retained typed replay")?,
        accepted
    );
    assert_eq!(
        handle.apply_transaction(fixture.initial, key),
        Err(SubmitError::Conflict)
    );
    let fresh = handle.next_key().map_err(|_| "next fresh key")?;
    assert_eq!(
        handle.apply_transaction(fixture.target, fresh),
        Err(SubmitError::Unsupported)
    );
    assert_eq!(
        handle.next_key().map_err(|_| "fresh key after refusal")?,
        fresh
    );
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn completed_lifecycle_compatibility_change_never_returns_the_new_version_frame() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    let reply = handle.lifecycle_reply(local::SECURE_UDP_VERSION, true, "ok", true);
    assert_eq!(reply.version, local::SECURE_UDP_VERSION);
    assert_eq!(reply.code, "outcome_unknown");
    assert!(!reply.ok && reply.state.is_none());
    let refused = handle.lifecycle_reply(local::SECURE_UDP_VERSION, false, "busy", false);
    assert_eq!(refused.code, "requires_version_3");
    assert_eq!(refused.version, local::SECURE_UDP_VERSION);
    assert!(refused.state.is_none());
    Ok(())
}

#[tokio::test]
async fn pending_complete_configuration_is_unknown_when_service_owner_drops() -> Result {
    let fixture = fixture()?;
    let (handle, run) = channel();
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    let key = handle.next_key().map_err(|_| "next key")?;
    let accepted = handle
        .apply_transaction(fixture.target, key)
        .map_err(|_| "typed admission")?;
    drop(run);
    assert_eq!(
        handle.wait(accepted.operation).await.map_err(|_| "wait")?,
        Completed::OutcomeUnknown
    );
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.phase, Phase::Closed);
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    let frame = snapshot
        .runtime
        .as_ref()
        .and_then(Observation::secure_udp_transaction)
        .ok_or("retained generic frame")?;
    assert_eq!(frame.service_terminal, Some(Terminal::Aborted));
    assert!(frame.runtime.is_none());
    Ok(())
}
