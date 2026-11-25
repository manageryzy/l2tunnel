//! Deterministic local admission/capture invariants, not authenticated runtime evidence.

use super::*;
use crate::secure_udp::{common_transaction_profile as transaction_profile, credentials};
use l2tunnel::record_configuration::{Catalog, Configuration};
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
    /// Server-role plan of the same profile (session list/kick admission).
    server: Prepared,
    old_backend: ObservedBackend,
    generic_backend: ObservedBackend,
    initial: Configuration,
    target: Configuration,
    opened: Arc<AtomicUsize>,
}
fn fixture() -> Result<Fixture> {
    let (legacy, peers) = crate::secure_udp::common_fixture::fixture(
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
    let initial = crate::service::prepared::transaction_tests::descriptor(
        initiator.send,
        initiator.receive,
        legacy.connection().max_packet,
    )?;
    let mut forward = initiator.send;
    forward.records.channels = 3;
    let target = crate::service::prepared::transaction_tests::descriptor(
        forward,
        initiator.receive,
        legacy.connection().max_packet,
    )?;
    let profile = Arc::new(transaction_profile::Profile::new(
        legacy.connection(),
        legacy.settings(),
        peers,
        initiator,
        responder,
        Catalog::new(initial, &[initial, target])?,
        transport::TransactionSettings {
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
    let old_profile = Arc::new(transaction_profile::Profile::new(
        legacy.connection(),
        legacy.settings(),
        peers,
        initiator,
        responder,
        Catalog::new(*initial.descriptor(), &[*initial.descriptor()])?,
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 << 20,
        },
    )?);
    let old =
        Prepared::secure_udp_common_client((*old_profile).clone(), credentials()?, attachment())?;
    let generic =
        Prepared::secure_udp_common_client((*profile).clone(), credentials()?, attachment())?;
    let server = Prepared::secure_udp_common_server(
        (*profile).clone(),
        credentials::Server::new(
            credentials::NoiseIdentity::new(
                Zeroizing::new([22; 32]),
                peers.initiator,
                hs::Profile::Ik,
                None,
            )?,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        attachment(),
    )?;
    let backend =
        |requested: Arc<transaction_profile::Profile>, generation| -> Result<ObservedBackend> {
            let settings = requested.settings();
            let authenticated = requested
                .establish_config(security::Role::Initiator)?
                .expected_binding(peers, security::SessionId([1; 16]))?;
            let info = member::Info {
                // Logical custody fixture only; actual paired service tests prove authentication.
                binding: security::SessionBinding {
                    session: security::SessionId([1; 16]),
                    transcript: [2; 32],
                },
                authenticated,
                member: settings.member,
                peers,
                role: security::Role::Initiator,
                local_addr: settings.gate.path.client,
                peer_addr: settings.gate.path.server,
                statistics: establish::Statistics::default(),
            };
            let (switcher, _requests) = transport::common_channel();
            Ok(ObservedBackend::SecureUdpCommon(Arc::new(
                SecureUdpCommonBackend {
                    requested,
                    info,
                    counters: Mutex::new(None),
                    observed: Mutex::new(None),
                    switcher,
                    generation,
                },
            )))
        };
    let old_backend = backend(old_profile, 11)?;
    let generic_backend = backend(profile, 22)?;
    Ok(Fixture {
        old,
        generic,
        server,
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

#[test]
fn disconnect_and_idle_runtime_exit_claim_the_same_generation_once() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    let key = RequestKey(1);
    let accepted = handle.disconnect(key).map_err(|_| "disconnect refused")?;
    assert!(!handle.0.lock().claim_runtime_exit());
    assert_eq!(handle.disconnect(key), Ok(accepted));
    assert_eq!(handle.snapshot().operation, Some(accepted.operation));

    let (handle, _run) = channel();
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    // Until the old owners finish dropping, admission cannot take over an
    // already claimed runtime failure or consume the caller's request key.
    assert!(handle.0.lock().claim_runtime_exit());
    assert_eq!(handle.disconnect(key), Err(SubmitError::Busy));
    assert_eq!(handle.next_key(), Ok(key));
    assert_eq!(handle.snapshot().generation, Some(OperationId(22)));
    assert_eq!(handle.snapshot().operation, None);
    Ok(())
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
            .api_version(&status_request(local::COMMON_VERSION))
            .is_none()
    );
    // Validate one generation, then replace the owner before actual admission.
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    for version in [2, 3] {
        for reconnect in [false, true] {
            let before = no_effects(&handle);
            refused(
                handle.submit_local_lifecycle(version, reconnect),
                version,
                "requires_version_4",
            )?;
            assert_eq!(no_effects(&handle), before);
        }
    }
    assert!(
        handle
            .api_version(&status_request(local::COMMON_VERSION))
            .is_none()
    );
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn validated_status_view_keeps_its_own_version_and_generation_after_replacement() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    for (
        before_plan,
        before_backend,
        before_generation,
        after_plan,
        after_backend,
        after_generation,
    ) in [
        (
            &fixture.old,
            &fixture.old_backend,
            11,
            &fixture.generic,
            &fixture.generic_backend,
            22,
        ),
        (
            &fixture.generic,
            &fixture.generic_backend,
            22,
            &fixture.old,
            &fixture.old_backend,
            11,
        ),
    ] {
        install(&handle, before_plan, before_backend, before_generation);
        let captured = handle
            .local_view(local::COMMON_VERSION)
            .map_err(|_| "captured view refused")?;
        install(&handle, after_plan, after_backend, after_generation);
        let reply =
            Handle::status_from_view(captured, status_request(local::COMMON_VERSION), false).await;
        assert_eq!(reply.version, local::COMMON_VERSION);
        let state = reply.state.ok_or("captured state")?;
        assert_eq!(
            state
                .common
                .as_ref()
                .ok_or("captured Common frame")?
                .generation,
            before_generation
        );
        assert_eq!(
            handle.snapshot().generation,
            Some(OperationId(after_generation))
        );
        assert!(handle.local_view(3).is_err());
    }
    Ok(())
}

#[test]
fn local_reconnect_selects_exact_retained_plan_and_key_in_the_same_admission() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    handle.0.lock().plan = Some(fixture.generic.clone());
    let accepted = handle
        .submit_local_lifecycle(local::COMMON_VERSION, true)
        .map_err(|_| "matching old-version reconnect refused")?;
    assert_eq!(accepted.operation, OperationId(1));
    assert_eq!(handle.next_key().map_err(|_| "next key")?, RequestKey(2));
    let state = handle.0.lock();
    let job = state.queued.as_ref().ok_or("missing reconnect")?;
    let Command::Reconnect(plan) = &job.command else {
        return Err("wrong local lifecycle command".into());
    };
    assert!(Arc::ptr_eq(&plan.identity, &fixture.generic.identity));
    assert!(plan.secure_udp_common());
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
        .apply_common(fixture.target, key)
        .map_err(|_| "initial typed admission")?;
    // Logical retained-entry test only; it does not fabricate transaction completion.
    install(&handle, &fixture.old, &fixture.old_backend, 11);
    assert_eq!(
        handle
            .apply_common(fixture.target, key)
            .map_err(|_| "retained typed replay")?,
        accepted
    );
    assert_eq!(
        handle.apply_common(fixture.initial, key),
        Err(SubmitError::Conflict)
    );
    let fresh = handle.next_key().map_err(|_| "next fresh key")?;
    assert_eq!(
        handle.apply_common(fixture.target, fresh),
        Err(SubmitError::InvalidConfiguration)
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
    let reply = handle.lifecycle_reply(2, true, "ok", true);
    assert_eq!(reply.version, 2);
    assert_eq!(reply.code, "outcome_unknown");
    assert!(!reply.ok && reply.state.is_none());
    let refused = handle.lifecycle_reply(2, false, "busy", false);
    assert_eq!(refused.code, "requires_version_4");
    assert_eq!(refused.version, 2);
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
        .apply_common(fixture.target, key)
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
        .and_then(Observation::secure_udp_common)
        .ok_or("retained generic frame")?;
    assert_eq!(frame.service_terminal, Some(Terminal::Aborted));
    assert!(frame.runtime.is_none());
    Ok(())
}

#[test]
fn server_session_list_and_kick_admission_relisten_with_the_retained_plan() -> Result {
    let fixture = fixture()?;
    let (handle, _run) = channel();
    let error = |error: SubmitError| format!("unexpected service result: {error:?}");
    // No plan, then a client plan: sessions are server-only.
    assert_eq!(handle.sessions(), Err(SubmitError::Unsupported));
    assert_eq!(handle.kick(RequestKey(1)), Err(SubmitError::State));
    install(&handle, &fixture.generic, &fixture.generic_backend, 22);
    assert_eq!(handle.sessions(), Err(SubmitError::Unsupported));
    assert_eq!(handle.kick(RequestKey(1)), Err(SubmitError::Unsupported));
    // A server plan that is not connected lists nothing and cannot be kicked.
    {
        let mut state = handle.0.lock();
        state.plan = Some(fixture.server.clone());
        state.backend = None;
        state.snapshot.phase = Phase::Disconnected;
        state.snapshot.generation = None;
    }
    assert_eq!(handle.sessions().map_err(error)?, Vec::new());
    assert_eq!(handle.kick(RequestKey(1)), Err(SubmitError::State));
    // Live server generation: one session; a kick reconnects with the same plan.
    install(&handle, &fixture.server, &fixture.generic_backend, 22);
    handle.0.lock().connected_at = Some(Instant::now());
    let sessions = handle.sessions().map_err(error)?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].generation, 22);
    assert!(sessions[0].connected_ms.is_some());
    assert_eq!((&sessions[0].profile, &sessions[0].member), (&None, &None));
    let accepted = handle.kick(RequestKey(1)).map_err(error)?;
    assert!(matches!(
        handle.0.lock().queued.as_ref().map(|job| &job.command),
        Some(Command::Reconnect(plan)) if Arc::ptr_eq(&plan.identity, &fixture.server.identity)
    ));
    // Exact replay returns the same operation; another action on the key conflicts.
    assert_eq!(handle.kick(RequestKey(1)), Ok(accepted));
    assert_eq!(handle.disconnect(RequestKey(1)), Err(SubmitError::Conflict));
    assert_eq!(handle.kick(RequestKey(2)), Err(SubmitError::Busy));
    // The relisten is a reconnect setup, so it can be cancelled.
    assert_eq!(handle.cancel(accepted.operation), Ok(()));
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 0);
    Ok(())
}
