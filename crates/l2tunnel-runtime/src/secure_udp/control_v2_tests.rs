//! Exact selected owner/Peer composition; authenticated ingress is the same
//! trusted test seam as the existing leased fixture, not a socket/crypto claim.

use super::*;

fn selected_v2() -> SettingsV2 {
    let mut values = [settings().streams[0]; 4];
    values[3].max_message_bytes = 4096;
    values[3].max_fragments = 32;
    values[3].max_reassembly_bytes = 8192;
    SettingsV2 { streams: values }
}
fn make_v2(role: mg::Role) -> Result<Owner> {
    let selected = selected_v2();
    let wrapper = wrapper_storage::Plan::new_v2(selected, base())?;
    let plans =
        selected.message_storage_plans(binding(role), Duration::ZERO, Duration::from_secs(10))?;
    Ok(Owner::new_leased_reserved_messages_v2_with_wrapper_plan(
        base(),
        selected,
        binding(role),
        control_scope(),
        data_scope(1, &modes()[0])?,
        Duration::ZERO,
        Duration::from_secs(10),
        plans.map(|plan| messages::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        }),
        wrapper,
        wrapper_storage::Limits {
            capacity_bytes: wrapper.capacity_bytes(),
        },
    )?)
}
impl Lab {
    fn new_v2() -> Result<Self> {
        let catalog = modes();
        let make = |role: mg::Role| -> Result<(Owner, tx::Peer)> {
            let owner = make_v2(role)?;
            let identity = tx::Identity {
                session: binding(role).session,
                role,
                lane: binding(role).lane,
                local: mg::EndpointId(if role == mg::Role::Client { 11 } else { 22 }),
                remote: mg::EndpointId(if role == mg::Role::Client { 22 } else { 11 }),
            };
            let peer = tx::Peer::new_leased(
                identity,
                Epoch(1),
                catalog[0].clone(),
                &catalog,
                tx::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 3_000,
                    reconcile_timeout_ms: 4_000,
                },
                tx::LeaseSettings {
                    session_expires: tx::Tick(10_000),
                    max_operation_ms: 5_000,
                    transaction_epoch: owner.transaction_binding()?.control_epoch,
                },
                tx::Tick(0),
            )?;
            Ok((owner, peer))
        };
        let (client_owner, client) = make(mg::Role::Client)?;
        let (server_owner, server) = make(mg::Role::Server)?;
        Ok(Self {
            owners: [client_owner, server_owner],
            peers: [client, server],
            now: Duration::ZERO,
            emitted: Vec::new(),
        })
    }
}
fn lifecycle_bytes(kind: streams::v2::LifecycleKind, bytes: &[u8]) -> Result<Vec<u8>> {
    let value = streams::v2::Lifecycle { kind, bytes };
    let mut output = vec![0; value.encoded_len(sc::MAX_LIFECYCLE_BYTES)?];
    value.encode(&mut output, sc::MAX_LIFECYCLE_BYTES)?;
    Ok(output)
}
fn actual_held(owner: &Owner, stream: streams::Stream) -> Result<Held> {
    let Backend::Streamed(streamed) = &owner.backend else {
        return Err("missing selected owner".into());
    };
    streamed.held[index(stream)].ok_or_else(|| "missing actual held message".into())
}

#[test]
fn four_actual_reserved_owners_charge_exact_plans_and_v1_rejects_without_upgrade() -> Result {
    let selected = selected_v2();
    let wrapper = wrapper_storage::Plan::new_v2(selected, base())?;
    let owner = make_v2(mg::Role::Client)?;
    let mut snapshot = Vec::new();
    owner.write_failure_snapshot(Duration::from_secs(10), &mut snapshot)?;
    let snapshot = std::str::from_utf8(&snapshot)?;
    assert_eq!(snapshot.lines().count(), 4);
    assert!(snapshot.contains("stream=Lifecycle"));
    let actual = owner
        .message_storage_usage_v2()
        .ok_or("missing four actual message usages")?;
    for (usage, plan) in actual.into_iter().zip(selected.message_storage_plans(
        binding(mg::Role::Client),
        Duration::ZERO,
        Duration::from_secs(10),
    )?) {
        assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
        assert_eq!(usage.limit_bytes, plan.capacity_bytes());
    }
    assert!(
        owner.message_storage_usage().is_none(),
        "v2 must not silently truncate usage into a v1 view"
    );
    assert_eq!(owner.wrapper_capacity_bytes()?, wrapper.capacity_bytes());
    let usage = owner
        .wrapper_storage_usage()?
        .ok_or("missing actual v2 wrapper usage")?;
    assert_eq!(usage.capacity_bytes, wrapper.capacity_bytes());
    assert_eq!(usage.allocations, 8);
    assert_eq!(
        owner.transaction_binding()?,
        streams::v2::delivery_binding(binding(mg::Role::Client), streams::Stream::Transaction)?
    );
    assert_eq!(selected.max_packet_bytes(base())?, owner.max_packet_bytes());

    let mut old = Lab::new()?;
    let body = lifecycle_bytes(
        streams::v2::LifecycleKind::Request,
        b"opaque nested protected request",
    )?;
    assert!(
        old.owners[0]
            .submit_lifecycle(&body, Duration::ZERO, CAP_DURATION)
            .is_err()
    );
    let mut packet = [0; 64];
    let length = streams::v2::Frame {
        stream: streams::Stream::Lifecycle,
        packet: &[0; recovery::DATA_HEADER_BYTES],
    }
    .encode(
        &mut packet,
        streams::Limits {
            max_packet_bytes: 236,
        },
    )?;
    assert!(
        old.owners[1]
            .receive(
                verified(mg::Role::Client),
                &packet[..length],
                Duration::ZERO
            )
            .is_err()
    );
    assert!(old.owners[1].message_storage_usage_v2().is_none());

    let mut allocation = wrapper_storage::Allocation::default();
    let plans = selected.message_storage_plans(
        binding(mg::Role::Client),
        Duration::ZERO,
        Duration::from_secs(10),
    )?;
    let mut limits = plans.map(|plan| messages::storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    });
    limits[3].capacity_bytes -= 1;
    let failure = Owner::construct_streamed(
        base(),
        selected.first_three(),
        binding(mg::Role::Client),
        control_scope(),
        data_scope(1, &modes()[0])?,
        Duration::ZERO,
        Duration::from_secs(10),
        raw_packet_bytes(base())?,
        Storage::ReservedMessagesV2 {
            messages: limits,
            wrapper: &wrapper,
            wrapper_limit: wrapper_storage::Limits {
                capacity_bytes: wrapper.capacity_bytes(),
            },
        },
        &mut allocation,
        Some(selected.streams[3]),
    );
    assert!(failure.is_err());
    assert_eq!(
        allocation.attempts(),
        0,
        "fourth limit must be checked before wrapper provisioning"
    );
    Ok(())
}

#[test]
fn fragmented_lifecycle_and_sixteen_confirmed_pings_progress_while_real_transaction_is_held()
-> Result {
    let mut lab = Lab::new_v2()?;
    let initial = lab.owners.each_ref().map(|owner| {
        (
            owner.message_storage_usage_v2(),
            owner.wrapper_storage_usage().ok().flatten(),
        )
    });
    let prepare = lab.prepare()?;
    let frozen = lab.send(0, &prepare)?;
    let effect = lab.dispatched(1)?;
    let held_tx = actual_held(&lab.owners[1], streams::Stream::Transaction)?;
    let original_phase = lab.peers[1].phase();
    let payload: Vec<_> = (0..2700).map(|i| (i % 251) as u8).collect();
    let body = lifecycle_bytes(streams::v2::LifecycleKind::NoiseFlight, &payload)?;
    let token = lab.owners[0]
        .submit_lifecycle(&body, lab.now, CAP_DURATION)?
        .ok_or("actual Lifecycle admission")?;
    let mut received = None;
    let mut scratch = [0; 4096];
    for _ in 0..500 {
        lab.pump()?;
        if let Some(incoming) = lab.owners[1].next(lab.now, &mut scratch)? {
            assert_eq!(incoming.stream, Some(streams::Stream::Lifecycle));
            let envelope =
                sc::Envelope::decode(&scratch[..incoming.bytes], envelope_limits(4096)?)?;
            assert_eq!(envelope.binding.scope, control_scope());
            let sc::Body::ProfileControl {
                tag: sc::ProfileTag::SessionRefreshV1,
                bytes,
            } = envelope.body
            else {
                return Err("wrong real Lifecycle body".into());
            };
            let parsed = streams::v2::Lifecycle::decode(bytes, sc::MAX_LIFECYCLE_BYTES)?;
            assert_eq!(parsed.kind, streams::v2::LifecycleKind::NoiseFlight);
            assert_eq!(parsed.bytes, payload);
            received = Some(incoming);
            break;
        }
    }
    let incoming = received.ok_or("bounded fragmented Lifecycle did not complete")?;
    let held_lifecycle = actual_held(&lab.owners[1], streams::Stream::Lifecycle)?;
    assert!(!held_lifecycle.dispatched);
    assert!(
        !lab.owners[0].confirmed(token, lab.now)?,
        "source ACK cannot imply whole-message acceptance"
    );
    for nonce in 0..16 {
        lab.ping_pong(nonce, false)?;
        let actual = actual_held(&lab.owners[1], streams::Stream::Lifecycle)?;
        assert_eq!(actual.incoming, incoming);
        assert_eq!(actual.deadline, held_lifecycle.deadline);
        assert!(!actual.dispatched);
        let transaction = actual_held(&lab.owners[1], streams::Stream::Transaction)?;
        assert_eq!(transaction.incoming, held_tx.incoming);
        assert_eq!(transaction.deadline, held_tx.deadline);
        assert_eq!(lab.peers[1].phase(), original_phase);
        assert_eq!(
            lab.peers[1]
                .operation()
                .ok_or("lost real Peer lease")?
                .expires(),
            CAP
        );
    }
    lab.owners[1].accepted(incoming, lab.now)?;
    assert!(
        lab.owners[1].next(lab.now, &mut scratch)?.is_none(),
        "accepted Lifecycle cannot redispatch"
    );
    let mut confirmed = false;
    for _ in 0..300 {
        lab.pump()?;
        if lab.owners[0].confirmed(token, lab.now)? {
            confirmed = true;
            break;
        }
    }
    assert!(confirmed);
    lab.owners[0].retire(token, lab.now)?;
    lab.accept(1, &effect, false)?;
    lab.confirm(0, &frozen, false, true)?;
    assert_eq!(
        lab.owners.each_ref().map(|owner| (
            owner.message_storage_usage_v2(),
            owner.wrapper_storage_usage().ok().flatten()
        )),
        initial
    );
    assert!(
        lab.emitted
            .iter()
            .any(|frame| frame.stream == streams::Stream::Lifecycle)
    );
    lab.assert_shared_wire_quota();
    Ok(())
}

#[test]
fn lifecycle_original_message_cap_is_not_renewed_by_independent_liveness() -> Result {
    let mut lab = Lab::new_v2()?;
    let deadline = Duration::from_millis(300);
    let body = lifecycle_bytes(
        streams::v2::LifecycleKind::Activation,
        b"opaque protected activation",
    )?;
    let token = lab.owners[0]
        .submit_lifecycle(&body, lab.now, deadline)?
        .ok_or("Lifecycle admission")?;
    let mut scratch = [0; 4096];
    let mut incoming = None;
    for _ in 0..100 {
        lab.pump()?;
        if let Some(value) = lab.owners[1].next(lab.now, &mut scratch)? {
            incoming = Some(value);
            break;
        }
    }
    let incoming = incoming.ok_or("missing actual held Lifecycle")?;
    assert_eq!(incoming.stream, Some(streams::Stream::Lifecycle));
    let receive_deadline = actual_held(&lab.owners[1], streams::Stream::Lifecycle)?.deadline;
    lab.ping_pong(99, false)?;
    assert_eq!(lab.owners[0].expiry(), deadline);
    assert_eq!(
        actual_held(&lab.owners[1], streams::Stream::Lifecycle)?.deadline,
        receive_deadline
    );
    assert!(!lab.owners[0].confirmed(token, lab.now)?);
    let before = match &lab.owners[0].backend {
        Backend::Streamed(value) => value.next,
        _ => return Err("wrong owner".into()),
    };
    lab.now = deadline;
    assert!(lab.owners[0].confirmed(token, lab.now).is_err());
    assert!(
        lab.owners[0]
            .submit_lifecycle(&body, lab.now, Duration::from_secs(1))
            .is_err()
    );
    assert_eq!(
        match &lab.owners[0].backend {
            Backend::Streamed(value) => value.next,
            _ => return Err("wrong owner".into()),
        },
        before
    );
    Ok(())
}
