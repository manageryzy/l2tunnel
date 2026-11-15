//! Pure selected copy execution with actual AEAD and actual native reconstruction.
//! Imported fixed test keys prove component protection, not Noise/member startup.
use super::*;
use crate::security;
use codec::source_copy::{Policy as CopyPolicy, Scope as CopyScope};
use zeroize::Zeroizing;

fn policies() -> CopyPolicies {
    CopyPolicies {
        forward: CopyPolicy {
            max_unit_bytes: 128,
            copies: 3,
            scope: CopyScope::ContextAndIndependent,
        },
        reverse: CopyPolicy {
            max_unit_bytes: 64,
            copies: 2,
            scope: CopyScope::AllShort,
        },
    }
}
fn selected(
    config: Config,
    role: Role,
    copies: CopyPolicies,
    reserved: bool,
) -> TestResult<Endpoint> {
    if reserved {
        let plan =
            storage::Plan::for_endpoint_with_copies(config, context(role), 17, Tick(0), copies)?;
        Ok(Endpoint::new_reserved_with_copies(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    } else {
        Ok(Endpoint::new_with_copies(
            config,
            context(role),
            17,
            Tick(0),
            copies,
        )?)
    }
}
fn root(role: security::Role, transcript: [u8; 32]) -> TestResult<security::SessionRoot> {
    Ok(security::SessionRoot::from_split_keys(
        Zeroizing::new([0x71; 32]),
        Zeroizing::new([0x93; 32]),
        security::SessionBinding {
            session: security::SessionId(context(Role::Client).session.to_be_bytes()),
            transcript,
        },
        role,
    )?)
}

#[test]
fn selected_copies_seal_distinct_numbers_keep_held_bytes_and_deliver_one_original() -> TestResult {
    for reserved in [false, true] {
        let mut config = config(true, rolling::wire::SourceWire::Exact);
        // This component envelope is actual packet-security AEAD plus IPv4/UDP;
        // full Common cover/route installation remains the integrator's gate.
        let protection = security::Protection::ChaCha20Poly1305;
        let overhead = 28 + protection.overhead_bytes();
        config.geometry.forward_overhead_bytes = overhead;
        config.geometry.reverse_overhead_bytes = overhead;
        let copies = policies();
        let mut client = selected(config, Role::Client, copies, reserved)?;
        let mut server = selected(config, Role::Server, copies, reserved)?;
        assert_eq!(client.packing.copy_policy(), copies.forward);
        assert_eq!(server.packing.copy_policy(), copies.reverse);
        let client_usage = client.storage_usage();
        let server_usage = server.storage_usage();
        let digest = copies.binding_digest(config, 17)?;
        assert_eq!(client.binding_digest(), digest);
        assert_eq!(server.binding_digest(), digest);
        let mut send_root = root(security::Role::Initiator, digest.0)?;
        let mut receive_root = root(security::Role::Responder, digest.0)?;
        let limits = security::Limits {
            max_body_bytes: 1024,
            packets_per_key: 64,
            max_body_bytes_per_key: 65536,
        };
        let mut sealer = send_root.sender(
            security::Purpose::Data,
            security::LaneId(1),
            limits,
            protection,
        )?;
        let mut opener = receive_root.receiver(
            security::Purpose::Data,
            security::LaneId(1),
            limits,
            protection,
        )?;
        let metadata = security::Metadata {
            epoch: security::Epoch(context(Role::Client).epoch),
            configuration: security::ConfigDigest(digest.0),
            extra: &[],
        };
        let original = packet(true, 0x53, 80);
        let native_id = client
            .enqueue_admitted_identified(Tick(0), 2, &original)?
            .ok_or("native admission")?;
        client.flush(Tick(0))?;
        assert_eq!(
            client.packing.status().next_unit,
            Some(receiver::SourceId(14))
        );
        let original_end = client.sender.deadline();
        let mut budget = OutboundBudget {
            packets: 3,
            wire_bytes: 6000,
        };
        let mut first_wire = None;
        let mut first_units = None;
        let mut previous = None;
        let mut all_debits = 0;
        for ordinal in 1..=3u8 {
            let now = Tick(u64::from(ordinal) * 1000);
            let mut output = vec![0; rolling::wire::MAX_RECORD_BYTES];
            let mut units = [witness(); 4];
            let prepared = client
                .prepare_output(
                    now,
                    sealer.next_number().0,
                    true,
                    &mut output,
                    &mut budget,
                    &mut units,
                )?
                .ok_or("actual copy output")?;
            let copy = prepared.source_copy().ok_or("actual source-copy witness")?;
            assert_eq!(copy.ordinal(), ordinal);
            assert_eq!(copy.total(), 3);
            assert_eq!(
                prepared.id,
                OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(0)))
            );
            assert_eq!(client.sender.deadline(), original_end);
            assert_eq!(client.sender_status().encoder.next_source, 1);
            let bytes = output[..prepared.bytes].to_vec();
            if let Some(first) = &first_wire {
                assert_eq!(&bytes, first);
            } else {
                first_wire = Some(bytes.clone());
            }
            let current_units = units[..prepared.witnesses]
                .iter()
                .map(|u| (u.identity, u.index, u.count))
                .collect::<Vec<_>>();
            if let Some(first) = &first_units {
                assert_eq!(&current_units, first);
            } else {
                first_units = Some(current_units);
            }
            let charged = budget;
            let mut untouched = vec![0xa5; output.len()];
            assert_eq!(
                client.prepare_output(
                    now,
                    sealer.next_number().0 + 99,
                    false,
                    &mut untouched,
                    &mut budget,
                    &mut units
                )?,
                Some(prepared)
            );
            assert!(untouched.iter().all(|b| *b == 0xa5));
            assert_eq!(budget, charged);
            let mut protected = vec![0; bytes.len() + sealer.overhead()];
            let sealed = sealer.seal(metadata, &bytes, &mut protected)?;
            assert_eq!(sealed.number.0, u64::from(ordinal - 1));
            assert_eq!(prepared.security_number, sealed.number.0);
            assert_eq!(prepared.wire_bytes, sealed.bytes + 28);
            let retained_ciphertext = protected.clone();
            // A simulated blocked send leaves the one actual sealed packet and
            // local witness untouched; only a later whole-send observation confirms.
            client.tick(now)?;
            assert_eq!(client.pending_output(), Some(prepared));
            assert_eq!(protected, retained_ciphertext);
            let mut plain = vec![0; protected.len()];
            let opened = opener.open(metadata, &protected, &mut plain)?;
            assert_eq!(&plain[..opened.bytes], bytes);
            let observed = Tick(now.0 + 1);
            client.confirm_output_at(observed, now, prepared)?;
            all_debits += prepared.wire_bytes;
            if let Some(stale) = previous {
                let state = client.statistics();
                assert_eq!(client.confirm_output(Tick(0), stale), Err(Error::Token));
                assert_eq!(client.statistics(), state);
            }
            previous = Some(prepared);
            server.accept_authenticated(observed, prepared.kind, &plain[..opened.bytes])?;
            for _ in 0..8 {
                server.step(observed, work())?;
            }
            let mut native = [0; 1024];
            for _ in 0..8 {
                if let NativePreparation::Ready(pending) =
                    server.prepare_native(observed, 16, Tick(100000), &mut native)?
                {
                    assert_eq!(ordinal, 1);
                    assert_eq!(pending.identity(), native_id);
                    assert_eq!(&native[..pending.bytes()], original);
                    server.commit_native(observed, pending.token())?;
                }
            }
            assert_eq!(server.statistics().committed, 1);
            if ordinal == 1 {
                let at = Tick(now.0 + 101);
                for _ in 0..8 {
                    server.step(at, work())?;
                }
                let mut number = 77;
                let (_, feedback) =
                    emit(&mut server, at, &mut number, false)?.ok_or("actual reverse feedback")?;
                assert_eq!(feedback.kind, record_engine::EmissionKind::Feedback);
                client.accept_authenticated(at, feedback.kind, &feedback.bytes)?;
                assert_eq!(client.sender_status().encoder.confirmed_prefix, 0);
                assert_eq!(client.sender_status().sent_sources, 1);
                assert!(!client.drained());
            }
        }
        assert_eq!(budget.packets, 0);
        assert_eq!(budget.wire_bytes, 6000 - all_debits);
        assert_eq!(client.statistics().admitted, 1);
        assert_eq!(client.statistics().handed, 3);
        assert_eq!(client.sender_status().encoder.confirmed_prefix, 1);
        assert_eq!(client.sender_status().encoder.next_source, 1);
        assert_eq!(client.sender_status().regular_due, 0);
        assert_eq!(client.storage_usage(), client_usage);
        assert_eq!(server.storage_usage(), server_usage);
    }
    Ok(())
}

#[test]
fn complete_copy_policy_binding_plans_and_one_copy_default_remain_exact() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let copies = policies();
    let literal = [
        0, 0, 0, 0, 0, 0, 0, 128, 3, 2, 0, 0, 0, 0, 0, 0, 0, 64, 2, 1,
    ];
    assert_eq!(copies.canonical_bytes()?, literal);
    assert_eq!(
        CopyPolicies::ONE.binding_digest(config, 17)?,
        config.binding_digest(17)?
    );
    assert_ne!(
        copies.binding_digest(config, 17)?,
        config.binding_digest(17)?
    );
    let mut changed = copies;
    changed.reverse.copies = 3;
    assert_ne!(
        changed.binding_digest(config, 17)?,
        copies.binding_digest(config, 17)?
    );
    let one = storage::Plan::for_endpoint(config, context(Role::Client), 17, Tick(0))?;
    let repeated = storage::Plan::for_endpoint_with_copies(
        config,
        context(Role::Client),
        17,
        Tick(0),
        copies,
    )?;
    assert_eq!(one.capacity_bytes(), repeated.capacity_bytes());
    assert_eq!(repeated.source_copy_policies(), copies);
    assert!(matches!(
        Endpoint::new_reserved(
            repeated,
            storage::Limits {
                capacity_bytes: repeated.capacity_bytes()
            }
        ),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Endpoint::new_reserved_with_copies(
            repeated,
            storage::Limits {
                capacity_bytes: repeated.capacity_bytes() - 1
            }
        ),
        Err(Error::Capacity { .. })
    ));
    let mut invalid = copies;
    invalid.forward.copies = 5;
    assert!(
        storage::Plan::for_endpoint_with_copies(
            config,
            context(Role::Client),
            17,
            Tick(0),
            invalid
        )
        .is_err()
    );
    let original = packet(true, 0x53, 80);
    let mut old = Endpoint::new(config, context(Role::Client), 17, Tick(0))?;
    let mut explicit = selected(config, Role::Client, CopyPolicies::ONE, false)?;
    for endpoint in [&mut old, &mut explicit] {
        endpoint
            .enqueue_admitted_identified(Tick(0), 2, &original)?
            .ok_or("admission")?;
        endpoint.flush(Tick(0))?;
    }
    let mut a = 91;
    let mut b = 91;
    let (left, left_bytes) = emit(&mut old, Tick(1), &mut a, true)?.ok_or("old output")?;
    let (right, right_bytes) =
        emit(&mut explicit, Tick(1), &mut b, true)?.ok_or("explicit one output")?;
    assert_eq!(left_bytes.bytes, right_bytes.bytes);
    assert_eq!(left.id, right.id);
    assert_eq!(left.wire_bytes, right.wire_bytes);
    assert_eq!(old.binding_digest(), explicit.binding_digest());
    Ok(())
}
