//! Actual logical-owner charging plus the maintained Fragmenter/AEAD/reassembler.
//! Imported keys and simulated whole writes are component evidence, not a carrier lab.
use super::*;
use crate::security;
use codec::source_copy::{Policy, Scope};
use zeroize::Zeroizing;

fn framing(config: Config) -> OutputFraming {
    OutputFraming {
        forward: codec::FragmentConfig {
            path_mtu: 160,
            outer_overhead_bytes: config.geometry.forward_overhead_bytes,
            max_message_bytes: 1024,
            max_fragments: 64,
        },
        reverse: codec::FragmentConfig {
            path_mtu: config.geometry.reverse_overhead_bytes + 40 + 31,
            outer_overhead_bytes: config.geometry.reverse_overhead_bytes,
            max_message_bytes: 1024,
            max_fragments: 64,
        },
    }
}
fn selected(
    config: Config,
    role: Role,
    copies: CopyPolicies,
    reserved: bool,
) -> TestResult<Endpoint> {
    let selected = framing(config);
    if reserved {
        let plan = storage::Plan::for_endpoint_with_output_framing(
            config,
            context(role),
            17,
            Tick(0),
            copies,
            None,
            Some(selected),
        )?;
        Ok(Endpoint::new_reserved_with_copies(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    } else {
        Ok(Endpoint::new_with_output_framing(
            config,
            context(role),
            17,
            Tick(0),
            copies,
            selected,
        )?)
    }
}

#[test]
fn exact_fragment_admission_keeps_unframed_bytes_held_token_and_actual_plan() -> TestResult {
    for reserved in [false, true] {
        let config = config(true, rolling::wire::SourceWire::Exact);
        let selected_framing = framing(config);
        let old = storage::Plan::for_endpoint(config, context(Role::Client), 17, Tick(0))?;
        let plan = storage::Plan::for_endpoint_with_output_framing(
            config,
            context(Role::Client),
            17,
            Tick(0),
            CopyPolicies::ONE,
            None,
            Some(selected_framing),
        )?;
        assert_eq!(plan.capacity_bytes(), old.capacity_bytes());
        assert_eq!(plan.output_framing(), Some(selected_framing));
        assert_eq!(old.output_framing(), None);
        assert!(matches!(
            Endpoint::new_reserved(
                plan,
                storage::Limits {
                    capacity_bytes: plan.capacity_bytes() - 1
                }
            ),
            Err(Error::Capacity { .. })
        ));
        let mut framed = selected(config, Role::Client, CopyPolicies::ONE, reserved)?;
        let mut plain = endpoint(config, Role::Client)?;
        assert_eq!(
            framed.output_fragment_config(),
            Some(selected_framing.forward)
        );
        assert_eq!(plain.output_fragment_config(), None);
        assert_eq!(plain.binding_digest(), config.binding_digest(17)?);
        assert_eq!(
            framed.binding_digest(),
            selected_framing.binding_digest(config, CopyPolicies::ONE, 17)?
        );
        assert_ne!(framed.binding_digest(), plain.binding_digest());
        let original = packet(true, 0x43, 64);
        for endpoint in [&mut framed, &mut plain] {
            endpoint
                .enqueue_admitted_identified(Tick(0), 0, &original)?
                .ok_or("admission")?;
            endpoint.flush(Tick(0))?;
            endpoint.step(Tick(0), work())?;
        }
        let length = framed.sender.pending_wire_len()?.ok_or("actual source")?;
        let geometry = selected_framing.forward.geometry(length)?;
        assert!(geometry.fragments() > 1);
        let mut output = [0xa5; rolling::wire::MAX_RECORD_BYTES];
        let mut witnesses = [witness(); 4];
        let sender = framed.sender_status();
        let serial = framed.next_output;
        let mut short_packets = OutboundBudget {
            packets: geometry.fragments() - 1,
            wire_bytes: geometry.wire_bytes(),
        };
        let saved_packets = short_packets;
        assert_eq!(
            framed.prepare_output(
                Tick(0),
                u64::MAX - 3,
                true,
                &mut output,
                &mut short_packets,
                &mut witnesses
            )?,
            None
        );
        assert_eq!(short_packets, saved_packets);
        let mut short_bytes = OutboundBudget {
            packets: geometry.fragments(),
            wire_bytes: geometry.wire_bytes() - 1,
        };
        let saved_bytes = short_bytes;
        assert_eq!(
            framed.prepare_output(
                Tick(0),
                u64::MAX - 3,
                true,
                &mut output,
                &mut short_bytes,
                &mut witnesses
            )?,
            None
        );
        assert_eq!(short_bytes, saved_bytes);
        assert_eq!(framed.sender_status(), sender);
        assert_eq!(framed.next_output, serial);
        assert_eq!(framed.pending_output(), None);
        assert!(output.iter().all(|byte| *byte == 0xa5));
        let mut exact = OutboundBudget {
            packets: geometry.fragments(),
            wire_bytes: geometry.wire_bytes(),
        };
        let prepared = framed
            .prepare_output(
                Tick(0),
                u64::MAX - 3,
                true,
                &mut output,
                &mut exact,
                &mut witnesses,
            )?
            .ok_or("exact geometry")?;
        assert_eq!(prepared.packets, geometry.fragments());
        assert_eq!(prepared.wire_bytes, geometry.wire_bytes());
        assert_eq!(prepared.security_number, u64::MAX - 3);
        assert_eq!(exact, OutboundBudget::default());
        let mut old_number = 19;
        let (old_prepared, old_wire) =
            emit(&mut plain, Tick(0), &mut old_number, true)?.ok_or("old output")?;
        assert_eq!(old_prepared.packets, 1);
        assert_eq!(&output[..prepared.bytes], old_wire.bytes);
        assert_eq!(old_prepared.id, prepared.id);
        let mut untouched = [0xa5; rolling::wire::MAX_RECORD_BYTES];
        assert_eq!(
            framed.prepare_output(
                Tick(1),
                7,
                false,
                &mut untouched,
                &mut exact,
                &mut witnesses
            )?,
            Some(prepared)
        );
        assert!(untouched.iter().all(|byte| *byte == 0xa5));
        assert_eq!(exact, OutboundBudget::default());
        assert_eq!(framed.statistics().handed, 0);
        framed.confirm_output_at(Tick(2), Tick(1), prepared)?;
        assert_eq!(framed.statistics().handed, 1);
        assert_eq!(framed.confirm_output(Tick(0), prepared), Err(Error::Token));
        if reserved {
            assert_eq!(
                framed
                    .storage_usage()
                    .ok_or("reserved usage")?
                    .capacity_bytes,
                plan.capacity_bytes()
            );
        }
        // Every global direction is admitted before selected allocation, including
        // feedback and a reverse direction that this client is not transmitting.
        for invalid in [
            OutputFraming {
                reverse: codec::FragmentConfig {
                    outer_overhead_bytes: selected_framing.reverse.outer_overhead_bytes + 1,
                    ..selected_framing.reverse
                },
                ..selected_framing
            },
            OutputFraming {
                reverse: codec::FragmentConfig {
                    max_message_bytes: 63,
                    ..selected_framing.reverse
                },
                ..selected_framing
            },
            OutputFraming {
                forward: codec::FragmentConfig {
                    max_fragments: 1,
                    ..selected_framing.forward
                },
                ..selected_framing
            },
            OutputFraming {
                forward: codec::FragmentConfig {
                    path_mtu: selected_framing.forward.outer_overhead_bytes + 40,
                    ..selected_framing.forward
                },
                ..selected_framing
            },
        ] {
            assert!(
                storage::Plan::for_endpoint_with_output_framing(
                    config,
                    context(Role::Client),
                    17,
                    Tick(0),
                    CopyPolicies::ONE,
                    None,
                    Some(invalid)
                )
                .is_err()
            );
        }
    }
    Ok(())
}

fn root(role: security::Role, digest: [u8; 32]) -> TestResult<security::SessionRoot> {
    Ok(security::SessionRoot::from_split_keys(
        Zeroizing::new([0x37; 32]),
        Zeroizing::new([0x59; 32]),
        security::SessionBinding {
            session: security::SessionId(context(Role::Client).session.to_be_bytes()),
            transcript: digest,
        },
        role,
    )?)
}
struct FragmentPath {
    config: codec::FragmentConfig,
    sender: codec::Fragmenter,
    receiver: codec::Reassembler,
    sealer: security::Sender,
    opener: security::Receiver,
}
impl FragmentPath {
    fn new(config: codec::FragmentConfig, digest: [u8; 32], reverse: bool) -> TestResult<Self> {
        let mut initiator = root(security::Role::Initiator, digest)?;
        let mut responder = root(security::Role::Responder, digest)?;
        let (sender, receiver) = if reverse {
            (&mut responder, &mut initiator)
        } else {
            (&mut initiator, &mut responder)
        };
        let limits = security::Limits {
            max_body_bytes: 1024,
            packets_per_key: 128,
            max_body_bytes_per_key: 65536,
        };
        let protection = security::Protection::ChaCha20Poly1305;
        let sealer = sender.sender(
            security::Purpose::Data,
            security::LaneId(1),
            limits,
            protection,
        )?;
        let opener = receiver.receiver(
            security::Purpose::Data,
            security::LaneId(1),
            limits,
            protection,
        )?;
        // An independent fragment label; the caller retains full authenticated
        // session/direction/configuration authority in metadata and actual keys.
        let fragment_context = codec::FragmentContext {
            session: codec::SessionId(if reverse { 12 } else { 11 }),
            epoch: crate::core::Epoch(7),
        };
        let sender = codec::Fragmenter::new(fragment_context, config, codec::MessageId(1))?;
        let receive = codec::ReassemblyConfig {
            max_message_bytes: 1024,
            max_messages: 2,
            max_fragment_payload_bytes: u16::try_from(config.geometry(1)?.chunk_bytes())?,
            max_fragments_per_message: 64,
            max_total_fragments: 128,
            max_reserved_bytes: 2048,
            max_lifetime_ticks: 10000,
            replay_window: 64,
        };
        let receiver = codec::Reassembler::new_reserved(
            fragment_context,
            receive,
            codec::fragment_storage::Limits {
                capacity_bytes: codec::fragment_storage::Plan::for_reassembly(receive)?
                    .capacity_bytes(),
            },
        )?;
        Ok(Self {
            config,
            sender,
            receiver,
            sealer,
            opener,
        })
    }
    fn transfer(
        &mut self,
        metadata: security::Metadata<'_>,
        bytes: &[u8],
        prepared: PreparedOutput,
        now: Tick,
        owner: &Endpoint,
    ) -> TestResult<Vec<u8>> {
        let geometry = self.sender.geometry(bytes.len())?;
        assert_eq!(geometry.fragments(), prepared.packets);
        assert_eq!(geometry.wire_bytes(), prepared.wire_bytes);
        assert_eq!(self.sealer.next_number().0, prepared.security_number);
        let mut flat = vec![0; geometry.encoded_bytes()];
        let batch = self.sender.fragment_into(bytes, &mut flat)?;
        let mut output = [0; 1024];
        let mut total = 0;
        let mut completed = None;
        for index in 0..batch.len() {
            let fragment = batch.fragment(index).ok_or("canonical fragment")?;
            let mut sealed = vec![0; fragment.len() + self.sealer.overhead()];
            let sent = self.sealer.seal(metadata, fragment, &mut sealed)?;
            assert_eq!(
                sent.number.0,
                prepared.security_number + u64::try_from(index)?
            );
            assert!(sent.bytes + 28 <= self.config.path_mtu);
            total += sent.bytes + 28;
            let mut plain = vec![0; sent.bytes];
            let received = self
                .opener
                .open(metadata, &sealed[..sent.bytes], &mut plain)?;
            assert_eq!(&plain[..received.bytes], fragment);
            assert_eq!(
                self.opener
                    .open(metadata, &sealed[..sent.bytes], &mut plain),
                Err(security::Error::Replay)
            );
            match self.receiver.accept_at_until(
                &plain[..received.bytes],
                now.0,
                now.0,
                9000,
                &mut output,
            )? {
                codec::TimedReassemblyStatus::Pending { .. } => assert!(index + 1 < batch.len()),
                codec::TimedReassemblyStatus::Complete { length, timing, .. } => {
                    assert_eq!(index + 1, batch.len());
                    assert_eq!(timing.first_received_ticks(), now.0);
                    assert_eq!(timing.deadline_ticks(), 9000);
                    completed = Some(output[..length].to_vec());
                }
                _ => return Err("unexpected real reassembly result".into()),
            }
            // Fragment acceptance cannot discharge the actual whole-copy token.
            assert_eq!(owner.pending_output(), Some(prepared));
        }
        assert_eq!(total, prepared.wire_bytes);
        let output = completed.ok_or("whole original body")?;
        assert_eq!(output, bytes);
        Ok(output)
    }
}

#[test]
fn physical_fragment_batches_keep_three_short_copies_one_debt_and_reverse_feedback() -> TestResult {
    for reserved in [false, true] {
        let mut config = config(true, rolling::wire::SourceWire::Exact);
        let overhead = 28 + security::Protection::ChaCha20Poly1305.overhead_bytes();
        config.geometry = Geometry {
            forward_overhead_bytes: overhead,
            reverse_overhead_bytes: overhead,
        };
        let copies = CopyPolicies {
            forward: Policy {
                max_unit_bytes: 128,
                copies: 3,
                scope: Scope::AllShort,
            },
            reverse: Policy::ONE,
        };
        let mut client = selected(config, Role::Client, copies, reserved)?;
        let mut server = selected(config, Role::Server, copies, reserved)?;
        let selected_framing = framing(config);
        let digest = selected_framing.binding_digest(config, copies, 17)?;
        assert_eq!(client.binding_digest(), server.binding_digest());
        let mut forward = FragmentPath::new(selected_framing.forward, digest.0, false)?;
        let mut reverse = FragmentPath::new(selected_framing.reverse, digest.0, true)?;
        let metadata = security::Metadata {
            epoch: security::Epoch(7),
            configuration: security::ConfigDigest(digest.0),
            extra: &[],
        };
        let original = packet(true, 0x71, 64);
        let identity = client
            .enqueue_admitted_identified(Tick(0), 1, &original)?
            .ok_or("admitted native")?;
        client.flush(Tick(0))?;
        client.step(Tick(0), work())?;
        let original_cap = client.sender.deadline();
        let client_usage = client.storage_usage();
        let server_usage = server.storage_usage();
        let mut first = None;
        for ordinal in 1..=3u8 {
            let now = Tick(u64::from(ordinal) * 1000);
            let mut output = [0; rolling::wire::MAX_RECORD_BYTES];
            let mut witnesses = [witness(); 4];
            let mut budget = OutboundBudget {
                packets: 64,
                wire_bytes: 65536,
            };
            let prepared = client
                .prepare_output(
                    now,
                    forward.sealer.next_number().0,
                    true,
                    &mut output,
                    &mut budget,
                    &mut witnesses,
                )?
                .ok_or("actual source copy")?;
            let copy = prepared.source_copy().ok_or("actual copy ordinal")?;
            assert_eq!((copy.ordinal(), copy.total()), (ordinal, 3));
            assert!(prepared.packets > 1);
            let body = &output[..prepared.bytes];
            if let Some(first) = &first {
                assert_eq!(body, first);
            } else {
                first = Some(body.to_vec());
            }
            let charged = budget;
            let mut blocked = [0xa5; rolling::wire::MAX_RECORD_BYTES];
            assert_eq!(
                client.prepare_output(
                    now,
                    999,
                    false,
                    &mut blocked,
                    &mut budget,
                    &mut witnesses
                )?,
                Some(prepared)
            );
            assert_eq!(budget, charged);
            assert!(blocked.iter().all(|byte| *byte == 0xa5));
            assert_eq!(client.sender.deadline(), original_cap);
            let complete = forward.transfer(metadata, body, prepared, now, &client)?;
            assert_eq!(client.statistics().handed, u64::from(ordinal - 1));
            client.confirm_output_at(Tick(now.0 + 1), now, prepared)?;
            assert_eq!(client.confirm_output(Tick(0), prepared), Err(Error::Token));
            server.accept_authenticated(Tick(now.0 + 1), prepared.kind, &complete)?;
            for _ in 0..8 {
                server.step(Tick(now.0 + 1), work())?;
            }
            let mut native = [0; 1024];
            for _ in 0..8 {
                if let NativePreparation::Ready(pending) =
                    server.prepare_native(Tick(now.0 + 1), 16, Tick(100000), &mut native)?
                {
                    assert_eq!(ordinal, 1);
                    assert_eq!(pending.identity(), identity);
                    assert_eq!(&native[..pending.bytes()], original);
                    server.commit_native(Tick(now.0 + 1), pending.token())?;
                }
            }
            assert_eq!(server.statistics().committed, 1);
            if ordinal == 1 {
                let at = Tick(now.0 + 101);
                for _ in 0..8 {
                    server.step(at, work())?;
                }
                let geometry = selected_framing
                    .reverse
                    .geometry(scheduler::FEEDBACK_BYTES)?;
                assert!(geometry.fragments() > 1);
                let mut feedback = [0xa5; 1024];
                let mut short = OutboundBudget {
                    packets: geometry.fragments() - 1,
                    wire_bytes: geometry.wire_bytes(),
                };
                let saved = short;
                assert_eq!(
                    server.prepare_output(
                        at,
                        reverse.sealer.next_number().0,
                        false,
                        &mut feedback,
                        &mut short,
                        &mut witnesses
                    )?,
                    None
                );
                assert_eq!(short, saved);
                assert!(feedback.iter().all(|byte| *byte == 0xa5));
                let mut budget = OutboundBudget {
                    packets: geometry.fragments(),
                    wire_bytes: geometry.wire_bytes(),
                };
                let pending = server
                    .prepare_output(
                        at,
                        reverse.sealer.next_number().0,
                        false,
                        &mut feedback,
                        &mut budget,
                        &mut witnesses,
                    )?
                    .ok_or("real reverse feedback")?;
                assert_eq!(pending.kind, record_engine::EmissionKind::Feedback);
                assert_eq!(pending.packets, geometry.fragments());
                assert_eq!(budget, OutboundBudget::default());
                let complete =
                    reverse.transfer(metadata, &feedback[..pending.bytes], pending, at, &server)?;
                server.confirm_output(at, pending)?;
                client.accept_authenticated(at, pending.kind, &complete)?;
                assert_eq!(client.sender_status().encoder.confirmed_prefix, 0);
                assert_eq!(client.sender_status().sent_sources, 1);
            }
        }
        assert_eq!(client.statistics().admitted, 1);
        assert_eq!(client.statistics().handed, 3);
        assert_eq!(client.sender_status().encoder.next_source, 1);
        assert_eq!(client.sender_status().encoder.confirmed_prefix, 1);
        assert_eq!(client.sender_status().regular_due, 0);
        assert_eq!(client.storage_usage(), client_usage);
        assert_eq!(server.storage_usage(), server_usage);
    }
    Ok(())
}
