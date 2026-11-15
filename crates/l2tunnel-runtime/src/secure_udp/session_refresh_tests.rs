//! Actual maintained Noise/member/Records and reserved four-stream composition.
//! These tests own no socket/device and do not qualify retained recovery.

use super::*;
use l2tunnel::{identity, security::Role};
use l2tunnel_management::{self as mg, delivery, messages};
use l2tunnel_recovery as recovery;
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
fn credentials(side: usize) -> establish::Identity {
    let own = if side == 0 { 11 } else { 22 };
    let peer = if side == 0 { 22 } else { 11 };
    establish::Identity {
        local: hs::LocalSecret::new(Zeroizing::new([own; 32])),
        peer: hs::LocalSecret::new(Zeroizing::new([peer; 32])).public_key(),
        psk: Some(hs::Psk::new(Zeroizing::new([31; 32]))),
    }
}
fn outer(number: u32) -> cover::PacketMeta {
    cover::PacketMeta {
        phase: cover::Phase::Established,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number),
    }
}
fn control_scope() -> record::Scope {
    record::Scope {
        epoch: security::Epoch(1),
        configuration: security::ConfigDigest([3; 32]),
    }
}
fn data_scope() -> record::Scope {
    record::Scope {
        epoch: security::Epoch(2),
        configuration: security::ConfigDigest([4; 32]),
    }
}
fn selection() -> Result<Selection> {
    Ok(Selection::new(hs::refresh::SelectionSpec {
        lane: security::LaneId(7),
        limits: security::Limits {
            max_body_bytes: 512,
            packets_per_key: security::MAX_PACKETS_PER_KEY,
            max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
        },
        protection: security::Protection::ChaCha20Poly1305,
        control_epoch: control_scope().epoch,
        control_digest: control_scope().configuration,
        envelope_digest: security::ConfigDigest([5; 32]),
        exchange_micros: 500_000,
        key_micros: 5_000_000,
        overlap_micros: 5_000,
        max_flight_copies: 4,
    })?)
}
fn member_key() -> Result<identity::IdentityKey> {
    let encoded = concat!(
        "3051020101300506032b657004220420",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "812100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn initial_pair(selected: Selection) -> Result<[hs::refresh::ConfirmedInitial; 2]> {
    let make = |side| -> Result<hs::Handshake> {
        let identity = credentials(side);
        Ok(hs::Handshake::new_refreshable(
            hs::Config {
                role: if side == 0 {
                    Role::Initiator
                } else {
                    Role::Responder
                },
                profile: hs::Profile::IkPsk2,
                binding: hs::Binding {
                    session: hs::SessionId([6; 16]),
                    configuration: [7; 32],
                    carrier: [8; 32],
                    outer: [9; 32],
                    member: [10; 32],
                },
                deadline: hs::Time(5_000_000),
            },
            selected,
            identity.local,
            identity.peer,
            identity.psk,
            hs::Time(0),
            &mut Entropy(41 + side as u8),
        )?)
    };
    let mut a = make(0)?;
    let mut b = make(1)?;
    let mut raw = [0; hs::MAX_FLIGHT_BYTES];
    let n = a.write(hs::Time(1), &mut raw)?;
    b.read(hs::Time(1), n.kind, &raw[..n.bytes])?;
    let n = b.write(hs::Time(2), &mut raw)?;
    a.read(hs::Time(2), n.kind, &raw[..n.bytes])?;
    let n = a.write(hs::Time(3), &mut raw)?;
    b.read(hs::Time(3), n.kind, &raw[..n.bytes])?;
    let n = b.write(hs::Time(3), &mut raw)?;
    a.read(hs::Time(3), n.kind, &raw[..n.bytes])?;
    let a = a.finish_refreshable_with_confirmation(hs::Time(3))?.initial;
    let b = b.finish_refreshable_with_confirmation(hs::Time(3))?.initial;
    let context = identity::Context {
        session: a.binding().session,
        transcript: a.binding().transcript,
        configuration: a.authenticated().configuration,
        initiator_noise: identity::NoisePublicKey(a.pins().0.0),
        responder_noise: identity::NoisePublicKey(a.pins().1.0),
        carrier: a.authenticated().carrier,
        outer: a.authenticated().outer,
    };
    let member = member_key()?;
    let proof = identity::MemberProof::sign(&member, context)?;
    let members = identity::Allowlist::new(&[member.public_key()])?;
    let mut a = a.joining(selected.spec().limits, hs::Time(4), hs::Time(4_000_000))?;
    let mut b = b.joining(selected.spec().limits, hs::Time(4), hs::Time(4_000_000))?;
    let mut raw = [0; 1024];
    let mut plain = [0; 512];
    let n = a.seal(hs::Time(5), proof.as_bytes(), &mut raw)?.bytes;
    let opened = b.open(hs::Time(5), &raw[..n], &mut plain)?;
    let accepted = identity::verify_member(&plain[..opened.bytes], context, &members)?;
    let mut acceptance = [0; 34];
    acceptance[..2].copy_from_slice(&[1, 2]);
    acceptance[2..].copy_from_slice(&accepted.0);
    let n = b.seal(hs::Time(6), &acceptance, &mut raw)?.bytes;
    let opened = a.open(hs::Time(6), &raw[..n], &mut plain)?;
    assert_eq!(&plain[..opened.bytes], &acceptance);
    Ok([a.retire(hs::Time(7))?, b.retire(hs::Time(7))?])
}

fn binding(side: usize) -> delivery::Binding {
    delivery::Binding {
        session: mg::SessionId([6; 16]),
        lane: mg::LaneId(7),
        local_role: if side == 0 {
            mg::Role::Client
        } else {
            mg::Role::Server
        },
        control_epoch: 1,
    }
}
fn management_scope(scope: record::Scope) -> sc::Scope {
    sc::Scope {
        epoch: l2tunnel_core::Epoch(scope.epoch.0),
        digest: l2tunnel_core::ConfigDigest(scope.configuration.0),
    }
}
fn make_control(side: usize, appearance: cover::Appearance) -> Result<control::Owner> {
    let wire_overhead = 28
        + 9
        + sec::PREFIX_BYTES
        + 16
        + if appearance == cover::Appearance::QuicLike {
            13
        } else {
            14
        };
    let base = delivery::Settings {
        recovery: recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 768,
            receive_bytes: 768,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(2),
            maximum_rto: Duration::from_millis(20),
            ack_delay: Duration::ZERO,
            max_retries: 128,
        },
        interval: Duration::from_millis(1),
        packets_per_interval: 4,
        bytes_per_interval: 4096,
        wire_overhead,
    };
    let message = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: wire_overhead + 8,
            ..base
        },
        path_mtu: 1500,
        max_message_bytes: 2048,
        max_outbound_messages: 4,
        max_outbound_bytes: 8192,
        max_fragments: 16,
        max_reassembly_bytes: 4096,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(1),
        work_per_call: 4,
    };
    let selected = control::SettingsV2 {
        streams: [message; 4],
    };
    let now = Duration::from_micros(9);
    let expires = Duration::from_secs(10);
    let plans = selected.message_storage_plans(binding(side), now, expires)?;
    let wrapper = control::wrapper_storage::Plan::new_v2(selected, base)?;
    Ok(
        control::Owner::new_leased_reserved_messages_v2_with_wrapper_plan(
            base,
            selected,
            binding(side),
            management_scope(control_scope()),
            management_scope(data_scope()),
            now,
            expires,
            plans.map(|plan| messages::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            }),
            wrapper,
            control::wrapper_storage::Limits {
                capacity_bytes: wrapper.capacity_bytes(),
            },
        )?,
    )
}

struct Endpoint {
    records: record::Records,
    control: control::Owner,
    refresh: Controller,
    outer: u32,
}
struct Lab {
    endpoints: [Endpoint; 2],
    now: Duration,
}
impl Lab {
    fn new(appearance: cover::Appearance) -> Result<Self> {
        let selected = selection()?;
        let [a, b] = initial_pair(selected)?;
        let make = |initial, side| -> Result<Endpoint> {
            let (local, peer) = if side == 0 { (11, 22) } else { (22, 11) };
            let cover = cover::Config::new(
                appearance,
                cover::ConnectionIds {
                    local: cover::ConnectionId([local; 8]),
                    peer: cover::ConnectionId([peer; 8]),
                },
                cover::MediaConfig {
                    local_ssrc: cover::Ssrc(u32::from(local)),
                    peer_ssrc: cover::Ssrc(u32::from(peer)),
                    payload_type: 96,
                },
                cover::Limits {
                    max_packet_bytes: 1500,
                    max_protected_bytes: 1024,
                },
            )?;
            let s = selected.spec();
            let records = record::Records::new_refreshable(
                initial,
                s.lane,
                s.limits,
                s.protection,
                cover,
                control_scope(),
                data_scope(),
                hs::Time(9),
                hs::Time(10_000_000),
            )?;
            let refresh = Controller::new(
                Settings {
                    retry_interval: Duration::from_millis(1),
                    min_attempt_interval: Duration::from_millis(50),
                    max_attempts: 3,
                    work_per_turn: 1,
                },
                selected,
                &records,
                Duration::from_micros(9),
                Duration::from_secs(10),
            )?;
            Ok(Endpoint {
                records,
                control: make_control(side, appearance)?,
                refresh,
                outer: 0,
            })
        };
        Ok(Self {
            endpoints: [make(a, 0)?, make(b, 1)?],
            now: Duration::from_millis(10),
        })
    }

    fn begin(&mut self) -> Result {
        let endpoint = &mut self.endpoints[0];
        let mut seal = [0; 2048];
        let mut packet = [0; 2048];
        let mut credentials = || Ok(credentials(0));
        let before = endpoint.refresh.status().protected_outputs;
        assert!(endpoint.refresh.begin(
            &mut endpoint.records,
            &mut endpoint.control,
            self.now,
            Duration::from_millis(400),
            outer(endpoint.outer),
            &mut credentials,
            &mut Entropy(71),
            &mut Scratch {
                seal: &mut seal,
                packet: &mut packet
            }
        )?);
        endpoint.outer += u32::try_from(endpoint.refresh.status().protected_outputs - before)?;
        Ok(())
    }

    fn service(&mut self, side: usize) -> Result {
        let endpoint = &mut self.endpoints[side];
        let before = endpoint.refresh.status().protected_outputs;
        endpoint.refresh.service(
            &mut endpoint.records,
            &mut endpoint.control,
            self.now,
            outer(endpoint.outer),
            &mut Scratch {
                seal: &mut [0; 2048],
                packet: &mut [0; 2048],
            },
        )?;
        endpoint.outer += u32::try_from(endpoint.refresh.status().protected_outputs - before)?;
        Ok(())
    }

    fn transmit(&mut self, side: usize, hold_lifecycle: bool) -> Result {
        let (source, target) = if side == 0 {
            let (a, b) = self.endpoints.split_at_mut(1);
            (&mut a[0], &mut b[0])
        } else {
            let (a, b) = self.endpoints.split_at_mut(1);
            (&mut b[0], &mut a[0])
        };
        for _ in 0..4 {
            let mut raw = [0; 2048];
            let Some(emitted) = source.control.poll(self.now, 4096, &mut raw)? else {
                break;
            };
            let frame = streams::v2::Frame::decode(
                &raw[..emitted.bytes],
                streams::Limits {
                    max_packet_bytes: 1024,
                },
            )?;
            if hold_lifecycle && frame.stream == streams::Stream::Lifecycle {
                continue;
            }
            let mut wire = [0; 2048];
            let sent = source.records.seal_at(
                hs::Time(micros(self.now)?),
                record::Class::Control,
                outer(source.outer),
                &raw[..emitted.bytes],
                &mut [0; 2048],
                &mut wire,
            )?;
            source.outer += 1;
            let mut plain = [0; 2048];
            let opened = target.records.open_at(
                hs::Time(micros(self.now)?),
                &wire[..sent.record.bytes],
                &mut [0; 2048],
                &mut plain,
            )?;
            assert_eq!(opened.record.class, record::Class::Control);
            assert_eq!(opened.record.scope, control_scope());
            target.control.receive(
                mg::Ingress::AuthenticatedManagement {
                    session: binding(side).session,
                    lane: binding(side).lane,
                    sender: binding(side).local_role,
                },
                &plain[..opened.record.bytes],
                self.now,
            )?;
        }
        Ok(())
    }

    fn dispatch(&mut self, side: usize) -> Result {
        let endpoint = &mut self.endpoints[side];
        let mut buffer = [0; 2048];
        while let Some(incoming) =
            endpoint
                .control
                .next_with_deferred_scope(self.now, &mut buffer, None)?
        {
            let envelope = sc::Envelope::decode(
                &buffer[..incoming.bytes],
                sc::Limits {
                    max_frame_bytes: 2048,
                    max_management_bytes: mg::HEADER_LEN,
                    max_feedback_bytes: 1024,
                },
            )?;
            match envelope.body {
                sc::Body::ProfileControl {
                    tag: sc::ProfileTag::SessionRefreshV1,
                    bytes,
                } => {
                    let mut credentials = || Ok(credentials(side));
                    endpoint.refresh.dispatch(
                        &mut endpoint.records,
                        &mut endpoint.control,
                        incoming,
                        bytes,
                        self.now,
                        Duration::from_millis(400),
                        &mut credentials,
                        &mut Entropy(91 + side as u8),
                        &mut Scratch {
                            seal: &mut [0; 2048],
                            packet: &mut [0; 2048],
                        },
                    )?;
                }
                sc::Body::Ping { nonce } => {
                    assert!(
                        endpoint
                            .control
                            .submit(
                                management_scope(control_scope()),
                                sc::Body::Pong { nonce },
                                self.now,
                                Duration::from_millis(400),
                                true
                            )?
                            .is_some()
                    );
                    endpoint.control.accepted(incoming, self.now)?;
                }
                sc::Body::Pong { .. } => endpoint.control.accepted(incoming, self.now)?,
                _ => return Err("unexpected fixture semantic body".into()),
            }
        }
        Ok(())
    }

    fn turn(&mut self, hold_lifecycle: bool) -> Result {
        for side in 0..2 {
            self.service(side)?;
        }
        for side in 0..2 {
            self.transmit(side, hold_lifecycle)?;
        }
        for side in 0..2 {
            self.dispatch(side)?;
        }
        self.now += Duration::from_millis(1);
        Ok(())
    }

    fn user(&mut self, side: usize, bytes: &[u8]) -> Result<security::PacketNumber> {
        let (source, target) = if side == 0 {
            let (a, b) = self.endpoints.split_at_mut(1);
            (&mut a[0], &mut b[0])
        } else {
            let (a, b) = self.endpoints.split_at_mut(1);
            (&mut b[0], &mut a[0])
        };
        let mut wire = [0; 2048];
        let sent = source.records.seal_user_in_at(
            hs::Time(micros(self.now)?),
            data_scope(),
            outer(source.outer),
            bytes,
            &mut [0; 2048],
            &mut wire,
        )?;
        source.outer += 1;
        let mut plain = [0; 512];
        let opened = target.records.open_at(
            hs::Time(micros(self.now)?),
            &wire[..sent.record.bytes],
            &mut [0; 2048],
            &mut plain,
        )?;
        assert_eq!(&plain[..opened.record.bytes], bytes);
        assert!(
            target
                .records
                .open_at(
                    hs::Time(micros(self.now)?),
                    &wire[..sent.record.bytes],
                    &mut [0; 2048],
                    &mut plain
                )
                .is_err()
        );
        Ok(sent.record.number)
    }
}

#[test]
fn actual_lifecycle_noise_refresh_preserves_scopes_numbers_and_reuses_fixed_outputs() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut lab = Lab::new(appearance)?;
        let capacities = lab
            .endpoints
            .each_ref()
            .map(|endpoint| endpoint.refresh.capacity_bytes());
        let pointers = lab.endpoints.each_ref().map(|endpoint| {
            endpoint
                .refresh
                .outputs
                .each_ref()
                .map(|output| output.bytes.as_ptr())
        });
        let staged = record::Scope {
            epoch: security::Epoch(3),
            configuration: security::ConfigDigest([12; 32]),
        };
        for endpoint in &mut lab.endpoints {
            endpoint.records.stage_data(staged)?;
        }
        let readers = lab
            .endpoints
            .each_ref()
            .map(|endpoint| endpoint.records.additional_data());
        let mut next = [security::PacketNumber(0); 2];
        let mut user_numbers = [
            lab.user(0, b"first old user")?,
            lab.user(1, b"second old user")?,
        ];
        for target in 1..=2 {
            lab.begin()?;
            for _ in 0..300 {
                lab.turn(false)?;
                if lab
                    .endpoints
                    .iter()
                    .all(|endpoint| endpoint.refresh.status().completed == target)
                {
                    break;
                }
            }
            for (side, endpoint) in lab.endpoints.iter().enumerate() {
                assert_eq!(endpoint.refresh.status().completed, target);
                assert_eq!(endpoint.records.key_epoch()?, KeyEpoch(target));
                assert_eq!(endpoint.records.additional_key_epoch()?, None);
                assert_eq!(endpoint.records.active_data(), data_scope());
                assert_eq!(endpoint.records.additional_data(), readers[side]);
                assert_eq!(endpoint.records.control_scope(), control_scope());
                assert!(endpoint.records.next_number(record::Class::Control) > next[side]);
                next[side] = endpoint.records.next_number(record::Class::Control);
                assert_eq!(endpoint.refresh.capacity_bytes(), capacities[side]);
                assert_eq!(
                    endpoint
                        .refresh
                        .outputs
                        .each_ref()
                        .map(|output| output.bytes.as_ptr()),
                    pointers[side]
                );
            }
            for (side, previous) in user_numbers.iter_mut().enumerate() {
                let number = lab.user(side, b"same session after refresh")?;
                assert!(number > *previous);
                *previous = number;
            }
            while lab.now < Duration::from_millis(70) {
                lab.turn(false)?;
            }
        }
        let mut wire = [0; 2048];
        let a = &mut lab.endpoints[0];
        let sent = a.records.seal_user_in_at(
            hs::Time(micros(lab.now)?),
            data_scope(),
            outer(a.outer),
            b"retained user bytes",
            &mut [0; 2048],
            &mut wire,
        )?;
        let mut plain = [0; 512];
        let b = &mut lab.endpoints[1];
        let opened = b.records.open_at(
            hs::Time(micros(lab.now)?),
            &wire[..sent.record.bytes],
            &mut [0; 2048],
            &mut plain,
        )?;
        assert_eq!(&plain[..opened.record.bytes], b"retained user bytes");
        assert!(
            b.records
                .open_at(
                    hs::Time(micros(lab.now)?),
                    &wire[..sent.record.bytes],
                    &mut [0; 2048],
                    &mut plain
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn held_lifecycle_keeps_actual_request_token_and_liveness_until_original_cap() -> Result {
    let mut lab = Lab::new(cover::Appearance::QuicLike)?;
    lab.begin()?;
    let request = lab.endpoints[0].refresh.outputs[0]
        .token
        .ok_or("request not admitted")?;
    let bytes = lab.endpoints[0].refresh.outputs[0].bytes.clone();
    let ping = lab.endpoints[0]
        .control
        .submit(
            management_scope(control_scope()),
            sc::Body::Ping { nonce: 55 },
            lab.now,
            Duration::from_millis(400),
            false,
        )?
        .ok_or("Ping not admitted")?;
    for _ in 0..15 {
        lab.turn(true)?;
    }
    assert!(lab.endpoints[0].control.confirmed(ping, lab.now)?);
    lab.endpoints[0].control.retire(ping, lab.now)?;
    assert_eq!(lab.endpoints[0].refresh.outputs[0].token, Some(request));
    assert_eq!(lab.endpoints[0].refresh.outputs[0].bytes, bytes);
    assert!(!lab.endpoints[0].refresh.outputs[0].confirmed);
    assert_eq!(lab.endpoints[0].records.key_epoch()?, KeyEpoch(0));
    assert_eq!(lab.endpoints[1].refresh.status().attempts, 0);
    let cap = lab.endpoints[0]
        .refresh
        .status()
        .original_deadline
        .ok_or("missing actual cap")?;
    let endpoint = &mut lab.endpoints[0];
    assert!(
        endpoint
            .refresh
            .service(
                &mut endpoint.records,
                &mut endpoint.control,
                cap - Duration::from_micros(1),
                outer(endpoint.outer),
                &mut Scratch {
                    seal: &mut [0; 2048],
                    packet: &mut [0; 2048]
                }
            )
            .is_ok()
    );
    let error = endpoint
        .refresh
        .service(
            &mut endpoint.records,
            &mut endpoint.control,
            cap,
            outer(endpoint.outer),
            &mut Scratch {
                seal: &mut [0; 2048],
                packet: &mut [0; 2048],
            },
        )
        .err()
        .ok_or("cap accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        endpoint
            .refresh
            .service(
                &mut endpoint.records,
                &mut endpoint.control,
                cap - Duration::from_micros(1),
                outer(endpoint.outer),
                &mut Scratch {
                    seal: &mut [0; 2048],
                    packet: &mut [0; 2048]
                }
            )
            .is_err()
    );
    assert_eq!(endpoint.refresh.outputs[0].token, Some(request));
    assert_eq!(endpoint.refresh.status().completed, 0);
    Ok(())
}

#[test]
fn authenticated_lifecycle_plaintext_cannot_mint_a_refresh_admission() -> Result {
    let mut lab = Lab::new(cover::Appearance::MediaLike)?;
    let mut bytes = [0; 128];
    let n = Lifecycle {
        kind: LifecycleKind::Request,
        bytes: &[0; 72],
    }
    .encode(&mut bytes, sc::MAX_LIFECYCLE_BYTES)?;
    assert!(
        lab.endpoints[0]
            .control
            .submit_lifecycle(&bytes[..n], lab.now, Duration::from_millis(400))?
            .is_some()
    );
    let mut error = None;
    for _ in 0..30 {
        for side in 0..2 {
            lab.service(side)?;
            lab.transmit(side, false)?;
        }
        match lab.dispatch(1) {
            Ok(()) => {}
            Err(value) => {
                error = Some(value);
                break;
            }
        }
        lab.now += Duration::from_millis(1);
    }
    assert!(error.is_some());
    assert_eq!(lab.endpoints[1].refresh.status().attempts, 0);
    assert_eq!(lab.endpoints[1].refresh.status().target, None);
    assert_eq!(lab.endpoints[1].records.key_epoch()?, KeyEpoch(0));
    assert_eq!(lab.endpoints[1].records.additional_key_epoch()?, None);
    assert!(!lab.endpoints[1].control.has_dispatched());
    Ok(())
}
