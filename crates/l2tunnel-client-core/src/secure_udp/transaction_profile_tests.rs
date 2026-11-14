//! Complete construction-plan evidence, separate from allocation or native readiness.

use super::*;
use l2tunnel_management::{control_streams as streams, delivery, messages};
use l2tunnel_swift::policy;
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Change<T> = (&'static str, fn(&mut T));

#[derive(Clone)]
struct Inputs {
    connection: ConnectionConfig,
    settings: Settings,
    peers: establish::Peers,
    initiator: transport::Config,
    responder: transport::Config,
    catalog: Catalog,
    parameters: Parameters,
}
impl Inputs {
    fn build(&self) -> io::Result<Profile> {
        Profile::new(
            self.connection,
            self.settings,
            self.peers,
            self.initiator,
            self.responder,
            self.catalog.clone(),
            self.parameters,
        )
    }
}

fn streamed(mut value: transport::Config) -> transport::Config {
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: value.control.wire_overhead + streams::HEADER_BYTES,
            ..value.control
        },
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    value.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
        streams: [entry; 3],
    });
    value
}

fn apply(value: &mut transport::Config, descriptor: Descriptor, role: security::Role) {
    value.path_mtu = descriptor.path_mtu();
    match role {
        security::Role::Initiator => {
            value.send = descriptor.forward();
            value.receive = descriptor.reverse();
        }
        security::Role::Responder => {
            value.send = descriptor.reverse();
            value.receive = descriptor.forward();
        }
    }
    if let Some(settings) = &mut value.streams {
        for entry in &mut settings.streams {
            entry.path_mtu = value.path_mtu;
        }
    }
}

fn inputs(kind: l2tunnel_cover::Appearance) -> Result<Inputs> {
    let path = l2tunnel_udp_control::Path {
        client: "127.0.0.1:41121".parse()?,
        server: "127.0.0.1:41122".parse()?,
    };
    let (legacy, peers) = super::super::profile::tests::fixture(
        path,
        kind,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )?;
    let connection = legacy.connection();
    let mut settings = legacy.settings();
    // An independent original seed, not the legacy profile's derived digest.
    settings.application = ConfigDigest([31; 32]);
    // Storage headroom lets individual cover-capacity changes remain valid;
    // actual bootstrap and selected data MTUs are still checked independently.
    settings.cover.max_packet_bytes += 16;
    let mut initiator = streamed(legacy.runtime(security::Role::Initiator));
    let mut responder = streamed(legacy.runtime(security::Role::Responder));
    let mut forward = initiator.send;
    let mut reverse = initiator.receive;
    forward.records.channels = 2;
    reverse.records.channels = 3;
    forward.bytes_per_second = 1_250_001;
    reverse.bytes_per_second = 625_013;
    forward.records.codec.window = 7;
    reverse.records.codec.window = 11;
    forward.records.codec.repair_numerator = 1;
    forward.records.codec.repair_denominator = 3;
    reverse.records.codec.repair_numerator = 2;
    reverse.records.codec.repair_denominator = 7;
    forward.records.codec.datagram_bytes = 1200;
    reverse.records.codec.datagram_bytes = 1024;
    let initial = Descriptor::new(1500, forward, reverse)?;
    forward.records.channels = 4;
    reverse.records.channels = 1;
    forward.bytes_per_second = 1_375_007;
    reverse.bytes_per_second = 575_011;
    forward.records.codec.datagram_bytes = 1280;
    reverse.records.codec.datagram_bytes = 1100;
    forward.records.codec.window = 9;
    reverse.records.codec.window = 5;
    forward.records.codec.repair_numerator = 2;
    forward.records.codec.repair_denominator = 9;
    reverse.records.codec.repair_numerator = 1;
    reverse.records.codec.repair_denominator = 3;
    forward.records.codec.queue_bytes += 7;
    reverse.records.codec.queue_bytes += 11;
    forward.records.codec.flush_micros = 123;
    reverse.records.codec.flush_micros = 321;
    forward.records.codec.feedback_micros += 3;
    reverse.records.codec.feedback_micros += 7;
    let target = Descriptor::new(1600, forward, reverse)?;
    apply(&mut initiator, initial, security::Role::Initiator);
    apply(&mut responder, initial, security::Role::Responder);
    Ok(Inputs {
        connection,
        settings,
        peers,
        initiator,
        responder,
        catalog: Catalog::new(initial, &[target, initial])?,
        parameters: Parameters {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 16 * 1024 * 1024,
        },
    })
}

fn target(value: &Inputs) -> Result<Descriptor> {
    value
        .catalog
        .descriptors()
        .iter()
        .copied()
        .find(|descriptor| *descriptor != value.catalog.initial())
        .ok_or_else(|| "missing noninitial exact descriptor".into())
}
fn assert_binding_changed(original: &Profile, changed: &Profile, label: &str) -> Result {
    assert_ne!(changed.envelope(), original.envelope(), "{label}");
    assert_ne!(changed.data_digest(), original.data_digest(), "{label}");
    assert_ne!(
        changed.configuration()?,
        original.configuration()?,
        "{label}"
    );
    Ok(())
}

#[test]
fn complete_asymmetric_catalog_resolves_exact_both_role_runtime_values() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let value = inputs(kind)?;
        let plan = value.build()?;
        assert_eq!(plan.peers(), value.peers);
        assert_eq!(plan.parameters(), value.parameters);
        assert_eq!(
            plan.connection().session()?.digest,
            value.connection.session()?.digest
        );
        assert_eq!(plan.catalog().initial(), value.catalog.initial());
        assert_eq!(plan.catalog().root(), value.catalog.root());
        assert_eq!(plan.initial().envelope(), plan.envelope());
        assert_eq!(plan.initial().descriptor(), value.catalog.initial());
        assert_eq!(
            plan.data_digest(),
            transaction::configuration_digest(&plan.initial())?
        );
        assert_ne!(plan.data_digest().0, plan.configuration()?.0);
        assert_eq!(
            plan.configuration()?,
            plan.settings().configuration(value.peers)?
        );
        for configuration in plan.catalog().configurations(plan.envelope()) {
            let descriptor = configuration.descriptor();
            let client = plan.runtime_for(configuration, security::Role::Initiator)?;
            let server = plan.runtime_for(configuration, security::Role::Responder)?;
            assert_eq!(client.send, descriptor.forward());
            assert_eq!(client.receive, descriptor.reverse());
            assert_eq!(server.send, descriptor.reverse());
            assert_eq!(server.receive, descriptor.forward());
            assert_eq!(client.send, server.receive);
            assert_eq!(client.receive, server.send);
            assert_eq!(client.path_mtu, descriptor.path_mtu());
            assert_eq!(server.path_mtu, descriptor.path_mtu());
            assert_eq!(client.wire, value.initiator.wire);
            assert_eq!(server.wire, value.responder.wire);
            for runtime in [client, server] {
                for entry in runtime.streams.ok_or("missing explicit streams")?.streams {
                    assert_eq!(entry.path_mtu, descriptor.path_mtu());
                }
            }
        }
        assert_eq!(plan.initial().descriptor().forward().records.channels, 2);
        assert_eq!(plan.initial().descriptor().reverse().records.channels, 3);
        assert_eq!(target(&value)?.forward().records.channels, 4);
        assert_eq!(target(&value)?.reverse().records.channels, 1);
        assert_eq!(
            plan.initial().descriptor().forward().bytes_per_second,
            1_250_001
        );
        assert_eq!(
            plan.initial()
                .descriptor()
                .forward()
                .records
                .codec
                .repair_denominator,
            3
        );
    }
    Ok(())
}

const MUTABLE: &[Change<policy::Direction>] = &[
    ("channels", |d| d.records.channels += 1),
    ("exact byte rate", |d| d.bytes_per_second += 1),
    ("source size", |d| d.records.codec.datagram_bytes += 1),
    ("linear repair window", |d| d.records.codec.window += 1),
    ("repair numerator", |d| {
        d.records.codec.repair_numerator += 1
    }),
    ("repair denominator", |d| {
        d.records.codec.repair_denominator += 1
    }),
    ("source flight bound", |d| d.records.codec.flow_sources += 1),
    ("packing bytes", |d| d.records.codec.queue_bytes += 1),
    ("flush timer", |d| d.records.codec.flush_micros += 1),
    ("feedback timer", |d| d.records.codec.feedback_micros += 1),
    ("tail timer", |d| d.records.codec.tail_micros += 1),
    ("minimum RTO", |d| d.records.codec.min_rto_micros += 1),
    ("maximum RTO", |d| d.records.codec.max_rto_micros += 1),
];

#[test]
fn every_complete_mutable_field_in_either_catalog_direction_is_authenticated() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let value = inputs(kind)?;
        let original = value.build()?;
        let next = target(&value)?;
        for forward in [false, true] {
            for &(label, change) in MUTABLE {
                let mut send = next.forward();
                let mut receive = next.reverse();
                change(if forward { &mut send } else { &mut receive });
                let descriptor = Descriptor::new(next.path_mtu(), send, receive)?;
                let mut changed = value.clone();
                changed.catalog = Catalog::new(
                    value.catalog.initial(),
                    &[value.catalog.initial(), descriptor],
                )?;
                let plan = changed.build()?;
                assert_binding_changed(&original, &plan, label)?;
                let exact = Configuration::new(plan.envelope(), descriptor)?;
                assert_eq!(
                    plan.runtime_for(exact, security::Role::Initiator)?.send,
                    send
                );
                assert_eq!(
                    plan.runtime_for(exact, security::Role::Responder)?.send,
                    receive
                );
            }
        }
        let mut changed = value.clone();
        changed.catalog = Catalog::new(
            value.catalog.initial(),
            &[
                value.catalog.initial(),
                Descriptor::new(next.path_mtu() + 1, next.forward(), next.reverse())?,
            ],
        )?;
        assert_binding_changed(&original, &changed.build()?, "active IP MTU")?;
    }
    Ok(())
}

#[test]
fn exact_catalog_membership_and_envelope_are_required_at_resolution() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let plan = value.build()?;
    let initial = plan.initial();
    let forged = Configuration::new(EnvelopeDigest::new([0; 32]), initial.descriptor())?;
    for role in [security::Role::Initiator, security::Role::Responder] {
        assert!(plan.runtime_for(forged, role).is_err());
        let mut unlisted = initial.descriptor().forward();
        unlisted.bytes_per_second += 1;
        let unlisted = Configuration::new(
            plan.envelope(),
            Descriptor::new(
                initial.descriptor().path_mtu(),
                unlisted,
                initial.descriptor().reverse(),
            )?,
        )?;
        assert!(plan.runtime_for(unlisted, role).is_err());
    }
    let mut reordered = value.clone();
    let entries: Vec<_> = value.catalog.descriptors().iter().rev().copied().collect();
    reordered.catalog = Catalog::new(value.catalog.initial(), &entries)?;
    let reordered = reordered.build()?;
    assert_eq!(reordered.envelope(), plan.envelope());
    assert_eq!(reordered.data_digest(), plan.data_digest());
    assert_eq!(reordered.configuration()?, plan.configuration()?);
    let mut reduced = value.clone();
    reduced.catalog = Catalog::new(value.catalog.initial(), &[value.catalog.initial()])?;
    assert_binding_changed(&plan, &reduced.build()?, "exact supported set")?;
    Ok(())
}

#[test]
fn envelope_is_initial_independent_but_data_and_setup_digests_bind_initial_value() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let original = inputs(kind)?;
        let first = original.build()?;
        let mut alternate = original.clone();
        let next = target(&original)?;
        alternate.catalog = Catalog::new(next, original.catalog.descriptors())?;
        apply(&mut alternate.initiator, next, security::Role::Initiator);
        apply(&mut alternate.responder, next, security::Role::Responder);
        let second = alternate.build()?;
        assert_eq!(first.catalog().root(), second.catalog().root());
        assert_eq!(first.envelope(), second.envelope());
        assert_ne!(first.initial(), second.initial());
        assert_ne!(first.data_digest(), second.data_digest());
        assert_ne!(first.settings().application, second.settings().application);
        assert_ne!(first.configuration()?, second.configuration()?);
        assert_ne!(first.data_digest().0, first.configuration()?.0);
        assert_ne!(second.data_digest().0, second.configuration()?.0);
        assert_eq!(original.settings.application, ConfigDigest([31; 32]));
        assert_eq!(alternate.settings.application, ConfigDigest([31; 32]));
        assert_ne!(first.settings().application, original.settings.application);
        // Reusing the unchanged original seed is deterministic. Passing the
        // already-derived application is a different explicit input, not a
        // recursive dependency hidden inside the first construction.
        assert_eq!(original.build()?.configuration()?, first.configuration()?);
        let mut derived_as_new_seed = original.clone();
        derived_as_new_seed.settings = first.settings();
        assert_binding_changed(
            &first,
            &derived_as_new_seed.build()?,
            "distinct explicit application seed",
        )?;
    }
    Ok(())
}

const PUBLIC_SETTINGS: &[Change<Settings>] = &[
    ("application seed", |s| s.application.0[0] ^= 1),
    ("outer binding", |s| s.outer[0] ^= 1),
    ("member identity", |s| s.member.0[0] ^= 1),
    ("Noise profile", |s| {
        s.profile = l2tunnel_handshake::Profile::IkPsk2
    }),
    ("initiator CID", |s| s.cover.initiator_connection.0[0] ^= 1),
    ("responder CID", |s| s.cover.responder_connection.0[0] ^= 1),
    ("initiator media source", |s| s.cover.initiator_ssrc.0 += 1),
    ("responder media source", |s| s.cover.responder_ssrc.0 += 1),
    ("media payload type", |s| s.cover.payload_type += 1),
    ("cover storage ceiling", |s| s.cover.max_packet_bytes += 1),
    ("protected body storage", |s| {
        s.cover.max_protected_bytes += 1
    }),
    ("joining retry interval", |s| {
        s.membership.retry_interval += Duration::from_nanos(1)
    }),
    ("joining receive interval", |s| {
        s.membership.receive_interval += Duration::from_nanos(1)
    }),
    ("joining retry bound", |s| s.membership.max_attempts += 1),
    ("joining receive bound", |s| {
        s.membership.receive_packets_per_interval += 1
    }),
    ("bootstrap receive bound", |s| {
        s.bootstrap_receive_packets_per_interval += 1
    }),
    ("admission profile", |s| s.gate.base_profile[0] ^= 1),
    ("admission key id", |s| s.gate.key_id += 1),
    ("client tuple", |s| s.gate.path.client.set_port(41123)),
    ("server tuple", |s| s.gate.path.server.set_port(41124)),
    ("cookie lifetime", |s| {
        s.gate.cookie_ttl -= Duration::from_micros(1)
    }),
    ("setup deadline", |s| {
        s.gate.handshake_timeout += Duration::from_micros(1)
    }),
    ("admission capacity", |s| s.gate.pending_sessions += 1),
    ("gate refill interval", |s| {
        s.gate.interval += Duration::from_micros(1)
    }),
    ("gate response quota", |s| s.gate.gate_responses += 1),
    ("gate initial RTO", |s| {
        s.gate.initial_rto += Duration::from_micros(1)
    }),
    ("gate maximum RTO", |s| {
        s.gate.maximum_rto += Duration::from_micros(1)
    }),
    ("gate attempt cap", |s| s.gate.gate_attempts += 1),
    ("bootstrap MTU", |s| s.gate.path_mtu += 1),
    ("bootstrap source ceiling", |s| {
        s.gate.arq.max_source_bytes += 1
    }),
    ("bootstrap send bytes", |s| s.gate.arq.send_bytes += 1),
    ("bootstrap receive bytes", |s| s.gate.arq.receive_bytes += 1),
    ("bootstrap send records", |s| s.gate.arq.send_records -= 1),
    ("bootstrap receive records", |s| {
        s.gate.arq.receive_records -= 1
    }),
    ("bootstrap initial RTO", |s| {
        s.gate.arq.initial_rto += Duration::from_micros(1)
    }),
    ("bootstrap maximum RTO", |s| {
        s.gate.arq.maximum_rto += Duration::from_micros(1)
    }),
    ("bootstrap ACK delay", |s| {
        s.gate.arq.ack_delay += Duration::from_micros(1)
    }),
    ("bootstrap retry cap", |s| s.gate.arq.max_retries += 1),
    ("bootstrap packet quota", |s| s.gate.control_packets += 1),
    ("bootstrap byte quota", |s| s.gate.control_bytes += 1),
];

#[test]
fn setup_trust_pins_and_every_valid_public_contract_class_bind_the_plan() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let value = inputs(kind)?;
        let original = value.build()?;
        for &(label, change) in PUBLIC_SETTINGS {
            let mut changed = value.clone();
            change(&mut changed.settings);
            assert_binding_changed(&original, &changed.build()?, label)?;
        }
        for initiator in [false, true] {
            let mut changed = value.clone();
            if initiator {
                changed.peers.initiator.0[0] ^= 1;
            } else {
                changed.peers.responder.0[0] ^= 1;
            }
            assert_binding_changed(&original, &changed.build()?, "retained trusted Noise pin")?;
        }
        let mut connection = value.clone();
        connection.connection.handshake_timeout += Duration::from_nanos(1);
        assert_binding_changed(&original, &connection.build()?, "exact connection deadline")?;
    }
    let quic = inputs(l2tunnel_cover::Appearance::QuicLike)?.build()?;
    let media = inputs(l2tunnel_cover::Appearance::MediaLike)?.build()?;
    assert_binding_changed(
        &quic,
        &media,
        "explicit selected appearance and exact overhead",
    )?;
    Ok(())
}

const RESOURCES: &[Change<transport::Config>] = &[
    ("policy original deadline", |r| {
        r.policy.transaction_micros += 1
    }),
    ("policy output custody", |r| r.policy.max_outbound += 1),
    ("common body storage", |r| r.security.max_body_bytes -= 1),
    ("key packet ceiling", |r| r.security.packets_per_key -= 1),
    ("key byte ceiling", |r| {
        r.security.max_body_bytes_per_key -= 1
    }),
    ("fixed control epoch", |r| r.control_epoch.0 += 1),
    ("initial data epoch", |r| r.data_epoch.0 += 1),
    ("wire burst", |r| r.wire.burst_bytes += 1),
    ("UDP receive work", |r| r.work.receive_packets += 1),
    ("UDP work interval", |r| {
        r.work.receive_interval += Duration::from_nanos(1)
    }),
    ("UDP send work", |r| r.work.send_batch += 1),
    ("native read work", |r| r.work.native_read_batch += 1),
    ("native write work", |r| r.work.native_write_batch += 1),
    ("native packet retention", |r| r.native.pending_packets += 1),
    ("native byte retention", |r| r.native.pending_bytes += 1),
    ("native original stall bound", |r| {
        r.native.stall_timeout += Duration::from_nanos(1)
    }),
    ("session lease", |r| {
        r.lifetime.lease += Duration::from_nanos(1)
    }),
    ("Ping interval", |r| {
        r.lifetime.ping_interval += Duration::from_nanos(1)
    }),
    ("original Pong bound", |r| {
        r.lifetime.pong_timeout += Duration::from_nanos(1)
    }),
    ("control source cap", |r| {
        r.control.recovery.max_source_bytes += 1
    }),
    ("control send bytes", |r| r.control.recovery.send_bytes += 1),
    ("control receive bytes", |r| {
        r.control.recovery.receive_bytes += 1
    }),
    ("control send records", |r| {
        r.control.recovery.send_records += 1
    }),
    ("control receive records", |r| {
        r.control.recovery.receive_records += 1
    }),
    ("control retry cap", |r| r.control.recovery.max_retries += 1),
    ("control initial RTO", |r| {
        r.control.recovery.initial_rto += Duration::from_nanos(1)
    }),
    ("control maximum RTO", |r| {
        r.control.recovery.maximum_rto += Duration::from_nanos(1)
    }),
    ("control ACK delay", |r| {
        r.control.recovery.ack_delay += Duration::from_nanos(1)
    }),
    ("control refill interval", |r| {
        r.control.interval += Duration::from_nanos(1)
    }),
    ("control packet quota", |r| {
        r.control.packets_per_interval += 1
    }),
    ("control byte quota", |r| r.control.bytes_per_interval += 1),
];

#[test]
fn fixed_runtime_resources_and_all_parameters_remain_authenticated() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let original = value.build()?;
    for &(label, change) in RESOURCES {
        let mut changed = value.clone();
        for runtime in [&mut changed.initiator, &mut changed.responder] {
            change(runtime);
            let base = runtime.control;
            for stream in &mut runtime.streams.as_mut().ok_or("missing streams")?.streams {
                stream.delivery = delivery::Settings {
                    wire_overhead: base.wire_overhead + streams::HEADER_BYTES,
                    ..base
                };
            }
        }
        assert_binding_changed(&original, &changed.build()?, label)?;
    }
    let parameters: &[Change<Parameters>] = &[
        ("generic retry", |p| p.protocol.retry_ms += 1),
        ("generic phase deadline", |p| {
            p.protocol.phase_timeout_ms += 1
        }),
        ("generic uncertainty deadline", |p| {
            p.protocol.reconcile_timeout_ms += 1
        }),
        ("whole-operation cap", |p| p.max_operation_ms += 1),
        ("combined retained-byte ceiling", |p| p.retained_bytes += 1),
    ];
    for &(label, change) in parameters {
        let mut changed = value.clone();
        change(&mut changed.parameters);
        assert_binding_changed(&original, &changed.build()?, label)?;
    }
    for initiator in [false, true] {
        let mut changed = value.clone();
        if initiator {
            changed.initiator.wire.burst_bytes += 1;
        } else {
            changed.responder.wire.burst_bytes += 1;
        }
        assert_binding_changed(
            &original,
            &changed.build()?,
            "independent role burst capacity",
        )?;
    }
    Ok(())
}

#[test]
fn each_fixed_stream_message_bound_is_authenticated() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let original = value.build()?;
    let bounds: &[Change<messages::Settings>] = &[
        ("message ceiling", |s| s.max_message_bytes += 1),
        ("outbound entries", |s| s.max_outbound_messages += 1),
        ("outbound bytes", |s| s.max_outbound_bytes += 1),
        ("fragment ceiling", |s| s.max_fragments += 1),
        ("reassembly bytes", |s| s.max_reassembly_bytes += 1),
        ("incomplete-message quota", |s| {
            s.max_incomplete_messages += 1
        }),
        ("original message lifetime", |s| {
            s.message_lifetime += Duration::from_nanos(1)
        }),
        ("message work", |s| s.work_per_call += 1),
    ];
    for (index, _) in streams::Stream::ALL.iter().enumerate() {
        for &(label, change) in bounds {
            let mut changed = value.clone();
            for runtime in [&mut changed.initiator, &mut changed.responder] {
                change(&mut runtime.streams.as_mut().ok_or("missing streams")?.streams[index]);
            }
            assert_binding_changed(&original, &changed.build()?, label)?;
        }
    }
    Ok(())
}

#[test]
fn local_reporting_is_excluded_from_all_selected_plan_digests() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let original = value.build()?;
    let mut changed = value.clone();
    changed.initiator.report_interval = None;
    changed.responder.report_interval = Some(Duration::from_nanos(17_000_001));
    let changed = changed.build()?;
    assert_eq!(changed.envelope(), original.envelope());
    assert_eq!(changed.initial(), original.initial());
    assert_eq!(changed.settings(), original.settings());
    assert_eq!(changed.configuration()?, original.configuration()?);
    assert_eq!(
        changed
            .runtime_for(changed.initial(), security::Role::Initiator)?
            .report_interval,
        None
    );
    assert_eq!(
        changed
            .runtime_for(changed.initial(), security::Role::Responder)?
            .report_interval,
        Some(Duration::from_nanos(17_000_001))
    );
    Ok(())
}

#[test]
fn noncomplementary_roles_unselected_streams_and_fixed_mismatches_are_refused() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let changes: &[Change<Inputs>] = &[
        ("role direction mismatch", |i| {
            i.responder.send.bytes_per_second += 1
        }),
        ("role active MTU mismatch", |i| i.responder.path_mtu -= 1),
        ("role fixed resource mismatch", |i| {
            i.responder.work.receive_packets += 1
        }),
        ("unselected initiator streams", |i| {
            i.initiator.streams = None
        }),
        ("unselected responder streams", |i| {
            i.responder.streams = None
        }),
        ("native attachment layer mismatch", |i| {
            i.connection.layer = PacketLayer::Ethernet
        }),
        ("native attachment maximum mismatch", |i| {
            i.connection.max_packet += 1
        }),
        ("half duplex selection", |i| {
            i.connection.duplex = Duplex::Half
        }),
        ("zero original setup deadline", |i| {
            i.connection.handshake_timeout = Duration::ZERO
        }),
        ("invalid whole-operation cap", |i| {
            i.parameters.max_operation_ms = 0
        }),
        ("whole-operation exceeds either lease", |i| {
            i.parameters.max_operation_ms = 3_600_001
        }),
        ("empty combined retention", |i| {
            i.parameters.retained_bytes = 0
        }),
        ("zero generic retry", |i| i.parameters.protocol.retry_ms = 0),
        ("retry exceeds phase", |i| {
            i.parameters.protocol.retry_ms = 501
        }),
        ("phase exceeds reconcile", |i| {
            i.parameters.protocol.phase_timeout_ms = 1001
        }),
        ("unbounded reconcile", |i| {
            i.parameters.protocol.reconcile_timeout_ms = 86_400_001
        }),
    ];
    for &(label, change) in changes {
        let mut changed = value.clone();
        change(&mut changed);
        assert!(changed.build().is_err(), "accepted {label}");
    }
    let mut wrong_initial = value.clone();
    wrong_initial.catalog = Catalog::new(target(&value)?, value.catalog.descriptors())?;
    assert!(wrong_initial.build().is_err());
    let mut wrong_overhead = value.clone();
    for runtime in [&mut wrong_overhead.initiator, &mut wrong_overhead.responder] {
        runtime.control.wire_overhead += 1;
        for entry in &mut runtime.streams.as_mut().ok_or("missing streams")?.streams {
            entry.delivery.wire_overhead += 1;
        }
    }
    assert!(
        wrong_overhead.build().is_err(),
        "selected cover geometry must match exact charge"
    );
    Ok(())
}

#[test]
fn every_supported_target_is_preflighted_against_fixed_native_and_cover_capacity() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let next = target(&value)?;
    let mut excessive = next.forward();
    excessive.records.codec.datagram_bytes = value.initiator.security.max_body_bytes + 1;
    let outside_body = Descriptor::new(1600, excessive, next.reverse())?;
    let mut changed = value.clone();
    changed.catalog = Catalog::new(
        value.catalog.initial(),
        &[value.catalog.initial(), outside_body],
    )?;
    assert!(
        changed.build().is_err(),
        "unselected target still requires full preflight"
    );
    let mut forward = next.forward();
    let mut reverse = next.reverse();
    for direction in [&mut forward, &mut reverse] {
        direction.records.max_native += 1;
        direction.records.codec.max_packet += 1;
    }
    let native = Descriptor::new(1600, forward, reverse)?;
    changed.catalog = Catalog::new(value.catalog.initial(), &[value.catalog.initial(), native])?;
    assert!(
        changed.build().is_err(),
        "catalog cannot change the fixed attachment maximum"
    );
    forward = next.forward();
    reverse = next.reverse();
    forward.records.layer = records::Layer::Ethernet;
    reverse.records.layer = records::Layer::Ethernet;
    let layer = Descriptor::new(1600, forward, reverse)?;
    changed.catalog = Catalog::new(value.catalog.initial(), &[value.catalog.initial(), layer])?;
    assert!(
        changed.build().is_err(),
        "catalog cannot change the fixed attachment layer"
    );
    let mtu = Descriptor::new(256, next.forward(), next.reverse())?;
    changed.catalog = Catalog::new(value.catalog.initial(), &[value.catalog.initial(), mtu])?;
    assert!(
        changed.build().is_err(),
        "source and control wire geometry exceed target MTU"
    );
    Ok(())
}

#[test]
fn whole_transaction_capacity_covers_the_largest_exact_catalog_sender() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    // Four channels occur only in the target. A stream that can carry the
    // smaller initial fence must not qualify the complete supported catalog.
    let encoded = largest_prepare(&value)?;
    let exact = encoded.len();
    assert_eq!(
        exact, 538,
        "actual PREPARE includes its eight-byte response-to prefix"
    );
    let mut boundary = value.clone();
    for runtime in [&mut boundary.initiator, &mut boundary.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_message_bytes = exact;
        runtime.validate()?;
    }
    boundary.build()?;
    for initiator in [false, true] {
        let mut undersized = boundary.clone();
        let runtime = if initiator {
            &mut undersized.initiator
        } else {
            &mut undersized.responder
        };
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_message_bytes -= 1;
        runtime.validate()?;
        assert!(
            undersized.build().is_err(),
            "one role cannot carry complete PREPARE"
        );
    }
    for runtime in [&mut boundary.initiator, &mut boundary.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_message_bytes -= 1;
        runtime.validate()?;
    }
    assert!(
        boundary.build().is_err(),
        "matching resources cannot conceal an undersized whole command"
    );
    Ok(())
}

fn largest_prepare(value: &Inputs) -> Result<Vec<u8>> {
    let plan = value.build()?;
    let old = Configuration::new(plan.envelope(), target(value)?)?;
    let supported = plan.catalog().configurations(plan.envelope());
    let now = transaction::Tick(0);
    let mut peer = transaction::Peer::new_directional(
        identity(mg::Role::Client),
        l2tunnel_core::Epoch(1),
        old,
        &supported,
        plan.parameters().protocol,
        now,
    )?;
    peer.propose(plan.initial(), now)?;
    let command = outgoing(peer.staged(transaction::Fence::new(&[0; 4])?, now)?)?;
    enclose(&command, old, mg::Role::Client)
}

fn enclose(command: &[u8], configuration: Configuration, role: mg::Role) -> Result<Vec<u8>> {
    let envelope = mg::session_control::Envelope {
        binding: mg::session_control::Binding {
            session: identity(mg::Role::Client).session,
            lane: mg::LaneId(0),
            sender: role,
            packet: mg::PacketNumber(1),
            scope: mg::session_control::Scope {
                epoch: l2tunnel_core::Epoch(1),
                digest: transaction::configuration_digest(&configuration)?,
            },
        },
        body: mg::session_control::Body::Management(command),
    };
    let limits = mg::session_control::Limits {
        max_frame_bytes: 4096,
        max_management_bytes: 4016,
        max_feedback_bytes: 1,
    };
    let exact = envelope.encoded_len(limits)?;
    let mut encoded = vec![0; exact];
    assert_eq!(envelope.encode(&mut encoded, limits)?, exact);
    assert_eq!(
        mg::session_control::Envelope::decode(&encoded, limits)?.body,
        mg::session_control::Body::Management(command)
    );
    Ok(encoded)
}

#[test]
fn server64_ready_capacity_does_not_charge_a_server_prepare_configuration() -> Result {
    let mut value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let mut forward = value.catalog.initial().forward();
    let mut reverse = value.catalog.initial().reverse();
    forward.records.channels = 1;
    reverse.records.channels = 64;
    let old = Descriptor::new(1500, forward, reverse)?;
    forward.bytes_per_second += 1;
    let next = Descriptor::new(1500, forward, reverse)?;
    value.catalog = Catalog::new(old, &[old, next])?;
    apply(&mut value.initiator, old, security::Role::Initiator);
    apply(&mut value.responder, old, security::Role::Responder);
    let plan = value.build()?;
    let supported = plan.catalog().configurations(plan.envelope());
    let initial = plan.initial();
    let target = Configuration::new(plan.envelope(), next)?;
    let now = transaction::Tick(0);
    let mut client = transaction::Peer::new_directional(
        identity(mg::Role::Client),
        l2tunnel_core::Epoch(1),
        initial,
        &supported,
        value.parameters.protocol,
        now,
    )?;
    let mut server = transaction::Peer::new_directional(
        identity(mg::Role::Server),
        l2tunnel_core::Epoch(1),
        initial,
        &supported,
        value.parameters.protocol,
        now,
    )?;
    client.propose(target, now)?;
    let prepare = outgoing(client.staged(transaction::Fence::new(&[0])?, now)?)?;
    server.receive(ingress(mg::Role::Client), &prepare, now)?;
    let ready = outgoing(server.staged(transaction::Fence::new(&[0; 64])?, now)?)?;
    let prepare = enclose(&prepare, initial, mg::Role::Client)?;
    let ready = enclose(&ready, initial, mg::Role::Server)?;
    assert_eq!((prepare.len(), ready.len()), (514, 714));
    for runtime in [&mut value.initiator, &mut value.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_message_bytes =
            ready.len();
    }
    value.build()?;
    for runtime in [&mut value.initiator, &mut value.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_message_bytes -= 1;
    }
    assert!(
        value.build().is_err(),
        "actual READY must fit the selected whole-message bound"
    );
    Ok(())
}

#[test]
fn transaction_storage_admits_the_actual_complete_message_at_its_exact_budget() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let bytes = largest_prepare(&value)?;
    let selected = value.initiator.streams.ok_or("missing streams")?.streams[0];
    let binding = streams::delivery_binding(
        delivery::Binding {
            session: mg::SessionId([3; 16]),
            lane: mg::LaneId(0),
            local_role: mg::Role::Client,
            control_epoch: value.initiator.control_epoch.0,
        },
        streams::Stream::Transaction,
    )?;
    let admits = |budget| -> Result<bool> {
        let settings = messages::Settings {
            max_outbound_bytes: budget,
            ..selected
        };
        let mut owner = messages::Owner::new(
            settings,
            binding,
            Duration::ZERO,
            value.initiator.lifetime.lease,
        )?;
        match owner.submit(
            messages::SubmissionId(1),
            &bytes,
            Duration::ZERO,
            Duration::from_millis(100),
        ) {
            Ok(_) => Ok(true),
            Err(messages::Error::Backpressure) => Ok(false),
            Err(error) => Err(error.into()),
        }
    };
    // Find the boundary through the actual message owner, independently of
    // client-side formulas for retained originals and encoded fragment batches.
    let (mut low, mut high) = (1, selected.max_outbound_bytes);
    assert!(!admits(low)?);
    assert!(admits(high)?);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if admits(middle)? {
            high = middle;
        } else {
            low = middle;
        }
    }
    let mut boundary = value.clone();
    for runtime in [&mut boundary.initiator, &mut boundary.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_outbound_bytes = high;
        runtime.validate()?;
    }
    boundary.build()?;
    assert!(!admits(high - 1)?);
    for runtime in [&mut boundary.initiator, &mut boundary.responder] {
        runtime.streams.as_mut().ok_or("missing streams")?.streams[0].max_outbound_bytes -= 1;
        runtime.validate()?;
    }
    assert!(
        boundary.build().is_err(),
        "unusable matching budgets must fail before authentication"
    );
    Ok(())
}

fn ingress(sender: mg::Role) -> mg::Ingress {
    mg::Ingress::AuthenticatedManagement {
        session: mg::SessionId([3; 16]),
        lane: mg::LaneId(0),
        sender,
    }
}
fn identity(role: mg::Role) -> transaction::Identity {
    transaction::Identity {
        session: mg::SessionId([3; 16]),
        role,
        local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
        lane: mg::LaneId(0),
    }
}
fn outgoing(effects: transaction::Effects<Configuration>) -> Result<Vec<u8>> {
    effects
        .outbound
        .ok_or_else(|| "expected actual generic command".into())
}

#[test]
fn real_leased_generic_peers_use_complete_c0_and_old_directional_fences() -> Result {
    let value = inputs(l2tunnel_cover::Appearance::QuicLike)?;
    let plan = value.build()?;
    let initial = plan.initial();
    let target = Configuration::new(plan.envelope(), target(&value)?)?;
    let supported = plan.catalog().configurations(plan.envelope());
    let binding = streams::delivery_binding(
        delivery::Binding {
            session: mg::SessionId([3; 16]),
            lane: mg::LaneId(0),
            local_role: mg::Role::Client,
            control_epoch: value.initiator.control_epoch.0,
        },
        streams::Stream::Transaction,
    )?;
    let lease = transaction::LeaseSettings {
        session_expires: transaction::Tick(10_000),
        max_operation_ms: plan.parameters().max_operation_ms,
        transaction_epoch: binding.control_epoch,
    };
    let mut client = transaction::Peer::new_leased_directional(
        identity(mg::Role::Client),
        l2tunnel_core::Epoch(1),
        initial,
        &supported,
        plan.parameters().protocol,
        lease,
        transaction::Tick(0),
    )?;
    let mut server = transaction::Peer::new_leased_directional(
        identity(mg::Role::Server),
        l2tunnel_core::Epoch(1),
        initial,
        &supported,
        plan.parameters().protocol,
        lease,
        transaction::Tick(0),
    )?;
    let now = transaction::Tick(0);
    let expires = transaction::Tick(1500);
    assert!(matches!(client.propose_until(target, now, expires)?.event,
        Some(transaction::Event::Stage { config, .. }) if config == target));
    let local = transaction::Fence::new(&[2, 4])?;
    let remote = transaction::Fence::new(&[3, 5, 7])?;
    let prepare = outgoing(client.staged(local.clone(), now)?)?;
    assert!(
        matches!(server.receive_until(ingress(mg::Role::Client), &prepare, now, expires)?.event,
        Some(transaction::Event::Stage { config, .. }) if config == target)
    );
    let ready = server.staged(remote.clone(), now)?;
    assert_eq!(
        ready.event,
        Some(transaction::Event::Drain {
            local: remote.clone(),
            peer: local.clone()
        })
    );
    let ready = outgoing(ready)?;
    assert_eq!(
        client
            .receive_until(ingress(mg::Role::Server), &ready, now, expires)?
            .event,
        Some(transaction::Event::Drain {
            local: local.clone(),
            peer: remote.clone()
        })
    );
    assert_eq!(
        client.operation().ok_or("missing lease")?.origin().digest,
        plan.data_digest()
    );
    let barrier = outgoing(client.confirm_drained(&local, &remote, now)?)?;
    assert!(
        server
            .receive_until(ingress(mg::Role::Client), &barrier, now, expires)?
            .outbound
            .is_none()
    );
    let barrier_ack = outgoing(server.confirm_drained(&remote, &local, now)?)?;
    let commit =
        outgoing(client.receive_until(ingress(mg::Role::Server), &barrier_ack, now, expires)?)?;
    let commit_ack =
        outgoing(server.receive_until(ingress(mg::Role::Client), &commit, now, expires)?)?;
    let retire =
        outgoing(client.receive_until(ingress(mg::Role::Server), &commit_ack, now, expires)?)?;
    let retire_ack =
        outgoing(server.receive_until(ingress(mg::Role::Client), &retire, now, expires)?)?;
    assert_eq!(
        client
            .receive_until(ingress(mg::Role::Server), &retire_ack, now, expires)?
            .event,
        Some(transaction::Event::Retired(l2tunnel_core::Epoch(1)))
    );
    for peer in [&client, &server] {
        assert_eq!(peer.active_config(), &target);
        assert_eq!(peer.sender_channels(mg::Role::Client), 4);
        assert_eq!(peer.sender_channels(mg::Role::Server), 1);
        assert_eq!(peer.active_epoch(), l2tunnel_core::Epoch(2));
        assert!(peer.reader(l2tunnel_core::Epoch(1)).is_none());
        // No source ACK or synthetic proof completes the retained whole-message
        // lease. Actual Owner acceptance/confirmation is a separate integration.
        assert_eq!(
            peer.operation().ok_or("lost final custody")?.expires(),
            expires
        );
    }
    Ok(())
}

#[test]
fn runtime_handoff_recomputes_retained_h0_and_exact_both_role_resolutions() -> Result {
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let value = inputs(kind)?;
        let profile = value.build()?;
        let original_settings = profile.settings();
        for role in [security::Role::Initiator, security::Role::Responder] {
            let handoff = profile.runtime_contract(role)?;
            assert_eq!(
                handoff.expected_configuration(),
                original_settings.configuration(profile.peers())?
            );
            assert_eq!(handoff.expected_configuration(), profile.configuration()?);
            assert_eq!(handoff.role(), role);
            assert_eq!(handoff.cover(), original_settings.cover.config(role)?);
            assert_eq!(handoff.ipv6(), value.settings.gate.path.client.is_ipv6());
            assert_eq!(handoff.envelope(), profile.envelope());
            assert_eq!(handoff.catalog().root(), profile.catalog().root());
            assert_eq!(handoff.initial(), profile.initial());
            assert_eq!(handoff.data_digest(), profile.data_digest());
            assert_eq!(handoff.settings(), profile.parameters());
            assert_ne!(handoff.data_digest().0, handoff.expected_configuration().0);
            for c in profile.catalog().configurations(profile.envelope()) {
                assert_eq!(handoff.resolve(c)?, profile.runtime_for(c, role)?);
            }
        }
        assert_eq!(profile.settings(), original_settings);
        let mut changed = value.clone();
        changed.peers.responder.0[0] ^= 1;
        let changed = changed.build()?;
        assert_ne!(
            changed
                .runtime_contract(security::Role::Initiator)?
                .expected_configuration(),
            profile
                .runtime_contract(security::Role::Initiator)?
                .expected_configuration()
        );
    }
    Ok(())
}

async fn handoff_pump(parts: &mut l2tunnel_runtime::secure_udp::member::Parts) -> Result {
    use l2tunnel_cover::{MediaTimestamp, PacketMeta, PacketNumber, Phase};
    let mut output = vec![0; parts.cover.limits().max_packet_bytes];
    for phase in [Phase::Handshake, Phase::Established] {
        let metadata = PacketMeta {
            phase,
            packet_number: PacketNumber(parts.next_outer),
            media_timestamp: MediaTimestamp(parts.next_outer.wrapping_mul(960)),
        };
        let length = match phase {
            Phase::Handshake => {
                parts
                    .bootstrap
                    .poll(tokio::time::Instant::now(), metadata, &mut output)?
            }
            Phase::Established => {
                parts
                    .joining
                    .poll(tokio::time::Instant::now(), metadata, &mut output)?
            }
        };
        if let Some(length) = length {
            parts.next_outer = parts.next_outer.checked_add(1).ok_or("outer exhausted")?;
            assert_eq!(parts.socket.send(&output[..length]).await?, length);
        }
    }
    let mut input = vec![0; output.len() + 1];
    for _ in 0..32 {
        let length = match parts.socket.try_recv(&mut input) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        };
        let decoded = parts.cover.decode(&input[..length])?;
        if !parts
            .bootstrap
            .receive(decoded, tokio::time::Instant::now())?
        {
            assert!(
                parts
                    .joining
                    .receive(decoded, tokio::time::Instant::now())?
            );
        }
    }
    Ok(())
}

struct HandoffSide {
    socket: tokio::net::UdpSocket,
    records: l2tunnel::secure_record::Records,
    bootstrap: establish::BootstrapTail,
    joining: l2tunnel_runtime::secure_udp::member::JoiningTail,
    cover: l2tunnel_cover::Config,
    outer: u32,
}

fn handoff_side(
    parts: l2tunnel_runtime::secure_udp::member::Parts,
    contract: &transport::TransactionContract,
) -> Result<HandoffSide> {
    use l2tunnel::secure_record::{Records, Scope};
    assert_eq!(parts.info.role, contract.role());
    assert_eq!(
        parts.info.authenticated.configuration,
        contract.expected_configuration().0
    );
    assert_eq!(parts.root.binding(), parts.info.binding);
    assert_eq!(parts.cover, contract.cover());
    assert_eq!(parts.socket.local_addr()?.is_ipv6(), contract.ipv6());
    let config = contract.config();
    let records = Records::new(
        parts.root,
        security::LaneId(0),
        config.security,
        security::Protection::ChaCha20Poly1305,
        parts.cover,
        Scope {
            epoch: config.control_epoch,
            configuration: contract.expected_configuration(),
        },
        Scope {
            epoch: config.data_epoch,
            configuration: security::ConfigDigest(contract.data_digest().0),
        },
    )?;
    Ok(HandoffSide {
        socket: parts.socket,
        records,
        bootstrap: parts.bootstrap,
        joining: parts.joining,
        cover: parts.cover,
        outer: parts.next_outer,
    })
}

async fn handoff_exchange(
    sender: &mut HandoffSide,
    receiver: &mut HandoffSide,
    class: l2tunnel::secure_record::Class,
    body: &[u8],
    deadline: tokio::time::Instant,
) -> Result {
    let capacity = sender.records.capacity(body.len())?;
    let mut workspace = vec![0; capacity.seal_workspace_bytes];
    let mut wire = vec![0; sender.cover.limits().max_packet_bytes];
    let metadata = l2tunnel_cover::PacketMeta {
        phase: l2tunnel_cover::Phase::Established,
        packet_number: l2tunnel_cover::PacketNumber(sender.outer),
        media_timestamp: l2tunnel_cover::MediaTimestamp(sender.outer.wrapping_mul(960)),
    };
    let sealed = sender
        .records
        .seal(class, metadata, body, &mut workspace, &mut wire)?;
    sender.outer = sender.outer.checked_add(1).ok_or("outer exhausted")?;
    assert_eq!(
        sender.socket.send(&wire[..sealed.bytes]).await?,
        sealed.bytes
    );
    let mut input = vec![0; receiver.cover.limits().max_packet_bytes + 1];
    let capacity = receiver.records.capacity(body.len())?;
    let mut open = vec![0; capacity.open_workspace_bytes];
    let mut plain = vec![0; body.len()];
    for _ in 0..128 {
        let length = tokio::time::timeout_at(deadline, receiver.socket.recv(&mut input)).await??;
        let decoded = receiver.cover.decode(&input[..length])?;
        if receiver
            .bootstrap
            .receive(decoded, tokio::time::Instant::now())?
            || receiver
                .joining
                .receive(decoded, tokio::time::Instant::now())?
        {
            continue;
        }
        let opened = receiver
            .records
            .open(&input[..length], &mut open, &mut plain)?;
        assert_eq!(opened.class, class);
        assert_eq!(&plain[..opened.bytes], body);
        let scope = match class {
            l2tunnel::secure_record::Class::User => receiver.records.active_data(),
            l2tunnel::secure_record::Class::Control => receiver.records.control_scope(),
        };
        assert_eq!(opened.scope, scope);
        return Ok(());
    }
    Err("protected handoff receive bound exhausted".into())
}

#[tokio::test]
async fn actual_original_socket_factory_roots_handoff_both_roles_and_distinct_scopes() -> Result {
    use l2tunnel_handshake::{LocalSecret, Psk};
    use l2tunnel_runtime::secure_udp::{establish, member};
    use zeroize::Zeroizing;
    // The actual auth adapter generates the existing Ed25519 fixture. The
    // X25519 inputs below are distinct explicit test keys, never conversions.
    let member = l2tunnel_identity::IdentityKey::from_pkcs8(&Zeroizing::new(
        l2tunnel_auth::MemberKey::generate_pkcs8()?,
    ))?;
    for kind in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let sockets = [
            tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
            tokio::net::UdpSocket::bind("127.0.0.1:0").await?,
        ];
        sockets[0].connect(sockets[1].local_addr()?).await?;
        sockets[1].connect(sockets[0].local_addr()?).await?;
        let tuples = [
            (sockets[0].local_addr()?, sockets[0].peer_addr()?),
            (sockets[1].local_addr()?, sockets[1].peer_addr()?),
        ];
        let mut value = inputs(kind)?;
        value.settings.gate.path = l2tunnel_udp_control::Path {
            client: tuples[0].0,
            server: tuples[1].0,
        };
        value.settings.member = member.public_key();
        let profile = value.build()?;
        let contracts = [
            profile.runtime_contract(security::Role::Initiator)?,
            profile.runtime_contract(security::Role::Responder)?,
        ];
        let local = LocalSecret::new(Zeroizing::new([11; 32]));
        let remote = LocalSecret::new(Zeroizing::new([22; 32]));
        assert_eq!(local.public_key(), profile.peers().initiator);
        assert_eq!(remote.public_key(), profile.peers().responder);
        let client_identity = establish::Identity {
            peer: remote.public_key(),
            local,
            psk: None::<Psk>,
        };
        let server_identity = establish::Identity {
            peer: client_identity.local.public_key(),
            local: remote,
            psk: None::<Psk>,
        };
        let origin = tokio::time::Instant::now();
        let deadline = origin + Duration::from_secs(2);
        let mut server = super::super::Server::new(
            profile.settings(),
            profile.peers(),
            l2tunnel_udp_control::Secret::new([41; 32]),
            l2tunnel_udp_control::Secret::new([42; 32]),
            origin,
        )?;
        let mut a_entropy = establish::RuntimeEntropy::new();
        let mut b_entropy = establish::RuntimeEntropy::new();
        let [a, b] = sockets;
        let client = super::super::connect(
            a,
            profile.settings(),
            client_identity,
            &member,
            l2tunnel_udp_control::Secret::new([41; 32]),
            deadline,
            &mut a_entropy,
        );
        let accepted = server.accept(b, server_identity, deadline, &mut b_entropy);
        tokio::pin!(client, accepted);
        let (early_side, early) = tokio::select! {
            result=&mut client=>(0,result?), result=&mut accepted=>(1,result?),
            _=tokio::time::sleep_until(deadline)=>return Err("factory deadline".into()),
        };
        let mut early = early.into_parts();
        let late = loop {
            tokio::select! {
                result=&mut client,if early_side==1=>break result?,
                result=&mut accepted,if early_side==0=>break result?,
                _=tokio::time::sleep(Duration::from_millis(1))=>handoff_pump(&mut early).await?,
                _=tokio::time::sleep_until(deadline)=>return Err("factory tail deadline".into()),
            }
        };
        let late: member::Parts = late.into_parts();
        let parts = if early_side == 0 {
            [early, late]
        } else {
            [late, early]
        };
        for (side, parts) in parts.iter().enumerate() {
            assert_eq!(
                (parts.socket.local_addr()?, parts.socket.peer_addr()?),
                tuples[side]
            );
            assert_eq!(parts.deadline, deadline);
            assert_eq!(
                parts.info.authenticated.configuration,
                contracts[side].expected_configuration().0
            );
        }
        let [a, b] = parts;
        let mut a = handoff_side(a, &contracts[0])?;
        let mut b = handoff_side(b, &contracts[1])?;
        for class in [
            l2tunnel::secure_record::Class::User,
            l2tunnel::secure_record::Class::Control,
        ] {
            handoff_exchange(&mut a, &mut b, class, b"initiator handoff", deadline).await?;
            handoff_exchange(&mut b, &mut a, class, b"responder handoff", deadline).await?;
        }
        assert_ne!(
            a.records.active_data().configuration,
            a.records.control_scope().configuration
        );
        assert_eq!(a.records.active_data(), b.records.active_data());
        assert_eq!(a.records.control_scope(), b.records.control_scope());
    }
    Ok(())
}
