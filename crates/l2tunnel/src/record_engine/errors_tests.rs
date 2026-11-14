use super::*;
use configuration::{CommonDirection, Descriptor, EnvelopeDigest, NativeWindow, Profile};
use l2tunnel_core::{Duplex, Mapping, traffic};
use l2tunnel_packet::ParseLimits;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(
    tcp: TcpControl,
    burst: usize,
) -> Result<configuration::Configuration, configuration::Error> {
    let tun = tcp != TcpControl::System;
    let common = CommonDirection::new(
        traffic::TrafficPolicy {
            layer: if tun {
                traffic::NetworkLayer::Tun
            } else {
                traffic::NetworkLayer::Tap
            },
            tcp,
            qos: if tun {
                traffic::Qos::WeightedDeficit
            } else {
                traffic::Qos::System
            },
        },
        pipeline::PipelineConfig {
            profile: if tun {
                pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                    base_quantum_bytes: 512,
                    max_weight: 2,
                    per_flow: pipeline::QueueLimits {
                        bytes: 4096,
                        packets: 8,
                    },
                })
            } else {
                pipeline::Profile::TapSystem
            },
            flows: pipeline::FlowTableConfig {
                capacity: 8,
                channels: 2,
                mapping: Mapping::ConnectionRoundRobin,
                idle_timeout: Duration::from_secs(3),
            },
            parse: ParseLimits {
                max_packet_bytes: 512,
                ..ParseLimits::default()
            },
            queue: pipeline::QueueLimits {
                bytes: 8192,
                packets: 16,
            },
        },
        123_457,
        burst,
        NativeWindow::Disabled,
    )?;
    let records = swift::records::Config {
        layer: if tun {
            swift::records::Layer::Ip
        } else {
            swift::records::Layer::Ethernet
        },
        channels: 2,
        max_native: 512,
        codec: swift::Config {
            datagram_bytes: 400,
            window: 7,
            repair_numerator: 1,
            repair_denominator: 3,
            flow_sources: 9,
            queue_bytes: 8192,
            max_packet: 513,
            flush_micros: 10,
            feedback_micros: 1000,
            tail_micros: 10_000,
            min_rto_micros: 20_000,
            max_rto_micros: 900_000,
        },
    };
    configuration::Configuration::new(
        EnvelopeDigest::new([7; 32]),
        Descriptor::new(
            1500,
            Duplex::Full,
            common,
            common,
            Profile::Swift {
                forward: records,
                reverse: records,
            },
        )?,
    )
}
fn context() -> Context {
    Context {
        session: 1,
        epoch: 2,
        role: Role::Client,
    }
}
fn geometry() -> Geometry {
    Geometry {
        forward_overhead_bytes: 28,
        reverse_overhead_bytes: 28,
    }
}
fn native() -> NativeLimits {
    NativeLimits {
        stall_micros: 100_000,
    }
}
fn engine() -> Result<Engine, Error> {
    Engine::new_functional(
        config(TcpControl::System, 1500).map_err(|_| Error::Configuration)?,
        context(),
        geometry(),
        native(),
    )
}

#[test]
fn rejects_uninstalled_owners_and_both_directional_geometries_before_construction() -> TestResult {
    for (tcp, capability) in [
        (TcpControl::TunnelCredits, Capability::TunnelCredits),
        (TcpControl::SplitTcpProxy, Capability::TcpProxy),
    ] {
        assert!(
            matches!(Engine::new_functional(config(tcp, 1500)?, context(), geometry(), native()),
            Err(Error::Unsupported(actual)) if actual == capability)
        );
    }
    for geometry in [
        Geometry {
            forward_overhead_bytes: 1101,
            ..geometry()
        },
        Geometry {
            reverse_overhead_bytes: 1101,
            ..geometry()
        },
    ] {
        assert!(matches!(
            Engine::new_functional(
                config(TcpControl::System, 1500)?,
                context(),
                geometry,
                native()
            ),
            Err(Error::Geometry)
        ));
    }
    assert!(matches!(
        Engine::new_functional(
            config(TcpControl::System, 427)?,
            context(),
            geometry(),
            native()
        ),
        Err(Error::Geometry)
    ));
    let exact = Engine::new_functional(
        config(TcpControl::System, 428)?,
        context(),
        geometry(),
        native(),
    )?;
    assert_eq!(exact.qualification(), Qualification::Functional);
    assert_eq!(
        exact
            .configuration()
            .descriptor()
            .local(Role::Client)
            .send()
            .common()
            .bytes_per_second(),
        123_457
    );
    for context in [
        Context {
            session: 0,
            ..context()
        },
        Context {
            epoch: 0,
            ..context()
        },
    ] {
        assert!(matches!(
            Engine::new_functional(
                config(TcpControl::System, 1500)?,
                context,
                geometry(),
                native()
            ),
            Err(Error::Configuration)
        ));
    }
    assert!(matches!(
        Engine::new_functional(
            config(TcpControl::System, 1500)?,
            context(),
            geometry(),
            NativeLimits { stall_micros: 0 }
        ),
        Err(Error::Configuration)
    ));
    Ok(())
}

#[test]
fn caller_output_and_work_refusals_leave_actual_owner_and_allowance_untouched() -> TestResult {
    let mut engine = engine()?;
    let mut budget = OutboundBudget {
        packets: 3,
        wire_bytes: 4500,
    };
    let before = budget;
    assert_eq!(
        engine.poll(
            Tick(0),
            1_u64 << 50,
            true,
            &mut [0; 399],
            &mut budget,
            &mut []
        ),
        Err(Error::Output { required: 400 })
    );
    assert_eq!(budget, before);
    assert_eq!(
        engine.prepare_native(Tick(0), 0, Tick(100), &mut [0; 512]),
        Err(Error::Work)
    );
    assert_eq!(
        engine.prepare_native(Tick(0), 1, Tick(100), &mut [0; 511]),
        Err(Error::Output { required: 512 })
    );
    assert_eq!(
        engine.prepare_native(Tick(0), 1, Tick(0), &mut [0; 512]),
        Err(Error::Expired)
    );
    assert_eq!(engine.failure(), None);
    assert!(engine.drained()?);
    assert_eq!(engine.statistics(), Statistics::default());
    Ok(())
}

#[test]
fn malformed_authenticated_kind_latches_terminal_and_enqueue_preserves_input() -> TestResult {
    let mut engine = engine()?;
    assert_eq!(
        engine.accept_authenticated(
            Tick(0),
            u64::MAX - 1,
            EmissionKind::Source(SourceForm::Swift),
            &mut [3]
        ),
        Err(Error::Kind)
    );
    let mut packet = Vec::with_capacity(1024);
    packet.extend_from_slice(&[1; 64]);
    let pointer = packet.as_ptr();
    let capacity = packet.capacity();
    let error = engine
        .enqueue(Tick(0), packet)
        .err()
        .ok_or(Error::Invariant)?;
    assert_eq!(error.kind, Error::Kind);
    assert_eq!(error.payload, [1; 64]);
    assert_eq!(error.payload.as_ptr(), pointer);
    assert_eq!(error.payload.capacity(), capacity);
    assert_eq!(engine.tick(Tick(1)), Err(Error::Kind));
    assert_eq!(engine.statistics(), Statistics::default());
    Ok(())
}

#[test]
fn local_counter_preflight_and_monotonic_failure_do_not_fabricate_native_custody() -> TestResult {
    let mut engine = engine()?;
    engine.statistics.prepared = u64::MAX;
    assert_eq!(
        engine.prepare_native(Tick(10), 1, Tick(100), &mut [0; 512]),
        Err(Error::Arithmetic)
    );
    assert_eq!(engine.pending_native(), None);
    assert_eq!(engine.statistics().committed, 0);
    assert_eq!(engine.tick(Tick(9)), Err(Error::Time));
    assert_eq!(engine.deadline(), Err(Error::Time));
    assert_eq!(engine.tick(Tick(11)), Err(Error::Time));
    Ok(())
}

#[test]
fn late_actual_physical_receipt_counts_once_but_never_completes_expired_owner() -> TestResult {
    for prior_failure in [false, true] {
        let mut engine = engine()?;
        let channel = swift::records::ChannelId::new(0).ok_or(Error::Invariant)?;
        let token = NativeToken {
            context: engine.context,
            digest: engine.digest,
            serial: 1,
            identity: ProfileIdentity::Swift(swift::records::NativeIdentity {
                channel,
                record: swift::records::NativeRecordId(0),
            }),
        };
        engine.pending = Some(PreparedNative {
            token,
            bytes: 64,
            early: false,
            deadline: Tick(10),
        });
        engine.statistics.prepared = 1;
        if prior_failure {
            assert_eq!(engine.tick(Tick(10)), Err(Error::Expired));
        }
        assert_eq!(engine.commit_native(Tick(10), token), Err(Error::Expired));
        assert_eq!(engine.statistics().committed, 1);
        assert_eq!(engine.pending_native(), None);
        assert_eq!(engine.commit_native(Tick(10), token), Err(Error::Token));
        assert_eq!(engine.statistics().committed, 1);
        assert_eq!(engine.drained(), Err(Error::Expired));
    }
    Ok(())
}
