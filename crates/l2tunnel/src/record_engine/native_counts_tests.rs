use super::super::tests::{Family, Link, context, fixture, geometry, packet};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn reserved(config: configuration::Configuration, role: Role) -> Result<Engine, storage::Error> {
    let plan = storage::Plan::for_engine(
        config,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )
}

#[test]
fn exhausted_selected_channel_refuses_before_actual_codec_admission() -> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        for borrowed in [false, true] {
            let config = fixture(family, false)?;
            let mut engine = if borrowed {
                reserved(config, Role::Client)?
            } else {
                Engine::new_functional(
                    config,
                    context(Role::Client),
                    geometry(),
                    NativeLimits {
                        stall_micros: 50_000,
                    },
                )?
            };
            let bytes = packet(false, 1001, 100, 7);
            let metadata = engine.enqueue_borrowed(Tick(0), &bytes)?;
            let channel = usize::from(metadata.binding.channel);
            engine.native_counts.admitted[channel] = u64::MAX;
            let queued = engine.queue_usage();
            let statistics = engine.statistics();
            let usage = engine.storage_usage();
            assert!(engine.owner.drained()?);
            if borrowed {
                assert_eq!(engine.admit_borrowed(Tick(0)), Err(Error::Arithmetic));
            } else {
                assert_eq!(engine.admit_one(Tick(0)), Err(Error::Arithmetic));
            }
            assert!(engine.owner.drained()?);
            assert_eq!(engine.queue_usage(), queued);
            assert_eq!(engine.statistics(), statistics);
            assert_eq!(engine.storage_usage(), usage);
            assert_eq!(engine.native_counts()?.admitted[channel], u64::MAX);
            assert!(
                engine
                    .native_counts()?
                    .prepared
                    .iter()
                    .all(|count| *count == 0)
            );
            assert_eq!(engine.failure(), Some(Error::Arithmetic));
        }
    }
    Ok(())
}

#[test]
fn real_early_short_write_is_an_event_total_while_an_older_body_is_missing() -> TestResult {
    for raw in [false, true] {
        for role in [Role::Client, Role::Server] {
            early_short_roundtrip(raw, role)?;
        }
    }
    Ok(())
}

fn early_short_roundtrip(raw: bool, role: Role) -> TestResult {
    let original = fixture(Family::Aligned, raw)?;
    let descriptor = original.descriptor();
    let configuration::Profile::Aligned {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("actual Aligned fixture".into());
    };
    match role {
        Role::Client => forward.receiver.body.independent_short_frame_bytes = 64,
        Role::Server => reverse.receiver.body.independent_short_frame_bytes = 64,
    }
    let config = configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(Role::Client).common(),
            *descriptor.direction(Role::Server).common(),
            configuration::Profile::Aligned { forward, reverse },
        )?,
    )?;
    let peer = match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    };
    let mut sender = reserved(config, role)?;
    let mut receiver = reserved(config, peer)?;
    let long = packet(raw, 1001, 100, 7);
    let short = packet(raw, 1001, 54, 8);
    sender.enqueue_borrowed(Tick(0), &long)?;
    sender.enqueue_borrowed(Tick(0), &short)?;
    let sender_usage = sender.storage_usage();
    let receiver_usage = receiver.storage_usage();
    let mut clock = 0_u64;
    let mut number = (1_u64 << 50) + 17;
    let mut feedback = Link::new(&config, peer);
    let mut output = vec![0; sender.send_max];
    let mut native = vec![0; receiver.native_max];
    let mut witnesses = vec![
        receiver::UnitWitness {
            identity: receiver::RecordIdentity {
                channel: receiver::ChannelId(0),
                record: receiver::RecordId(0)
            },
            index: 0,
            count: 1,
        };
        sender.witnesses
    ];
    let mut admitted = Vec::new();
    let mut dropped = false;
    let mut delivered = Vec::new();
    let mut saw_context_progress = false;
    for step in 0..80_u64 {
        clock = clock.max(step * 10_000);
        for _ in 0..8 {
            let Some(admission) = sender.admit_borrowed(Tick(clock))? else {
                break;
            };
            admitted.push(admission.permit);
        }
        for _ in 0..16 {
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: output.len() + sender.overhead,
            };
            let Some(emission) = sender.poll(
                Tick(clock),
                number,
                true,
                &mut output,
                &mut budget,
                &mut witnesses,
            )?
            else {
                break;
            };
            // The drop below models network loss after whole physical send,
            // not a WouldBlock refusal at the retained carrier boundary.
            let token = sender
                .pending_carrier_output()
                .ok_or("actual Aligned carrier token")?;
            assert_eq!(token.emission(), emission);
            sender.confirm_carrier_output(Tick(clock), token)?;
            let first = admitted.first().ok_or("first actual codec admission")?;
            let carries_first = witnesses[..emission.witnesses]
                .iter()
                .any(|unit| ProfileIdentity::Aligned(unit.identity) == *first);
            // Hold the older body and repair equations until the independent
            // short body is physically committed; keep actual FEC enabled.
            if delivered.is_empty() && (carries_first || emission.kind == EmissionKind::Repair) {
                dropped |= carries_first;
            } else {
                let mut duplicate = output[..emission.bytes].to_vec();
                clock += 1;
                receiver.accept_authenticated(
                    Tick(clock),
                    number,
                    emission.kind,
                    &mut output[..emission.bytes],
                )?;
                // A fresh protected-record number may carry a retransmitted
                // source. Actual receiver proofs must not deliver it twice.
                number = number.checked_add(1).ok_or("test duplicate counter")?;
                clock += 1;
                receiver.accept_authenticated(
                    Tick(clock),
                    number,
                    emission.kind,
                    &mut duplicate,
                )?;
            }
            number = number.checked_add(1).ok_or("test wire counter")?;
            clock += 1;
        }
        for _ in 0..16 {
            clock += 1;
            let first = admitted.first().ok_or("first actual codec admission")?;
            let before = receiver.native_counts()?.prepared.to_vec();
            match receiver.prepare_native(Tick(clock), 1, Tick(clock + 20_000), &mut native)? {
                NativePreparation::Progress => {
                    saw_context_progress = true;
                    assert_eq!(receiver.native_counts()?.prepared, before);
                }
                NativePreparation::Ready(prepared) => {
                    if delivered.is_empty() {
                        assert!(dropped);
                        assert!(prepared.early());
                        assert_ne!(&prepared.identity(), first);
                        assert_eq!(&native[..prepared.bytes()], short);
                        assert_eq!(receiver.native_counts()?.prepared[0], 1);
                        assert_eq!(receiver.native_counts()?.committed[0], 0);
                        assert!(!receiver.drained()?);
                        assert!(!sender.drained()?);
                    } else {
                        assert_eq!(&prepared.identity(), first);
                        assert_eq!(&native[..prepared.bytes()], long);
                    }
                    let record = match prepared.identity() {
                        ProfileIdentity::Aligned(identity) => identity.record.0,
                        _ => return Err("unexpected native identity".into()),
                    };
                    assert!(record >= 7, "codec IDs stay separate from native counts");
                    receiver.commit_native(Tick(clock), prepared.token())?;
                    delivered.push(record);
                    assert_eq!(
                        receiver.native_counts()?.committed[0],
                        delivered.len() as u64
                    );
                }
                NativePreparation::Idle => assert_eq!(receiver.native_counts()?.prepared, before),
                NativePreparation::AlreadyPending(_) => {
                    return Err("test commits each real pending body".into());
                }
            }
        }
        feedback.transfer(&mut receiver, &mut sender, false, &mut clock)?;
        // Ready bodies may remain after a control/feedback-only turn.
        if delivered.len() == 2 && sender.drained()? && receiver.drained()? {
            break;
        }
    }
    assert!(dropped);
    assert!(saw_context_progress);
    assert_eq!(admitted.len(), 2);
    assert_eq!(delivered.len(), 2);
    assert!(delivered[0] > delivered[1]);
    let mut expected = vec![0; usize::from(config.descriptor().direction(role).channels())];
    expected[0] = 2;
    assert_eq!(sender.native_counts()?.admitted, expected);
    assert_eq!(receiver.native_counts()?.prepared, expected);
    assert_eq!(receiver.native_counts()?.committed, expected);
    assert_eq!(sender.storage_usage(), sender_usage);
    assert_eq!(receiver.storage_usage(), receiver_usage);
    Ok(())
}
