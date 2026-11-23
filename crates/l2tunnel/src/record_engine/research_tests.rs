//! Finite actual-byte research composition, not a socket/authentication proof.
use super::tests::{context, geometry, packet};
use super::*;
use crate::{
    fec::{research, rolling},
    record_bank as bank, research_records,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn policies() -> [research::Profile; 3] {
    [
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 0,
        },
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 2,
        },
        research::Profile::Accumulator {
            lanes: 3,
            window: 16,
        },
    ]
}
fn configuration(profile: research::Profile) -> TestResult<configuration::Configuration> {
    let original = super::rolling_tests::fixture(false, rolling::wire::SourceWire::Exact)?;
    let configuration::Profile::Rolling { config, stream } = *original.descriptor().profile()
    else {
        return Err("fixture family".into());
    };
    let direction = |d: rolling_records::DirectionConfig| research_records::DirectionConfig {
        native_release: Default::default(),
        return_guard: Default::default(),
        native_policy: d.native_policy,
        receiver: d.receiver,
        packing: d.packing,
        codec_stage_micros: d.codec_stage_micros,
        scheduler: research::Config {
            recovery: d.scheduler.recovery,
            profile,
            feedback_ticks: 100,
            memory_bytes: 16 << 20,
        },
    };
    let config = research_records::Config {
        forward: direction(config.forward),
        reverse: direction(config.reverse),
        geometry: config.geometry,
        native_stall_micros: config.native_stall_micros,
    };
    Ok(configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            original.descriptor().path_mtu(),
            original.descriptor().duplex(),
            *original.descriptor().direction(Role::Client).common(),
            *original.descriptor().direction(Role::Server).common(),
            configuration::Profile::Research { config, stream },
        )?,
    )?)
}
fn plan(c: configuration::Configuration, role: Role) -> TestResult<storage::Plan> {
    Ok(storage::Plan::for_engine(
        c,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?)
}
fn build(c: configuration::Configuration, role: Role) -> TestResult<Engine> {
    let plan = plan(c, role)?;
    Ok(Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn work() -> rolling::WorkBudget {
    rolling::WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    }
}
fn witnesses() -> [receiver::UnitWitness; 4] {
    [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4]
}
struct Link {
    number: u64,
    lost_source: bool,
    lost_feedback: bool,
    repairs: usize,
    feedback: usize,
    fallbacks: usize,
}
impl Link {
    fn transfer(&mut self, now: Tick, sender: &mut Engine, peer: &mut Engine) -> TestResult {
        let mut body = [0; 1500];
        let mut units = witnesses();
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let Some(emission) =
            sender.poll(now, self.number, true, &mut body, &mut budget, &mut units)?
        else {
            return Ok(());
        };
        assert_eq!(&body[..4], b"L2RS");
        assert_eq!(
            emission.wire_bytes,
            emission.bytes
                + if sender.context.role == Role::Client {
                    geometry().forward_overhead_bytes
                } else {
                    geometry().reverse_overhead_bytes
                }
        );
        assert_eq!(
            budget,
            OutboundBudget {
                packets: 0,
                wire_bytes: 1500 - emission.wire_bytes
            }
        );
        let token = sender
            .pending_carrier_output()
            .ok_or("actual output token")?;
        let before = sender.research_status().ok_or("actual research status")?;
        let mut untouched = [0x91; 1500];
        let held_budget = budget;
        assert_eq!(
            sender.poll(
                now,
                u64::MAX,
                false,
                &mut untouched,
                &mut budget,
                &mut units
            )?,
            Some(emission)
        );
        assert_eq!(untouched, [0x91; 1500]);
        assert_eq!(budget, held_budget);
        assert_eq!(
            sender.research_status().ok_or("retained research status")?,
            before
        );
        let duplicate = sender.pending_carrier_output().ok_or("retained token")?;
        // Actual whole carrier ownership is distinct from subsequent wire loss.
        sender.confirm_carrier_output(now, token)?;
        assert_eq!(
            sender.confirm_carrier_output(now, duplicate),
            Err(Error::Token)
        );
        let drop = match emission.kind {
            EmissionKind::Source(_) if !self.lost_source => {
                self.lost_source = true;
                true
            }
            EmissionKind::Feedback if !self.lost_feedback => {
                self.lost_feedback = true;
                true
            }
            EmissionKind::Repair => {
                self.repairs += 1;
                let configuration::Profile::Research { config, .. } =
                    *sender.configuration.descriptor().profile()
                else {
                    return Err("selected family".into());
                };
                let policy = if sender.context.role == Role::Client {
                    config.forward.scheduler
                } else {
                    config.reverse.scheduler
                };
                let research::wire::View::Repair(repair) =
                    research::wire::inspect(policy, &body[..emission.bytes])?
                else {
                    return Err("actual repair body".into());
                };
                if policy.profile.mode(u32::try_from(repair.equation.id.0)?)?
                    == research::RepairMode::Fallback
                {
                    self.fallbacks += 1;
                }
                false
            }
            EmissionKind::Feedback => {
                self.feedback += 1;
                false
            }
            _ => false,
        };
        if !drop {
            peer.accept_authenticated_at(
                now,
                now,
                emission.security_number,
                emission.kind,
                &mut body[..emission.bytes],
            )?;
        }
        self.number = self.number.checked_add(1).ok_or("number exhausted")?;
        Ok(())
    }
}

#[test]
fn actual_research_profiles_recover_native_bytes_with_loss_and_exact_physical_custody() -> TestResult
{
    for policy in policies() {
        let c = configuration(policy)?;
        let mut a = build(c, Role::Client)?;
        let mut b = build(c, Role::Server)?;
        let capacity = [a.storage_usage(), b.storage_usage()];
        let forward = [
            packet(false, 2101, 1024, 0x39),
            packet(false, 2103, 1024, 0x49),
        ];
        let reverse = [
            packet(false, 2102, 1024, 0x57),
            packet(false, 2104, 1024, 0x67),
        ];
        for bytes in &forward {
            a.enqueue_borrowed(Tick(0), bytes)?;
        }
        for bytes in &reverse {
            b.enqueue_borrowed(Tick(0), bytes)?;
        }
        let mut ab = Link {
            number: (1 << 48) + 17,
            lost_source: false,
            lost_feedback: false,
            repairs: 0,
            feedback: 0,
            fallbacks: 0,
        };
        let mut ba = Link {
            number: (1 << 56) + 91,
            lost_source: false,
            lost_feedback: false,
            repairs: 0,
            feedback: 0,
            fallbacks: 0,
        };
        let mut got_a = [false; 2];
        let mut got_b = [false; 2];
        let mut encoding_observations = [0; 2];
        for turn in 0..5000u64 {
            let now = Tick(turn * 100);
            for (index, owner) in [&mut a, &mut b].into_iter().enumerate() {
                if let Some(admitted) = owner.admit_borrowed_observed(now)? {
                    assert!(matches!(
                        admitted.permit.identity,
                        ProfileIdentity::Research(_)
                    ));
                    assert!(admitted.permit.encoding.original_native_bytes > 0);
                    assert!(admitted.permit.encoding.framing_bytes > 0);
                    encoding_observations[index] += 1;
                }
            }
            a.step(now, work())?;
            b.step(now, work())?;
            ab.transfer(now, &mut a, &mut b)?;
            ba.transfer(now, &mut b, &mut a)?;
            for (owner, expected, got) in [
                (&mut a, &reverse, &mut got_a),
                (&mut b, &forward, &mut got_b),
            ] {
                let mut output = [0; 1024];
                if let NativePreparation::Ready(p) =
                    owner.prepare_native(now, 128, Tick(1_000_000), &mut output)?
                {
                    let which = expected
                        .iter()
                        .position(|bytes| bytes.as_slice() == &output[..p.bytes()])
                        .ok_or("changed native bytes")?;
                    assert!(!got[which]);
                    assert!(matches!(p.identity(), ProfileIdentity::Research(_)));
                    let mut untouched = [0x82; 1024];
                    assert_eq!(
                        owner.prepare_native(now, 128, Tick(u64::MAX), &mut untouched)?,
                        NativePreparation::AlreadyPending(p)
                    );
                    assert_eq!(untouched, [0x82; 1024]);
                    owner.commit_native(now, p.token())?;
                    assert_eq!(owner.commit_native(now, p.token()), Err(Error::Token));
                    got[which] = true;
                }
            }
            if got_a.iter().all(|got| *got)
                && got_b.iter().all(|got| *got)
                && a.drained()?
                && b.drained()?
            {
                break;
            }
        }
        assert!(got_a.iter().all(|got| *got) && got_b.iter().all(|got| *got));
        assert_eq!(encoding_observations, [forward.len(), reverse.len()]);
        assert!(a.drained()? && b.drained()?);
        assert!(ab.lost_source && ba.lost_source && ab.lost_feedback && ba.lost_feedback);
        assert!(ab.repairs >= 2 && ba.repairs >= 2 && ab.feedback > 0 && ba.feedback > 0);
        if matches!(
            policy,
            research::Profile::Recursive {
                fresh_interval: 2,
                ..
            }
        ) {
            assert!(ab.fallbacks > 0 && ba.fallbacks > 0);
        }
        assert_eq!(a.native_counts()?.committed.iter().sum::<u64>(), 2);
        assert_eq!(b.native_counts()?.committed.iter().sum::<u64>(), 2);
        assert_eq!([a.storage_usage(), b.storage_usage()], capacity);
    }
    Ok(())
}

#[test]
fn research_canonical_binding_reserved_limits_and_bank_custody_are_exact() -> TestResult {
    let c = configuration(policies()[1])?;
    let mut bytes = [0; configuration::CONFIGURATION_BYTES];
    c.encode_into(&mut bytes)?;
    assert_eq!(bytes[5], 9);
    assert_eq!(configuration::Configuration::decode(&bytes)?, c);
    let mut bad = bytes;
    bad[5] = 10;
    assert!(configuration::Configuration::decode(&bad).is_err());
    let mut changed = c;
    let configuration::Profile::Research { mut config, stream } = *changed.descriptor().profile()
    else {
        return Err("family".into());
    };
    config.forward.scheduler.feedback_ticks += 1;
    changed = configuration::Configuration::new(
        c.envelope(),
        configuration::Descriptor::new(
            c.descriptor().path_mtu(),
            c.descriptor().duplex(),
            *c.descriptor().direction(Role::Client).common(),
            *c.descriptor().direction(Role::Server).common(),
            configuration::Profile::Research { config, stream },
        )?,
    )?;
    assert_ne!(c.digest()?, changed.digest()?);
    let p = plan(c, Role::Client)?;
    assert!(matches!(
        Engine::new_reserved(
            p,
            storage::Limits {
                capacity_bytes: p.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let bp = bank::storage::Plan::for_bank(p, 0)?;
    let mut bank = bank::Bank::new(
        bp,
        bank::storage::Limits {
            capacity_bytes: bp.capacity_bytes(),
        },
    )?;
    let id = bank.initial();
    let usage = bank.usage();
    let original = packet(false, 2301, 1024, 0x71);
    bank.entry(id)?.enqueue_borrowed(Tick(0), &original)?;
    let mut emitted = false;
    for turn in 0..1000u64 {
        let now = Tick(turn * 100);
        bank.entry(id)?.admit_borrowed(now)?;
        bank.entry(id)?.step(now, work())?;
        let mut body = [0; 1500];
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let mut units = witnesses();
        if let Some(e) =
            bank.entry(id)?
                .poll(now, 1 << 53, true, &mut body, &mut budget, &mut units)?
        {
            assert!(matches!(e.kind, EmissionKind::Source(_)));
            assert_eq!(&body[..4], b"L2RS");
            let token = bank
                .entry(id)?
                .pending_carrier_output()
                .ok_or("bank physical token")?;
            assert_eq!(token.emission(), e);
            assert!(!bank.engine(id)?.drained()?);
            bank.entry(id)?.confirm_carrier_output_at(now, now, token)?;
            assert_eq!(
                bank.engine(id)?
                    .research_status()
                    .ok_or("research bank status")?
                    .0
                    .sent_sources,
                1
            );
            emitted = true;
            break;
        }
    }
    assert!(emitted);
    assert_eq!(bank.usage(), usage);
    Ok(())
}

#[test]
fn later_feedback_cannot_rewrite_delayed_source_completion_and_physical_token_retires() -> TestResult
{
    let c = configuration(policies()[2])?;
    // The direct public owner rejects an impossible receipt before actual source
    // availability, while retaining the irreversible send fact exactly once.
    let configuration::Profile::Research { config, .. } = *c.descriptor().profile() else {
        return Err("actual Research configuration".into());
    };
    let scope = research::Scope {
        session: [0x31; 16],
        epoch: 1,
        stream: 7,
        direction: 0,
    };
    let mut direct = research::Sender::new(config.forward.scheduler, scope, research::Tick(7))?;
    let source = direct.admit_source(&[0x41], research::Tick(7), research::Tick(10))?;
    assert_eq!(
        direct.confirm_output_at(
            research::OutputId::Source(source),
            research::Tick(9),
            research::Tick(10)
        ),
        Err(research::Error::TimeRegression)
    );
    assert_eq!(direct.status().sent_sources, 1);
    assert!(direct.pending_output().is_none());
    assert_eq!(
        direct.status().terminal,
        Some(research::Error::TimeRegression)
    );
    assert!(
        direct
            .confirm_output_at(
                research::OutputId::Source(source),
                research::Tick(10),
                research::Tick(10)
            )
            .is_err()
    );

    let mut a = build(c, Role::Client)?;
    let mut b = build(c, Role::Server)?;
    a.enqueue_borrowed(Tick(0), &packet(false, 2401, 1024, 0x61))?;
    let mut sent = 0;
    let mut held = None;
    for turn in 0..1000u64 {
        let now = Tick(turn * 100);
        a.admit_borrowed(now)?;
        a.step(now, work())?;
        let mut body = [0; 1500];
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let mut units = witnesses();
        if let Some(e) = a.poll(now, turn + 1, true, &mut body, &mut budget, &mut units)? {
            let token = a.pending_carrier_output().ok_or("physical source token")?;
            assert!(matches!(e.kind, EmissionKind::Source(_)));
            if sent < 4 {
                a.confirm_carrier_output(now, token)?;
                if sent == 0 {
                    b.accept_authenticated(now, e.security_number, e.kind, &mut body[..e.bytes])?;
                    b.step(now, work())?;
                }
                sent += 1;
            } else {
                held = Some((token, now));
                break;
            }
        }
    }
    let (token, prepared) = held.ok_or("fifth actual source earning the first repair")?;
    let duplicate = a.pending_carrier_output().ok_or("held actual source")?;
    let accepted = Tick(prepared.0 + 1);
    let feedback_at = Tick(prepared.0 + 2);
    let observed = Tick(prepared.0 + 3);
    b.step(feedback_at, work())?;
    let mut body = [0; 1500];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1500,
    };
    let mut units = witnesses();
    let feedback = b
        .poll(
            feedback_at,
            1 << 54,
            false,
            &mut body,
            &mut budget,
            &mut units,
        )?
        .ok_or("real peer feedback")?;
    assert_eq!(feedback.kind, EmissionKind::Feedback);
    b.confirm_carrier_output(
        feedback_at,
        b.pending_carrier_output().ok_or("feedback custody")?,
    )?;
    a.accept_authenticated_at(
        feedback_at,
        feedback_at,
        feedback.security_number,
        feedback.kind,
        &mut body[..feedback.bytes],
    )?;
    let usage = a.storage_usage();
    assert_eq!(
        a.confirm_carrier_output_at(observed, accepted, token),
        Err(Error::Rolling(rolling_records::Error::Rolling(
            rolling::Error::TimeRegression
        )))
    );
    assert!(a.pending_carrier_output().is_none());
    assert_eq!(
        a.confirm_carrier_output_at(observed, accepted, duplicate),
        Err(Error::Token)
    );
    let status = a.research_status().ok_or("terminal actual owner status")?.0;
    assert_eq!(status.sent_sources, 5);
    assert!(!status.output_ready);
    assert_eq!(status.terminal, Some(rolling::Error::TimeRegression));
    assert_eq!(a.storage_usage(), usage);
    Ok(())
}

#[path = "research_order_tests.rs"]
mod precise_order;
