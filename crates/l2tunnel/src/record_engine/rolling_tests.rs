//! Actual fourth-family composition; no sender-source oracle or OS device.
use super::tests::{Family, context, fixture as old_fixture, geometry, packet};
use super::*;
use crate::{
    codec::{aligned_body, aligned_sender, packed, packed_sender},
    fec::rolling,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) fn fixture(
    raw: bool,
    wire: rolling::wire::SourceWire,
) -> TestResult<configuration::Configuration> {
    let old = old_fixture(Family::Swift, raw)?;
    let direction = |reverse: bool| {
        let symbol_bytes = if reverse { 224 } else { 192 };
        let channels = if reverse { 2 } else { 3 };
        let body = aligned_body::Config {
            max_frame_bytes: 1024,
            symbol_bytes,
            elide_payload_length: !raw,
            predictive: !raw,
            timestamp_pair_dictionary: !raw,
            independent_short_frame_bytes: 64,
        };
        let first_record = receiver::RecordId(if reverse { 19 } else { 7 });
        let first_source = receiver::SourceId(if reverse { 91 } else { 13 });
        rolling_records::DirectionConfig {
            native_policy: if raw {
                aligned::NativePolicy::RawIp
            } else {
                aligned::NativePolicy::EthernetHeaders
            },
            receiver: receiver::Limits {
                body,
                channels,
                first_record,
                first_source,
                record_window: 32,
                source_window: 32,
                lookahead_records: 4,
                lookahead_bytes: 4 * 65535,
                lookahead_fragments: 64,
                max_fragments_per_record: 8,
                lifetime_ticks: 5_000_000,
            },
            packing: packed_sender::Config {
                sender: aligned_sender::Config {
                    body,
                    channels,
                    first_record,
                },
                packing: packed::Config {
                    symbol_bytes,
                    hold_micros: if reverse { 701 } else { 503 },
                },
                max_units: 4,
                first_unit: first_source,
                work_limit: 4,
            },
            codec_stage_micros: 1_000_000,
            scheduler: rolling::scheduler::Policy {
                recovery: rolling::Config {
                    window: 16,
                    local_window: 4,
                    global_every: 2,
                    max_payload: 512,
                    max_rows: 16,
                    repair_history: 64,
                    handoff_sources: 2,
                    job_ticks: 1_000_000,
                    debt_ticks: 10_000_000,
                    handoff_ticks: 2_000_000,
                    memory_bytes: 16 << 20,
                },
                repair_numerator: 1,
                repair_denominator: 2,
                tail_ticks: 1000,
                feedback_ticks: 100,
                feedback_packets: 2,
                memory_bytes: 16 << 20,
                source_wire: wire,
            },
        }
    };
    let profile = configuration::Profile::Rolling {
        config: rolling_records::Config {
            forward: direction(false),
            reverse: direction(true),
            geometry: geometry(),
            native_stall_micros: 50_000,
        },
        stream: 17,
    };
    Ok(configuration::Configuration::new(
        old.envelope(),
        configuration::Descriptor::new(
            1500,
            crate::core::Duplex::Full,
            *old.descriptor().direction(Role::Client).common(),
            *old.descriptor().direction(Role::Server).common(),
            profile,
        )?,
    )?)
}

fn build(config: configuration::Configuration, role: Role, reserved: bool) -> TestResult<Engine> {
    let limits = NativeLimits {
        stall_micros: 50_000,
    };
    Ok(if reserved {
        let plan = storage::Plan::for_engine(config, context(role), geometry(), limits)?;
        Engine::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?
    } else {
        Engine::new_functional(config, context(role), geometry(), limits)?
    })
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
}
impl Link {
    fn transfer(
        &mut self,
        now: Tick,
        sender: &mut Engine,
        peer: &mut Engine,
        allow_data: bool,
    ) -> TestResult {
        let mut output = [0u8; 1500];
        let mut units = witnesses();
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        let Some(emission) = sender.poll(
            now,
            self.number,
            allow_data,
            &mut output,
            &mut budget,
            &mut units,
        )?
        else {
            return Ok(());
        };
        let token = sender
            .pending_carrier_output()
            .ok_or("missing real carrier token")?;
        assert_eq!(token.emission(), emission);
        assert_eq!(budget.packets, 0);
        assert_eq!(budget.wire_bytes, 1500 - emission.wire_bytes);
        let mut untouched = [0x91; 1500];
        let before = budget;
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
        assert_eq!(budget, before);
        let duplicate = sender
            .pending_carrier_output()
            .ok_or("missing retained token")?;
        // This simulates whole carrier ownership, independently of network loss.
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
                false
            }
            EmissionKind::Feedback => {
                self.feedback += 1;
                false
            }
            _ => false,
        };
        if !drop {
            peer.accept_authenticated(
                now,
                emission.security_number,
                emission.kind,
                &mut output[..emission.bytes],
            )?;
        }
        self.number = self.number.checked_add(1).ok_or("number overflow")?;
        Ok(())
    }
}

#[test]
fn actual_fourth_family_uses_reserved_owners_recovers_bytes_and_routes_typed_custody() -> TestResult
{
    for raw in [false, true] {
        for wire in [
            rolling::wire::SourceWire::Padded,
            rolling::wire::SourceWire::Exact,
        ] {
            let config = fixture(raw, wire)?;
            let mut client = build(config, Role::Client, true)?;
            let mut server = build(config, Role::Server, true)?;
            let initial = [client.storage_usage(), server.storage_usage()];
            let mut forward = packet(raw, 2101, 1024, 0x39);
            let mut reverse = packet(raw, 2102, 811, 0x57);
            forward[984..].fill(0);
            reverse[771..].fill(0);
            client.enqueue_borrowed(Tick(0), &forward)?;
            server.enqueue_borrowed(Tick(0), &reverse)?;
            let mut a = Link {
                number: (1u64 << 48) + 17,
                lost_source: false,
                lost_feedback: false,
                repairs: 0,
                feedback: 0,
            };
            let mut b = Link {
                number: (1u64 << 56) + 91,
                lost_source: false,
                lost_feedback: false,
                repairs: 0,
                feedback: 0,
            };
            let mut received_a = false;
            let mut received_b = false;
            for iteration in 0..5000u64 {
                let now = Tick(iteration * 100);
                client.admit_borrowed(now)?;
                server.admit_borrowed(now)?;
                assert!(client.step(now, work())?.is_some());
                assert!(server.step(now, work())?.is_some());
                a.transfer(now, &mut client, &mut server, true)?;
                b.transfer(now, &mut server, &mut client, true)?;
                for (engine, expected, received) in [
                    (&mut client, &reverse, &mut received_a),
                    (&mut server, &forward, &mut received_b),
                ] {
                    let mut output = [0u8; 1024];
                    if let NativePreparation::Ready(prepared) =
                        engine.prepare_native(now, 128, Tick(1_000_000), &mut output)?
                    {
                        assert!(!*received);
                        assert_eq!(&output[..prepared.bytes()], expected.as_slice());
                        assert!(matches!(prepared.identity(), ProfileIdentity::Rolling(_)));
                        assert_eq!(engine.statistics().committed, 0);
                        let mut unchanged = [0x82; 1024];
                        assert_eq!(
                            engine.prepare_native(now, 128, Tick(u64::MAX), &mut unchanged)?,
                            NativePreparation::AlreadyPending(prepared)
                        );
                        assert_eq!(unchanged, [0x82; 1024]);
                        engine.commit_native(now, prepared.token())?;
                        assert_eq!(
                            engine.commit_native(now, prepared.token()),
                            Err(Error::Token)
                        );
                        *received = true;
                    }
                }
                if received_a && received_b && client.drained()? && server.drained()? {
                    break;
                }
            }
            assert!(received_a && received_b);
            assert!(client.drained()? && server.drained()?);
            assert!(a.repairs > 0 && b.repairs > 0 && a.feedback > 0 && b.feedback > 0);
            assert_eq!(client.native_counts()?.committed.iter().sum::<u64>(), 1);
            assert_eq!(server.native_counts()?.committed.iter().sum::<u64>(), 1);
            assert_eq!([client.storage_usage(), server.storage_usage()], initial);
        }
    }
    Ok(())
}

#[test]
fn actual_rolling_plan_limits_aliases_foreign_tokens_and_functional_emissions_are_exact()
-> TestResult {
    let config = fixture(false, rolling::wire::SourceWire::Exact)?;
    let plan = storage::Plan::for_engine(
        config,
        context(Role::Client),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    assert!(matches!(
        Engine::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let mut reserved = build(config, Role::Client, true)?;
    let mut functional = build(config, Role::Client, false)?;
    let bytes = packet(false, 3333, 512, 0x43);
    reserved.enqueue_borrowed(Tick(0), &bytes)?;
    functional.enqueue_borrowed(Tick(0), &bytes)?;
    assert_eq!(
        reserved.admit_borrowed(Tick(0))?,
        functional.admit_borrowed(Tick(0))?
    );
    for engine in [&mut reserved, &mut functional] {
        engine.step(Tick(1000), work())?;
    }
    let mut a = [0; 1500];
    let mut b = a;
    let mut wa = witnesses();
    let mut wb = witnesses();
    let mut ba = OutboundBudget {
        packets: 1,
        wire_bytes: 1500,
    };
    let mut bb = ba;
    let ea = reserved
        .poll(
            Tick(1000),
            (1u64 << 60) + 17,
            true,
            &mut a,
            &mut ba,
            &mut wa,
        )?
        .ok_or("missing real source")?;
    let eb = functional
        .poll(
            Tick(1000),
            (1u64 << 60) + 17,
            true,
            &mut b,
            &mut bb,
            &mut wb,
        )?
        .ok_or("missing real source")?;
    assert_eq!(ea, eb);
    assert_eq!(a, b);
    assert_eq!(wa, wb);
    assert_eq!(ba, bb);
    let foreign = functional
        .pending_carrier_output()
        .ok_or("missing foreign token")?;
    assert_eq!(
        reserved.confirm_carrier_output(Tick(u64::MAX), foreign),
        Err(Error::Token)
    );
    reserved.tick(Tick(1000))?;
    let token = reserved
        .pending_carrier_output()
        .ok_or("missing same-owner token")?;
    reserved.confirm_carrier_output(Tick(1000), token)?;
    let mut wrong = geometry();
    wrong.forward_overhead_bytes += 1;
    assert!(matches!(
        storage::Plan::for_engine(
            config,
            context(Role::Client),
            wrong,
            NativeLimits {
                stall_micros: 50_000
            }
        ),
        Err(storage::Error::Engine(Error::Geometry))
    ));
    Ok(())
}
