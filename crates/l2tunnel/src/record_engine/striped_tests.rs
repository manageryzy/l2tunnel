use super::tests::{context, geometry, packet};
#[path = "striped_tests/credit.rs"]
mod credit;
#[path = "striped_tests/overlap.rs"]
mod overlap;
use super::*;
use crate::{fec, striped_records};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn queued_fragmented_frames_fill_a_mixed_group_in_one_admission_turn() -> TestResult {
    let mut client = Engine::new_functional(
        fixture()?,
        context(Role::Client),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    client.enable_compact_wire(31)?;
    let now = Tick(10);
    for value in 1..=4 {
        client.enqueue_borrowed(now, &packet(true, 5100, 340, value))?;
    }
    let mut admitted = 0;
    while client.admit_borrowed(now)?.is_some() {
        admitted += 1;
    }
    assert!(
        admitted >= 3,
        "only {admitted} queued frames reached the codec"
    );
    let mut bytes = [0; 1500];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: bytes.len(),
    };
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    let output = client
        .poll(now, 0, true, &mut bytes, &mut budget, &mut witnesses)?
        .ok_or("five ready sources should emit before the first hold expires")?;
    let configuration::Profile::Striped { forward, .. } =
        *client.configuration().descriptor().profile()
    else {
        return Err("expected mixed policy".into());
    };
    let (shape, member) = forward.profile.inspect(&bytes[..output.bytes])?;
    assert_eq!(shape, fec::mixed_datagram::GroupShape::Originals(5));
    assert_eq!(member.geometry().data_cells(), 4);
    Ok(())
}

#[test]
fn two_mixed_epochs_reserve_exact_custody_and_release_only_the_cancelled_one() -> TestResult {
    use crate::record_bank::{self as bank, Bank};
    let config = fixture()?;
    let initial_context = context(Role::Client);
    let limits = NativeLimits {
        stall_micros: 50_000,
    };
    let first = storage::Plan::for_engine(config, initial_context, geometry(), limits)?;
    let next = storage::Plan::for_engine(
        config,
        Context {
            epoch: initial_context.epoch + 1,
            ..initial_context
        },
        geometry(),
        limits,
    )?;
    let inventory = bank::storage::Plan::for_bank(first, 137)?;
    let peak = inventory.capacity_bytes() + next.heap_bytes();
    for allowance in [peak - 1, peak] {
        let mut owners = Bank::new(
            inventory,
            bank::storage::Limits {
                capacity_bytes: allowance,
            },
        )?;
        let initial = owners.usage();
        if allowance < peak {
            assert!(
                matches!(owners.prepare(next),Err(bank::Error::Limit {required,limit}) if required == peak && limit == allowance)
            );
            assert_eq!(owners.usage(), initial);
        } else {
            let mut prepared = owners.prepare(next)?;
            let staged = owners
                .prepared_engine(&prepared)?
                .storage_usage()
                .ok_or("missing staged striped storage")?;
            assert_eq!(owners.usage().capacity_bytes, peak);
            assert_eq!(
                owners.usage().allocations,
                initial.allocations + staged.allocations
            );
            owners.cancel(&mut prepared)?;
            assert_eq!(owners.usage().capacity_bytes, initial.capacity_bytes);
            assert_eq!(owners.usage().peak_bytes, peak);
        }
    }
    Ok(())
}

#[test]
fn negotiated_slots_bind_both_directions_and_reject_unfinishable_records() -> TestResult {
    let config = fixture()?;
    let descriptor = config.descriptor();
    let configuration::Profile::Striped { forward, reverse } = *descriptor.profile() else {
        return Err("expected mixed directions".into());
    };
    let rebuild = |forward, reverse| {
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(Role::Client).common(),
            *descriptor.direction(Role::Server).common(),
            configuration::Profile::Striped { forward, reverse },
        )
    };
    let mut bytes = [0; configuration::DESCRIPTOR_BYTES];
    descriptor.encode_into(&mut bytes)?;
    assert_eq!(configuration::Descriptor::decode(&bytes)?, *descriptor);
    let mut changed = reverse;
    changed.timing.ack_delay += 1;
    let other = rebuild(forward, changed)?;
    let catalog = configuration::Catalog::new(*descriptor, &[*descriptor, other])?;
    let policies = catalog.configurations(config.envelope())?;
    assert_ne!(policies[0].digest()?, policies[1].digest()?);
    bytes[configuration::HEADER_BYTES + configuration::DIRECTION_BYTES - 1] = 1;
    assert_eq!(
        configuration::Descriptor::decode(&bytes),
        Err(configuration::Error::Padding)
    );

    let mut blocked = forward;
    blocked.source_limit = 1;
    assert_eq!(
        rebuild(blocked, reverse),
        Err(configuration::Error::Profile)
    );
    blocked = forward;
    blocked.expanded_limit =
        fec::striped_group::ReceiveWindow::frontier_reserve(blocked.profile, blocked.source_limit)?;
    assert_eq!(
        rebuild(blocked, reverse),
        Err(configuration::Error::Profile)
    );
    Ok(())
}

fn fixture() -> TestResult<configuration::Configuration> {
    let original = rolling_tests::fixture(true, fec::rolling::wire::SourceWire::Exact)?;
    let desc = original.descriptor();
    let configuration::Profile::Rolling { config, .. } = desc.profile() else {
        return Err("expected packed fixture".into());
    };
    let direction =
        |d: rolling_records::DirectionConfig, overhead, stream| striped_records::Direction {
            packing: d.packing,
            native_policy: d.native_policy,
            receiver: d.receiver,
            profile: fec::mixed_datagram::Profile {
                data_cells: 4,
                parity_cells: 1,
                max_body_bytes: 1000,
                max_wire_bytes: 1000,
            },
            first: fec::GenerationId(u64::from(u32::MAX) + 12),
            source_limit: 20,
            expanded_limit: 70_000,
            hold_micros: 100,
            timing: fec::striped_group::schedule::RecoveryTiming {
                gap_delay: 120,
                gap_repeat: 300,
                ack_delay: 80,
                quiet: 700,
            },
            overhead_bytes: overhead,
            stream,
            codec_stage_micros: d.codec_stage_micros,
            native_stall_micros: config.native_stall_micros,
        };
    let profile = configuration::Profile::Striped {
        forward: direction(config.forward, geometry().forward_overhead_bytes, 7),
        reverse: direction(config.reverse, geometry().reverse_overhead_bytes, 13),
    };
    Ok(configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            desc.path_mtu(),
            desc.duplex(),
            *desc.direction(Role::Client).common(),
            *desc.direction(Role::Server).common(),
            profile,
        )?,
    )?)
}

#[test]
fn physical_split_members_each_cover_the_two_packed_natives_after_one_loss() -> TestResult {
    let config = fixture()?;
    let limits = NativeLimits {
        stall_micros: 50_000,
    };
    let reserved = |role| -> Result<Engine, storage::Error> {
        let plan = storage::Plan::for_engine(config, context(role), geometry(), limits)?;
        let bytes = plan.capacity_bytes();
        assert!(
            matches!(Engine::new_reserved(plan, storage::Limits {capacity_bytes: bytes - 1}),Err(storage::Error::Limit {required, ..}) if required == bytes)
        );
        let owner = Engine::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: bytes,
            },
        )?;
        assert_eq!(owner.storage_usage().map(|u| u.capacity_bytes), Some(bytes));
        Ok(owner)
    };
    let mut client = reserved(Role::Client)?;
    let mut server = reserved(Role::Server)?;
    assert_eq!(client.enable_compact_wire(1500), Err(Error::Geometry));
    client.enable_compact_wire(31)?;
    server.enable_compact_wire(87)?;
    let frames = [packet(true, 5100, 54, 1), packet(true, 5100, 55, 2)];
    for frame in &frames {
        client.enqueue_borrowed(Tick(0), frame)?;
    }
    let mut delivered = Vec::new();
    let mut physical = 0usize;
    let mut feedback = 0usize;
    let mut previous: Option<CarrierOutputToken> = None;
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    for time in (0..10_000).step_by(20) {
        let now = Tick(time);
        client.admit_borrowed(now)?;
        {
            let mut bytes = [0; 1500];
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 1500,
            };
            if let Some(e) = client.poll(now, 17, true, &mut bytes, &mut budget, &mut witnesses)? {
                assert_eq!(e.kind, EmissionKind::Source(SourceForm::SystematicFec));
                assert_eq!(e.wire_bytes, e.bytes + geometry().forward_overhead_bytes);
                assert_eq!(e.witnesses, frames.len());
                assert_ne!(witnesses[0].identity, witnesses[1].identity);
                let body = &mut bytes[..e.bytes];
                assert_eq!(body[0], 0);
                let extent = client.inspect_striped_output_extent(body)?;
                assert_eq!(
                    e.bytes,
                    extent.header_bytes + extent.parity_bytes + extent.systematic_bytes
                );
                assert_eq!(
                    client
                        .inspect_output_extent(body, e.kind, false)?
                        .codec_coverage,
                    CodecCoverage::StripedMixed
                );
                assert_eq!(server.inspect_peer(body), Err(Error::Kind));
                assert_eq!(server.inspect_peer_class(body, false)?, e.kind);
                let token = client
                    .pending_carrier_output()
                    .ok_or("missing physical custody")?;
                let duplicate = client
                    .pending_carrier_output()
                    .ok_or("missing duplicate witness")?;
                if let Some(stale) = previous.take() {
                    // Guard the local issuing operation even when all public
                    // metadata, including a supplied security number, coincide.
                    assert_eq!(stale.emission(), e);
                    assert_eq!(client.confirm_carrier_output(now, stale), Err(Error::Token));
                }
                previous = Some(duplicate);
                client.confirm_carrier_output(now, token)?;
                physical += 1;
                if physical > 1 {
                    server.accept_authenticated(now, e.security_number, e.kind, body)?;
                }
            }
        }
        let mut native = [0; 1024];
        if let NativePreparation::Ready(p) =
            server.prepare_native(now, 8, Tick(1_000_000), &mut native)?
        {
            assert!(matches!(p.identity(), ProfileIdentity::Striped(_)));
            delivered.push(native[..p.bytes()].to_vec());
            server.commit_native(now, p.token())?;
        }
        let mut bytes = [0; 1500];
        let mut budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1500,
        };
        if let Some(e) = server.poll(
            now,
            time + 5,
            false,
            &mut bytes,
            &mut budget,
            &mut witnesses,
        )? {
            assert_eq!(e.kind, EmissionKind::Feedback);
            assert_eq!(e.wire_bytes, e.bytes + 87);
            assert_eq!(e.witnesses, 0);
            let body = &mut bytes[..e.bytes];
            assert_eq!(client.inspect_peer_class(body, true)?, e.kind);
            assert_eq!(
                server
                    .inspect_output_extent(body, e.kind, false)?
                    .recovery
                    .ok_or("missing feedback extent")?
                    .header_bytes,
                e.bytes
            );
            let token = server
                .pending_carrier_output()
                .ok_or("missing feedback token")?;
            server.confirm_carrier_output(now, token)?;
            client.accept_authenticated(now, e.security_number, e.kind, body)?;
            feedback += 1;
        }
        if !delivered.is_empty() && client.drained()? && server.drained()? {
            break;
        }
    }
    assert_eq!(delivered, frames);
    assert!(physical >= 2 && feedback > 0);
    assert_eq!(client.native_counts()?.admitted.iter().sum::<u64>(), 2);
    assert_eq!(server.native_counts()?.prepared.iter().sum::<u64>(), 2);
    assert_eq!(server.native_counts()?.committed.iter().sum::<u64>(), 2);
    assert!(client.drained()? && server.drained()?);
    Ok(())
}
