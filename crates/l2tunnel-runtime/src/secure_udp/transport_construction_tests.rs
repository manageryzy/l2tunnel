//! Known construction admission against actual controlled owners, without setup/auth claims.

use super::*;
use std::{cell::Cell, mem::size_of};

fn identity(contract: &TransactionContract) -> transaction::Identity {
    let role = if contract.role() == security::Role::Initiator {
        mg::Role::Client
    } else {
        mg::Role::Server
    };
    transaction::Identity {
        session: mg::SessionId([0x62; 16]),
        lane: mg::LaneId(LANE),
        role,
        local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
    }
}

fn binding(contract: &TransactionContract) -> delivery::Binding {
    let identity = identity(contract);
    delivery::Binding {
        session: identity.session,
        lane: identity.lane,
        local_role: identity.role,
        control_epoch: contract.config().control_epoch.0,
    }
}

/// Explicit pure geometry for this bounded fixture; no authenticated Records owner is implied.
fn geometry(contract: &TransactionContract) -> io::Result<record::Capacity> {
    let plaintext_bytes = contract.config().security.max_body_bytes;
    let protection = security::Protection::ChaCha20Poly1305;
    let seal_workspace_bytes = plaintext_bytes
        .checked_add(protection.overhead_bytes())
        .and_then(|bytes| bytes.checked_add(record::ROUTE_BYTES))
        .ok_or_else(|| invalid("fixture record geometry"))?;
    let packet_bytes = seal_workspace_bytes
        .checked_add(
            contract
                .cover()
                .overhead(cover::Phase::Established, seal_workspace_bytes)
                .map_err(invalid)?,
        )
        .ok_or_else(|| invalid("fixture packet geometry"))?;
    if packet_bytes > contract.cover().limits().max_packet_bytes {
        return Err(invalid("fixture packet exceeds cover geometry"));
    }
    let open_workspace_bytes = plaintext_bytes
        .checked_add(protection.tag_bytes())
        .ok_or_else(|| invalid("fixture open geometry"))?;
    Ok(record::Capacity {
        plaintext_bytes,
        seal_workspace_bytes,
        open_workspace_bytes,
        packet_bytes,
    })
}

fn plan(contract: &TransactionContract) -> io::Result<construction::Plan> {
    construction::Plan::new(
        contract.config(),
        contract.cover(),
        geometry(contract)?,
        binding(contract),
        contract.initial(),
        identity(contract).role,
    )
}

/// Retain the actual owners together so all observed heaps coexist at the known peak.
struct Known {
    control: control_owner::Owner,
    buffers: buffers::Buffers,
    inputs: buffers::Inputs,
    native: native_storage::Queue<Native>,
    bank: engines::Bank,
}

fn provision(
    contract: &TransactionContract,
    plan: construction::Plan,
    limit: usize,
) -> io::Result<Known> {
    let config = contract.config();
    plan.provision(limit, |plan| {
        let control = control_owner::Owner::new_leased_reserved_messages(
            config.control,
            config.streams.ok_or_else(|| invalid("fixture streams"))?,
            binding(contract),
            envelope_scope(Scope {
                epoch: config.control_epoch,
                configuration: contract.expected_configuration(),
            }),
            envelope_scope(Scope {
                epoch: config.data_epoch,
                configuration: security::ConfigDigest(contract.data_digest().0),
            }),
            Duration::ZERO,
            config.lifetime.lease,
            plan.messages.map(|message| messages::storage::Limits {
                capacity_bytes: message.capacity_bytes(),
            }),
        )?;
        let usage = control
            .message_storage_usage()
            .ok_or_else(|| protocol("missing actual message storage"))?;
        let arq = control
            .arq_storage_usage()
            .ok_or_else(|| protocol("missing actual recovery storage"))?;
        for ((actual, nested), expected) in usage.iter().zip(arq).zip(plan.messages) {
            assert_eq!(actual.capacity_bytes, expected.capacity_bytes());
            assert_eq!(actual.limit_bytes, expected.capacity_bytes());
            assert_eq!(actual.arq, nested);
            assert_eq!(
                actual.arq.capacity_bytes,
                expected.arq_plan().capacity_bytes()
            );
            assert_eq!(
                actual.reassembly.capacity_bytes,
                expected.reassembly_plan().capacity_bytes()
            );
            assert!(actual.allocations > 0);
        }
        let expected_buffers = plan.buffers.capacity_bytes();
        let expected_inputs = plan.inputs.capacity_bytes();
        let expected_native = plan.native.capacity_bytes();
        let buffers = buffers::Buffers::with_plan(plan.buffers)?;
        let inputs = buffers::Inputs::with_plan(plan.inputs)?;
        let native = native_storage::Queue::with_plan(plan.native)?;
        assert_eq!(buffers.capacity_bytes(), expected_buffers);
        assert_eq!(inputs.capacity_bytes(), expected_inputs);
        assert_eq!(native.capacity_bytes(), expected_native);
        let wrapper = control.wrapper_capacity_bytes()?;
        assert_eq!(wrapper, plan.wrapper_bytes);
        let messages = usage.iter().map(|actual| actual.capacity_bytes).sum();
        let external = construction::external_capacity(
            buffers.capacity_bytes(),
            inputs.capacity_bytes(),
            native.capacity_bytes(),
            messages,
            wrapper,
        )?;
        assert_eq!(external, plan.external_bytes);
        let bank = engines::Bank::new(
            identity(contract),
            core::Epoch(config.data_epoch.0),
            contract.initial(),
            swift::storage::Limits {
                capacity_bytes: limit,
            },
            external,
        )?;
        assert_eq!(bank.usage().peak_bytes, plan.required_bytes);
        Ok(Known {
            control,
            buffers,
            inputs,
            native,
            bank,
        })
    })
}

#[test]
fn one_short_known_budget_refuses_before_the_actual_owner_factory_for_both_covers_and_roles()
-> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for contract in contracts(kind)? {
            let plan = plan(&contract)?;
            let limit = plan
                .required_bytes
                .checked_sub(1)
                .ok_or("empty construction plan")?;
            let entered = Cell::new(false);
            let error = plan
                .provision(limit, |_| {
                    entered.set(true);
                    Err::<Known, _>(io::Error::other("owner factory should not run"))
                })
                .err()
                .ok_or("one-short construction was admitted")?;
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<swift::storage::Error>()),
                Some(swift::storage::Error::Budget)
            ));
            assert!(!entered.get());
        }
    }
    Ok(())
}

#[test]
fn exact_and_one_extra_byte_provision_coexisting_real_owners_and_charge_nested_storage_once()
-> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for contract in contracts(kind)? {
            let catalog = contract.catalog().configurations(contract.envelope());
            assert_eq!(catalog.len(), 2);
            let required = plan(&contract)?.required_bytes;
            for extra in [0, 1] {
                let actual = provision(&contract, plan(&contract)?, required + extra)?;
                let messages = actual
                    .control
                    .message_storage_usage()
                    .ok_or("missing actual owners")?;
                let message_bytes: usize = messages.iter().map(|usage| usage.capacity_bytes).sum();
                let nested_arq: usize = messages.iter().map(|usage| usage.arq.capacity_bytes).sum();
                let nested_reassembly: usize = messages
                    .iter()
                    .map(|usage| usage.reassembly.capacity_bytes)
                    .sum();
                assert!(nested_arq > 0 && nested_reassembly > 0);
                assert!(message_bytes > nested_arq + nested_reassembly);
                let external = size_of::<Driver>() + size_of::<transactions::State>()
                    - size_of::<swift::storage::Set>()
                    + size_of::<buffers::Inputs>()
                    + actual.buffers.capacity_bytes()
                    + actual.inputs.capacity_bytes()
                    + actual.native.capacity_bytes()
                    + message_bytes
                    + actual.control.wrapper_capacity_bytes()?;
                let usage = actual.bank.usage();
                assert_eq!(usage.external_bytes, external);
                assert_eq!(
                    usage.fixed_bytes + usage.external_bytes + usage.engine_bytes,
                    required
                );
                assert_eq!(usage.peak_bytes, required);
                assert_eq!(usage.limit_bytes, required + extra);
                assert_eq!(usage.building_bytes, 0);
                assert_eq!(actual.bank.current(), &contract.initial());
                assert_eq!(
                    actual.inputs.datagram.len(),
                    contract.cover().limits().max_packet_bytes + 1
                );
                assert_eq!(actual.buffers.frame.len(), 0);
                assert!(actual.native.is_empty());
                let engine = actual
                    .bank
                    .engine(core::Epoch(contract.config().data_epoch.0))?;
                for (direction, channels) in [
                    (
                        records::Direction::Send,
                        contract.config().send.records.channels,
                    ),
                    (
                        records::Direction::Receive,
                        contract.config().receive.records.channels,
                    ),
                ] {
                    let observed = (0..64)
                        .filter_map(records::ChannelId::new)
                        .filter(|channel| engine.boundary(direction, *channel).is_some())
                        .count();
                    assert_eq!(observed, channels);
                }
                for member in &catalog {
                    let resolved = contract.resolve(*member)?;
                    let descriptor = member.descriptor();
                    let (send, receive) = if identity(&contract).role == mg::Role::Client {
                        (descriptor.forward(), descriptor.reverse())
                    } else {
                        (descriptor.reverse(), descriptor.forward())
                    };
                    assert_eq!((resolved.send, resolved.receive), (send, receive));
                    assert_eq!(resolved.path_mtu, descriptor.path_mtu());
                }
                assert_eq!(
                    contract.catalog().configurations(contract.envelope()),
                    catalog
                );
            }
        }
    }
    Ok(())
}

#[test]
fn invalid_selected_geometry_and_each_external_overflow_refuse_during_pure_planning() -> Result {
    let [contract, _] = contracts(cover::Appearance::QuicLike)?;
    let base = contract.config();
    let capacity = geometry(&contract)?;
    for case in 0..5 {
        let mut config = base;
        let mut geometry = capacity;
        match case {
            0 => config.streams = None,
            1 => config.native.pending_packets = 0,
            2 => {
                config
                    .streams
                    .as_mut()
                    .ok_or("missing fixture streams")?
                    .streams[2]
                    .max_message_bytes = 0
            }
            3 => {
                geometry.seal_workspace_bytes = 0;
                geometry.open_workspace_bytes = 0;
            }
            4 => config.lifetime.lease = Duration::ZERO,
            _ => unreachable!(),
        }
        assert_eq!(
            construction::Plan::new(
                config,
                contract.cover(),
                geometry,
                binding(&contract),
                contract.initial(),
                identity(&contract).role
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    for position in 0..5 {
        let mut sizes = [1; 5];
        sizes[position] = usize::MAX;
        assert_eq!(
            construction::external_capacity(sizes[0], sizes[1], sizes[2], sizes[3], sizes[4])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}
