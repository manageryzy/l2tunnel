use super::*;
use crate::{LaneId, SessionId};
use l2tunnel_recovery::{EndpointRole, PacketView, RecoveryContext, inspect_packet};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn control_expiry_snapshot_separates_acknowledged_sources_from_confirmation_custody() -> Result {
    for reserved in [false, true] {
        let mut sender = owner(settings(), 0, reserved)?;
        let mut receiver = owner(settings(), 1, reserved)?;
        let deadline = Duration::from_secs(1);
        let body = b"diagnostic payload must remain private";
        let ticket = sender.submit(SubmissionId(7), body, Duration::ZERO, deadline)?;
        let mut packet = [0; 512];
        let emission = sender
            .poll(Duration::ZERO, 4096, &mut packet)?
            .ok_or("missing real source")?;
        let before = sender.expiry_snapshot(deadline);
        let Some(ExpiryCandidate {
            deadline: original,
            kind: ExpiryKind::Outbound(pending),
        }) = before.candidate
        else {
            return Err("missing outbound candidate".into());
        };
        assert_eq!(original, deadline);
        assert_eq!(pending.submission, SubmissionId(7));
        assert_eq!(pending.message, ticket.message());
        assert_eq!((pending.fragments, pending.submitted_fragments), (1, 1));
        assert_eq!(pending.source_custody, 1);
        assert_eq!(pending.first_source_confirmed, Some(Ok(false)));
        assert!(!pending.semantic_accepted);
        receiver.receive(verified(0), &packet[..emission.bytes], Duration::ZERO)?;
        let ack = receiver
            .poll(Duration::ZERO, 4096, &mut packet)?
            .ok_or("missing real source ACK")?;
        assert!(matches!(
            view(1, &packet[..ack.bytes])?,
            PacketView::Ack { .. }
        ));
        // Feed the actual ACK to its existing source owner before the bounded
        // whole-message confirmation sweep consumes that source's custody.
        sender
            .service
            .receive(verified(1), &packet[..ack.bytes], Duration::ZERO)?;
        let state = (
            sender.last_now,
            sender.failed,
            sender.retained(),
            sender.statistics(),
        );
        let storage = reserved.then(|| inventory(&sender)).transpose()?;
        let snapshot = sender.expiry_snapshot(deadline);
        let Some(ExpiryCandidate {
            kind: ExpiryKind::Outbound(pending),
            ..
        }) = snapshot.candidate
        else {
            return Err("missing ACKed outbound candidate".into());
        };
        assert_eq!(pending.source_custody, 1);
        assert_eq!(pending.first_source_confirmed, Some(Ok(true)));
        assert!(!pending.semantic_accepted);
        assert_eq!(snapshot.last_successful_at, Duration::ZERO);
        assert_eq!(snapshot.owner_error, None);
        assert_eq!(
            (
                sender.last_now,
                sender.failed,
                sender.retained(),
                sender.statistics()
            ),
            state
        );
        assert_eq!(reserved.then(|| inventory(&sender)).transpose()?, storage);
        assert!(!format!("{snapshot:?}").contains(std::str::from_utf8(body)?));
        sender.tick(Duration::ZERO)?;
        let Some(ExpiryCandidate {
            kind: ExpiryKind::Outbound(pending),
            ..
        }) = sender.expiry_snapshot(deadline).candidate
        else {
            return Err("missing semantic-receipt candidate".into());
        };
        assert_eq!(pending.source_custody, 0);
        assert_eq!(pending.first_source_confirmed, None);
        assert!(!pending.semantic_accepted);
    }
    Ok(())
}

#[test]
fn control_expiry_snapshot_preserves_reassembly_identity_after_payload_expiry() -> Result {
    for reserved in [false, true] {
        let mut sender = owner(settings(), 0, reserved)?;
        let mut receiver = owner(settings(), 1, reserved)?;
        let ticket = sender.submit(
            SubmissionId(1),
            &[0x91; 200],
            Duration::ZERO,
            Duration::from_secs(2),
        )?;
        let mut packet = [0; 512];
        let emission = sender
            .poll(Duration::ZERO, 4096, &mut packet)?
            .ok_or("missing first fragment")?;
        receiver.receive(verified(0), &packet[..emission.bytes], Duration::ZERO)?;
        receiver.tick(Duration::ZERO)?;
        assert_eq!(receiver.retained().incomplete_messages, 1);
        let deadline = settings().message_lifetime;
        assert_eq!(
            receiver
                .expiry_snapshot(deadline - Duration::from_nanos(1))
                .candidate,
            None
        );
        assert_eq!(receiver.tick(deadline), Err(Error::Expired));
        assert_eq!(receiver.retained().incomplete_messages, 0);
        let snapshot = receiver.expiry_snapshot(deadline + Duration::from_nanos(1));
        assert_eq!(
            snapshot.candidate,
            Some(ExpiryCandidate {
                deadline,
                kind: ExpiryKind::Reassembly {
                    message: MessageId(ticket.message())
                },
            })
        );
        assert_eq!(snapshot.owner_error, Some(Error::Expired));
        assert_eq!(snapshot.last_successful_at, Duration::ZERO);
    }
    Ok(())
}

fn settings() -> Settings {
    Settings {
        delivery: delivery::Settings {
            recovery: l2tunnel_recovery::ArqConfig {
                max_source_bytes: 128,
                send_bytes: 384,
                receive_bytes: 384,
                send_records: 3,
                receive_records: 3,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(40),
                ack_delay: Duration::ZERO,
                max_retries: 32,
            },
            interval: Duration::from_millis(5),
            packets_per_interval: 4,
            bytes_per_interval: 1024,
            wire_overhead: 64,
        },
        path_mtu: 512,
        max_message_bytes: 1024,
        max_outbound_messages: 3,
        max_outbound_bytes: 8192,
        max_fragments: 16,
        max_reassembly_bytes: 3072,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(3),
        work_per_call: 4,
    }
}
fn binding(role: Role) -> delivery::Binding {
    delivery::Binding {
        session: SessionId([0xC5; 16]),
        lane: LaneId(3),
        local_role: role,
        control_epoch: 9,
    }
}
fn role(side: usize) -> Role {
    if side == 0 {
        Role::Client
    } else {
        Role::Server
    }
}
fn verified(side: usize) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: binding(role(side)).session,
        lane: LaneId(3),
        sender: role(side),
    }
}
fn end() -> Duration {
    Duration::from_secs(600)
}
fn owner(settings: Settings, side: usize, reserved: bool) -> Result<Owner> {
    Ok(if reserved {
        let bytes = storage::Plan::for_owner(settings, binding(role(side)), Duration::ZERO, end())?
            .capacity_bytes();
        Owner::new_reserved(
            settings,
            binding(role(side)),
            Duration::ZERO,
            end(),
            storage::Limits {
                capacity_bytes: bytes,
            },
        )?
    } else {
        Owner::new(settings, binding(role(side)), Duration::ZERO, end())?
    })
}
fn inventory(owner: &Owner) -> Result<Vec<(usize, usize, usize)>> {
    let mut result = owner.outbound.inventory();
    result.push(
        owner
            .arrivals
            .inventory()
            .ok_or("missing actual arrival backing")?,
    );
    result.push((
        owner.source_scratch.as_ptr() as usize,
        owner.source_scratch.capacity(),
        1,
    ));
    result.push((
        owner.complete.as_ptr() as usize,
        owner.complete.capacity(),
        1,
    ));
    Ok(result)
}
fn view(side: usize, packet: &[u8]) -> Result<PacketView<'_>> {
    Ok(inspect_packet(
        packet,
        RecoveryContext {
            session: u128::from_be_bytes(binding(role(side)).session.0),
            epoch: 9,
            role: if side == 0 {
                EndpointRole::Responder
            } else {
                EndpointRole::Initiator
            },
        },
        128,
    )?)
}

#[derive(Default)]
struct Faults {
    enabled: bool,
    dropped: [bool; 5],
    duplicates: usize,
}
impl Faults {
    fn discard(&mut self, side: usize, bytes: &[u8]) -> Result<bool> {
        let candidate = match view(side, bytes)? {
            PacketView::Data { payload, .. }
                if side == 0 && payload.first() == Some(&FRAGMENT_KIND) =>
            {
                let index = u16::from_be_bytes(
                    payload
                        .get(33..35)
                        .ok_or("missing real LX index")?
                        .try_into()?,
                );
                let count = u16::from_be_bytes(
                    payload
                        .get(35..37)
                        .ok_or("missing real LX count")?
                        .try_into()?,
                );
                if index == 0 {
                    Some(0)
                } else if index == count / 2 {
                    Some(1)
                } else if index + 1 == count {
                    Some(2)
                } else {
                    None
                }
            }
            PacketView::Data { payload, .. }
                if side == 1 && payload.first() == Some(&ACCEPTED_KIND) =>
            {
                Some(3)
            }
            PacketView::Ack { .. } if side == 1 => Some(4),
            _ => None,
        };
        if self.enabled
            && let Some(index) = candidate
            && !self.dropped[index]
        {
            self.dropped[index] = true;
            return Ok(true);
        }
        Ok(false)
    }
}
struct Pair {
    peers: [Owner; 2],
    time: u64,
    queued: Vec<(u64, usize, Vec<u8>)>,
    faults: Faults,
}
impl Pair {
    fn new(settings: Settings, reserved: bool, faults: bool) -> Result<Self> {
        Ok(Self {
            peers: [owner(settings, 0, reserved)?, owner(settings, 1, reserved)?],
            time: 0,
            queued: Vec::new(),
            faults: Faults {
                enabled: faults,
                ..Faults::default()
            },
        })
    }
    fn now(&self) -> Duration {
        Duration::from_millis(self.time)
    }
    fn step(&mut self) -> Result<Vec<(usize, Vec<u8>)>> {
        let now = self.now();
        let mut emitted = Vec::new();
        let previous = std::mem::take(&mut self.queued);
        for (at, target, bytes) in previous {
            if at > self.time {
                self.queued.push((at, target, bytes));
            } else {
                self.peers[target].receive(verified(1 - target), &bytes, now)?;
            }
        }
        for side in 0..2 {
            self.peers[side].tick(now)?;
            let mut allowance = 1024;
            for _ in 0..4 {
                let mut output = [0; 512];
                let Some(result) = self.peers[side].poll(now, allowance, &mut output)? else {
                    break;
                };
                assert_eq!(result.wire_bytes, result.bytes + 64);
                assert!(result.wire_bytes <= allowance);
                allowance -= result.wire_bytes;
                let bytes = output[..result.bytes].to_vec();
                emitted.push((side, bytes.clone()));
                if self.faults.discard(side, &bytes)? {
                    continue;
                }
                self.queued.push((
                    self.time + if self.time.is_multiple_of(2) { 3 } else { 1 },
                    1 - side,
                    bytes.clone(),
                ));
                if self.faults.enabled {
                    self.queued.push((self.time + 4, 1 - side, bytes));
                    self.faults.duplicates += 1;
                }
            }
        }
        assert!(
            self.queued.len() <= 96,
            "finite fault queue exceeded its fixture bound"
        );
        self.time += 1;
        Ok(emitted)
    }
    fn pending(&self, side: usize) -> Option<(Ticket, Vec<u8>, Duration)> {
        self.peers[side]
            .pending()
            .map(|held| (held.ticket(), held.bytes().to_vec(), held.deadline()))
    }
}

#[test]
fn full_plan_exact_limit_all_local_failure_drops_and_successful_transfer() -> Result {
    let settings = settings();
    let binding = binding(Role::Client);
    let plan = storage::Plan::for_owner(settings, binding, Duration::ZERO, end())?;
    let nested = plan.arq_plan().capacity_bytes() + plan.reassembly_plan().capacity_bytes();
    assert_eq!(plan.capacity_bytes(), plan.own_bytes + nested);
    assert!(
        matches!(Owner::new_reserved(settings, binding, Duration::ZERO, end(), storage::Limits {
        capacity_bytes: plan.capacity_bytes() - 1 }), Err(storage::Error::Limit { required, .. }) if required == plan.capacity_bytes())
    );
    let count = 5 + 3 * settings.max_outbound_messages;
    for point in 1..=count {
        let mut allocation = storage::Allocation::failing(plan.own_bytes, point);
        let result = Owner::build_reserved(
            settings,
            binding,
            Duration::ZERO,
            end(),
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
            &mut allocation,
        );
        assert!(
            matches!(result, Err(storage::Error::Allocation)),
            "local failpoint {point} published no Owner"
        );
        assert_eq!(allocation.allocations(), point - 1);
        let trace = allocation.trace.borrow();
        let mut released = 0;
        assert!(trace.len().is_multiple_of(2));
        for events in trace.chunks_exact(2) {
            let storage::DropEvent::Before(bytes) = events[0] else {
                return Err("drop bracket starts after release".into());
            };
            assert_eq!(events[1], storage::DropEvent::After(bytes));
            released += bytes;
        }
        assert_eq!(
            released,
            allocation.used() + nested,
            "same production Drop statements released every prior heap at failpoint {point}"
        );
    }
    let mut allocation = storage::Allocation::new(plan.own_bytes);
    let transferred = Owner::build_reserved(
        settings,
        binding,
        Duration::ZERO,
        end(),
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
        &mut allocation,
    )?;
    assert!(
        allocation.trace.borrow().is_empty(),
        "successful transfer cannot drop live backing"
    );
    let usage = transferred.storage_usage().ok_or("missing full usage")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(
        usage.capacity_bytes,
        inventory(&transferred)?
            .iter()
            .map(|(_, n, size)| n * size)
            .sum::<usize>()
            + nested
    );
    assert_eq!(
        usage.allocations,
        count + usage.arq.allocations + usage.reassembly.allocations
    );
    assert_eq!(transferred.arq_storage_usage(), Some(usage.arq));
    assert_eq!(owner(settings, 0, false)?.storage_usage(), None);
    let arq_only = Owner::new_reserved_arq(
        settings,
        binding,
        Duration::ZERO,
        end(),
        l2tunnel_recovery::storage::Limits {
            capacity_bytes: plan.arq_plan().capacity_bytes(),
        },
    )?;
    assert_eq!(arq_only.storage_usage(), None);
    assert!(arq_only.arq_storage_usage().is_some());
    let invalid = Settings {
        max_message_bytes: 0,
        ..settings
    };
    assert_eq!(
        storage::Plan::for_owner(invalid, binding, Duration::ZERO, end()),
        Err(storage::Error::Message(Error::Settings))
    );
    let invalid_nested = Settings {
        delivery: delivery::Settings {
            recovery: l2tunnel_recovery::ArqConfig {
                initial_rto: Duration::ZERO,
                ..settings.delivery.recovery
            },
            ..settings.delivery
        },
        ..settings
    };
    let expected = Owner::new(invalid_nested, binding, Duration::ZERO, end())
        .err()
        .ok_or("legacy invalid settings accepted")?;
    assert!(
        matches!(storage::Plan::for_owner(invalid_nested, binding, Duration::ZERO, end()),
        Err(storage::Error::Message(error)) if error == expected)
    );
    assert!(matches!(
        storage::array_bytes::<u64>(usize::MAX),
        Err(storage::Error::Layout)
    ));
    Ok(())
}

#[test]
fn more_than_64_full_outbound_cycles_keep_all_slots_and_real_proof_custody() -> Result {
    let mut pair = Pair::new(settings(), true, false)?;
    let before = [inventory(&pair.peers[0])?, inventory(&pair.peers[1])?];
    let usage = [pair.peers[0].storage_usage(), pair.peers[1].storage_usage()];
    for round in 0..130_u64 {
        let deadline = pair.now() + Duration::from_secs(2);
        let now = pair.now();
        let payloads: [Vec<Vec<u8>>; 2] = std::array::from_fn(|side| {
            (0..3)
                .map(|slot| vec![((round + slot) as u8) ^ side as u8; 200 + slot as usize])
                .collect()
        });
        let mut tickets = [Vec::new(), Vec::new()];
        for side in 0..2 {
            for (index, payload) in payloads[side].iter().enumerate() {
                tickets[side].push(pair.peers[side].submit(
                    SubmissionId(1 + round * 3 + index as u64),
                    payload,
                    now,
                    deadline,
                )?);
            }
            assert_eq!(pair.peers[side].retained().outbound_messages, 3);
        }
        let mut accepted = [0; 2];
        let mut completed = false;
        for _ in 0..1000 {
            pair.step()?;
            let now = pair.now();
            for receiver in 0..2 {
                if let Some((ticket, bytes, _)) = pair.pending(receiver) {
                    let sender = 1 - receiver;
                    assert_eq!(bytes, payloads[sender][accepted[receiver]]);
                    let proof = pair.peers[receiver].accept_with_receipt(ticket, now)?;
                    assert_eq!(proof.ticket(), ticket);
                    accepted[receiver] += 1;
                }
            }
            let mut all = accepted == [3, 3];
            for (side, side_tickets) in tickets.iter().enumerate() {
                for ticket in side_tickets {
                    all &= pair.peers[side].confirmation(*ticket, now)?.is_some();
                }
            }
            if all {
                completed = true;
                break;
            }
        }
        assert!(
            completed,
            "full pool round {round} exceeded finite delivery bound"
        );
        for side in 0..2 {
            let now = pair.now();
            for (index, ticket) in tickets[side].iter().enumerate() {
                assert_eq!(
                    pair.peers[side].submit(
                        ticket.submission,
                        &payloads[side][index],
                        now,
                        deadline
                    )?,
                    *ticket
                );
                pair.peers[side].retire(*ticket, now)?;
            }
            assert_eq!(pair.peers[side].retained().outbound_messages, 0);
            assert_eq!(pair.peers[side].storage_usage(), usage[side]);
            assert_eq!(inventory(&pair.peers[side])?, before[side]);
        }
    }
    Ok(())
}

#[test]
fn legacy_and_full_reserved_paths_match_loss_reorder_duplicate_receipt_and_short_output() -> Result
{
    let mut legacy = Pair::new(settings(), false, true)?;
    let mut reserved = Pair::new(settings(), true, true)?;
    let payload: Vec<_> = (0..1024).map(|index| (index % 251) as u8).collect();
    let cap = Duration::from_secs(2);
    let mut tickets = Vec::new();
    for pair in [&mut legacy, &mut reserved] {
        tickets.push(pair.peers[0].submit(SubmissionId(1), &payload, Duration::ZERO, cap)?);
        let before = pair.peers[0].retained();
        let mut short = [0xA5; 1];
        assert_eq!(
            pair.peers[0].poll(Duration::ZERO, usize::MAX, &mut short),
            Err(Error::Delivery(delivery::Error::OutputTooSmall))
        );
        assert_eq!(short, [0xA5]);
        assert_eq!(pair.peers[0].retained(), before);
    }
    assert_eq!(tickets[0], tickets[1]);
    let mut accepted = false;
    let mut complete = false;
    for _ in 0..1500 {
        assert_eq!(
            legacy.step()?,
            reserved.step()?,
            "actual emitted ARQ bytes differ"
        );
        for side in 0..2 {
            assert_eq!(
                legacy.peers[side].retained(),
                reserved.peers[side].retained()
            );
            assert_eq!(
                legacy.peers[side].statistics(),
                reserved.peers[side].statistics()
            );
            assert_eq!(legacy.peers[side].expiry(), reserved.peers[side].expiry());
        }
        assert_eq!(legacy.pending(1), reserved.pending(1));
        if !accepted && let Some((incoming, bytes, _)) = legacy.pending(1) {
            assert_eq!(bytes, payload);
            for pair in [&mut legacy, &mut reserved] {
                let now = pair.now();
                pair.peers[1].accept_with_receipt(incoming, now)?;
            }
            accepted = true;
        }
        let now = legacy.now();
        let a = legacy.peers[0].confirmed(tickets[0], now)?;
        assert_eq!(a, reserved.peers[0].confirmed(tickets[1], now)?);
        if a {
            complete = true;
            break;
        }
    }
    assert!(accepted && complete);
    assert_eq!(legacy.faults.dropped, [true; 5]);
    assert_eq!(reserved.faults.dropped, [true; 5]);
    assert!(reserved.faults.duplicates > 0);
    assert_eq!(legacy.peers[0].retained().outbound_bytes, 0);
    assert_eq!(
        reserved.peers[0]
            .outbound
            .source_cursor(0)
            .map(|(length, consumed, _)| (length, consumed)),
        Some((0, 0))
    );
    Ok(())
}

// The raw side is the actual existing ordered ARQ Service. It deliberately does
// not run the message sender's confirmation scan, so genuine confirmed IDs can
// accumulate without fabricated source state or acceptance flags.
fn raw_transfer(sender: &mut delivery::Service, receiver: &mut Owner, time: &mut u64) -> Result {
    let now = Duration::from_millis(*time);
    let mut output = [0; 512];
    for _ in 0..4 {
        let Some(emission) = sender.poll(now, 1024, &mut output)? else {
            break;
        };
        receiver.receive(verified(0), &output[..emission.bytes], now)?;
    }
    for _ in 0..4 {
        let Some(emission) = receiver.poll(now, 1024, &mut output)? else {
            break;
        };
        sender.receive(verified(1), &output[..emission.bytes], now)?;
    }
    let mut source = [0; 128];
    while sender.deliver(&mut source, now)?.is_some() {}
    *time += 1;
    Ok(())
}
fn raw_source(
    sender: &mut delivery::Service,
    receiver: &mut Owner,
    bytes: &[u8],
    time: &mut u64,
) -> Result {
    let source = sender.submit(bytes, Duration::from_millis(*time))?;
    for _ in 0..200 {
        raw_transfer(sender, receiver, time)?;
        if sender.source_confirmed(source, Duration::from_millis(*time))? {
            return Ok(());
        }
    }
    Err("actual raw source was not acknowledged before finite fixture bound".into())
}

#[test]
fn every_receive_slot_is_filled_and_recycled_for_130_complete_windows() -> Result {
    let settings = settings();
    let mut receiver = owner(settings, 1, true)?;
    let plan = storage::Plan::for_owner(settings, binding(Role::Client), Duration::ZERO, end())?;
    let mut sender = delivery::Service::new_reserved_arq(
        settings.delivery,
        binding(Role::Client),
        Duration::ZERO,
        end(),
        l2tunnel_recovery::storage::Limits {
            capacity_bytes: plan.arq_plan().capacity_bytes(),
        },
    )?;
    let mut fragmenter =
        validate_settings(settings, binding(Role::Client), Duration::ZERO, end())?.fragmenter;
    let inventory = inventory(&receiver)?;
    let usage = receiver.storage_usage();
    let mut time = 0;
    for round in 0..130_u64 {
        let payloads = [vec![round as u8; 300], vec![(round as u8) ^ 0x55; 301]];
        let batches = [
            fragmenter.fragment(&payloads[0])?,
            fragmenter.fragment(&payloads[1])?,
        ];
        for batch in &batches {
            let mut source = vec![FRAGMENT_KIND];
            source.extend_from_slice(&batch.fragments[0]);
            raw_source(&mut sender, &mut receiver, &source, &mut time)?;
        }
        assert_eq!(receiver.retained().incomplete_messages, 2);
        assert_eq!(receiver.reassembler.reserved_bytes(), 601);
        for index in [1, 0] {
            for fragment in batches[index].fragments.iter().skip(1) {
                let mut source = vec![FRAGMENT_KIND];
                source.extend_from_slice(fragment);
                raw_source(&mut sender, &mut receiver, &source, &mut time)?;
            }
            let held = receiver
                .pending()
                .ok_or("complete actual receive window not presented")?;
            assert_eq!(held.bytes(), payloads[index]);
            let ticket = held.ticket();
            receiver.accept_with_receipt(ticket, Duration::from_millis(time))?;
            for _ in 0..10 {
                raw_transfer(&mut sender, &mut receiver, &mut time)?;
            }
        }
        assert_eq!(receiver.retained().incomplete_messages, 0);
        assert!(receiver.pending().is_none());
        assert_eq!(receiver.storage_usage(), usage);
        assert_eq!(super::storage_tests::inventory(&receiver)?, inventory);
    }
    Ok(())
}

#[test]
fn source_fifo_reserves_total_fragments_and_reuses_consumed_prefix_after_real_confirmation()
-> Result {
    let settings = settings();
    let mut sender = owner(settings, 0, true)?;
    let mut receiver = owner(settings, 1, true)?;
    let inventory = inventory(&sender)?;
    let mut time = 0;
    for round in 0..3_u64 {
        let payload = vec![round as u8; 1024];
        let cap = Duration::from_millis(time) + Duration::from_secs(2);
        let ticket = sender.submit(
            SubmissionId(round + 1),
            &payload,
            Duration::from_millis(time),
            cap,
        )?;
        for _ in 0..500 {
            let now = Duration::from_millis(time);
            sender.observe(now)?;
            sender.submit_one(now)?;
            let mut output = [0; 512];
            for _ in 0..4 {
                let Some(emission) = sender.service.poll(now, 1024, &mut output)? else {
                    break;
                };
                receiver.receive(verified(0), &output[..emission.bytes], now)?;
            }
            for _ in 0..4 {
                let Some(emission) = receiver.service.poll(now, 1024, &mut output)? else {
                    break;
                };
                sender
                    .service
                    .receive(verified(1), &output[..emission.bytes], now)?;
            }
            time += 1;
            if sender
                .outbound
                .get(0)
                .is_some_and(|entry| entry.next_fragment == entry.batch.fragments.len())
                && sender.service.retained().send_records == 0
            {
                break;
            }
        }
        let (length, consumed, capacity) = sender
            .outbound
            .source_cursor(0)
            .ok_or("missing actual source cursor")?;
        assert_eq!((length, consumed, capacity), (12, 0, 12));
        assert!(length > settings.delivery.recovery.send_records);
        for _ in 0..length {
            assert!(sender.confirm_one(Duration::from_millis(time))?);
        }
        assert_eq!(sender.outbound.source_cursor(0), Some((12, 12, 12)));
        assert!(
            !sender.confirmed(ticket, Duration::from_millis(time))?,
            "source ACKs alone are not whole confirmation"
        );
        for _ in 0..20 {
            if receiver.pending().is_some() {
                break;
            }
            receiver.tick(Duration::from_millis(time))?;
        }
        let held = receiver
            .pending()
            .ok_or("genuine full message not delivered")?;
        assert_eq!(held.bytes(), payload);
        let incoming = held.ticket();
        receiver.accept_with_receipt(incoming, Duration::from_millis(time))?;
        let mut complete = false;
        for _ in 0..200 {
            let now = Duration::from_millis(time);
            let mut packet = [0; 512];
            for side in 0..2 {
                let (from, to) = if side == 0 {
                    (&mut sender, &mut receiver)
                } else {
                    (&mut receiver, &mut sender)
                };
                for _ in 0..4 {
                    let Some(emission) = from.poll(now, 1024, &mut packet)? else {
                        break;
                    };
                    to.receive(verified(side), &packet[..emission.bytes], now)?;
                }
            }
            time += 1;
            if sender.confirmed(ticket, Duration::from_millis(time))? {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert_eq!(sender.outbound.source_cursor(0), Some((0, 0, 12)));
        sender.retire(ticket, Duration::from_millis(time))?;
        assert_eq!(super::storage_tests::inventory(&sender)?, inventory);
    }
    Ok(())
}

#[test]
fn independent_logical_byte_and_count_pressure_and_retries_are_atomic_in_both_backings() -> Result {
    for selected in [false, true] {
        let config = Settings {
            max_outbound_bytes: 470,
            ..settings()
        };
        let mut owner = owner(config, 0, selected)?;
        let cap = Duration::from_secs(2);
        let ticket = owner.submit(SubmissionId(1), &[0x51; 100], Duration::ZERO, cap)?;
        let before = owner.retained();
        assert_eq!(
            owner.submit(SubmissionId(2), &[0x52; 100], Duration::ZERO, cap),
            Err(Error::Backpressure)
        );
        assert_eq!(owner.retained(), before);
        assert_eq!(owner.last_submission, 1);
        assert_eq!(
            owner.submit(SubmissionId(1), &[0x51; 100], Duration::ZERO, cap)?,
            ticket
        );
        assert_eq!(
            owner.submit(
                SubmissionId(1),
                &[0x51; 100],
                Duration::ZERO,
                cap + Duration::from_nanos(1)
            ),
            Err(Error::ChangedSubmission)
        );
        assert_eq!(
            owner
                .submit(SubmissionId(2), b"small", Duration::ZERO, cap)?
                .message(),
            2
        );
        let mut count_owner = super::storage_tests::owner(
            Settings {
                max_outbound_messages: 1,
                ..settings()
            },
            0,
            selected,
        )?;
        count_owner.submit(SubmissionId(1), b"one", Duration::ZERO, cap)?;
        assert_eq!(
            count_owner.submit(SubmissionId(2), b"two", Duration::ZERO, cap),
            Err(Error::Backpressure)
        );
        assert_eq!(count_owner.last_submission, 1);
        let mut fragment_owner = super::storage_tests::owner(
            Settings {
                max_fragments: 2,
                ..settings()
            },
            0,
            selected,
        )?;
        let before = fragment_owner.retained();
        assert_eq!(
            fragment_owner.submit(SubmissionId(1), &[0x31; 175], Duration::ZERO, cap),
            Err(Error::Fragment(FragmentError::TooManyFragments))
        );
        assert_eq!(fragment_owner.last_submission, 0);
        assert_eq!(fragment_owner.retained(), before);
        assert_eq!(
            fragment_owner
                .submit(SubmissionId(1), &[0x31; 174], Duration::ZERO, cap)?
                .message(),
            1
        );
    }
    Ok(())
}

#[test]
fn held_acceptance_backpressure_preserves_exact_bytes_and_original_expiry_in_both_backings()
-> Result {
    for selected in [false, true] {
        let mut pair = Pair::new(settings(), selected, false)?;
        let cap = Duration::from_millis(1000);
        let ticket = pair.peers[0].submit(SubmissionId(1), b"held body", Duration::ZERO, cap)?;
        for _ in 0..200 {
            pair.step()?;
            if pair.pending(1).is_some() {
                break;
            }
        }
        let (incoming, bytes, deadline) = pair.pending(1).ok_or("no actual held custody")?;
        let now = pair.now();
        assert_eq!(bytes, b"held body");
        assert!(!pair.peers[0].confirmed(ticket, now)?);
        // Occupy every actual outgoing recovery source slot through its public
        // API; no fabricated flags or message acceptance creates the pressure.
        let now = pair.now();
        for _ in 0..3 {
            pair.peers[1].service.submit(&[0x77; 45], now)?;
        }
        assert_eq!(
            pair.peers[1].accept(incoming, now),
            Err(Error::Backpressure)
        );
        assert_eq!(pair.pending(1), Some((incoming, bytes.clone(), deadline)));
        assert_eq!(
            pair.peers[1].accept(incoming, deadline),
            Err(Error::Expired)
        );
        let snapshot = pair.peers[1].expiry_snapshot(deadline);
        assert_eq!(
            snapshot.candidate,
            Some(ExpiryCandidate {
                deadline,
                kind: ExpiryKind::Held {
                    message: incoming.message(),
                    length: bytes.len()
                },
            })
        );
        assert_eq!(snapshot.owner_error, Some(Error::Expired));
        assert_eq!(
            pair.peers[1]
                .pending()
                .ok_or("terminal hold disappeared")?
                .bytes(),
            bytes
        );
        assert_eq!(pair.peers[1].storage_usage().is_some(), selected);
    }
    Ok(())
}

#[test]
fn full_message_65536_and_last_nonwrapping_message_and_submission_ids_remain_supported() -> Result {
    let settings = Settings {
        max_message_bytes: 65_536,
        max_outbound_messages: 1,
        max_outbound_bytes: 200_000,
        max_fragments: u16::MAX,
        max_reassembly_bytes: 2 * 65_536,
        max_incomplete_messages: 1,
        ..settings()
    };
    for selected in [false, true] {
        let mut owner = owner(settings, 0, selected)?;
        let full = vec![0x65; 65_536];
        let cap = Duration::from_secs(2);
        let ticket = owner.submit(SubmissionId(1), &full, Duration::ZERO, cap)?;
        let entry = owner
            .outbound
            .get(0)
            .ok_or("missing full-message backing")?;
        assert_eq!(entry.bytes, full);
        assert_eq!(ticket.length(), 65_536);
        assert_eq!(entry.batch.fragments.len(), 754);
        let mut last = super::storage_tests::owner(settings, 0, selected)?;
        let charge = DATA_HEADER_BYTES
            + settings.delivery.recovery.max_source_bytes
            + settings.delivery.wire_overhead;
        last.fragmenter = Fragmenter::new(
            context(binding(Role::Client), Role::Client),
            FragmentConfig {
                path_mtu: charge,
                outer_overhead_bytes: settings.delivery.wire_overhead + DATA_HEADER_BYTES + 1,
                max_message_bytes: settings.max_message_bytes,
                max_fragments: settings.max_fragments,
            },
            MessageId(u64::MAX),
        )?;
        let ticket = last.submit(SubmissionId(u64::MAX), b"last", Duration::ZERO, cap)?;
        assert_eq!(ticket.message(), u64::MAX);
        assert_eq!(
            last.submit(SubmissionId(u64::MAX), b"last", Duration::ZERO, cap)?,
            ticket
        );
        assert_eq!(
            last.submit(SubmissionId(u64::MAX), b"changed", Duration::ZERO, cap),
            Err(Error::ChangedSubmission)
        );
        assert_eq!(last.tick(cap), Err(Error::Expired));
        let mut backwards = super::storage_tests::owner(settings, 0, selected)?;
        backwards.tick(Duration::from_millis(2))?;
        assert_eq!(
            backwards.tick(Duration::from_millis(1)),
            Err(Error::NonMonotonicTime)
        );
        assert_eq!(
            settings.validate(binding(Role::Client), Duration::MAX, Duration::MAX),
            Err(Error::Settings)
        );
    }
    Ok(())
}

fn encoded_source(payload: &[u8]) -> Result<Vec<u8>> {
    let mut source = delivery::Service::new(
        settings().delivery,
        binding(Role::Client),
        Duration::ZERO,
        end(),
    )?;
    source.submit(payload, Duration::ZERO)?;
    let mut output = [0; 512];
    let emitted = source
        .poll(Duration::ZERO, 1024, &mut output)?
        .ok_or("real source did not emit")?;
    Ok(output[..emitted.bytes].to_vec())
}

#[test]
fn actual_opaque_source_dispatch_preserves_binding_parser_context_and_terminal_inventory() -> Result
{
    let mut fragmenter =
        validate_settings(settings(), binding(Role::Client), Duration::ZERO, end())?.fragmenter;
    let batch = fragmenter.fragment(&[0x51; 200])?;
    let mut source = vec![FRAGMENT_KIND];
    source.extend_from_slice(&batch.fragments[0]);
    let valid = encoded_source(&source)?;
    for selected in [false, true] {
        for wrong in [
            Ingress::AuthenticatedManagement {
                session: SessionId([0x99; 16]),
                lane: LaneId(3),
                sender: Role::Client,
            },
            Ingress::AuthenticatedManagement {
                session: binding(Role::Client).session,
                lane: LaneId(4),
                sender: Role::Client,
            },
            verified(1),
        ] {
            let mut receiver = owner(settings(), 1, selected)?;
            let before = receiver.retained();
            assert_eq!(
                receiver.receive(wrong, &valid, Duration::ZERO),
                Err(Error::Delivery(delivery::Error::Binding))
            );
            assert_eq!(receiver.retained(), before);
            assert_eq!(receiver.failed, None);
            receiver.receive(verified(0), &valid, Duration::ZERO)?;
            assert_eq!(receiver.retained().incomplete_messages, 1);
        }
        let mut wrong_context = source.clone();
        wrong_context[5] ^= 0x01;
        for (body, expected) in [
            (
                vec![FRAGMENT_KIND],
                Error::Fragment(FragmentError::Truncated),
            ),
            (vec![0x7F], Error::Protocol),
            (wrong_context, Error::Fragment(FragmentError::WrongContext)),
        ] {
            let mut receiver = owner(settings(), 1, selected)?;
            let pointers = if selected {
                Some(inventory(&receiver)?)
            } else {
                None
            };
            let usage = receiver.storage_usage();
            let packet = encoded_source(&body)?;
            assert_eq!(
                receiver.receive(verified(0), &packet, Duration::ZERO),
                Err(expected)
            );
            assert_eq!(receiver.tick(Duration::from_millis(1)), Err(expected));
            assert_eq!(receiver.storage_usage(), usage);
            if let Some(pointers) = pointers {
                assert_eq!(inventory(&receiver)?, pointers);
            }
        }
    }
    Ok(())
}

#[test]
fn fragment_id_exhaustion_refuses_without_burning_a_new_submission_or_reserved_slot() -> Result {
    for selected in [false, true] {
        let settings = settings();
        let mut owner = owner(settings, 0, selected)?;
        let charge = DATA_HEADER_BYTES
            + settings.delivery.recovery.max_source_bytes
            + settings.delivery.wire_overhead;
        // Only the otherwise unreachable counter is initialized at its public
        // boundary; all bytes, geometry, admission and retained slots are real.
        owner.fragmenter = Fragmenter::new(
            context(binding(Role::Client), Role::Client),
            FragmentConfig {
                path_mtu: charge,
                outer_overhead_bytes: settings.delivery.wire_overhead + DATA_HEADER_BYTES + 1,
                max_message_bytes: settings.max_message_bytes,
                max_fragments: settings.max_fragments,
            },
            MessageId(u64::MAX),
        )?;
        assert_eq!(
            owner
                .submit(
                    SubmissionId(1),
                    b"last wire id",
                    Duration::ZERO,
                    Duration::from_secs(2)
                )?
                .message(),
            u64::MAX
        );
        let before = owner.retained();
        let pointers = if selected {
            Some(inventory(&owner)?)
        } else {
            None
        };
        assert_eq!(
            owner.submit(
                SubmissionId(2),
                b"next",
                Duration::ZERO,
                Duration::from_secs(2)
            ),
            Err(Error::Fragment(FragmentError::Exhausted))
        );
        assert_eq!(owner.last_submission, 1);
        assert_eq!(owner.retained(), before);
        if let Some(pointers) = pointers {
            assert_eq!(inventory(&owner)?, pointers);
        }
    }
    Ok(())
}

#[test]
fn complete_reserved_owner_preserves_all_existing_message_count_work_and_byte_maxima() -> Result {
    let config = Settings {
        max_outbound_messages: 64,
        max_incomplete_messages: 64,
        work_per_call: 4096,
        max_message_bytes: 65_536,
        max_fragments: u16::MAX,
        max_outbound_bytes: 16 * 1024 * 1024,
        max_reassembly_bytes: 16 * 1024 * 1024,
        ..settings()
    };
    // Preserve the existing actual delivery geometry and its three-source
    // window. Complete message capacity must not require changing those bounds.
    assert_eq!(config.delivery, settings().delivery);
    config.validate(binding(Role::Client), Duration::ZERO, end())?;
    let plan = storage::Plan::for_owner(config, binding(Role::Client), Duration::ZERO, end())?;
    let mut owner = Owner::new_reserved(
        config,
        binding(Role::Client),
        Duration::ZERO,
        end(),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = owner
        .storage_usage()
        .ok_or("missing actual maximum-owner backing")?;
    let pointers = inventory(&owner)?;
    assert_eq!(owner.settings, config);
    assert_eq!(plan.reassembly_plan().config().max_messages, 64);
    assert_eq!(
        plan.reassembly_plan().config().max_fragments_per_message,
        u16::MAX
    );
    assert_eq!(plan.reassembly_plan().config().replay_window, 65_536);
    assert_eq!(usage.limit_bytes, plan.capacity_bytes());
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(usage.arq.capacity_bytes, plan.arq_plan().capacity_bytes());
    assert_eq!(
        usage.reassembly.capacity_bytes,
        plan.reassembly_plan().capacity_bytes()
    );
    assert_eq!(
        usage.capacity_bytes,
        pointers
            .iter()
            .map(|(_, count, size)| count * size)
            .sum::<usize>()
            + usage.arq.capacity_bytes
            + usage.reassembly.capacity_bytes
    );
    assert_eq!(
        usage.allocations,
        5 + 3 * 64 + usage.arq.allocations + usage.reassembly.allocations
    );

    let body = vec![0x6D; 65_536];
    let cap = Duration::from_secs(2);
    for id in 1..=64_u64 {
        let ticket = owner.submit(SubmissionId(id), &body, Duration::ZERO, cap)?;
        assert_eq!(ticket.message(), id);
        assert_eq!(ticket.length(), body.len());
    }
    let before = owner.retained();
    assert_eq!(before.outbound_messages, 64);
    assert_eq!(before.outbound_bytes, 64 * body.len());
    let retained = before.outbound_bytes + before.outbound_fragment_bytes;
    assert!(
        retained
            + 2 * body.len()
            + FRAGMENT_HEADER_BYTES * body.len().div_ceil(owner.fragmenter.chunk_bytes())
            < config.max_outbound_bytes,
        "the next complete message fits the byte budget, isolating count pressure"
    );
    let tickets: Vec<_> = owner.outbound.iter().map(|entry| entry.ticket).collect();
    assert_eq!(
        owner.submit(SubmissionId(65), &body, Duration::ZERO, cap),
        Err(Error::Backpressure)
    );
    assert_eq!(owner.last_submission, 64);
    assert_eq!(owner.retained(), before);
    assert_eq!(
        owner
            .outbound
            .iter()
            .map(|entry| entry.ticket)
            .collect::<Vec<_>>(),
        tickets
    );
    assert_eq!(owner.storage_usage(), Some(usage));
    assert_eq!(inventory(&owner)?, pointers);
    // Observe the next ID through the actual Fragmenter API after the refusal.
    // This final local witness is not submitted or treated as delivery custody.
    assert_eq!(
        owner
            .fragmenter
            .fragment(b"next unused wire identity")?
            .message,
        MessageId(65)
    );
    Ok(())
}
