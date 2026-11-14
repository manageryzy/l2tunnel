use super::*;
use std::collections::BTreeMap;

mod partial_drain;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config(channels: usize) -> records::Config {
    records::Config {
        codec: crate::Config {
            datagram_bytes: 512,
            window: 8,
            repair_numerator: 0,
            repair_denominator: 1000,
            flow_sources: 128,
            queue_bytes: 64 * 1024,
            max_packet: 901,
            flush_micros: 0,
            feedback_micros: 100,
            tail_micros: 1_000,
            min_rto_micros: 1_000,
            max_rto_micros: 10_000,
        },
        channels,
        layer: records::Layer::Ip,
        max_native: 900,
    }
}
fn public_policy() -> Policy {
    Policy {
        path_mtu: 600,
        forward_kbit: 16_000,
        reverse_kbit: 8_000,
        channels: 2,
        window: 8,
        repair_permille: 0,
    }
}
fn resolved(client: bool) -> Resolved {
    let forward = Direction {
        records: config(2),
        bytes_per_second: 2_000_000,
    };
    let reverse = Direction {
        records: config(2),
        bytes_per_second: 1_000_000,
    };
    Resolved {
        send: if client { forward } else { reverse },
        receive: if client { reverse } else { forward },
        digest: Digest([7; 32]),
    }
}
fn coordinator(authority: Authority, max_outbound: usize) -> Result<Coordinator, Fault> {
    Coordinator::new(
        authority,
        Committed {
            epoch: Epoch(0),
            policy: None,
        },
        Settings {
            transaction_micros: 100_000,
            max_outbound,
        },
        Time(0),
    )
}
struct Data {
    records: records::Engine,
    next: RecordNumber,
    send: Direction,
    receive: Direction,
    fail_send: bool,
    fail_receive: bool,
}
impl Data {
    fn new() -> Result<Self, records::Error> {
        let initial = Direction {
            records: config(4),
            bytes_per_second: 3_000_000,
        };
        Ok(Self {
            records: records::Engine::new(initial.records)?,
            next: RecordNumber(0x1_0000_0100),
            send: initial,
            receive: initial,
            fail_send: false,
            fail_receive: false,
        })
    }
    fn packet(&mut self, now: u64) -> TestResult<Option<(RecordNumber, Vec<u8>)>> {
        let number = self.next;
        let Some(body) = self.records.poll(now, number, true)? else {
            return Ok(None);
        };
        let body = body.to_vec();
        self.next.0 = self.next.0.checked_add(1).ok_or(Fault::CounterExhausted)?;
        Ok(Some((number, body)))
    }
}
impl Hooks for Data {
    type Error = records::Error;
    fn status(&self) -> Status {
        Status {
            send_drained: self.records.send_drained(),
            receive_deliverable: self.records.deliverable(),
            receive_drained: self.records.receive_drained(),
            next_number: self.next,
        }
    }
    fn replace_send(
        &mut self,
        _now: Time,
        policy: Direction,
        feedback_from: RecordNumber,
    ) -> Result<(), Self::Error> {
        if self.fail_send {
            return Err(records::Error::NotDrained);
        }
        self.records.replace_send(policy.records, feedback_from)?;
        self.send = policy;
        Ok(())
    }
    fn replace_receive(
        &mut self,
        policy: Direction,
        source_from: RecordNumber,
    ) -> Result<(), Self::Error> {
        if self.fail_receive {
            return Err(records::Error::NotDrained);
        }
        self.records.replace_receive(policy.records, source_from)?;
        self.receive = policy;
        Ok(())
    }
}
fn complete(owner: &mut Coordinator, now: u64) -> TestResult<Message> {
    let output = owner.outbound().ok_or(Fault::Ownership)?;
    owner.complete_outbound(Time(now), output.id)?;
    Ok(output.message)
}
fn deliver(
    from: &mut Coordinator,
    to: &mut Coordinator,
    data: &mut Data,
    now: u64,
    client: bool,
) -> TestResult {
    while let Some(output) = from.outbound() {
        to.receive(Time(now), output.message, |_| Some(resolved(client)), data)?;
        from.complete_outbound(Time(now), output.id)?;
    }
    Ok(())
}
fn begin(owner: &mut Coordinator, data: &mut Data, now: u64) -> TestResult {
    owner
        .request(Time(now), public_policy(), Some(resolved(true)))
        .map_err(|_| Fault::Configuration)?;
    complete(owner, now)?;
    owner.receive(
        Time(now),
        Message::Accept {
            epoch: 1,
            digest: resolved(true).digest.0,
        },
        |_| None,
        data,
    )?;
    Ok(())
}

#[test]
fn actual_record_engines_cross_directional_barriers_under_loss_without_counter_reset() -> TestResult
{
    let mut left = coordinator(Authority::Coordinator, 8)?;
    let mut right = coordinator(Authority::Participant, 8)?;
    let mut left_data = Data::new()?;
    let mut right_data = Data::new()?;
    let expected: Vec<Vec<u8>> = (0..24_u8)
        .map(|id| {
            let mut packet = vec![id; 600];
            packet[..4].copy_from_slice(&u32::from(id).to_be_bytes());
            packet[598..].fill(0);
            packet
        })
        .collect();
    for packet in &expected {
        assert_eq!(
            left_data.records.offer(0, packet)?,
            records::Admission::Accepted
        );
        assert_eq!(
            right_data.records.offer(0, packet)?,
            records::Admission::Accepted
        );
    }
    let (mut received_left, mut received_right) = (Vec::new(), Vec::new());
    let mut attempts = 0_u64;
    for tick in 0..500_u64 {
        let now = tick * 100;
        if tick == 1 {
            left.request(Time(now), public_policy(), Some(resolved(true)))
                .map_err(|_| Fault::Configuration)?;
        }
        left.progress(Time(now), &mut left_data)?;
        right.progress(Time(now), &mut right_data)?;
        deliver(&mut left, &mut right, &mut right_data, now, false)?;
        deliver(&mut right, &mut left, &mut left_data, now, true)?;
        for forward in [true, false] {
            let (from, to, received) = if forward {
                (&mut left_data, &mut right_data, &mut received_right)
            } else {
                (&mut right_data, &mut left_data, &mut received_left)
            };
            while let Some((number, mut body)) = from.packet(now)? {
                attempts += 1;
                if !attempts.is_multiple_of(7) {
                    to.records.accept(now, number, &mut body)?;
                }
            }
            while let Some(packet) = to.records.pop()? {
                received.push(packet.to_vec());
            }
        }
        if left.committed().epoch == Epoch(1)
            && right.committed().epoch == Epoch(1)
            && left_data.records.send_drained()
            && right_data.records.send_drained()
        {
            break;
        }
    }
    let counts = |packets: &[Vec<u8>]| {
        let mut counts = BTreeMap::new();
        for packet in packets {
            *counts.entry(packet.clone()).or_insert(0) += 1;
        }
        counts
    };
    assert_eq!(counts(&received_left), counts(&expected));
    assert_eq!(counts(&received_right), counts(&expected));
    assert_eq!(left.take_outcome(), Some(Outcome::Applied(Epoch(1))));
    for (owner, data, client) in [(&left, &left_data, true), (&right, &right_data, false)] {
        assert_eq!(owner.committed().epoch, Epoch(1));
        assert_eq!(data.send, resolved(client).send);
        assert_eq!(data.receive, resolved(client).receive);
        assert!(data.next.0 > 0x1_0000_0100);
        assert!(data.records.source_floor().0 > 0x1_0000_0100);
        assert!(data.records.feedback_floor().0 > 0x1_0000_0100);
        assert!(data.records.stats().sender.retransmits > 0);
        assert_eq!(data.records.stats().native_read, expected.len() as u64);
    }
    Ok(())
}

#[test]
fn proposal_and_barrier_silence_keep_the_original_total_deadline() -> TestResult {
    for agreed in [false, true] {
        let mut owner = coordinator(Authority::Coordinator, 4)?;
        let mut data = Data::new()?;
        owner
            .request(Time(10), public_policy(), Some(resolved(true)))
            .map_err(|_| Fault::Configuration)?;
        let deadline = owner.deadline().ok_or(Fault::Deadline)?;
        assert!(owner.admission_allowed());
        let token = owner.outbound().ok_or(Fault::Ownership)?;
        for _ in 0..100 {
            assert_eq!(owner.outbound(), Some(token));
        }
        complete(&mut owner, 10)?;
        if agreed {
            owner.receive(
                Time(deadline.0 - 2),
                Message::Accept {
                    epoch: 1,
                    digest: resolved(true).digest.0,
                },
                |_| None,
                &mut data,
            )?;
            owner.progress(Time(deadline.0 - 1), &mut data)?;
            assert!(!owner.admission_allowed());
            assert!(matches!(
                owner.outbound().map(|output| output.message),
                Some(Message::Barrier { .. })
            ));
        } else {
            let packet = [9, 0, 0];
            assert_eq!(
                data.records.offer(20, &packet)?,
                records::Admission::Accepted
            );
            let (number, mut body) = data.packet(20)?.ok_or(Fault::Protocol)?;
            let mut peer = Data::new()?;
            peer.records.accept(20, number, &mut body)?;
            assert_eq!(peer.records.pop()?, Some(packet.as_slice()));
            owner.progress(Time(deadline.0 - 1), &mut data)?;
        }
        assert_eq!(owner.deadline(), Some(deadline));
        assert_eq!(
            owner.progress(deadline, &mut data),
            Err(Error::Fault(Fault::Deadline))
        );
        assert_eq!(owner.committed().epoch, Epoch(0));
        assert_eq!(owner.take_outcome(), None);
    }
    Ok(())
}

#[test]
fn duplicate_proposals_never_renew_real_receive_flushing_or_re_resolve() -> TestResult {
    let mut owner = coordinator(Authority::Participant, 4)?;
    let mut data = Data::new()?;
    let mut sender = Data::new()?;
    assert_eq!(
        sender.records.offer(0, &[0, 1, 0, 0])?,
        records::Admission::Accepted
    );
    let (number, mut body) = sender.packet(0)?.ok_or(Fault::Protocol)?;
    data.records.accept(0, number, &mut body)?;
    let proposal = Message::Propose {
        epoch: 1,
        policy: public_policy(),
    };
    owner.receive(Time(10), proposal, |_| Some(resolved(false)), &mut data)?;
    let original = owner.outbound();
    owner.receive(Time(11), proposal, |_| None, &mut data)?;
    assert_eq!(owner.outbound(), original);
    assert_eq!(owner.outstanding().count(), 1);
    owner.receive(
        Time(12),
        Message::Barrier {
            epoch: 1,
            first_number: sender.next.0,
        },
        |_| None,
        &mut data,
    )?;
    let deadline = owner.deadline().ok_or(Fault::Deadline)?;
    owner.progress(Time(deadline.0 - 1), &mut data)?;
    owner.receive(Time(deadline.0 - 1), proposal, |_| None, &mut data)?;
    assert_eq!(owner.deadline(), Some(deadline));
    assert!(matches!(
        owner.pending().map(|pending| pending.receive),
        Some(ReceivePhase::Flushing { .. })
    ));
    assert_eq!(
        owner.progress(deadline, &mut data),
        Err(Error::Fault(Fault::Deadline))
    );
    assert_eq!(data.records.pop()?, Some([0, 1, 0, 0].as_slice()));
    assert_eq!(owner.committed().epoch, Epoch(0));
    Ok(())
}

#[test]
fn final_output_custody_blocks_commit_and_expiry_never_rolls_back_directional_work() -> TestResult {
    for expire in [false, true] {
        let mut owner = coordinator(Authority::Coordinator, 4)?;
        let mut data = Data::new()?;
        begin(&mut owner, &mut data, 10)?;
        owner.receive(
            Time(11),
            Message::Barrier {
                epoch: 1,
                first_number: 0x1_0000_0200,
            },
            |_| None,
            &mut data,
        )?;
        owner.progress(Time(12), &mut data)?;
        assert!(matches!(complete(&mut owner, 12)?, Message::Barrier { .. }));
        owner.receive(
            Time(13),
            Message::BarrierAck {
                epoch: 1,
                feedback_from: 0x1_0000_0300,
            },
            |_| None,
            &mut data,
        )?;
        owner.progress(Time(14), &mut data)?;
        let terminal = owner.outbound().ok_or(Fault::Ownership)?;
        assert!(matches!(terminal.message, Message::BarrierAck { .. }));
        assert_eq!(owner.committed().epoch, Epoch(0));
        assert_eq!(owner.take_outcome(), None);
        let deadline = owner.deadline().ok_or(Fault::Deadline)?;
        if expire {
            assert_eq!(
                owner.complete_outbound(deadline, terminal.id),
                Err(Fault::Deadline)
            );
            assert_eq!(owner.outbound(), Some(terminal));
            assert_eq!(
                owner.progress(deadline, &mut data),
                Err(Error::Fault(Fault::Deadline))
            );
            assert_eq!(owner.committed().epoch, Epoch(0));
            assert_eq!(owner.take_outcome(), None);
        } else {
            owner.complete_outbound(Time(deadline.0 - 1), terminal.id)?;
            owner.complete_outbound(Time(deadline.0 - 1), terminal.id)?;
            owner.progress(Time(deadline.0 - 1), &mut data)?;
            assert_eq!(owner.take_outcome(), Some(Outcome::Applied(Epoch(1))));
            assert!(owner.pending().is_none());
        }
        assert_eq!(data.send, resolved(true).send);
        assert_eq!(data.receive, resolved(true).receive);
        assert_eq!(data.records.source_floor(), RecordNumber(0x1_0000_0200));
        assert_eq!(data.records.feedback_floor(), RecordNumber(0x1_0000_0300));
    }
    Ok(())
}

#[test]
fn failed_hooks_preserve_error_and_do_not_publish_done_or_applied() -> TestResult {
    for send in [false, true] {
        let mut owner = coordinator(Authority::Coordinator, 4)?;
        let mut data = Data::new()?;
        begin(&mut owner, &mut data, 0)?;
        if send {
            owner.progress(Time(1), &mut data)?;
            data.fail_send = true;
            assert_eq!(
                owner.receive(
                    Time(2),
                    Message::BarrierAck {
                        epoch: 1,
                        feedback_from: 8
                    },
                    |_| None,
                    &mut data
                ),
                Err(Error::Apply(records::Error::NotDrained))
            );
            assert_eq!(
                owner.pending().map(|pending| pending.send),
                Some(SendPhase::Barrier)
            );
        } else {
            owner.receive(
                Time(1),
                Message::Barrier {
                    epoch: 1,
                    first_number: 8,
                },
                |_| None,
                &mut data,
            )?;
            data.fail_receive = true;
            assert_eq!(
                owner.progress(Time(2), &mut data),
                Err(Error::Apply(records::Error::NotDrained))
            );
            assert!(matches!(
                owner.pending().map(|pending| pending.receive),
                Some(ReceivePhase::Flushing { .. })
            ));
            assert!(
                owner
                    .outstanding()
                    .all(|output| !matches!(output.message, Message::BarrierAck { .. }))
            );
        }
        assert_eq!(owner.committed().epoch, Epoch(0));
        assert_eq!(owner.take_outcome(), None);
    }
    Ok(())
}

#[test]
fn bounded_tokens_apply_backpressure_and_require_exact_completion_order() -> TestResult {
    let mut owner = coordinator(Authority::Participant, 1)?;
    let mut data = Data::new()?;
    owner.receive(
        Time(0),
        Message::Propose {
            epoch: 1,
            policy: public_policy(),
        },
        |_| Some(resolved(false)),
        &mut data,
    )?;
    owner.receive(
        Time(1),
        Message::Barrier {
            epoch: 1,
            first_number: 8,
        },
        |_| None,
        &mut data,
    )?;
    owner.progress(Time(2), &mut data)?;
    assert_eq!(
        owner.pending().map(|pending| pending.send),
        Some(SendPhase::Draining)
    );
    let accepted = owner.outbound().ok_or(Fault::Ownership)?;
    assert_eq!(
        owner.complete_outbound(Time(2), OutboundId(accepted.id.0 + 1)),
        Err(Fault::Ownership)
    );
    owner.complete_outbound(Time(3), accepted.id)?;
    owner.progress(Time(4), &mut data)?;
    assert!(matches!(
        owner.outbound().map(|output| output.message),
        Some(Message::Barrier { .. })
    ));
    assert!(matches!(
        owner.pending().map(|pending| pending.receive),
        Some(ReceivePhase::Flushing { .. })
    ));
    complete(&mut owner, 5)?;
    owner.progress(Time(6), &mut data)?;
    assert!(matches!(
        owner.outbound().map(|output| output.message),
        Some(Message::BarrierAck { .. })
    ));
    assert_eq!(owner.outstanding().count(), 1);
    assert_eq!(
        owner.complete_outbound(Time(6), OutboundId(0)),
        Err(Fault::Ownership)
    );
    Ok(())
}

#[test]
fn malformed_state_digest_capacity_clock_and_integer_limits_are_explicit() -> TestResult {
    let mut data = Data::new()?;
    let mut owner = coordinator(Authority::Coordinator, 2)?;
    assert!(matches!(
        owner.receive(
            Time(0),
            Message::BarrierAck {
                epoch: 1,
                feedback_from: 0
            },
            |_| None,
            &mut data
        ),
        Err(Error::Fault(Fault::Protocol))
    ));
    owner
        .request(Time(10), public_policy(), Some(resolved(true)))
        .map_err(|_| Fault::Configuration)?;
    assert_eq!(
        owner.receive(
            Time(11),
            Message::Accept {
                epoch: 1,
                digest: [8; 32]
            },
            |_| None,
            &mut data
        ),
        Err(Error::Fault(Fault::Digest))
    );
    assert_eq!(owner.check(Time(9)), Err(Fault::NonMonotonicTime));
    let mut owner = coordinator(Authority::Participant, 1)?;
    owner.receive(
        Time(0),
        Message::Propose {
            epoch: 7,
            policy: public_policy(),
        },
        |_| None,
        &mut data,
    )?;
    let before = owner.outbound();
    assert_eq!(
        owner.receive(
            Time(1),
            Message::Propose {
                epoch: 8,
                policy: public_policy()
            },
            |_| None,
            &mut data
        ),
        Err(Error::Fault(Fault::Capacity))
    );
    assert_eq!(owner.outbound(), before);
    assert!(owner.pending().is_none());
    for (timeout, maximum) in [(0, 1), (1, 0), (1, 65)] {
        assert!(matches!(
            Coordinator::new(
                Authority::Coordinator,
                Committed {
                    epoch: Epoch(0),
                    policy: None
                },
                Settings {
                    transaction_micros: timeout,
                    max_outbound: maximum
                },
                Time(0)
            ),
            Err(Fault::Configuration)
        ));
    }
    let mut owner = coordinator(Authority::Coordinator, 1)?;
    assert_eq!(
        owner.request(Time(u64::MAX), public_policy(), Some(resolved(true))),
        Err(RequestError::Invalid)
    );
    assert!(owner.pending().is_none() && owner.outbound().is_none());
    let mut owner = Coordinator::new(
        Authority::Coordinator,
        Committed {
            epoch: Epoch(u64::MAX),
            policy: None,
        },
        Settings {
            transaction_micros: 1,
            max_outbound: 1,
        },
        Time(0),
    )?;
    assert_eq!(
        owner.request(Time(0), public_policy(), Some(resolved(true))),
        Err(RequestError::Invalid)
    );
    let mut owner = coordinator(Authority::Coordinator, 1)?;
    owner.next_output = Some(u64::MAX);
    owner
        .request(Time(0), public_policy(), Some(resolved(true)))
        .map_err(|_| Fault::Configuration)?;
    assert_eq!(
        owner.outbound().map(|output| output.id),
        Some(OutboundId(u64::MAX))
    );
    complete(&mut owner, 0)?;
    owner.receive(
        Time(0),
        Message::Accept {
            epoch: 1,
            digest: resolved(true).digest.0,
        },
        |_| None,
        &mut data,
    )?;
    assert_eq!(
        owner.progress(Time(1), &mut data),
        Err(Error::Fault(Fault::CounterExhausted))
    );
    assert_eq!(
        owner.pending().map(|pending| pending.send),
        Some(SendPhase::Draining)
    );
    Ok(())
}
