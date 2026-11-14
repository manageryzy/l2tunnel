//! An inconsistent authenticated barrier must not discard incomplete native bytes.

use super::*;

fn initial_data() -> TestResult<Data> {
    let mut records = config(1);
    records.codec.datagram_bytes = 256;
    let direction = Direction {
        records,
        bytes_per_second: 3_000_000,
    };
    Ok(Data {
        records: records::Engine::new(records)?,
        next: RecordNumber(0x1_0000_0100),
        send: direction,
        receive: direction,
        fail_send: false,
        fail_receive: false,
    })
}

fn inconsistent_barrier_preserves_partial_native(prefix: bool) -> TestResult {
    let mut owner = coordinator(Authority::Coordinator, 4)?;
    let mut data = initial_data()?;
    let mut sender = initial_data()?;
    let before_partial = vec![0x6d; 244];
    let incomplete = vec![0xa7; 400];

    // The literal tag plus length prefix make the first packet 247 bytes.
    // A 248-byte source therefore carries one byte of the next length prefix.
    if prefix {
        assert_eq!(
            sender.records.offer(0, &before_partial)?,
            records::Admission::Accepted
        );
    }
    assert_eq!(
        sender.records.offer(0, &incomplete)?,
        records::Admission::Accepted
    );
    let (number, mut first) = sender.packet(0)?.ok_or(Fault::Protocol)?;
    assert_eq!(first[0], crate::KIND_SOURCE);
    assert_eq!(first.len(), crate::SOURCE_HEADER + 248);
    data.records.accept(0, number, &mut first)?;
    if prefix {
        assert_eq!(data.records.pop()?, Some(before_partial.as_slice()));
    }
    assert_eq!(data.records.pop()?, None);
    assert!(!data.records.deliverable());
    let channel = data.records.channel_stats(0).ok_or(Fault::Protocol)?;
    assert_eq!(channel.receive_pending, 0);
    assert_eq!(channel.receive.ok_or(Fault::Protocol)?.sources, 1);
    assert!(
        sender
            .records
            .channel_stats(0)
            .ok_or(Fault::Protocol)?
            .send
            .ok_or(Fault::Protocol)?
            .queued_bytes
            > 0
    );
    assert!(!sender.records.send_drained());

    begin(&mut owner, &mut data, 10)?;
    // This is deliberately inconsistent peer control: an honest sender cannot
    // finish draining while its native suffix is still queued and unconfirmed.
    owner.receive(
        Time(11),
        Message::Barrier {
            epoch: 1,
            first_number: sender.next.0,
        },
        |_| None,
        &mut data,
    )?;
    let deadline = owner.deadline();
    let pending = owner.pending();
    let config = data.records.receive_config();
    let source_floor = data.records.source_floor();
    let feedback_floor = data.records.feedback_floor();
    let stats = data.records.stats();
    let receive = data.receive;

    // Assert the coordinator decision first: the old source-debt-only predicate
    // instead resets reception and emits BarrierAck for this genuine partial.
    assert_eq!(
        owner.progress(Time(12), &mut data),
        Err(Error::Fault(Fault::Protocol))
    );
    assert_eq!(owner.deadline(), deadline);
    assert_eq!(owner.pending(), pending);
    assert_eq!(owner.committed().epoch, Epoch(0));
    assert_eq!(owner.take_outcome(), None);
    assert!(
        owner
            .outstanding()
            .all(|outbound| !matches!(outbound.message, Message::BarrierAck { .. }))
    );
    assert_eq!(data.records.receive_config(), config);
    assert_eq!(data.records.source_floor(), source_floor);
    assert_eq!(data.records.feedback_floor(), feedback_floor);
    assert_eq!(data.records.stats(), stats);
    assert_eq!(data.receive, receive);
    assert!(!data.records.receive_drained());

    // Exercise the retained record engine directly after the coordinator error;
    // a runtime must terminate that protocol fault rather than resume switching.
    let mut recovered = Vec::new();
    for now in 13..=15 {
        if let Some((number, mut body)) = sender.packet(now)? {
            data.records.accept(now, number, &mut body)?;
        }
        while let Some(packet) = data.records.pop()? {
            recovered.push(packet.to_vec());
        }
    }
    assert_eq!(recovered, vec![incomplete]);
    assert_eq!(data.records.pop()?, None);
    assert!(data.records.receive_drained());
    assert_eq!(data.records.receive_config(), config);
    assert_eq!(data.records.source_floor(), source_floor);
    assert_eq!(data.records.feedback_floor(), feedback_floor);
    assert_eq!(data.receive, receive);
    Ok(())
}

#[test]
fn actual_policy_hooks_reject_barrier_over_partial_native_prefix() -> TestResult {
    inconsistent_barrier_preserves_partial_native(true)
}

#[test]
fn actual_policy_hooks_reject_barrier_over_partial_native_payload() -> TestResult {
    inconsistent_barrier_preserves_partial_native(false)
}
