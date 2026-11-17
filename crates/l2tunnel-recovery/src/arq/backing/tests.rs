use super::*;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn send_slots() -> Vec<SendSlot> {
    (0..4)
        .map(|_| SendSlot {
            source: None,
            flight: Flight {
                prepared_at: Duration::ZERO,
                transmission: 0,
                acknowledged: false,
                payload: Vec::with_capacity(8),
                attempts: 0,
                retry_at: None,
                rto: Duration::ZERO,
            },
        })
        .collect()
}

#[test]
fn send_occupancy_preserves_refusal_retirement_and_slot_reuse() -> Result {
    for mut sent in [
        Sent::Reserved(send_slots(), 0),
        Sent::Indexed(send_slots(), 0),
    ] {
        assert!(sent.is_empty());
        for source in 0..4 {
            sent.insert_payload(SourceId(source), &[source as u8], Duration::ZERO)?;
        }
        assert_eq!(sent.len(), 4);
        assert!(matches!(
            sent.insert_payload(SourceId(4), &[4], Duration::ZERO),
            Err(RecoveryError::Capacity(BufferSide::Send))
        ));
        assert_eq!(sent.len(), 4);
        sent.remove(&SourceId(2));
        sent.remove(&SourceId(2));
        sent.remove(&SourceId(99));
        assert_eq!(sent.len(), 3);
        assert!(matches!(
            sent.insert_payload(SourceId(6), &[0; 9], Duration::ZERO),
            Err(RecoveryError::Capacity(BufferSide::Send))
        ));
        assert_eq!(sent.len(), 3);
        sent.insert_payload(SourceId(6), &[6], Duration::ZERO)?;
        assert_eq!(sent.len(), 4);
        sent.retain(|source, flight| {
            flight.acknowledged = true;
            source.0 % 2 == 1
        });
        assert_eq!(sent.len(), 2);
        assert!(sent.get(&SourceId(0)).is_none());
        assert!(sent.get(&SourceId(6)).is_none());
        assert_eq!(
            sent.get(&SourceId(1)).map(|flight| &flight.payload[..]),
            Some(&[1][..])
        );
        assert!(sent.values().all(|flight| flight.acknowledged));
        sent.retain(|_, _| false);
        sent.retain(|_, _| false);
        assert!(sent.is_empty());
        sent.insert_payload(SourceId(10), &[10], Duration::ZERO)?;
        assert_eq!(sent.len(), 1);
    }
    Ok(())
}

#[test]
fn receive_occupancy_preserves_refusal_and_repeated_retirement() -> Result {
    let slots = || {
        (0..4)
            .map(|_| ReceiveSlot {
                source: None,
                payload: Vec::with_capacity(8),
            })
            .collect()
    };
    for mut received in [
        Received::Reserved(slots(), 0),
        Received::Indexed(slots(), 0),
    ] {
        assert!(received.is_empty());
        for source in 0..4 {
            received.insert_payload(SourceId(source), &[source as u8])?;
        }
        assert_eq!(received.len(), 4);
        assert!(matches!(
            received.insert_payload(SourceId(4), &[4]),
            Err(RecoveryError::Capacity(BufferSide::Receive))
        ));
        assert_eq!(received.len(), 4);
        received.remove(&SourceId(2));
        received.remove(&SourceId(2));
        received.remove(&SourceId(99));
        assert_eq!(received.len(), 3);
        assert!(matches!(
            received.insert_payload(SourceId(6), &[0; 9]),
            Err(RecoveryError::Capacity(BufferSide::Receive))
        ));
        assert_eq!(received.len(), 3);
        received.insert_payload(SourceId(6), &[6])?;
        assert_eq!(received.len(), 4);
        assert_eq!(
            received.get(&SourceId(6)).map(Vec::as_slice),
            Some(&[6][..])
        );
        for source in [0, 1, 3, 6] {
            received.remove(&SourceId(source));
        }
        assert!(received.is_empty());
        received.insert_payload(SourceId(10), &[10])?;
        assert_eq!(received.len(), 1);
    }
    Ok(())
}
