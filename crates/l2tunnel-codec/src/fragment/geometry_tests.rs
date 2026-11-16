use super::*;

#[test]
fn checked_geometry_matches_literal_one_two_many_and_actual_flat_wire_without_ids() -> Result {
    let config = FragmentConfig {
        path_mtu: 100,
        outer_overhead_bytes: 44,
        max_message_bytes: 128,
        max_fragments: 8,
    };
    let mut sender = Fragmenter::new(context(), config, MessageId(9))?;
    for (length, count, encoded, wire) in [
        (1, 1, 41, 85),
        (16, 1, 56, 100),
        (17, 2, 97, 185),
        (65, 5, 265, 485),
    ] {
        let geometry = config.geometry(length)?;
        assert_eq!(sender.geometry(length)?, geometry);
        assert_eq!(geometry.logical_bytes(), length);
        assert_eq!(geometry.chunk_bytes(), 16);
        assert_eq!(geometry.fragments(), count);
        assert_eq!(geometry.encoded_bytes(), encoded);
        assert_eq!(geometry.wire_bytes(), wire);
        assert_eq!(sender.next_message, Some(MessageId(9)));
        let body = vec![0x5a; length];
        let mut output = vec![0xa5; encoded + 1];
        let batch = sender.fragment_into(&body, &mut output)?;
        assert_eq!(batch.message(), MessageId(9));
        assert_eq!(batch.len(), count);
        assert_eq!(batch.encoded().len(), encoded);
        let mut total = 0;
        let mut restored = Vec::new();
        for index in 0..count {
            let fragment = batch.fragment(index).ok_or("actual fragment")?;
            assert_eq!(
                geometry.fragment_range(index),
                batch.layout().fragment_range(index)
            );
            assert_eq!(&fragment[..4], b"LX\x01\x00");
            assert_eq!(&fragment[34..36], &u16::try_from(count)?.to_be_bytes());
            assert_eq!(&fragment[36..38], &[0, 16]);
            assert!(fragment.len() + 44 <= 100);
            total += fragment.len() + 44;
            restored.extend_from_slice(&fragment[40..]);
        }
        assert_eq!(total, wire);
        assert_eq!(restored, body);
        assert_eq!(geometry.fragment_range(count), None);
        assert_eq!(geometry.fragment_range(usize::MAX), None);
        assert_eq!(output[encoded], 0xa5);
        assert_eq!(sender.next_message, Some(MessageId(10)));
        sender = Fragmenter::new(context(), config, MessageId(9))?;
    }
    Ok(())
}

#[test]
fn geometry_refusals_never_assign_ids_and_legacy_encoding_keeps_aggregate_overflow_behavior()
-> Result {
    let config = FragmentConfig {
        path_mtu: 100,
        outer_overhead_bytes: 44,
        max_message_bytes: 128,
        max_fragments: 2,
    };
    let mut sender = Fragmenter::new(context(), config, MessageId(u64::MAX))?;
    assert_eq!(sender.geometry(0), Err(FragmentError::EmptyMessage));
    assert_eq!(sender.geometry(129), Err(FragmentError::MessageTooLarge));
    assert_eq!(sender.geometry(33), Err(FragmentError::TooManyFragments));
    assert_eq!(sender.next_message, Some(MessageId(u64::MAX)));
    let mut short = [0xa5; 40];
    assert!(matches!(
        sender.fragment_into(&[3], &mut short),
        Err(FragmentError::OutputTooSmall)
    ));
    assert_eq!(short, [0xa5; 40]);
    assert_eq!(sender.next_message, Some(MessageId(u64::MAX)));
    let last = sender.fragment(&[3])?;
    assert_eq!(last.message, MessageId(u64::MAX));
    assert_eq!(sender.next_message, None);
    assert_eq!(sender.geometry(1)?.wire_bytes(), 85);
    assert_eq!(sender.fragment(&[3]), Err(FragmentError::Exhausted));
    assert_eq!(
        FragmentConfig {
            max_fragments: 0,
            ..config
        }
        .geometry(1),
        Err(FragmentError::InvalidConfig)
    );
    assert_eq!(
        FragmentConfig {
            path_mtu: 84,
            ..config
        }
        .geometry(1),
        Err(FragmentError::MtuTooSmall)
    );
    assert_eq!(
        FragmentConfig {
            outer_overhead_bytes: usize::MAX,
            ..config
        }
        .geometry(1),
        Err(FragmentError::Arithmetic)
    );
    // Existing encoding needs each packet to fit; aggregate outer accounting is
    // additive and must not change that old behavior on synthetic extreme limits.
    let extreme = FragmentConfig {
        path_mtu: usize::MAX,
        outer_overhead_bytes: usize::MAX - 41,
        max_message_bytes: 2,
        max_fragments: 2,
    };
    let mut old = Fragmenter::new(context(), extreme, MessageId(4))?;
    assert_eq!(old.chunk_bytes(), 1);
    assert_eq!(old.geometry(2), Err(FragmentError::Arithmetic));
    let encoded = old.fragment(&[1, 2])?;
    assert_eq!(encoded.fragments.len(), 2);
    assert!(
        encoded
            .fragments
            .iter()
            .all(|fragment| fragment.len() == 41)
    );
    assert_eq!(old.next_message, Some(MessageId(5)));
    Ok(())
}
