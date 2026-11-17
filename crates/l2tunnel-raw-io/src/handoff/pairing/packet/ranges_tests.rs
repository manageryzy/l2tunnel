use super::*;

#[test]
fn every_other_byte_in_maximum_horizon_is_representable_without_allocation() -> Result<(), Error> {
    let horizon = 1_048_576u32;
    let mut ranges = Ranges::new(horizon)?;
    let pointer = ranges.words.as_ptr();
    let capacity = ranges.capacity_bytes();
    assert_eq!(capacity, 131_072);
    assert_eq!(capacity, Ranges::planned_capacity_bytes(horizon)?);
    for start in (0..u64::from(horizon)).step_by(2) {
        ranges.commit(start, start + 1, start + 1, u64::from(horizon))?;
    }
    assert_eq!(ranges.occupied_bytes(), u64::from(horizon / 2));
    for index in (0..horizon / 2).rev() {
        let start = u64::from(index) * 2 + 1;
        ranges.commit(start, start + 1, start + 1, u64::from(horizon))?;
    }
    assert_eq!(ranges.occupied_bytes(), u64::from(horizon));
    assert_eq!(ranges.words.as_ptr(), pointer);
    assert_eq!(ranges.capacity_bytes(), capacity);
    assert!(matches!(
        ranges.validate(0, 1, u64::from(horizon), u64::from(horizon)),
        Err(Error::Proof)
    ));
    Ok(())
}

#[test]
fn overlap_and_adjacency_are_exact_across_word_boundaries() -> Result<(), Error> {
    let mut ranges = Ranges::new(256)?;
    ranges.commit(63, 65, 65, 256)?;
    ranges.commit(128, 192, 192, 256)?;
    for (start, end) in [(62, 64), (64, 66), (0, 256), (127, 129), (191, 193)] {
        assert!(matches!(
            ranges.commit(start, end, end.max(192), 256),
            Err(Error::Proof)
        ));
    }
    ranges.commit(65, 128, 128, 256)?;
    ranges.commit(0, 63, 63, 256)?;
    ranges.commit(192, 256, 256, 256)?;
    assert_eq!(ranges.occupied_bytes(), 256);
    assert_eq!(ranges.retired, 256);
    Ok(())
}

#[test]
fn wrapped_horizon_preserves_holes_and_rejects_old_replays() -> Result<(), Error> {
    let mut ranges = Ranges::new(65)?;
    assert_eq!(ranges.capacity_bytes(), 16);
    ranges.commit(0, 1, 1, 65)?;
    ranges.commit(63, 65, 65, 65)?;
    ranges.commit(128, 129, 129, 65)?;
    assert_eq!(ranges.floor, 64);
    assert!(matches!(
        ranges.validate(63, 64, 129, 65),
        Err(Error::Proof)
    ));
    assert!(matches!(
        ranges.validate(64, 65, 129, 65),
        Err(Error::Proof)
    ));
    ranges.commit(65, 128, 129, 65)?;
    assert!(matches!(
        ranges.validate(127, 129, 129, 65),
        Err(Error::Proof)
    ));
    ranges.commit(129, 193, 193, 65)?;
    assert_eq!(ranges.floor, 128);
    assert!(matches!(
        ranges.validate(128, 129, 193, 65),
        Err(Error::Proof)
    ));
    ranges.commit(1_000, 1_001, 1_001, 65)?;
    assert_eq!(ranges.occupied_bytes(), 1);
    ranges.commit(936, 937, 937, 65)?;
    assert_eq!(ranges.retired, 1_001);
    Ok(())
}

#[test]
fn validation_and_rejected_commit_never_age_authenticated_state() -> Result<(), Error> {
    let mut ranges = Ranges::new(128)?;
    ranges.commit(1, 3, 3, 128)?;
    let before = ranges.words.clone();
    ranges.validate(1_000, 1_001, 1_001, 128)?;
    for (start, end, retired, horizon) in [
        (0, 0, 0, 128),
        (2, 4, 4, 128),
        (1, 3, 3, 128),
        (1_000, 1_001, 1_000, 128),
        (1_000, 1_001, 1_001, 0),
        (1_000, 1_001, 1_001, 129),
    ] {
        assert!(matches!(
            ranges.commit(start, end, retired, horizon),
            Err(Error::Proof)
        ));
        assert_eq!(ranges.words, before);
        assert_eq!(ranges.retired, 3);
        assert_eq!(ranges.floor, 0);
    }
    assert!(matches!(ranges.validate(1, 2, 3, 128), Err(Error::Proof)));
    ranges.commit(3, 4, 4, 128)?;
    Ok(())
}

#[test]
fn replay_floor_does_not_move_backward_when_horizon_or_end_changes() -> Result<(), Error> {
    let mut ranges = Ranges::new(128)?;
    ranges.commit(200, 201, 201, 64)?;
    assert_eq!(ranges.floor, 137);
    assert!(matches!(
        ranges.commit(100, 101, 201, 128),
        Err(Error::Proof)
    ));
    ranges.commit(137, 138, 138, 128)?;
    assert_eq!(ranges.retired, 201);
    assert_eq!(ranges.floor, 137);
    assert!(matches!(
        ranges.commit(136, 137, 137, 128),
        Err(Error::Proof)
    ));
    Ok(())
}

#[test]
fn checked_configuration_and_extents_near_integer_limit() -> Result<(), Error> {
    for horizon in [0, 1_048_577, u32::MAX] {
        assert!(matches!(Ranges::new(horizon), Err(Error::Configuration)));
    }
    for horizon in [1, 63, 64, 65, 127, 128, 1_048_576] {
        let ranges = Ranges::new(horizon)?;
        assert_eq!(
            ranges.capacity_bytes(),
            Ranges::planned_capacity_bytes(horizon)?
        );
    }
    let mut ranges = Ranges::new(65)?;
    ranges.commit(u64::MAX - 65, u64::MAX - 64, u64::MAX, 65)?;
    ranges.commit(u64::MAX - 64, u64::MAX, u64::MAX, 65)?;
    assert!(matches!(
        ranges.validate(u64::MAX - 1, u64::MAX, u64::MAX, 65),
        Err(Error::Proof)
    ));
    assert!(matches!(
        ranges.validate(u64::MAX - 66, u64::MAX - 65, u64::MAX, 65),
        Err(Error::Proof)
    ));
    Ok(())
}

#[test]
fn deterministic_reordering_matches_exact_byte_occupancy_model() -> Result<(), Error> {
    for horizon in [1u32, 63, 64, 65, 127, 128, 257] {
        let mut ranges = Ranges::new(horizon)?;
        let mut occupied = std::collections::BTreeSet::new();
        let mut retired = 0u64;
        let mut floor = 0u64;
        let mut seed = 17u64;
        for _ in 0..4_096 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let start = retired.saturating_sub(u64::from(horizon))
                + (seed >> 17) % (u64::from(horizon) * 2 + 1);
            let length = (seed >> 43) % 17 + 1;
            let end = start + length;
            let next_retired = retired.max(end);
            let next_floor = next_retired.saturating_sub(u64::from(horizon)).max(floor);
            let expected =
                start >= next_floor && !(start..end).any(|byte| occupied.contains(&byte));
            assert_eq!(
                ranges.validate(start, end, end, u64::from(horizon)).is_ok(),
                expected
            );
            assert_eq!(
                ranges.commit(start, end, end, u64::from(horizon)).is_ok(),
                expected
            );
            if expected {
                occupied.retain(|byte| *byte >= next_floor);
                occupied.extend(start..end);
                retired = next_retired;
                floor = next_floor;
            }
            assert_eq!(ranges.retired, retired);
            assert_eq!(ranges.floor, floor);
            for byte in floor..retired {
                assert_eq!(
                    ranges
                        .validate(byte, byte + 1, retired, u64::from(horizon))
                        .is_err(),
                    occupied.contains(&byte)
                );
            }
        }
    }
    Ok(())
}
