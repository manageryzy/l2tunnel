use super::*;
use crate::{ChannelId, Direction, Epoch, SessionId};

const CONTEXT: FecContext = FecContext {
    session: SessionId([5; 16]),
    channel: ChannelId(7),
    epoch: Epoch(3),
    direction: Direction::ClientToServer,
};
const GROUP: GenerationId = GenerationId(19);
type TestResult = Result<(), Error>;

type Packets = Vec<Vec<u8>>;

#[test]
fn caller_owned_group_sealing_matches_individual_encoding_at_all_supported_edges() -> TestResult {
    for (k, m) in [
        (1, 1),
        (2, 1),
        (3, 2),
        (4, 1),
        (8, 2),
        (16, 8),
        (255, 1),
        (1, 255),
    ] {
        let n = usize::from(k + m);
        let originals: Vec<_> = (0..n)
            .map(|i| vec![(i as u8).wrapping_mul(3); 1 + i % 19])
            .collect();
        let refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
        let g = Geometry::for_group(k, m, &refs, 65535)?;
        let reference = Encoder::new(g, &refs)?;
        let mut all = vec![0xa7; n * g.body_bytes() + 1];
        let size = all.len() - 1;
        assert_eq!(
            g.encode_group_into(&refs, &mut all[..size - 1]),
            Err(Error::OutputTooSmall { required: size })
        );
        assert!(all.iter().all(|&b| b == 0xa7));
        assert_eq!(g.encode_group_into(&refs, &mut all)?, size);
        assert_eq!(all[size], 0xa7);
        let mut one = vec![0; g.body_bytes()];
        for (i, body) in all[..size].chunks_exact(g.body_bytes()).enumerate() {
            reference.write_packet(i as u8, &mut one)?;
            assert_eq!(body, one);
        }
    }
    Ok(())
}

fn make(k: u16, m: u16) -> Result<(Geometry, Packets, Packets), Error> {
    let originals: Vec<Vec<u8>> = (0..k + m)
        .map(|p| {
            (0..1 + (usize::from(p) * 111) % 1024)
                .map(|b| (b * 17 + usize::from(p)) as u8)
                .collect()
        })
        .collect();
    let refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
    let g = Geometry::for_group(k, m, &refs, 1500)?;
    let enc = Encoder::new(g, &refs)?;
    let mut bodies = vec![vec![0; g.body_bytes()]; g.packet_count()];
    for (p, buf) in bodies.iter_mut().enumerate() {
        assert_eq!(enc.write_packet(p as u8, buf)?, g.body_bytes());
    }
    Ok((g, originals, bodies))
}

#[test]
fn every_k_survivors_recover_all_originals_and_lengths_without_pure_repairs() -> TestResult {
    for (k, m) in [(1, 2), (2, 3), (3, 3), (8, 2)] {
        let (g, originals, bodies) = make(k, m)?;
        let n = g.packet_count();
        for survivors in 0_usize..1 << n {
            if survivors.count_ones() != u32::from(k) {
                continue;
            }
            let mut rx = Receiver::new(CONTEXT, GROUP, g)?;
            for p in (0..n).rev().filter(|p| survivors & (1 << p) != 0) {
                assert_eq!(
                    rx.accept_authenticated(CONTEXT, GROUP, p as u8, &bodies[p])?,
                    Admission::Accepted
                );
                assert_eq!(rx.original(p as u8)?, Some(originals[p].as_slice()));
                assert_eq!(
                    rx.accept_authenticated(CONTEXT, GROUP, p as u8, &bodies[p])?,
                    Admission::Duplicate
                );
            }
            assert_eq!(rx.received_count(), usize::from(k));
            assert!(rx.can_recover());
            for p in (0..n).filter(|p| survivors & (1 << p) == 0) {
                assert_eq!(rx.original(p as u8)?, None);
            }
            assert_eq!(rx.recover_missing()?, usize::from(m));
            assert_eq!(rx.recover_missing()?, 0);
            for (p, source) in originals.iter().enumerate() {
                assert_eq!(rx.original(p as u8)?, Some(source.as_slice()));
            }
        }
    }
    Ok(())
}

#[test]
fn shared_scattered_recovery_reuses_one_allocation_after_failed_and_short_groups() -> TestResult {
    let profile = crate::mixed_datagram::Profile {
        data_cells: 3,
        parity_cells: 2,
        max_body_bytes: 1500,
        max_wire_bytes: 1500,
    };
    let plan = RecoveryPlan::for_profile(profile)?;
    let mut scratch = RecoveryScratch::new(plan)?;
    let mut base = None;
    let (g, _, bodies) = make(3, 2)?;
    let mut corrupt = bodies[3].clone();
    corrupt[g.systematic_bytes()] ^= 0x33;
    let four = [true, true, true, true, false];
    assert_eq!(
        scratch.recover(g, &four, |p| {
            Some(if p == 3 { &corrupt } else { &bodies[p] })
        }),
        Err(Error::Conflict)
    );
    assert_eq!(scratch.recover(g, &four, |_| None), Err(Error::Malformed));
    assert_eq!(
        scratch.recover(g, &four[..4], |_| None),
        Err(Error::InvalidDimensions)
    );
    assert_eq!(
        scratch.recover(g, &[true, false, false, true, false], |_| None),
        Err(Error::InsufficientRank)
    );
    let tiny = RecoveryPlan::for_geometry(Geometry::new(1, 1, 3, 6)?);
    let mut smaller = RecoveryScratch::new(tiny)?;
    assert_eq!(
        smaller.recover(g, &four, |_| None),
        Err(Error::OutputTooSmall {
            required: RecoveryPlan::for_geometry(g).heap_bytes()
        })
    );
    for (k, m) in [(3, 2), (2, 2), (1, 1), (3, 2)] {
        let (geom, originals, rows) = make(k, m)?;
        let n = geom.packet_count();
        let arrived: Vec<_> = (0..n).map(|p| p >= usize::from(m)).collect();
        let (result, longest) = scratch.recover(geom, &arrived, |p| {
            assert!(arrived[p]);
            Some(rows[p].as_slice())
        })?;
        assert_eq!(result.as_ptr(), *base.get_or_insert(result.as_ptr()));
        assert_eq!(result, rows.concat());
        assert_eq!(Some(longest), originals.iter().map(Vec::len).max());
        assert_eq!(scratch.reserved_bytes(), plan.heap_bytes());
    }
    Ok(())
}

#[test]
fn scratch_plan_handles_negotiated_body_bound_and_last_gf_coordinate() -> TestResult {
    let mut profile = crate::mixed_datagram::Profile {
        data_cells: 4,
        parity_cells: 1,
        max_body_bytes: 1451,
        max_wire_bytes: 1451,
    };
    assert_eq!(RecoveryPlan::for_profile(profile)?.heap_bytes(), 7_838);
    profile.max_body_bytes = 2;
    assert_eq!(
        RecoveryPlan::for_profile(profile),
        Err(Error::InvalidDimensions)
    );
    for (k, m) in [(1, 255), (2, 254), (255, 1)] {
        let originals: Vec<_> = (0..=u8::MAX).map(|p| [p]).collect();
        let refs: Vec<_> = originals.iter().map(<[u8; 1]>::as_slice).collect();
        let g = Geometry::for_group(k, m, &refs, 768)?;
        let mut all = vec![0; g.packet_count() * g.body_bytes()];
        g.encode_group_into(&refs, &mut all)?;
        let mut scratch = RecoveryScratch::new(RecoveryPlan::for_geometry(g))?;
        let arrived: Vec<_> = (0..g.packet_count()).map(|p| p >= usize::from(m)).collect();
        let (restored, longest) = scratch.recover(g, &arrived, |p| {
            Some(&all[p * g.body_bytes()..(p + 1) * g.body_bytes()])
        })?;
        assert_eq!(restored, all);
        assert_eq!(longest, 1);
    }
    Ok(())
}

#[test]
fn clean_group_has_direct_payload_only_recovery_is_never_invoked() -> TestResult {
    let (g, originals, bodies) = make(8, 2)?;
    let mut rx = Receiver::new(CONTEXT, GROUP, g)?;
    for (p, bytes) in bodies.iter().enumerate() {
        rx.accept_authenticated(CONTEXT, GROUP, p as u8, bytes)?;
        assert_eq!(rx.original(p as u8)?, Some(originals[p].as_slice()));
        assert!(!rx.restored);
    }
    assert_eq!(rx.received_count(), 10);
    assert_eq!(rx.recover_missing()?, 0);
    assert!(!rx.restored);
    Ok(())
}

#[test]
fn excess_losses_wait_for_a_distinct_late_arrival_and_check_duplicates() -> TestResult {
    let (g, originals, bodies) = make(8, 2)?;
    let mut rx = Receiver::new(CONTEXT, GROUP, g)?;
    for p in [9, 7, 6, 4, 3, 1, 0] {
        rx.accept_authenticated(CONTEXT, GROUP, p, &bodies[usize::from(p)])?;
    }
    assert_eq!(rx.recover_missing(), Err(Error::InsufficientRank));
    assert_eq!(rx.original(8)?, None);
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GenerationId(20), 8, &bodies[8]),
        Err(Error::ContextMismatch)
    );
    let mut corrupt = bodies[7].clone();
    if let Some(v) = corrupt.last_mut() {
        *v ^= 1;
    }
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 7, &corrupt),
        Err(Error::Conflict)
    );
    assert_eq!(rx.received_count(), 7);
    rx.accept_authenticated(CONTEXT, GROUP, 8, &bodies[8])?;
    assert_eq!(rx.recover_missing()?, 2);
    assert_eq!(rx.original(5)?, Some(originals[5].as_slice()));
    let mut wrong_late = bodies[5].clone();
    if let Some(v) = wrong_late.last_mut() {
        *v ^= 1;
    }
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 5, &wrong_late),
        Err(Error::Conflict)
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 5, &bodies[5])?,
        Admission::Accepted
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 5, &bodies[5])?,
        Admission::Duplicate
    );
    Ok(())
}

#[test]
fn limits_invalid_padding_and_inconsistent_unused_parity_are_transactional() -> TestResult {
    assert_eq!(Geometry::new(0, 2, 4, 1500), Err(Error::InvalidDimensions));
    assert_eq!(
        Geometry::new(255, 2, 4, 1500),
        Err(Error::InvalidDimensions)
    );
    assert_eq!(Geometry::new(8, 2, 151, 1500), Err(Error::PacketTooLarge));
    assert_eq!(
        Geometry::for_group(2, 1, &[b"x".as_slice(); 2], 1500),
        Err(Error::InvalidDimensions)
    );
    assert_eq!(
        Geometry::for_group(2, 1, &[b"x", b"", b"y"], 1500),
        Err(Error::InvalidSource)
    );
    let (g, _, bodies) = make(3, 2)?;
    let mut rx = Receiver::new(CONTEXT, GROUP, g)?;
    let mut bad = bodies[0].clone();
    bad[g.systematic_bytes() - 1] = 9;
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 0, &bad),
        Err(Error::InvalidSource)
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 6, &bodies[0]),
        Err(Error::InvalidDimensions)
    );
    assert_eq!(
        rx.accept_authenticated(CONTEXT, GROUP, 0, &bodies[0][..3]),
        Err(Error::Malformed)
    );
    assert_eq!(rx.received_count(), 0);
    // Four survivors, one missing member. Corrupt an overdetermined stripe's
    // redundant parity cell while preserving this packet's direct original.
    for (p, b) in bodies.iter().enumerate().take(4) {
        let mut bytes = b.clone();
        if p == 3 {
            bytes[g.systematic_bytes()] ^= 0x33;
        }
        rx.accept_authenticated(CONTEXT, GROUP, p as u8, &bytes)?;
    }
    assert_eq!(rx.recover_missing(), Err(Error::Conflict));
    assert_eq!(rx.original(4)?, None);
    assert_eq!(rx.received_count(), 4);
    Ok(())
}

#[test]
fn cauchy_array_matches_independent_python_bytes_with_two_rotating_parities() -> TestResult {
    // Generated independently with simulator/coding.py block_coefficients and PRODUCT.
    let originals: &[&[u8]] = &[
        &[11],
        &[7, 0, 200],
        &[90, 81],
        &[255, 1, 2, 3, 4],
        &[112, 4, 8, 16],
    ];
    let reference = [
        [0, 1, 11, 0, 0, 0, 0, 0, 0, 142, 244, 185, 66, 201, 200],
        [0, 3, 7, 0, 200, 0, 0, 0, 0, 2, 7, 93, 167, 221, 108],
        [0, 2, 90, 81, 0, 0, 0, 0, 0, 0, 247, 219, 166, 23, 84],
        [0, 5, 255, 1, 2, 3, 4, 0, 0, 0, 144, 242, 0, 1, 28],
        [0, 4, 112, 4, 8, 16, 0, 0, 0, 162, 1, 246, 0, 221, 203],
    ];
    let g = Geometry::for_group(3, 2, originals, 15)?;
    let encoder = Encoder::new(g, originals)?;
    let mut rx = Receiver::new(CONTEXT, GROUP, g)?;
    for (i, body) in reference.iter().enumerate() {
        let mut output = [0xa5; 16];
        assert_eq!(encoder.write_packet(i as u8, &mut output)?, 15);
        assert_eq!(&output[..15], body);
        assert_eq!(output[15], 0xa5);
        if [0, 2, 4].contains(&i) {
            rx.accept_authenticated(CONTEXT, GROUP, i as u8, body)?;
        }
    }
    assert_eq!(rx.recover_missing()?, 2);
    for (i, p) in originals.iter().enumerate() {
        assert_eq!(rx.original(i as u8)?, Some(*p));
    }
    Ok(())
}
