//! Low-level key-import tests. Actual maintained-Noise/member composition is
//! tested by the facade integration fixture, not inferred from these imports.
use super::*;
use crate::{Epoch, LaneId, Limits, SessionBinding, SessionId};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn selection(protection: Protection) -> Result<Selection> {
    Ok(Selection::new(super::super::SelectionSpec {
        lane: LaneId(7),
        limits: Limits {
            max_body_bytes: 512,
            packets_per_key: 4,
            max_body_bytes_per_key: 2048,
        },
        protection,
        control_epoch: Epoch(9),
        control_digest: ConfigDigest([3; 32]),
        envelope_digest: ConfigDigest([4; 32]),
        exchange_micros: 1_000,
        key_micros: 10_000,
        overlap_micros: 20,
        max_flight_copies: 4,
    })?)
}
fn initial(role: Role, selection: Selection) -> Result<Initial> {
    Ok(Initial::from_split_keys(
        Zeroizing::new([11; 32]),
        Zeroizing::new([22; 32]),
        Context {
            binding: SessionBinding {
                session: SessionId([1; 16]),
                transcript: [2; 32],
            },
            configuration: [3; 32],
            carrier: [4; 32],
            outer: [5; 32],
            member: [6; 32],
            pins: [[7; 32], [8; 32]],
            profile: 1,
        },
        selection,
        role,
        Tick(0),
        Tick(100),
        None,
        [9; 32],
    )?)
}
fn owner(role: Role, selection: Selection) -> Result<Owners> {
    let s = selection.spec();
    Ok(initial(role, selection)?.install(
        s.lane,
        s.limits,
        s.protection,
        s.control_epoch,
        s.control_digest,
        Tick(1),
        Tick(20_000),
    )?)
}
fn meta() -> Metadata<'static> {
    Metadata {
        epoch: Epoch(9),
        configuration: ConfigDigest([3; 32]),
        extra: b"typed scope",
    }
}
fn seal(a: &mut Owners, class: Class, now: u64, body: &[u8]) -> Result<(Sealed, Vec<u8>)> {
    let mut out = [0; 1024];
    let sealed = a.seal(Tick(now), class, meta(), body, &mut out)?;
    Ok((sealed, out[..sealed.record.bytes].to_vec()))
}
fn request(a: &mut Owners, b: &mut Owners) -> Result<(Started, Admission)> {
    let started = a.begin_refresh(Tick(10), Tick(900))?;
    let mut out = [0; 1024];
    let p = a.seal_request(&started.request, Tick(11), &mut out)?;
    let mut plain = [0; 1024];
    let admission = match b.open_request(Tick(11), Tick(900), &out[..p.record.bytes], &mut plain)? {
        RequestOutcome::New(a) => a,
        RequestOutcome::Duplicate => return Err("first request was a duplicate".into()),
    };
    Ok((started, admission))
}
fn prepare(a: &mut Owners, b: &mut Owners) -> Result<(Prepared, Prepared)> {
    let (started, remote) = request(a, b)?;
    let material = |admission| {
        Material::from_split_keys(
            admission,
            Zeroizing::new([31; 32]),
            Zeroizing::new([32; 32]),
            [33; 32],
            Tick(12),
        )
    };
    Ok((
        material(started.admission)?.prepare_into(a, Tick(12))?,
        material(remote)?.prepare_into(b, Tick(12))?,
    ))
}
fn initial_body_used(owner: &mut Owners) -> Result<u64> {
    // These fixtures remain at generation zero. Candidate(0) observes the
    // already-existing key and creates no generation or authentication proof.
    Ok(owner.current.receive[0]
        .opening
        .as_mut()
        .ok_or("reader missing")?
        .candidate(KeyGeneration(0))?
        .body_bytes)
}

#[test]
fn selection_exact_encoding_and_bounds_are_explicit() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let mut expected = Vec::from(*b"L2RS\x01\x01\0\0");
    expected.extend_from_slice(&7u32.to_be_bytes());
    expected.extend_from_slice(&512u32.to_be_bytes());
    for n in [4u64, 2048, 9] {
        expected.extend_from_slice(&n.to_be_bytes());
    }
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[4; 32]);
    for n in [1_000u64, 10_000, 20] {
        expected.extend_from_slice(&n.to_be_bytes());
    }
    expected.extend_from_slice(&4u32.to_be_bytes());
    assert_eq!(selected.canonical_bytes().as_slice(), expected);
    assert_eq!(Selection::decode(&expected)?, selected);
    let mut short = [0xA5; 131];
    assert_eq!(
        selected.encode(&mut short),
        Err(Error::Protection(crate::Error::OutputTooSmall))
    );
    assert_eq!(short, [0xA5; 131]);
    for at in [4, 5, 6, 7] {
        let mut invalid = expected.clone();
        invalid[at] = 0xff;
        assert!(Selection::decode(&invalid).is_err());
    }
    assert!(Selection::decode(&expected[..131]).is_err());
    let mut invalid = selected.spec();
    invalid.limits.max_body_bytes = 87;
    assert_eq!(Selection::new(invalid), Err(Error::Configuration));
    invalid = selected.spec();
    invalid.overlap_micros = invalid.exchange_micros;
    assert_eq!(Selection::new(invalid), Err(Error::Configuration));
    let mut boundary = selected.spec();
    boundary.protection = Protection::HmacSha256;
    // The current public body ceiling is already tighter than the v2 HMAC
    // packet ceiling. Preserve that real accepted boundary and its one-over.
    boundary.limits.max_body_bytes = crate::MAX_BODY_BYTES;
    boundary.limits.max_body_bytes_per_key = boundary.limits.max_body_bytes as u64;
    Selection::new(boundary)?;
    boundary.limits.max_body_bytes += 1;
    boundary.limits.max_body_bytes_per_key += 1;
    assert_eq!(
        Selection::new(boundary),
        Err(Error::Protection(crate::Error::InvalidLimits))
    );
    Ok(())
}

#[test]
fn managed_joining_retires_actual_owners_and_never_reopens_registry() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let limits = selected.spec().limits;
    let mut a = initial(Role::Initiator, selected)?.joining(limits, Tick(1), Tick(90))?;
    let mut b = initial(Role::Responder, selected)?.joining(limits, Tick(1), Tick(90))?;
    let mut packet = [0; 1024];
    let mut plain = [0; 1024];
    let first = a.seal(Tick(2), b"proof", &mut packet)?;
    let mut retry = [0; 1024];
    let n = a.retransmit(Tick(3), &mut retry)?;
    assert_eq!(&retry[..n], &packet[..first.bytes]);
    assert_eq!(
        b.open(Tick(3), &packet[..first.bytes], &mut plain)?.number,
        PacketNumber(0)
    );
    let response = b.seal(Tick(4), b"accept", &mut packet)?;
    a.open(Tick(4), &packet[..response.bytes], &mut plain)?;
    let a = a.retire(Tick(5))?;
    let b = b.retire(Tick(5))?;
    assert!(a.root.managed_registry(LaneId(7), true));
    assert!(b.root.managed_registry(LaneId(7), true));
    assert!(matches!(
        a.joining(limits, Tick(6), Tick(90)),
        Err(Error::Domains)
    ));
    let mut expired = initial(Role::Initiator, selected)?.joining(limits, Tick(1), Tick(8))?;
    assert_eq!(
        expired.seal(Tick(8), b"late", &mut packet),
        Err(Error::Deadline)
    );
    assert_eq!(
        expired.seal(Tick(7), b"rewound", &mut packet),
        Err(Error::State)
    );
    // A raw owner minted before managed transfer leaves a tombstone and is refused.
    let mut unmanaged = initial(Role::Initiator, selected)?;
    let raw = unmanaged.root.sender(
        crate::Purpose::Data,
        LaneId(7),
        limits,
        Protection::ChaCha20Poly1305,
    )?;
    drop(raw);
    assert!(matches!(
        unmanaged.install(
            LaneId(7),
            limits,
            selected.spec().protection,
            Epoch(9),
            ConfigDigest([3; 32]),
            Tick(1),
            Tick(20_000)
        ),
        Err(Error::Domains)
    ));
    Ok(())
}

#[test]
fn abort_burns_target_but_keeps_valid_old_keys_and_global_numbers() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let mut a = owner(Role::Initiator, selected)?;
    let mut b = owner(Role::Responder, selected)?;
    let (pa, _) = prepare(&mut a, &mut b)?;
    let before = a.next;
    assert_eq!(a.abort_refresh(KeyEpoch(2), Tick(13)), Err(Error::Context));
    assert_eq!(a.additional_epoch(), Some(KeyEpoch(1)));
    a.abort_refresh(KeyEpoch(1), Tick(14))?;
    assert_eq!(a.next, before);
    assert_eq!(a.key_epoch(), KeyEpoch(0));
    assert!(a.additional_epoch().is_none());
    assert!(a.pending.is_none());
    assert_eq!(a.activate_refresh(&pa, Tick(15)), Err(Error::State));
    let (_, packet) = seal(&mut a, Class::Data, 16, b"old still valid")?;
    b.open(Tick(16), Class::Data, meta(), &packet, &mut [0; 1024])?;
    assert_eq!(
        a.begin_refresh(Tick(17), Tick(900))?.admission.target(),
        KeyEpoch(2)
    );
    Ok(())
}

#[test]
fn prepared_old_reader_obeys_authenticated_new_base_and_abort_refuses_peer_effects() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let mut a = owner(Role::Initiator, selected)?;
    let mut b = owner(Role::Responder, selected)?;
    let (pa, _) = prepare(&mut a, &mut b)?;
    let (_, initial_data) = seal(&mut a, Class::Data, 13, b"old-zero")?;
    b.open(Tick(13), Class::Data, meta(), &initial_data, &mut [0; 1024])?;
    a.activate_refresh(&pa, Tick(14))?;
    let mut packet = [0; 1024];
    let n = a.seal_activation(Tick(15), &mut packet)?.record.bytes;
    assert_eq!(
        b.open_activation(Tick(15), &packet[..n], &mut [0; 1024])?,
        ActivationOutcome::Accepted
    );
    assert_eq!(b.key_epoch(), KeyEpoch(0));
    assert_eq!(b.additional_epoch(), Some(KeyEpoch(1)));
    assert_eq!(b.abort_refresh(KeyEpoch(1), Tick(16)), Err(Error::State));
    // Trusted-import shadow is solely an adversarial invariant seam: it makes
    // valid old-key ciphertext above the authenticated new base, not an honest
    // sender transition or a second production packet owner.
    let mut shadow = owner(Role::Initiator, selected)?;
    shadow.next[0] = 5;
    let (_, hostile) = seal(&mut shadow, Class::Data, 16, b"old beyond fence")?;
    let highest = b.highest_number(Class::Data);
    let old_used = initial_body_used(&mut b)?;
    let new_base = b.additional.as_ref().ok_or("new reader missing")?.receive[0].base;
    assert_eq!(
        b.open(Tick(17), Class::Data, meta(), &hostile, &mut [0; 1024]),
        Err(Error::Context)
    );
    assert_eq!(b.highest_number(Class::Data), highest);
    assert_eq!(initial_body_used(&mut b)?, old_used);
    assert_eq!(
        b.additional.as_ref().ok_or("new reader missing")?.receive[0].base,
        new_base
    );
    Ok(())
}

#[test]
fn abort_also_refuses_first_authenticated_new_data_without_activation_message() -> Result {
    let selected = selection(Protection::HmacSha256)?;
    let mut a = owner(Role::Initiator, selected)?;
    let mut b = owner(Role::Responder, selected)?;
    let (pa, _) = prepare(&mut a, &mut b)?;
    a.activate_refresh(&pa, Tick(14))?;
    let (_, packet) = seal(&mut a, Class::Data, 15, b"actual new-key data")?;
    b.open(Tick(15), Class::Data, meta(), &packet, &mut [0; 1024])?;
    assert_eq!(b.abort_refresh(KeyEpoch(1), Tick(16)), Err(Error::State));
    assert_eq!(b.additional_epoch(), Some(KeyEpoch(1)));
    Ok(())
}

#[test]
fn operation_key_and_monotonic_bounds_latch_without_number_reset() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let mut a = owner(Role::Initiator, selected)?;
    a.begin_refresh(Tick(10), Tick(20))?;
    assert_eq!(a.abort_refresh(KeyEpoch(1), Tick(20)), Err(Error::Deadline));
    assert_eq!(a.check_time(Tick(19)), Err(Error::State));
    let mut a = owner(Role::Initiator, selected)?;
    let mut b = owner(Role::Responder, selected)?;
    let (pa, _) = prepare(&mut a, &mut b)?;
    a.activate_refresh(&pa, Tick(20))?;
    a.activate_refresh(&pa, Tick(30))?;
    assert_eq!(a.check_time(Tick(29)), Err(Error::TimeRegression));
    assert_eq!(a.check_time(Tick(31)), Err(Error::State));
    let mut a = owner(Role::Initiator, selected)?;
    let before = a.next;
    assert_eq!(a.check_time(Tick(10_000)), Err(Error::KeyExpired));
    assert_eq!(a.next, before);
    assert_eq!(a.check_time(Tick(9_999)), Err(Error::State));
    Ok(())
}

#[test]
fn malformed_or_short_output_cannot_commit_replay_base_or_usage() -> Result {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let selected = selection(protection)?;
        let mut a = owner(Role::Initiator, selected)?;
        let mut b = owner(Role::Responder, selected)?;
        let mut short = [0xA5; 1];
        assert_eq!(
            a.seal(Tick(2), Class::Data, meta(), b"body", &mut short),
            Err(Error::Protection(crate::Error::OutputTooSmall))
        );
        assert_eq!(a.next_number(Class::Data), PacketNumber(0));
        assert_eq!(short, [0xA5]);
        let (_, packet) = seal(&mut a, Class::Data, 3, b"body")?;
        let mut damaged = packet.clone();
        let last = damaged.last_mut().ok_or("empty packet")?;
        *last ^= 1;
        assert!(
            b.open(Tick(3), Class::Data, meta(), &damaged, &mut [0; 1024])
                .is_err()
        );
        assert_eq!(b.highest_number(Class::Data), None);
        assert_eq!(b.current.receive[0].base, Some(0));
        assert_eq!(initial_body_used(&mut b)?, 0);
        b.open(Tick(4), Class::Data, meta(), &packet, &mut [0; 1024])?;
        assert_eq!(
            b.open(Tick(5), Class::Data, meta(), &packet, &mut [0; 1024]),
            Err(Error::Protection(crate::Error::Replay))
        );
    }
    Ok(())
}

#[test]
fn checked_selector_and_counter_exhaustion_never_allocate_replacement_identity() -> Result {
    let selected = selection(Protection::ChaCha20Poly1305)?;
    let mut a = owner(Role::Initiator, selected)?;
    a.high = KeyEpoch(u64::MAX - 1);
    assert!(matches!(
        a.begin_refresh(Tick(2), Tick(900)),
        Err(Error::EpochExhausted)
    ));
    assert!(a.pending.is_none());
    let mut a = owner(Role::Initiator, selected)?;
    a.next[0] = u64::MAX;
    let mut out = [0xA5; 1024];
    assert_eq!(
        a.seal(Tick(2), Class::Data, meta(), b"body", &mut out),
        Err(Error::Protection(crate::Error::CounterExhausted))
    );
    assert_eq!(a.next_number(Class::Data), PacketNumber(u64::MAX));
    assert_eq!(out, [0xA5; 1024]);
    Ok(())
}
