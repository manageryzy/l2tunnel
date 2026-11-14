use super::*;
use crate::{EntropyError, Error as HandshakeError, SessionId};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct CountingEntropy {
    calls: usize,
    byte: u8,
}
impl CountingEntropy {
    fn new(byte: u8) -> Self {
        Self { calls: 0, byte }
    }
}
impl Entropy for CountingEntropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), EntropyError> {
        self.calls += 1;
        output.fill(self.byte);
        self.byte = self.byte.wrapping_add(1);
        Ok(())
    }
}

fn selected() -> Result<Selection> {
    Ok(Selection::new(SelectionSpec {
        lane: LaneId(7),
        limits: Limits {
            max_body_bytes: 512,
            packets_per_key: 4,
            max_body_bytes_per_key: 2048,
        },
        protection: Protection::ChaCha20Poly1305,
        control_epoch: Epoch(9),
        control_digest: ConfigDigest([3; 32]),
        envelope_digest: ConfigDigest([4; 32]),
        exchange_micros: 1000,
        key_micros: 10_000,
        overlap_micros: 20,
        max_flight_copies: 4,
    })?)
}
fn local(role: Role) -> LocalSecret {
    LocalSecret::new(Zeroizing::new(
        [if role == Role::Initiator { 11 } else { 22 }; 32],
    ))
}
fn peer(role: Role) -> PeerKey {
    local(if role == Role::Initiator {
        Role::Responder
    } else {
        Role::Initiator
    })
    .public_key()
}
fn psk(profile: Profile) -> Option<Psk> {
    (profile == Profile::IkPsk2).then(|| Psk::new(Zeroizing::new([31; 32])))
}
fn config(role: Role, profile: Profile) -> Config {
    Config {
        role,
        profile,
        binding: Binding {
            session: SessionId([1; 16]),
            configuration: [2; 32],
            carrier: [3; 32],
            outer: [4; 32],
            member: [5; 32],
        },
        deadline: Time(1000),
    }
}
fn handshake(role: Role, profile: Profile, selection: Option<Selection>) -> Result<Handshake> {
    let mut entropy = CountingEntropy::new(if role == Role::Initiator { 41 } else { 52 });
    let result = match selection {
        Some(selection) => Handshake::new_refreshable(
            config(role, profile),
            selection,
            local(role),
            peer(role),
            psk(profile),
            Time(0),
            &mut entropy,
        ),
        None => Handshake::new(
            config(role, profile),
            local(role),
            peer(role),
            psk(profile),
            Time(0),
            &mut entropy,
        ),
    }?;
    assert_eq!(entropy.calls, 1);
    Ok(result)
}
fn confirmed_pair(profile: Profile, selection: Option<Selection>) -> Result<[Handshake; 2]> {
    let mut a = handshake(Role::Initiator, profile, selection)?;
    let mut b = handshake(Role::Responder, profile, selection)?;
    let mut bytes = [0; crate::MAX_FLIGHT_BYTES];
    let flight = a.write(Time(1), &mut bytes)?;
    assert_eq!(
        b.read(Time(1), flight.kind, &bytes[..flight.bytes])?,
        ReadOutcome::Accepted
    );
    let flight = b.write(Time(1), &mut bytes)?;
    assert_eq!(
        a.read(Time(1), flight.kind, &bytes[..flight.bytes])?,
        ReadOutcome::Accepted
    );
    let flight = a.write(Time(2), &mut bytes)?;
    assert_eq!(
        b.read(Time(2), flight.kind, &bytes[..flight.bytes])?,
        ReadOutcome::Accepted
    );
    assert!(!a.is_complete());
    assert!(!b.is_complete());
    let flight = b.write(Time(2), &mut bytes)?;
    assert!(b.is_complete());
    assert_eq!(
        a.read(Time(2), flight.kind, &bytes[..flight.bytes])?,
        ReadOutcome::Accepted
    );
    assert!(a.is_complete());
    Ok([a, b])
}
fn owners(profile: Profile) -> Result<[sec::Owners; 2]> {
    let selection = selected()?;
    let [a, b] = confirmed_pair(profile, Some(selection))?;
    let install = |handshake: Handshake| -> Result<sec::Owners> {
        let initial = handshake
            .finish_refreshable_with_confirmation(Time(2))?
            .initial;
        // Handshake-only ownership fixture; member signature acceptance is tested separately.
        Ok(initial.install(
            LaneId(7),
            selection.spec().limits,
            Protection::ChaCha20Poly1305,
            Epoch(9),
            ConfigDigest([3; 32]),
            Time(3),
            Time(50_000),
        )?)
    };
    Ok([install(a)?, install(b)?])
}

#[test]
fn selected_initial_and_legacy_finishes_preserve_distinct_actual_authority() -> Result {
    for profile in [Profile::Ik, Profile::IkPsk2] {
        let selection = selected()?;
        let [a, b] = confirmed_pair(profile, Some(selection))?;
        assert!(matches!(
            a.finish_with_confirmation(Time(2)),
            Err(HandshakeError::State)
        ));
        let actual = b.finish_refreshable_with_confirmation(Time(2))?;
        assert_eq!(actual.initial.role(), Role::Responder);
        assert_eq!(
            actual.initial.authenticated(),
            config(Role::Responder, profile).binding
        );
        assert_eq!(
            actual.initial.pins(),
            (
                local(Role::Initiator).public_key(),
                local(Role::Responder).public_key()
            )
        );
        assert_eq!(actual.initial.selection(), selection);
        assert_eq!(actual.confirmation.deadline(), Time(1000));

        let [a, b] = confirmed_pair(profile, None)?;
        assert!(matches!(
            a.finish_refreshable_with_confirmation(Time(2)),
            Err(Error::Handshake(HandshakeError::State))
        ));
        let legacy = b.finish_with_confirmation(Time(2))?;
        assert_eq!(legacy.root.binding().session, SessionId([1; 16]));
        assert_eq!(legacy.confirmation.deadline(), Time(1000));
    }
    Ok(())
}

#[test]
fn selected_initial_mismatch_fails_inside_actual_noise_authentication() -> Result {
    let selection = selected()?;
    let mut changed = selection.spec();
    changed.max_flight_copies -= 1;
    let different = Selection::new(changed)?;
    let mut a = handshake(Role::Initiator, Profile::IkPsk2, Some(selection))?;
    let mut b = handshake(Role::Responder, Profile::IkPsk2, Some(different))?;
    let mut bytes = [0; crate::MAX_FLIGHT_BYTES];
    let flight = a.write(Time(1), &mut bytes)?;
    assert_eq!(
        b.read(Time(1), flight.kind, &bytes[..flight.bytes]),
        Err(HandshakeError::Authentication)
    );
    assert!(!a.is_complete());
    assert!(!b.is_complete());
    assert!(matches!(
        b.finish_refreshable_with_confirmation(Time(2)),
        Err(Error::Handshake(HandshakeError::State))
    ));
    Ok(())
}

#[test]
fn exchange_rejects_changed_actual_pins_and_psk_before_fresh_entropy() -> Result {
    for refusal in 0..4 {
        let [mut owner, _remote] = owners(Profile::IkPsk2)?;
        let started = owner.begin_refresh(Tick(10), Tick(900))?;
        let own = if refusal == 0 {
            LocalSecret::new(Zeroizing::new([77; 32]))
        } else {
            local(Role::Initiator)
        };
        let remote = if refusal == 1 {
            local(Role::Initiator).public_key()
        } else {
            peer(Role::Initiator)
        };
        let secret = match refusal {
            2 => Some(Psk::new(Zeroizing::new([32; 32]))),
            3 => None,
            _ => psk(Profile::IkPsk2),
        };
        let mut entropy = CountingEntropy::new(91);
        assert!(matches!(
            Exchange::new(
                started.admission,
                own,
                remote,
                secret,
                Time(11),
                &mut entropy
            ),
            Err(Error::Credentials)
        ));
        assert_eq!(entropy.calls, 0, "credential refusal {refusal}");
    }
    Ok(())
}

#[test]
fn real_exchange_duplicates_copy_custody_and_original_cap_survive_material_handoff() -> Result {
    let [mut old_a, mut old_b] = owners(Profile::IkPsk2)?;
    let started = old_a.begin_refresh(Tick(10), Tick(900))?;
    let mut request = [0; 1024];
    let sent = old_a.seal_request(&started.request, Tick(11), &mut request)?;
    let mut opened = [0; 1024];
    let sec::RequestOutcome::New(remote) = old_b.open_request(
        Tick(11),
        Tick(900),
        &request[..sent.record.bytes],
        &mut opened,
    )?
    else {
        return Err("missing actual remote admission".into());
    };
    let mut entropy_a = CountingEntropy::new(71);
    let mut entropy_b = CountingEntropy::new(82);
    let mut a = Exchange::new(
        started.admission,
        local(Role::Initiator),
        peer(Role::Initiator),
        psk(Profile::IkPsk2),
        Time(12),
        &mut entropy_a,
    )?;
    let mut b = Exchange::new(
        remote,
        local(Role::Responder),
        peer(Role::Responder),
        psk(Profile::IkPsk2),
        Time(12),
        &mut entropy_b,
    )?;
    assert_eq!(entropy_a.calls, 1);
    assert_eq!(entropy_b.calls, 1);
    assert_eq!(a.deadline(), Time(900));
    assert_eq!(b.deadline(), Time(900));

    let mut short = [0xa5; 167];
    assert_eq!(
        a.write(Time(12), &mut short),
        Err(Error::Handshake(HandshakeError::OutputTooSmall))
    );
    assert_eq!(short, [0xa5; 167]);
    assert_eq!(a.next_flight(), Some(FlightKind::Initiation));
    let mut first = [0; 168];
    let initiation = a.write(Time(13), &mut first)?;
    assert_eq!(initiation.bytes, 168);
    let mut retry = [0; 168];
    for _ in 0..3 {
        assert_eq!(
            a.retransmit(Time(13), FlightKind::Initiation, &mut retry)?,
            initiation
        );
        assert_eq!(retry, first);
    }
    assert_eq!(
        a.retransmit(Time(13), FlightKind::Initiation, &mut retry),
        Err(Error::Security(sec::Error::CopiesExhausted))
    );
    assert_eq!(b.read(Time(13), &first)?, ReadOutcome::Accepted);
    assert_eq!(b.read(Time(14), &first)?, ReadOutcome::Duplicate);
    assert!(!b.is_complete());

    let mut response = [0; 168];
    let flight = b.write(Time(15), &mut response)?;
    assert_eq!(flight.bytes, 120);
    assert_eq!(
        a.read(Time(15), &response[..flight.bytes])?,
        ReadOutcome::Accepted
    );
    assert_eq!(
        a.read(Time(16), &response[..flight.bytes])?,
        ReadOutcome::Duplicate
    );
    assert!(!a.is_complete());
    assert!(!b.is_complete());
    let mut confirmation_a = [0; 145];
    assert_eq!(
        a.write(Time(17), &mut confirmation_a)?.kind,
        FlightKind::Confirmation
    );
    assert_eq!(b.read(Time(18), &confirmation_a)?, ReadOutcome::Accepted);
    assert!(!a.is_complete());
    assert!(!b.is_complete());
    let mut repeated_a = [0; 145];
    a.retransmit(Time(19), FlightKind::Confirmation, &mut repeated_a)?;
    assert_eq!(repeated_a, confirmation_a);
    assert_eq!(b.read(Time(19), &repeated_a)?, ReadOutcome::Duplicate);
    assert!(!b.is_complete());

    let mut confirmation_b = [0; 145];
    b.write(Time(20), &mut confirmation_b)?;
    assert!(b.is_complete());
    assert!(!a.is_complete());
    let completed_b = b.finish_with_confirmation(Time(21))?;
    let mut cache_b = completed_b.confirmation;
    assert_eq!(cache_b.deadline(), Time(900));
    let mut repeated_b = [0; 145];
    cache_b.retransmit(Time(22), &mut repeated_b)?;
    assert_eq!(repeated_b, confirmation_b);
    assert_eq!(a.read(Time(22), &repeated_b)?, ReadOutcome::Accepted);
    assert!(a.is_complete());
    assert_eq!(a.read(Time(23), &repeated_b)?, ReadOutcome::Duplicate);
    let completed_a = a.finish_with_confirmation(Time(24))?;
    let mut cache_a = completed_a.confirmation;
    let _prepared_a = completed_a.material.prepare_into(&mut old_a, Time(25))?;
    let _prepared_b = completed_b.material.prepare_into(&mut old_b, Time(25))?;
    assert_eq!(cache_a.deadline(), Time(900));
    for now in [26, 27] {
        cache_a.retransmit(Time(now), &mut repeated_a)?;
        assert_eq!(repeated_a, confirmation_a);
    }
    let mut untouched = [0xa5; 145];
    assert_eq!(
        cache_a.retransmit(Time(28), &mut untouched),
        Err(Error::Security(sec::Error::CopiesExhausted))
    );
    assert_eq!(untouched, [0xa5; 145]);
    assert_eq!(
        cache_a.retransmit(Time(900), &mut untouched),
        Err(Error::Handshake(HandshakeError::Deadline))
    );
    assert_eq!(untouched, [0xa5; 145]);
    assert_eq!(
        cache_a.retransmit(Time(899), &mut untouched),
        Err(Error::Handshake(HandshakeError::State))
    );
    Ok(())
}
