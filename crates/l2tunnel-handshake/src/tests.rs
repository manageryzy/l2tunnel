use super::*;
use clatter::rand_core::{CryptoRng, RngCore};
use l2tunnel_security::{ConfigDigest, Epoch, LaneId, Limits, Metadata, Protection, Purpose};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct TestEntropy {
    byte: u8,
    calls: usize,
    fail: bool,
}

impl TestEntropy {
    fn new(byte: u8) -> Self {
        Self {
            byte,
            calls: 0,
            fail: false,
        }
    }
}

impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), EntropyError> {
        self.calls += 1;
        output.fill(self.byte);
        if self.fail { Err(EntropyError) } else { Ok(()) }
    }
}

fn local(byte: u8) -> LocalSecret {
    LocalSecret::new(Zeroizing::new([byte; 32]))
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
        deadline: Time(10_000),
    }
}

fn psk(profile: Profile, byte: u8) -> Option<Psk> {
    (profile == Profile::IkPsk2).then(|| Psk::new(Zeroizing::new([byte; 32])))
}

fn make(c: Config, byte: u8, peer: u8, psk_byte: u8) -> Result<Handshake> {
    let mut entropy = TestEntropy::new(byte + 10);
    let handshake = Handshake::new(
        c,
        local(byte),
        local(peer).public_key(),
        psk(c.profile, psk_byte),
        Time(0),
        &mut entropy,
    )?;
    assert_eq!(entropy.calls, 1);
    Ok(handshake)
}

fn pair(profile: Profile) -> Result<(Handshake, Handshake)> {
    Ok((
        make(config(Role::Initiator, profile), 11, 22, 33)?,
        make(config(Role::Responder, profile), 22, 11, 33)?,
    ))
}

fn emit(handshake: &mut Handshake) -> Result<(FlightKind, Vec<u8>)> {
    let mut output = [0xE7; MAX_FLIGHT_BYTES + 1];
    let flight = handshake.write(Time(1), &mut output)?;
    assert_eq!(output[flight.bytes], 0xE7);
    Ok((flight.kind, output[..flight.bytes].to_vec()))
}

fn receive(handshake: &mut Handshake, flight: &(FlightKind, Vec<u8>)) -> Result {
    assert_eq!(
        handshake.read(Time(1), flight.0, &flight.1)?,
        ReadOutcome::Accepted
    );
    Ok(())
}

fn noise_only(a: &mut Handshake, b: &mut Handshake) -> Result {
    receive(b, &emit(a)?)?;
    receive(a, &emit(b)?)?;
    assert!(!a.is_complete() && !b.is_complete());
    Ok(())
}

fn complete(a: &mut Handshake, b: &mut Handshake) -> Result {
    noise_only(a, b)?;
    // A peer confirmation may arrive before this endpoint emits its own.
    receive(b, &emit(a)?)?;
    assert!(!b.is_complete());
    receive(a, &emit(b)?)?;
    assert!(a.is_complete() && b.is_complete());
    Ok(())
}

#[test]
fn confirmed_public_split_handoff_opens_opaque_packet_bytes_in_both_modes() -> Result {
    for profile in [Profile::Ik, Profile::IkPsk2] {
        let (mut a, mut b) = pair(profile)?;
        complete(&mut a, &mut b)?;
        let (mut a, mut b) = (a.finish(Time(2))?, b.finish(Time(2))?);
        let limits = Limits {
            max_body_bytes: 1500,
            packets_per_key: 1 << 28,
            max_body_bytes_per_key: 1 << 40,
        };
        let metadata = Metadata {
            epoch: Epoch(7),
            configuration: ConfigDigest([2; 32]),
            extra: b"opaque Ethernet/repair/control",
        };
        for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
            let lane = LaneId(if protection == Protection::ChaCha20Poly1305 {
                0
            } else {
                1
            });
            let mut sender = a.sender(Purpose::Data, lane, limits, protection)?;
            let mut receiver = b.receiver(Purpose::Data, lane, limits, protection)?;
            let payload = [0xA5; 127];
            let mut wire = [0; 256];
            let sealed = sender.seal(metadata, &payload, &mut wire)?;
            let mut output = [0; 256];
            let opened = receiver.open(metadata, &wire[..sealed.bytes], &mut output)?;
            assert_eq!(&output[..opened.bytes], payload);
        }
        let mut sender = b.sender(
            Purpose::Management,
            LaneId(0),
            limits,
            Protection::ChaCha20Poly1305,
        )?;
        let mut receiver = a.receiver(
            Purpose::Management,
            LaneId(0),
            limits,
            Protection::ChaCha20Poly1305,
        )?;
        let mut wire = [0; 128];
        let sealed = sender.seal(metadata, b"reverse control", &mut wire)?;
        let mut output = [0; 128];
        let opened = receiver.open(metadata, &wire[..sealed.bytes], &mut output)?;
        assert_eq!(&output[..opened.bytes], b"reverse control");
    }
    Ok(())
}

#[test]
fn own_peer_prologue_binding_and_role_mismatches_fail_before_roots() -> Result {
    for field in 0..7 {
        let (mut a, _) = pair(Profile::Ik)?;
        let mut server = config(Role::Responder, Profile::Ik);
        match field {
            0 => server.binding.configuration[0] ^= 1,
            1 => server.binding.carrier[0] ^= 1,
            2 => server.binding.outer[0] ^= 1,
            3 => server.binding.member[0] ^= 1,
            4 => server.binding.session.0[0] ^= 1,
            5 => server.role = Role::Initiator,
            _ => {}
        }
        let mut b = make(server, 22, if field == 6 { 44 } else { 11 }, 33)?;
        let initial = emit(&mut a)?;
        assert!(b.read(Time(1), initial.0, &initial.1).is_err());
        assert!(!b.is_complete());
        assert!(b.finish(Time(2)).is_err());
    }
    // Initiator pins a different valid server, so the actual responder cannot
    // authenticate the initiation under its own static key and prologue.
    let mut a = make(config(Role::Initiator, Profile::Ik), 11, 44, 33)?;
    let (_, mut b) = pair(Profile::Ik)?;
    let first = emit(&mut a)?;
    assert_eq!(
        b.read(Time(1), first.0, &first.1),
        Err(Error::Authentication)
    );
    Ok(())
}

#[test]
fn psk_selection_is_explicit_and_wrong_secret_cannot_complete() -> Result {
    let mut entropy = TestEntropy::new(9);
    assert_eq!(
        Handshake::new(
            config(Role::Initiator, Profile::IkPsk2),
            local(11),
            local(22).public_key(),
            None,
            Time(0),
            &mut entropy
        )
        .err(),
        Some(Error::Configuration)
    );
    assert_eq!(
        Handshake::new(
            config(Role::Initiator, Profile::Ik),
            local(11),
            local(22).public_key(),
            psk(Profile::IkPsk2, 33),
            Time(0),
            &mut entropy
        )
        .err(),
        Some(Error::Configuration)
    );
    assert_eq!(entropy.calls, 0);
    let mut a = make(config(Role::Initiator, Profile::IkPsk2), 11, 22, 33)?;
    let mut b = make(config(Role::Responder, Profile::IkPsk2), 22, 11, 34)?;
    receive(&mut b, &emit(&mut a)?)?;
    let response = emit(&mut b)?;
    assert_eq!(
        a.read(Time(1), response.0, &response.1),
        Err(Error::Authentication)
    );
    assert!(a.finish(Time(2)).is_err());
    Ok(())
}

#[test]
fn low_order_static_and_ephemeral_inputs_fail_contributory_check() -> Result {
    let mut one = [0; 32];
    one[0] = 1;
    for low in [[0; 32], one] {
        let mut entropy = TestEntropy::new(8);
        assert_eq!(
            Handshake::new(
                config(Role::Initiator, Profile::Ik),
                local(11),
                PeerKey(low),
                None,
                Time(0),
                &mut entropy
            )
            .err(),
            Some(Error::Authentication)
        );
        assert_eq!(entropy.calls, 0);
        let (mut a, mut b) = pair(Profile::Ik)?;
        let mut initial = emit(&mut a)?;
        initial.1[..32].copy_from_slice(&low);
        assert_eq!(
            b.read(Time(1), initial.0, &initial.1),
            Err(Error::Authentication)
        );
        assert!(b.finish(Time(2)).is_err());
        let (mut a, mut b) = pair(Profile::Ik)?;
        receive(&mut b, &emit(&mut a)?)?;
        let mut response = emit(&mut b)?;
        response.1[..32].copy_from_slice(&low);
        assert_eq!(
            a.read(Time(1), response.0, &response.1),
            Err(Error::Authentication)
        );
        assert!(a.finish(Time(2)).is_err());
    }
    Ok(())
}

#[test]
fn fixed_lengths_reject_every_truncation_and_oversize_before_crypto() -> Result {
    for kind in [
        FlightKind::Initiation,
        FlightKind::Response,
        FlightKind::Confirmation,
    ] {
        // An Initiation may carry an optional payload, so only lengths past
        // the largest payload are oversize; see the payload tests below.
        let oversize = if kind == FlightKind::Initiation {
            MAX_INITIATION_BYTES + 1
        } else {
            kind.size() + 1
        };
        for size in (0..kind.size()).chain([oversize, 65_536]) {
            let (mut a, mut b) = pair(Profile::Ik)?;
            let mut output = [0; MAX_FLIGHT_BYTES];
            match kind {
                FlightKind::Initiation => {}
                FlightKind::Response => {
                    receive(&mut b, &emit(&mut a)?)?;
                }
                FlightKind::Confirmation => {
                    noise_only(&mut a, &mut b)?;
                }
            }
            let (sender, receiver) = if kind == FlightKind::Response {
                (&mut b, &mut a)
            } else {
                (&mut a, &mut b)
            };
            let flight = sender.write(Time(1), &mut output)?;
            assert_eq!(flight.kind, kind);
            let mut bytes = vec![0; size];
            let copied = size.min(flight.bytes);
            bytes[..copied].copy_from_slice(&output[..copied]);
            assert_eq!(receiver.read(Time(1), kind, &bytes), Err(Error::Length));
            assert!(receiver.next_flight().is_none());
        }
    }
    Ok(())
}

#[test]
fn duplicates_retransmit_exact_bytes_without_nonce_use_or_new_entropy() -> Result {
    let (mut a, mut b) = pair(Profile::IkPsk2)?;
    let first = emit(&mut a)?;
    receive(&mut b, &first)?;
    assert_eq!(b.read(Time(1), first.0, &first.1)?, ReadOutcome::Duplicate);
    let response = emit(&mut b)?;
    let mut repeated = [0; MAX_FLIGHT_BYTES];
    let replay = b.retransmit(Time(1), response.0, &mut repeated)?;
    assert_eq!(&repeated[..replay.bytes], response.1);
    assert_eq!(b.deadline(), Time(10_000));
    receive(&mut a, &response)?;
    assert_eq!(
        a.read(Time(1), response.0, &response.1)?,
        ReadOutcome::Duplicate
    );
    let confirmation = emit(&mut a)?;
    let repeated_confirmation = a.retransmit(Time(1), FlightKind::Confirmation, &mut repeated)?;
    assert_eq!(&repeated[..repeated_confirmation.bytes], confirmation.1);
    receive(&mut b, &confirmation)?;
    assert_eq!(
        b.read(Time(1), confirmation.0, &confirmation.1)?,
        ReadOutcome::Duplicate
    );
    receive(&mut a, &emit(&mut b)?)?;
    assert!(a.finish(Time(2)).is_ok() && b.finish(Time(2)).is_ok());
    let (mut a, mut b) = pair(Profile::Ik)?;
    let mut first = emit(&mut a)?;
    receive(&mut b, &first)?;
    first.1[50] ^= 1;
    assert_eq!(b.read(Time(1), first.0, &first.1), Err(Error::Conflict));
    assert!(b.finish(Time(2)).is_err());
    Ok(())
}

#[test]
fn final_confirmation_custody_survives_asymmetric_loss_and_root_release() -> Result {
    for profile in [Profile::Ik, Profile::IkPsk2] {
        for lost_role in [Role::Initiator, Role::Responder] {
            let (mut a, mut b) = pair(profile)?;
            noise_only(&mut a, &mut b)?;
            let (mut established_side, mut waiting_side) = if lost_role == Role::Initiator {
                (a, b)
            } else {
                (b, a)
            };
            let lost = emit(&mut established_side)?;
            assert_eq!(lost.0, FlightKind::Confirmation);
            receive(&mut established_side, &emit(&mut waiting_side)?)?;
            assert!(established_side.is_complete());
            assert!(!waiting_side.is_complete());
            let Established {
                mut root,
                mut confirmation,
            } = established_side.finish_with_confirmation(Time(2))?;
            assert_eq!(confirmation.deadline(), Time(10_000));
            let mut retransmitted = [0xD3; MAX_FLIGHT_BYTES];
            let copied = confirmation.retransmit(Time(3), &mut retransmitted)?;
            assert_eq!(copied.kind, FlightKind::Confirmation);
            assert_eq!(&retransmitted[..copied.bytes], lost.1);
            assert!(
                retransmitted[copied.bytes..]
                    .iter()
                    .all(|byte| *byte == 0xD3)
            );
            assert_eq!(
                waiting_side.read(Time(3), copied.kind, &retransmitted[..copied.bytes])?,
                ReadOutcome::Accepted
            );
            let copied_again = confirmation.retransmit(Time(4), &mut retransmitted)?;
            assert_eq!(&retransmitted[..copied_again.bytes], lost.1);
            assert_eq!(
                waiting_side.read(
                    Time(4),
                    copied_again.kind,
                    &retransmitted[..copied_again.bytes]
                )?,
                ReadOutcome::Duplicate
            );
            assert!(waiting_side.is_complete());
            // Its nonce-one invariant proves retries copied the original flight
            // rather than running the original transport encryption again.
            let mut peer = waiting_side.finish_with_confirmation(Time(4))?.root;
            let limits = Limits {
                max_body_bytes: 1500,
                packets_per_key: 1 << 28,
                max_body_bytes_per_key: 1 << 40,
            };
            let metadata = Metadata {
                epoch: Epoch(0),
                configuration: ConfigDigest([2; 32]),
                extra: &[],
            };
            let mut sender = root.sender(
                Purpose::Management,
                LaneId(0),
                limits,
                Protection::ChaCha20Poly1305,
            )?;
            let mut receiver = peer.receiver(
                Purpose::Management,
                LaneId(0),
                limits,
                Protection::ChaCha20Poly1305,
            )?;
            let mut wire = [0; 128];
            let sealed = sender.seal(metadata, b"post-loss handoff", &mut wire)?;
            let mut output = [0; 128];
            let opened = receiver.open(metadata, &wire[..sealed.bytes], &mut output)?;
            assert_eq!(&output[..opened.bytes], b"post-loss handoff");
        }
    }
    Ok(())
}

#[test]
fn final_confirmation_cache_capacity_deadline_and_time_are_nonrenewing() -> Result {
    fn confirmation_cache() -> Result<ConfirmationCache> {
        let (mut a, mut b) = pair(Profile::Ik)?;
        complete(&mut a, &mut b)?;
        Ok(a.finish_with_confirmation(Time(2))?.confirmation)
    }
    let mut cache = confirmation_cache()?;
    let saved = *cache.ciphertext;
    let mut short = [0xA7; CONFIRM_BYTES - 1];
    assert_eq!(
        cache.retransmit(Time(5), &mut short),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(cache.now, Time(2));
    assert_eq!(*cache.ciphertext, saved);
    assert!(short.iter().all(|byte| *byte == 0xA7));
    let mut output = [0xA7; CONFIRM_BYTES];
    cache.retransmit(Time(3), &mut output)?;
    assert_eq!(output[..], saved[..cache.length]);
    output.fill(0xA7);
    assert_eq!(cache.retransmit(Time(2), &mut output), Err(Error::Deadline));
    assert!(cache.ciphertext.iter().all(|byte| *byte == 0));
    assert!(output.iter().all(|byte| *byte == 0xA7));
    assert_eq!(cache.retransmit(Time(4), &mut output), Err(Error::State));
    let mut cache = confirmation_cache()?;
    cache.retransmit(Time(9_999), &mut output)?;
    assert_eq!(cache.deadline(), Time(10_000));
    output.fill(0xA7);
    assert_eq!(
        cache.retransmit(Time(10_000), &mut output),
        Err(Error::Deadline)
    );
    assert!(cache.ciphertext.iter().all(|byte| *byte == 0));
    assert!(output.iter().all(|byte| *byte == 0xA7));
    assert_eq!(
        cache.retransmit(Time(9_999), &mut output),
        Err(Error::State)
    );
    Ok(())
}

#[test]
fn unexpected_kinds_and_authenticated_wrong_confirmation_retire_state() -> Result {
    for kind in [
        FlightKind::Initiation,
        FlightKind::Response,
        FlightKind::Confirmation,
    ] {
        let (mut a, _) = pair(Profile::Ik)?;
        assert_eq!(
            a.read(Time(1), kind, &vec![0; kind.size()]),
            Err(Error::State)
        );
        assert!(a.finish(Time(2)).is_err());
    }
    for kind in [FlightKind::Response, FlightKind::Confirmation] {
        let (_, mut b) = pair(Profile::Ik)?;
        assert_eq!(
            b.read(Time(1), kind, &vec![0; kind.size()]),
            Err(Error::State)
        );
    }
    for kind in [FlightKind::Initiation, FlightKind::Response] {
        let (mut a, mut b) = pair(Profile::Ik)?;
        noise_only(&mut a, &mut b)?;
        // A previously accepted Response has a conflicting byte sequence.
        let expected = if kind == FlightKind::Response {
            Error::Conflict
        } else {
            Error::State
        };
        assert_eq!(a.read(Time(1), kind, &vec![0; kind.size()]), Err(expected));
        assert!(a.finish(Time(2)).is_err());
    }
    for field in [0, 8, 9, 25] {
        let (mut a, mut b) = pair(Profile::Ik)?;
        noise_only(&mut a, &mut b)?;
        let mut body = a.confirmation(Role::Initiator);
        body[field] ^= 1;
        let mut wire = [0; CONFIRM_BYTES];
        a.transport
            .as_mut()
            .ok_or(Error::State)?
            .send(&body, &mut wire)
            .map_err(|_| Error::Crypto)?;
        assert_eq!(
            b.read(Time(1), FlightKind::Confirmation, &wire),
            Err(Error::Authentication)
        );
        assert!(b.finish(Time(2)).is_err());
    }
    Ok(())
}

#[test]
fn output_preflight_entropy_failure_and_absolute_deadline_are_nonrenewing() -> Result {
    let (mut a, _) = pair(Profile::Ik)?;
    assert_eq!(a.write(Time(1), &mut [0; 95]), Err(Error::OutputTooSmall));
    assert_eq!(a.next_flight(), Some(FlightKind::Initiation));
    let first = emit(&mut a)?;
    let (mut reference, _) = pair(Profile::Ik)?;
    assert_eq!(first, emit(&mut reference)?);
    let mut entropy = TestEntropy::new(9);
    entropy.fail = true;
    assert_eq!(
        Handshake::new(
            config(Role::Initiator, Profile::Ik),
            local(11),
            local(22).public_key(),
            None,
            Time(0),
            &mut entropy
        )
        .err(),
        Some(Error::Entropy)
    );
    assert_eq!(entropy.calls, 1);
    let (mut a, _) = pair(Profile::Ik)?;
    assert_eq!(a.write(Time(10_000), &mut [0; 96]), Err(Error::Deadline));
    assert!(a.finish(Time(10_000)).is_err());
    let (mut a, _) = pair(Profile::Ik)?;
    a.write(Time(2), &mut [0; 96])?;
    assert_eq!(
        a.retransmit(Time(1), FlightKind::Initiation, &mut [0; 96]),
        Err(Error::Deadline)
    );
    let mut c = config(Role::Initiator, Profile::Ik);
    c.deadline = Time(u64::MAX);
    let mut entropy = TestEntropy::new(9);
    let mut a = Handshake::new(
        c,
        local(11),
        local(22).public_key(),
        None,
        Time(u64::MAX - 1),
        &mut entropy,
    )?;
    assert_eq!(a.write(Time(u64::MAX), &mut [0; 96]), Err(Error::Deadline));
    Ok(())
}

#[test]
fn unfinished_handshakes_never_release_packet_roots() -> Result {
    let (a, _) = pair(Profile::Ik)?;
    assert!(a.finish(Time(1)).is_err());
    let (mut a, mut b) = pair(Profile::Ik)?;
    noise_only(&mut a, &mut b)?;
    assert!(a.finish(Time(1)).is_err() && b.finish(Time(1)).is_err());
    let (mut a, mut b) = pair(Profile::Ik)?;
    noise_only(&mut a, &mut b)?;
    receive(&mut b, &emit(&mut a)?)?;
    assert!(!b.is_complete() && b.finish(Time(1)).is_err());
    Ok(())
}

#[derive(Clone, Default)]
struct SpyRandom {
    calls: usize,
}

impl RngCore for SpyRandom {
    fn next_u32(&mut self) -> u32 {
        self.calls += 1;
        0
    }
    fn next_u64(&mut self) -> u64 {
        self.calls += 1;
        0
    }
    fn fill_bytes(&mut self, output: &mut [u8]) {
        self.calls += 1;
        output.fill(0);
    }
    fn try_fill_bytes(
        &mut self,
        _: &mut [u8],
    ) -> std::result::Result<(), clatter::rand_core::Error> {
        self.calls += 1;
        Err(std::num::NonZeroU32::MIN.into())
    }
}

impl CryptoRng for SpyRandom {}

#[test]
fn absent_explicit_ephemeral_fails_without_consulting_any_rng() -> Result {
    let mut spy = SpyRandom::default();
    assert!(CheckedX25519::genkey_rng(&mut spy).is_err());
    assert_eq!(spy.calls, 0);
    let static_key = SensitiveByteArray::new([11; 32]);
    let mut noise = Noise::new(
        noise_ik(),
        b"fixed-proof",
        true,
        Some(KeyPair::new(CheckedX25519::pubkey(&static_key), static_key)),
        None,
        Some(local(22).public_key().0),
        None,
    )
    .map_err(|_| Error::Crypto)?;
    assert!(noise.write_message(&[], &mut [0; 96]).is_err());
    Ok(())
}

#[test]
fn owned_key_and_psk_fields_use_maintained_zeroizing_storage() {
    fn has_drop_wipe<T: zeroize::ZeroizeOnDrop>() {}
    has_drop_wipe::<Zeroizing<[u8; 32]>>();
    let mut secret = local(11);
    secret.0.zeroize();
    assert_eq!(&*secret.0, &[0; 32]);
    let mut secret = Psk::new(Zeroizing::new([22; 32]));
    secret.0.zeroize();
    assert_eq!(&*secret.0, &[0; 32]);
}

fn emit_large(handshake: &mut Handshake) -> Result<(FlightKind, Vec<u8>)> {
    let mut output = vec![0xE7; MAX_INITIATION_BYTES + 1];
    let flight = handshake.write(Time(1), &mut output)?;
    assert_eq!(output[flight.bytes], 0xE7);
    Ok((flight.kind, output[..flight.bytes].to_vec()))
}

#[test]
fn initiation_payload_is_delivered_and_bound_by_the_context_confirmation() -> Result {
    for profile in [Profile::Ik, Profile::IkPsk2] {
        let (mut a, mut b) = pair(profile)?;
        let proposal = b"LT\x01\x00proposal bytes";
        a.set_initiation_payload(proposal)?;
        let first = emit_large(&mut a)?;
        assert_eq!(first.1.len(), 96 + proposal.len());
        // The payload is encrypted, never visible in the flight.
        assert!(!first.1.windows(proposal.len()).any(|w| w == proposal));
        receive(&mut b, &first)?;
        assert_eq!(b.initiation_payload(), proposal);
        // Message 2 needs the responder's verdict on the payload.
        assert_eq!(
            emit_large(&mut b).err().map(|e| e.to_string()),
            Some(Error::State.to_string())
        );
        b.set_response_payload(&[0])?;
        let second = emit_large(&mut b)?;
        assert_eq!(second.1.len(), 48 + 1);
        receive(&mut a, &second)?;
        assert_eq!(a.response_payload(), &[0]);
        // Neither side may confirm until it bound the derived context.
        assert_eq!(
            emit_large(&mut a).err().map(|e| e.to_string()),
            Some(Error::State.to_string())
        );
        assert!(!a.is_complete());
        a.set_confirmation_context([7; 32])?;
        b.set_confirmation_context([7; 32])?;
        let confirm = emit_large(&mut a)?;
        assert_eq!(confirm.1.len(), CONTEXT_CONFIRM_BYTES);
        receive(&mut b, &confirm)?;
        receive(&mut a, &emit_large(&mut b)?)?;
        assert!(a.is_complete() && b.is_complete());
        // The final-flight custody keeps the longer confirmation.
        let mut confirmed = a.finish_with_confirmation(Time(1))?;
        let mut output = [0; CONTEXT_CONFIRM_BYTES];
        let again = confirmed.confirmation.retransmit(Time(1), &mut output)?;
        assert_eq!(again.bytes, CONTEXT_CONFIRM_BYTES);
        assert_eq!(output.to_vec(), confirm.1);
        b.finish_with_confirmation(Time(1))?;
    }
    Ok(())
}

#[test]
fn differing_contexts_or_payload_rules_never_complete() -> Result {
    // Ends that derived different catalogs fail authentication.
    let (mut a, mut b) = pair(Profile::Ik)?;
    a.set_initiation_payload(b"choices")?;
    receive(&mut b, &emit_large(&mut a)?)?;
    b.set_response_payload(&[0])?;
    receive(&mut a, &emit_large(&mut b)?)?;
    a.set_confirmation_context([1; 32])?;
    b.set_confirmation_context([2; 32])?;
    let confirm = emit_large(&mut a)?;
    assert_eq!(
        b.read(Time(1), confirm.0, &confirm.1),
        Err(Error::Authentication)
    );
    assert!(b.next_flight().is_none());

    // A context without a payload, a responder payload, an oversized
    // payload, a late payload and a second context are refused.
    let (mut a, mut b) = pair(Profile::Ik)?;
    assert_eq!(
        a.set_confirmation_context([1; 32]),
        Err(Error::Configuration)
    );
    assert_eq!(b.set_initiation_payload(b"x"), Err(Error::Configuration));
    assert_eq!(
        a.set_initiation_payload(&[0; MAX_INITIATION_PAYLOAD + 1]),
        Err(Error::Configuration)
    );
    a.set_initiation_payload(&[9; MAX_INITIATION_PAYLOAD])?;
    let first = emit_large(&mut a)?;
    assert_eq!(first.1.len(), MAX_INITIATION_BYTES);
    assert_eq!(a.set_initiation_payload(b"late"), Err(Error::Configuration));
    receive(&mut b, &first)?;
    assert_eq!(b.initiation_payload().len(), MAX_INITIATION_PAYLOAD);
    b.set_confirmation_context([3; 32])?;
    assert_eq!(
        b.set_confirmation_context([3; 32]),
        Err(Error::Configuration)
    );
    // Verdict rules: responder only, nonempty, bounded, once, before message 2.
    assert_eq!(a.set_response_payload(&[0]), Err(Error::Configuration));
    assert_eq!(b.set_response_payload(&[]), Err(Error::Configuration));
    assert_eq!(
        b.set_response_payload(&[0; MAX_RESPONSE_PAYLOAD + 1]),
        Err(Error::Configuration)
    );
    b.set_response_payload(&[5; MAX_RESPONSE_PAYLOAD])?;
    assert_eq!(b.set_response_payload(&[5]), Err(Error::Configuration));
    let second = emit_large(&mut b)?;
    assert_eq!(second.1.len(), MAX_RESPONSE_BYTES);
    receive(&mut a, &second)?;
    assert_eq!(a.response_payload(), &[5; MAX_RESPONSE_PAYLOAD]);

    // An initiator that carried a payload refuses a message 2 without a
    // verdict, and one that did not refuses a message 2 with one.
    let (mut a, mut b) = pair(Profile::Ik)?;
    a.set_initiation_payload(b"choices")?;
    receive(&mut b, &emit_large(&mut a)?)?;
    let bare = (FlightKind::Response, vec![0; 48]);
    assert_eq!(a.read(Time(1), bare.0, &bare.1), Err(Error::Length));
    let (mut a, mut b) = pair(Profile::Ik)?;
    receive(&mut b, &emit_large(&mut a)?)?;
    assert_eq!(b.set_response_payload(&[0]), Err(Error::Configuration));
    let padded = (FlightKind::Response, vec![0; 49]);
    assert_eq!(a.read(Time(1), padded.0, &padded.1), Err(Error::Length));

    // A plain confirmation does not satisfy a context-bound peer.
    let (mut a, mut b) = pair(Profile::Ik)?;
    a.set_initiation_payload(b"choices")?;
    receive(&mut b, &emit_large(&mut a)?)?;
    b.set_response_payload(&[0])?;
    receive(&mut a, &emit_large(&mut b)?)?;
    b.set_confirmation_context([4; 32])?;
    let plain = (FlightKind::Confirmation, vec![0; PLAIN_CONFIRM_BYTES]);
    assert_eq!(b.read(Time(1), plain.0, &plain.1), Err(Error::Length));

    // Without a payload the handshake is byte-for-byte the original.
    let (mut a, mut b) = pair(Profile::Ik)?;
    let first = emit_large(&mut a)?;
    assert_eq!(first.1.len(), 96);
    receive(&mut b, &first)?;
    assert!(b.initiation_payload().is_empty());
    let second = emit_large(&mut b)?;
    assert_eq!(second.1.len(), 48);
    receive(&mut a, &second)?;
    assert!(a.response_payload().is_empty());
    let confirm = emit_large(&mut a)?;
    assert_eq!(confirm.1.len(), PLAIN_CONFIRM_BYTES);
    Ok(())
}
