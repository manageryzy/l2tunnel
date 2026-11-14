//! Pure maintained-Noise/member/covered-record composition. No runtime recovery,
//! fragmented lifecycle stream or native/transaction debt preservation is implied.
use hs::{Entropy, EntropyError, FlightKind, Handshake, LocalSecret, Profile, Psk, Time, refresh};
use l2tunnel::{
    cover, handshake as hs, identity,
    secure_record::{self as records, Class, Records, Scope},
    security as sec,
};
use sec::{ConfigDigest, Epoch, LaneId, Limits, PacketNumber, Protection, Role, SessionId};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct TestEntropy(u8);
impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), EntropyError> {
        output.fill(self.0);
        Ok(())
    }
}
fn local(byte: u8) -> LocalSecret {
    LocalSecret::new(Zeroizing::new([byte; 32]))
}
fn psk(profile: Profile) -> Option<Psk> {
    (profile == Profile::IkPsk2).then(|| Psk::new(Zeroizing::new([0x53; 32])))
}
fn scope(epoch: u64, byte: u8) -> Scope {
    Scope {
        epoch: Epoch(epoch),
        configuration: ConfigDigest([byte; 32]),
    }
}
fn selected(protection: Protection) -> Result<refresh::Selection> {
    Ok(refresh::Selection::new(refresh::SelectionSpec {
        lane: LaneId(7),
        limits: Limits {
            max_body_bytes: 512,
            packets_per_key: 4,
            max_body_bytes_per_key: 4096,
        },
        protection,
        control_epoch: Epoch(9),
        control_digest: ConfigDigest([3; 32]),
        envelope_digest: ConfigDigest([0xE1; 32]),
        exchange_micros: 1_000,
        key_micros: 10_000,
        overlap_micros: 20,
        max_flight_copies: 4,
    })?)
}
fn covers(appearance: cover::Appearance) -> Result<[cover::Config; 2]> {
    let make = |a, b| {
        cover::Config::new(
            appearance,
            cover::ConnectionIds {
                local: cover::ConnectionId([a; 8]),
                peer: cover::ConnectionId([b; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(u32::from(a)),
                peer_ssrc: cover::Ssrc(u32::from(b)),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1200,
                max_protected_bytes: 1100,
            },
        )
    };
    Ok([make(11, 22)?, make(22, 11)?])
}
fn outer(number: u32, phase: cover::Phase) -> cover::PacketMeta {
    cover::PacketMeta {
        phase,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number),
    }
}
fn initial_pair(
    selection: refresh::Selection,
    profile: Profile,
) -> Result<[refresh::ConfirmedInitial; 2]> {
    let binding = hs::Binding {
        session: SessionId([1; 16]),
        configuration: [2; 32],
        carrier: [3; 32],
        outer: [4; 32],
        member: [5; 32],
    };
    let make = |role, own, peer| {
        Handshake::new_refreshable(
            hs::Config {
                role,
                profile,
                binding,
                deadline: Time(200),
            },
            selection,
            local(own),
            local(peer).public_key(),
            psk(profile),
            Time(0),
            &mut TestEntropy(own + 20),
        )
    };
    let mut a = make(Role::Initiator, 11, 22)?;
    let mut b = make(Role::Responder, 22, 11)?;
    let mut buffer = [0; 256];
    let first = a.write(Time(1), &mut buffer)?;
    b.read(Time(1), first.kind, &buffer[..first.bytes])?;
    let second = b.write(Time(1), &mut buffer)?;
    a.read(Time(1), second.kind, &buffer[..second.bytes])?;
    let a_final = a.write(Time(2), &mut buffer)?;
    let first = buffer[..a_final.bytes].to_vec();
    let b_final = b.write(Time(2), &mut buffer)?;
    let second = buffer[..b_final.bytes].to_vec();
    b.read(Time(2), a_final.kind, &first)?;
    a.read(Time(2), b_final.kind, &second)?;
    let a = a.finish_refreshable_with_confirmation(Time(3))?;
    let b = b.finish_refreshable_with_confirmation(Time(3))?;
    assert_eq!(a.initial.binding(), b.initial.binding());
    assert_eq!(a.initial.authenticated(), b.initial.authenticated());
    Ok([a.initial, b.initial])
}
fn member_key() -> Result<identity::IdentityKey> {
    // Public RFC8032 section7.1 test key, not provisioning or runtime entropy.
    let encoded = "3051020101300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\
                   812100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let mut bytes = Vec::new();
    for pair in encoded.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn member_context(initial: &refresh::ConfirmedInitial) -> identity::Context {
    let binding = initial.authenticated();
    let pins = initial.pins();
    identity::Context {
        session: initial.binding().session,
        transcript: initial.binding().transcript,
        configuration: binding.configuration,
        carrier: binding.carrier,
        outer: binding.outer,
        initiator_noise: identity::NoisePublicKey(pins.0.0),
        responder_noise: identity::NoisePublicKey(pins.1.0),
    }
}
fn joining_wire(config: cover::Config, raw: &[u8]) -> Result<Vec<u8>> {
    let mut protected = vec![3];
    protected.extend_from_slice(raw);
    let mut packet = [0; 1200];
    let n = config.encode(outer(0, cover::Phase::Established), &protected, &mut packet)?;
    Ok(packet[..n].to_vec())
}
fn joining_raw(config: cover::Config, packet: &[u8]) -> Result<&[u8]> {
    let protected = config.decode(packet)?.protected;
    assert_eq!(protected.first(), Some(&3));
    Ok(protected.get(1..).ok_or("joining route missing")?)
}
fn members(
    initial: [refresh::ConfirmedInitial; 2],
    cover: [cover::Config; 2],
) -> Result<[refresh::ConfirmedInitial; 2]> {
    let [a, b] = initial;
    let member = member_key()?;
    let context = member_context(&a);
    assert_eq!(context, member_context(&b));
    let proof = identity::MemberProof::sign(&member, context)?;
    let allowlist = identity::Allowlist::new(&[member.public_key()])?;
    let joining_limits = a.selection().spec().limits;
    let mut a = a.joining(joining_limits, Time(4), Time(190))?;
    let mut b = b.joining(joining_limits, Time(4), Time(190))?;
    let mut raw = [0; 1024];
    let mut plain = [0; 1024];
    let n = a.seal(Time(5), proof.as_bytes(), &mut raw)?.bytes;
    let proof_wire = joining_wire(cover[0], &raw[..n])?;
    let mut retry = [0; 1024];
    let retry_n = a.retransmit(Time(6), &mut retry)?;
    assert_eq!(&retry[..retry_n], &raw[..n]);
    let opened = b.open(Time(6), joining_raw(cover[1], &proof_wire)?, &mut plain)?;
    let admitted = identity::verify_member(&plain[..opened.bytes], context, &allowlist)?;
    assert_eq!(admitted, member.public_key());
    let mut mismatched = context;
    mismatched.transcript[0] ^= 1;
    assert!(identity::verify_member(&plain[..opened.bytes], mismatched, &allowlist).is_err());
    assert!(
        identity::verify_member(
            &plain[..opened.bytes],
            context,
            &identity::Allowlist::new(&[identity::MemberPublicKey([0x55; 32])])?
        )
        .is_err()
    );
    let mut accept = [0; 34];
    accept[..2].copy_from_slice(&[1, 2]);
    accept[2..].copy_from_slice(&admitted.0);
    let n = b.seal(Time(7), &accept, &mut raw)?.bytes;
    let accept_wire = joining_wire(cover[1], &raw[..n])?;
    let opened = a.open(Time(7), joining_raw(cover[0], &accept_wire)?, &mut plain)?;
    assert_eq!(&plain[..opened.bytes], accept);
    Ok([a.retire(Time(8))?, b.retire(Time(8))?])
}
fn records(
    appearance: cover::Appearance,
    protection: Protection,
    profile: Profile,
) -> Result<([Records; 2], [cover::Config; 2])> {
    let selection = selected(protection)?;
    let cover = covers(appearance)?;
    let [a, b] = members(initial_pair(selection, profile)?, cover)?;
    let s = selection.spec();
    let make = |initial, cover| {
        Records::new_refreshable(
            initial,
            s.lane,
            s.limits,
            protection,
            cover,
            scope(9, 3),
            scope(10, 4),
            Time(9),
            Time(20_000),
        )
    };
    Ok(([make(a, cover[0])?, make(b, cover[1])?], cover))
}
fn seal(
    owner: &mut Records,
    class: Class,
    now: u64,
    body: &[u8],
) -> Result<(records::refresh::Sealed, Vec<u8>)> {
    let mut workspace = [0; 1200];
    let mut packet = [0; 1200];
    let out = owner.seal_at(
        Time(now),
        class,
        outer(now as u32, cover::Phase::Established),
        body,
        &mut workspace,
        &mut packet,
    )?;
    Ok((out, packet[..out.record.bytes].to_vec()))
}
fn open(
    owner: &mut Records,
    now: u64,
    packet: &[u8],
) -> Result<(records::refresh::Opened, Vec<u8>)> {
    let mut workspace = [0; 1200];
    let mut plain = [0; 512];
    let opened = owner.open_at(Time(now), packet, &mut workspace, &mut plain)?;
    Ok((opened, plain[..opened.record.bytes].to_vec()))
}
fn request(
    a: &mut Records,
    b: &mut Records,
) -> Result<(sec::refresh::Admission, sec::refresh::Admission)> {
    let started = a.begin_refresh(Time(20), Time(900))?;
    let mut workspace = [0; 1200];
    let mut packet = [0; 1200];
    let sealed = a.seal_refresh_request(
        &started.request,
        Time(21),
        outer(21, cover::Phase::Established),
        &mut workspace,
        &mut packet,
    )?;
    let admission = match b.open_refresh_request(
        &packet[..sealed.bytes],
        Time(21),
        Time(900),
        &mut workspace,
    )? {
        sec::refresh::RequestOutcome::New(value) => value,
        sec::refresh::RequestOutcome::Duplicate => return Err("initial request duplicate".into()),
    };
    // The same immutable request can be resent under a fresh old-key number,
    // but the authenticated duplicate never grants a second exchange owner.
    let sealed = a.seal_refresh_request(
        &started.request,
        Time(22),
        outer(22, cover::Phase::Established),
        &mut workspace,
        &mut packet,
    )?;
    assert!(matches!(
        b.open_refresh_request(
            &packet[..sealed.bytes],
            Time(22),
            Time(50_000),
            &mut workspace
        )?,
        sec::refresh::RequestOutcome::Duplicate
    ));
    assert_eq!(admission.deadline(), sec::refresh::Tick(900));
    Ok((started.admission, admission))
}
fn exchange(
    admission: sec::refresh::Admission,
    role: Role,
    profile: Profile,
) -> Result<refresh::Exchange> {
    let (own, peer, entropy) = if role == Role::Initiator {
        (11, 22, 61)
    } else {
        (22, 11, 62)
    };
    Ok(refresh::Exchange::new(
        admission,
        local(own),
        local(peer).public_key(),
        psk(profile),
        Time(30),
        &mut TestEntropy(entropy),
    )?)
}
fn flight(
    sender: &mut refresh::Exchange,
    sender_cover: cover::Config,
    receiver_cover: cover::Config,
    now: u64,
) -> Result<Vec<u8>> {
    let mut raw = [0; 256];
    let emitted = sender.write(Time(now), &mut raw)?;
    let mut packet = [0; 1200];
    let n = sender_cover.encode(
        outer(now as u32, cover::Phase::Handshake),
        &raw[..emitted.bytes],
        &mut packet,
    )?;
    let decoded = receiver_cover.decode(&packet[..n])?;
    assert_eq!(decoded.phase, cover::Phase::Handshake);
    Ok(decoded.protected.to_vec())
}

#[test]
fn actual_member_noise_refresh_preserves_numbers_replay_and_scope_under_final_loss() -> Result {
    // Four finite compositions exercise both covers/protections/profiles; they
    // do not qualify the broader runtime/full loss and retained-state matrix.
    for (appearance, protection, profile) in [
        (
            cover::Appearance::QuicLike,
            Protection::ChaCha20Poly1305,
            Profile::Ik,
        ),
        (
            cover::Appearance::MediaLike,
            Protection::ChaCha20Poly1305,
            Profile::IkPsk2,
        ),
        (
            cover::Appearance::QuicLike,
            Protection::HmacSha256,
            Profile::IkPsk2,
        ),
        (
            cover::Appearance::MediaLike,
            Protection::HmacSha256,
            Profile::Ik,
        ),
    ] {
        let ([mut a, mut b], cover) = records(appearance, protection, profile)?;
        let old_scope = a.active_data();
        let staged = scope(11, 5);
        a.stage_data(staged)?;
        b.stage_data(staged)?;
        // This exercises the existing local scope registry, not a negotiated
        // mode transaction. Refresh must not alter either scope disposition.
        a.activate_data(staged)?;
        b.activate_data(staged)?;
        let reader = a.additional_data();
        let (_, first) = seal(&mut a, Class::User, 10, b"old delivered")?;
        assert_eq!(open(&mut b, 10, &first)?.1, b"old delivered");
        let (_, delayed_old) = seal(&mut a, Class::User, 11, b"old delayed")?;
        let (_, retired_old) = seal(&mut a, Class::User, 12, b"old after retirement")?;
        let (aa, ba) = request(&mut a, &mut b)?;
        // Old data and management continue beyond the request snapshot, so
        // bases must be chosen at actual activation rather than request time.
        for now in 23..26 {
            let (_, packet) = seal(&mut a, Class::Control, now, b"old control")?;
            assert_eq!(open(&mut b, now, &packet)?.1, b"old control");
        }
        let (mut ax, mut bx) = (
            exchange(aa, Role::Initiator, profile)?,
            exchange(ba, Role::Responder, profile)?,
        );
        let init = flight(&mut ax, cover[0], cover[1], 31)?;
        bx.read(Time(31), &init)?;
        assert_eq!(bx.read(Time(31), &init)?, hs::ReadOutcome::Duplicate);
        let response = flight(&mut bx, cover[1], cover[0], 32)?;
        ax.read(Time(32), &response)?;
        let a_final = flight(&mut ax, cover[0], cover[1], 33)?;
        let b_final = flight(&mut bx, cover[1], cover[0], 33)?;
        bx.read(Time(33), &a_final)?;
        assert!(bx.is_complete());
        assert!(!ax.is_complete());
        let complete_b = bx.finish_with_confirmation(Time(34))?;
        let mut b_cache = complete_b.confirmation;
        let prepared_b = b.prepare_refresh(complete_b.material, Time(34))?;
        b.activate_refresh(&prepared_b, Time(35))?;
        // The responder already released the actual exchange/activated keys.
        // Its exact saved final flight still completes the incomplete initiator.
        let mut retry = [0; 256];
        let copied = b_cache.retransmit(Time(36), &mut retry)?;
        assert_eq!(copied.kind, FlightKind::Confirmation);
        assert_eq!(&retry[..copied.bytes], b_final);
        ax.read(Time(36), &retry[..copied.bytes])?;
        let complete_a = ax.finish_with_confirmation(Time(37))?;
        let prepared_a = a.prepare_refresh(complete_a.material, Time(37))?;
        let before = [a.next_number(Class::User), a.next_number(Class::Control)];
        let activation = a.activate_refresh(&prepared_a, Time(38))?;
        assert_eq!(activation.bases, before);
        assert!(activation.bases[1].0 > 2);
        assert_eq!(a.next_number(Class::User), before[0]);
        assert_eq!(
            a.abort_refresh(activation.target, Time(38)),
            Err(records::Error::Refresh(sec::refresh::Error::State))
        );
        assert_eq!(a.active_data(), staged);
        assert_eq!(a.additional_data(), reader);
        assert_eq!(a.control_scope(), scope(9, 3));
        let mut workspace = [0; 1200];
        let mut packet = [0; 1200];
        // First new data is lost; later adjacent generation still works.
        seal(&mut a, Class::User, 39, b"new lost")?;
        let (_, new_packet) = seal(&mut a, Class::User, 40, b"new delivered")?;
        assert_eq!(open(&mut b, 40, &new_packet)?.1, b"new delivered");
        let delayed = open(&mut b, 41, &delayed_old)?;
        assert_eq!(delayed.1, b"old delayed");
        assert_eq!(delayed.0.key_epoch, sec::refresh::KeyEpoch(0));
        assert_eq!(
            b.open_at(Time(42), &first, &mut [0; 1200], &mut [0; 512]),
            Err(records::Error::Refresh(sec::refresh::Error::Protection(
                sec::Error::Replay
            )))
        );
        let an = a
            .seal_refresh_activation(
                Time(43),
                outer(43, cover::Phase::Established),
                &mut workspace,
                &mut packet,
            )?
            .bytes;
        assert_eq!(
            b.open_refresh_activation(&packet[..an], Time(43), &mut workspace)?,
            sec::refresh::ActivationOutcome::Accepted
        );
        let bn = b
            .seal_refresh_activation(
                Time(44),
                outer(44, cover::Phase::Established),
                &mut workspace,
                &mut packet,
            )?
            .bytes;
        assert_eq!(
            a.open_refresh_activation(&packet[..bn], Time(44), &mut workspace)?,
            sec::refresh::ActivationOutcome::Accepted
        );
        assert_eq!(
            a.retire_refresh(activation.target, Time(45)),
            Err(records::Error::Refresh(sec::refresh::Error::OverlapActive))
        );
        a.retire_refresh(activation.target, Time(60))?;
        b.retire_refresh(activation.target, Time(60))?;
        assert_eq!(a.additional_key_epoch()?, None);
        assert_eq!(b.additional_key_epoch()?, None);
        assert_eq!(a.active_data(), staged);
        assert_eq!(a.additional_data(), reader);
        for now in 61..69 {
            let (sent, packet) = seal(&mut a, Class::User, now, b"same logical stream")?;
            let (opened, payload) = open(&mut b, now, &packet)?;
            assert_eq!(opened.record.number, sent.record.number);
            assert_eq!(payload, b"same logical stream");
            assert_eq!(opened.key_epoch, sec::refresh::KeyEpoch(1));
        }
        assert_eq!(a.active_data().epoch, Epoch(11));
        assert_eq!(old_scope.epoch, Epoch(10));
        assert_eq!(a.next_number(Class::User), PacketNumber(before[0].0 + 10));
        assert_eq!(
            b.open_at(Time(70), &retired_old, &mut [0; 1200], &mut [0; 512]),
            Err(records::Error::Refresh(sec::refresh::Error::Retired))
        );
        let (_, reverse) = seal(&mut b, Class::User, 71, b"reverse actual fresh key")?;
        assert_eq!(open(&mut a, 71, &reverse)?.1, b"reverse actual fresh key");
    }
    Ok(())
}

#[test]
fn selected_facade_never_bypasses_key_deadline_through_legacy_or_bad_outer_input() -> Result {
    let ([mut a, _], _) = records(
        cover::Appearance::QuicLike,
        Protection::ChaCha20Poly1305,
        Profile::Ik,
    )?;
    let mut workspace = [0; 1200];
    let mut packet = [0; 1200];
    assert_eq!(
        a.seal(
            Class::User,
            outer(1, cover::Phase::Established),
            b"untimed",
            &mut workspace,
            &mut packet
        ),
        Err(records::Error::Refresh(sec::refresh::Error::Mode))
    );
    let started = a.begin_refresh(Time(20), Time(30))?;
    assert_eq!(started.admission.deadline(), sec::refresh::Tick(30));
    // Expiry wins over malformed cover/short workspace and then remains terminal.
    assert_eq!(
        a.open_at(Time(30), &[], &mut [], &mut []),
        Err(records::Error::Refresh(sec::refresh::Error::Deadline))
    );
    assert_eq!(
        a.abort_refresh(sec::refresh::KeyEpoch(1), Time(29)),
        Err(records::Error::Refresh(sec::refresh::Error::State))
    );
    assert_eq!(a.next_number(Class::User), PacketNumber(0));
    Ok(())
}
