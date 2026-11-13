use super::*;
use l2tunnel_security::{
    ConfigDigest, Epoch, LaneId, Limits, Metadata, Protection, Purpose, Role, SessionBinding,
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 {
        return Err(Error::InvalidKey.into());
    }
    let mut bytes = [0; N];
    for (destination, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *destination = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

// Public RFC8032 section7.1 test keys, never provisioning examples or real secrets.
fn vector(other: bool) -> Result<([u8; 32], [u8; 32])> {
    if other {
        Ok((
            unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")?,
            unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")?,
        ))
    } else {
        Ok((
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?,
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?,
        ))
    }
}

fn encoded(other: bool) -> Result<Vec<u8>> {
    let (seed, public) = vector(other)?;
    let mut bytes = unhex::<16>("3051020101300506032b657004220420")?.to_vec();
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&[0x81, 0x21, 0]);
    bytes.extend_from_slice(&public);
    Ok(bytes)
}

fn key(other: bool) -> Result<IdentityKey> {
    Ok(IdentityKey::from_pkcs8(&encoded(other)?)?)
}

fn context() -> Context {
    Context {
        session: SessionId([1; 16]),
        transcript: [2; 32],
        configuration: [3; 32],
        carrier: [4; 32],
        outer: [5; 32],
        initiator_noise: NoisePublicKey([8; 32]),
        responder_noise: NoisePublicKey([9; 32]),
    }
}

fn root(role: Role, context: Context) -> Result<SessionRoot> {
    Ok(SessionRoot::from_split_keys(
        Zeroizing::new([11; 32]),
        Zeroizing::new([22; 32]),
        SessionBinding {
            session: context.session,
            transcript: context.transcript,
        },
        role,
    )?)
}

fn pending(now: Time, deadline: Time) -> Result<ServerPending> {
    Ok(ServerPending::new(
        root(Role::Responder, context())?,
        context(),
        Allowlist::new(&[key(false)?.public_key()])?,
        now,
        deadline,
    )?)
}

fn limits() -> Limits {
    Limits {
        max_body_bytes: 1024,
        packets_per_key: 1 << 28,
        max_body_bytes_per_key: 1 << 40,
    }
}

#[test]
fn retained_ed25519_bytes_match_rfc8032_and_exact_generic_bounds() -> Result {
    let key = key(false)?;
    assert_eq!(key.public_key(), MemberPublicKey(vector(false)?.1));
    let signature = key.sign(&[])?;
    assert_eq!(
        signature,
        unhex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )?
    );
    verify_signature(key.public_key(), &[], &signature)?;
    let message = [0xA5; MAX_SIGNED_BYTES];
    let signed = key.sign(&message)?;
    verify_signature(key.public_key(), &message, &signed)?;
    assert_eq!(
        key.sign(&vec![0; MAX_SIGNED_BYTES + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        verify_signature(key.public_key(), &vec![0; MAX_SIGNED_BYTES + 1], &signed),
        Err(Error::TooLarge)
    );
    assert_eq!(
        verify_signature(key.public_key(), b"changed", &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        verify_signature(MemberPublicKey(vector(true)?.1), &[], &signature),
        Err(Error::InvalidSignature)
    );
    for length in (0..64).chain([65, 65_536]) {
        assert_eq!(
            verify_signature(key.public_key(), &[], &vec![0; length]),
            Err(Error::InvalidSignature)
        );
    }
    Ok(())
}

#[test]
fn retained_tls_and_https_domains_match_the_pre_extraction_ring_bytes() -> Result {
    let encoded = encoded(false)?;
    let member = IdentityKey::from_pkcs8(&encoded)?;
    // This is the maintained pre-extraction operation, used only as a reference.
    let legacy =
        ring::signature::Ed25519KeyPair::from_pkcs8(&encoded).map_err(|_| Error::InvalidKey)?;
    let mut challenge = [0; 113];
    for (index, byte) in challenge.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut prefix = [0; 97];
    prefix[..32].fill(7);
    prefix[32..64].copy_from_slice(&member.public_key().0);
    prefix[64] = 2;
    prefix[65..].fill(8);
    let mut signatures = Vec::new();
    for domain in [
        b"l2tunnel/member-auth/v1\0".as_slice(),
        b"l2tunnel/member-auth/quic/v1\0".as_slice(),
        b"l2tunnel/member-auth/openvpn-like/v1\0".as_slice(),
        b"l2tunnel/member-auth/https-h2/v1\0".as_slice(),
    ] {
        let mut transcript = domain.to_vec();
        transcript.extend_from_slice(&[6; 32]);
        transcript.extend_from_slice(&challenge);
        transcript.extend_from_slice(&prefix);
        let actual = member.sign(&transcript)?;
        assert_eq!(actual.as_slice(), legacy.sign(&transcript).as_ref());
        verify_signature(member.public_key(), &transcript, &actual)?;
        for earlier in &signatures {
            assert_ne!(&actual, earlier);
        }
        signatures.push(actual);
    }
    // Preserve the maximum current canonical HTTPS request transcript exactly,
    // including all length prefixes and the existing member/nonce prefix.
    let mut transcript = b"l2tunnel/https-h2-request/v1\0".to_vec();
    transcript.extend_from_slice(&[6; 32]);
    transcript.extend_from_slice(&[7; 32]);
    transcript.push(2);
    transcript.extend_from_slice(&[8; 32]);
    transcript.extend_from_slice(&[9; 32]);
    let authority = [b'a'; 255];
    let mut path = [b'a'; 512];
    path[0] = b'/';
    for field in [b"POST".as_slice(), &authority, &path] {
        transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    let mut request_prefix = [0; 65];
    request_prefix[0] = 1;
    request_prefix[1..33].copy_from_slice(&member.public_key().0);
    request_prefix[33..].fill(10);
    transcript.extend_from_slice(&request_prefix);
    assert_eq!(transcript.len(), 1000);
    assert!(transcript.len() <= MAX_SIGNED_BYTES);
    let actual = member.sign(&transcript)?;
    assert_eq!(actual.as_slice(), legacy.sign(&transcript).as_ref());
    verify_signature(member.public_key(), &transcript, &actual)?;
    Ok(())
}

#[test]
fn pkcs8_rejects_truncation_oversize_and_inconsistent_public_key() -> Result {
    let mut bytes = encoded(false)?;
    let original = bytes.clone();
    let _ = IdentityKey::from_pkcs8(&bytes)?;
    assert_eq!(bytes, original);
    for length in 0..bytes.len() {
        assert_eq!(
            IdentityKey::from_pkcs8(&bytes[..length]).err(),
            Some(Error::InvalidKey)
        );
    }
    assert_eq!(
        IdentityKey::from_pkcs8(&vec![0; MAX_PKCS8_BYTES + 1]).err(),
        Some(Error::InvalidKey)
    );
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        IdentityKey::from_pkcs8(&bytes).err(),
        Some(Error::InvalidKey)
    );
    Ok(())
}

#[test]
fn allowlist_preserves_legacy_bounds_sorting_and_deduplication() -> Result {
    let member = key(false)?.public_key();
    assert_eq!(Allowlist::new(&[]).err(), Some(Error::InvalidAllowlist));
    assert_eq!(
        Allowlist::new(&vec![member; MAX_MEMBERS + 1]).err(),
        Some(Error::InvalidAllowlist)
    );
    let repeated = Allowlist::new(&vec![member; MAX_MEMBERS])?;
    assert_eq!(repeated.0.len(), 1);
    assert!(repeated.contains(member));
    assert!(!repeated.contains(key(true)?.public_key()));
    let mut entries = Vec::new();
    for number in (0..MAX_MEMBERS as u32).rev() {
        let mut public = [0; 32];
        public[..4].copy_from_slice(&number.to_be_bytes());
        entries.push(MemberPublicKey(public));
    }
    let members = Allowlist::new(&entries)?;
    assert_eq!(members.0.len(), MAX_MEMBERS);
    assert!(entries.iter().all(|entry| members.contains(*entry)));
    Ok(())
}

#[test]
fn fixed_member_proof_is_deterministic_and_rejects_every_context_substitution() -> Result {
    let key = key(false)?;
    let members = Allowlist::new(&[key.public_key()])?;
    let proof = MemberProof::sign(&key, context())?;
    assert_eq!(proof.as_bytes().len(), MEMBER_PROOF_BYTES);
    assert_eq!(&proof.as_bytes()[..2], &[1, 1]);
    assert_eq!(
        proof.as_bytes(),
        MemberProof::sign(&key, context())?.as_bytes()
    );
    assert_eq!(
        verify_member(proof.as_bytes(), context(), &members)?,
        key.public_key()
    );
    for field in 0..8 {
        let mut wrong = context();
        match field {
            0 => wrong.session.0[0] ^= 1,
            1 => wrong.transcript[0] ^= 1,
            2 => wrong.configuration[0] ^= 1,
            3 => wrong.carrier[0] ^= 1,
            4 => wrong.outer[0] ^= 1,
            5 => wrong.initiator_noise.0[0] ^= 1,
            6 => wrong.responder_noise.0[0] ^= 1,
            _ => std::mem::swap(&mut wrong.initiator_noise, &mut wrong.responder_noise),
        }
        assert_eq!(
            verify_member(proof.as_bytes(), wrong, &members),
            Err(Error::InvalidSignature)
        );
    }
    let mut reflected = context();
    reflected.responder_noise = reflected.initiator_noise;
    assert_eq!(
        MemberProof::sign(&key, reflected).err(),
        Some(Error::BindingMismatch)
    );
    assert_eq!(
        verify_member(proof.as_bytes(), reflected, &members),
        Err(Error::BindingMismatch)
    );
    Ok(())
}

#[test]
fn proof_parser_and_possession_reject_wrong_roles_members_and_signatures() -> Result {
    let member = key(false)?;
    let members = Allowlist::new(&[member.public_key()])?;
    let proof = MemberProof::sign(&member, context())?;
    for length in (0..MEMBER_PROOF_BYTES).chain([MEMBER_PROOF_BYTES + 1, 65_536]) {
        assert_eq!(
            MemberProof::from_bytes(&vec![0; length]).err(),
            Some(Error::InvalidProof)
        );
        assert!(
            pending(Time(0), Time(100))?
                .accept(Time(1), &vec![0; length])
                .is_err()
        );
    }
    for index in [0, 1] {
        for value in [0, 2, 255] {
            let mut wrong = *proof.as_bytes();
            wrong[index] = value;
            assert_eq!(
                verify_member(&wrong, context(), &members),
                Err(Error::InvalidProof)
            );
            assert!(
                pending(Time(0), Time(100))?
                    .accept(Time(1), &wrong)
                    .is_err()
            );
        }
    }
    let other = MemberProof::sign(&key(true)?, context())?;
    assert_eq!(
        verify_member(other.as_bytes(), context(), &members),
        Err(Error::MemberDenied)
    );
    let mut forged = *proof.as_bytes();
    forged[PROOF_PREFIX..].copy_from_slice(&other.as_bytes()[PROOF_PREFIX..]);
    assert_eq!(
        verify_member(&forged, context(), &members),
        Err(Error::InvalidSignature)
    );
    assert!(
        pending(Time(0), Time(100))?
            .accept(Time(1), &forged)
            .is_err()
    );
    let prefix: [u8; PROOF_PREFIX] = proof.as_bytes()[..PROOF_PREFIX].try_into()?;
    let signed = context().signed(&prefix);
    assert_eq!(
        verify_signature(
            member.public_key(),
            &signed[DOMAIN.len()..],
            &proof.as_bytes()[PROOF_PREFIX..]
        ),
        Err(Error::InvalidSignature)
    );
    Ok(())
}

#[test]
fn pending_root_checks_binding_and_original_deadline_without_data_release() -> Result {
    let member = key(false)?;
    let proof = MemberProof::sign(&member, context())?;
    assert_eq!(
        ServerPending::new(
            root(Role::Initiator, context())?,
            context(),
            Allowlist::new(&[member.public_key()])?,
            Time(0),
            Time(100)
        )
        .err(),
        Some(Error::BindingMismatch)
    );
    for field in 0..2 {
        let mut wrong = context();
        if field == 0 {
            wrong.session.0[0] ^= 1;
        } else {
            wrong.transcript[0] ^= 1;
        }
        assert_eq!(
            ServerPending::new(
                root(Role::Responder, context())?,
                wrong,
                Allowlist::new(&[member.public_key()])?,
                Time(0),
                Time(100)
            )
            .err(),
            Some(Error::BindingMismatch)
        );
    }
    assert_eq!(
        pending(Time(100), Time(100))
            .err()
            .map(|error| error.to_string()),
        Some(Error::Deadline.to_string())
    );
    for now in [Time(9), Time(100), Time(u64::MAX)] {
        assert_eq!(
            pending(Time(10), Time(100))?
                .accept(now, proof.as_bytes())
                .err(),
            Some(Error::Deadline)
        );
    }
    let gate = pending(Time(0), Time(100))?;
    assert_eq!(gate.deadline(), Time(100));
    let accepted = gate.accept(Time(99), proof.as_bytes())?;
    assert_eq!(accepted.member, member.public_key());
    let accepted = pending(Time(u64::MAX - 1), Time(u64::MAX))?
        .accept(Time(u64::MAX - 1), proof.as_bytes())?;
    assert_eq!(accepted.member, member.public_key());
    Ok(())
}

#[test]
fn protected_joining_works_while_gate_holds_root_and_owners_survive_release() -> Result {
    let member = key(false)?;
    let context = context();
    let mut client = root(Role::Initiator, context)?;
    let mut server = root(Role::Responder, context)?;
    let mut joining_send = client.sender(
        Purpose::Joining,
        LaneId(0),
        limits(),
        Protection::ChaCha20Poly1305,
    )?;
    let mut joining_receive = server.receiver(
        Purpose::Joining,
        LaneId(0),
        limits(),
        Protection::ChaCha20Poly1305,
    )?;
    let _joining_accept = server.sender(
        Purpose::Joining,
        LaneId(0),
        limits(),
        Protection::ChaCha20Poly1305,
    )?;
    let gate = ServerPending::new(
        server,
        context,
        Allowlist::new(&[member.public_key()])?,
        Time(0),
        Time(100),
    )?;
    let proof = MemberProof::sign(&member, context)?;
    let metadata = Metadata {
        epoch: Epoch(0),
        configuration: ConfigDigest(context.configuration),
        extra: b"member joining v1",
    };
    let mut wire = [0; 256];
    let sealed = joining_send.seal(metadata, proof.as_bytes(), &mut wire)?;
    let mut workspace = [0; 256];
    let opened = joining_receive.open(metadata, &wire[..sealed.bytes], &mut workspace)?;
    let mut authenticated = gate.accept(Time(1), &workspace[..opened.bytes])?;
    assert_eq!(authenticated.member, member.public_key());
    assert_eq!(
        authenticated
            .root
            .receiver(
                Purpose::Joining,
                LaneId(0),
                limits(),
                Protection::ChaCha20Poly1305
            )
            .err(),
        Some(l2tunnel_security::Error::DomainInUse)
    );
    assert_eq!(
        authenticated
            .root
            .sender(
                Purpose::Joining,
                LaneId(0),
                limits(),
                Protection::ChaCha20Poly1305
            )
            .err(),
        Some(l2tunnel_security::Error::DomainInUse)
    );
    let mut send = authenticated.root.sender(
        Purpose::Data,
        LaneId(0),
        limits(),
        Protection::ChaCha20Poly1305,
    )?;
    let mut receive = client.receiver(
        Purpose::Data,
        LaneId(0),
        limits(),
        Protection::ChaCha20Poly1305,
    )?;
    let sealed = send.seal(metadata, b"admitted opaque user bytes", &mut wire)?;
    let opened = receive.open(metadata, &wire[..sealed.bytes], &mut workspace)?;
    assert_eq!(&workspace[..opened.bytes], b"admitted opaque user bytes");
    Ok(())
}
