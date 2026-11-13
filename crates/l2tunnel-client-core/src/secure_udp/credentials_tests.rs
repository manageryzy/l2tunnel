use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn noise(profile: hs::Profile) -> io::Result<NoiseIdentity> {
    let peer = hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key();
    NoiseIdentity::new(
        Zeroizing::new([11; 32]),
        peer,
        profile,
        (profile == hs::Profile::IkPsk2).then(|| Zeroizing::new([33; 32])),
    )
}
fn secret(value: u8) -> io::Result<Secret32> {
    Secret32::new(Zeroizing::new([value; 32]))
}

#[test]
fn fixed_credentials_preserve_distinct_identities_and_fresh_consuming_attempts() -> Result {
    for profile in [hs::Profile::Ik, hs::Profile::IkPsk2] {
        let identity = noise(profile)?;
        let first = identity.attempt();
        let second = identity.attempt();
        assert_eq!(first.local.public_key(), second.local.public_key());
        assert_eq!(first.peer, identity.peer());
        assert_eq!(first.psk.is_some(), profile == hs::Profile::IkPsk2);
        assert_eq!(
            identity.peers(Role::Initiator).initiator,
            identity.public_key()
        );
        assert_eq!(identity.peers(Role::Responder).initiator, identity.peer());
        let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
        let member = identity::IdentityKey::from_pkcs8(&encoded)?;
        let public = member.public_key();
        let client = Client::new(identity, member, secret(44)?)?;
        assert_eq!(client.member_key(), public);
        assert_eq!(client.member().public_key(), public);
        let _ = client.admission();
        let server = Server::new(noise(profile)?, secret(44)?, secret(55)?)?;
        let _ = (server.admission(), server.cookie());
    }
    Ok(())
}

#[test]
fn missing_psk_zero_self_pin_and_overlapping_purpose_credentials_fail() -> Result {
    let peer = hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key();
    assert!(NoiseIdentity::new(Zeroizing::new([0; 32]), peer, hs::Profile::Ik, None).is_err());
    assert!(
        NoiseIdentity::new(
            Zeroizing::new([11; 32]),
            hs::PeerKey([0; 32]),
            hs::Profile::Ik,
            None
        )
        .is_err()
    );
    let own = hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key();
    assert!(NoiseIdentity::new(Zeroizing::new([11; 32]), own, hs::Profile::Ik, None).is_err());
    assert!(NoiseIdentity::new(Zeroizing::new([11; 32]), peer, hs::Profile::IkPsk2, None).is_err());
    assert!(
        NoiseIdentity::new(
            Zeroizing::new([11; 32]),
            peer,
            hs::Profile::Ik,
            Some(Zeroizing::new([33; 32]))
        )
        .is_err()
    );
    for psk in [0, 11] {
        assert!(
            NoiseIdentity::new(
                Zeroizing::new([11; 32]),
                peer,
                hs::Profile::IkPsk2,
                Some(Zeroizing::new([psk; 32]))
            )
            .is_err()
        );
    }
    assert!(secret(0).is_err());
    for (admission, cookie) in [(44, 44), (11, 55), (44, 11), (33, 55), (44, 33)] {
        assert!(
            Server::new(
                noise(hs::Profile::IkPsk2)?,
                secret(admission)?,
                secret(cookie)?
            )
            .is_err()
        );
    }
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    assert!(Client::new(noise(hs::Profile::IkPsk2)?, member, secret(11)?).is_err());
    Ok(())
}

#[cfg(unix)]
mod files {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-secure-credentials-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }
        fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .write_all(bytes)?;
            Ok(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exact_files_reject_wrong_modes_lengths_symlinks_and_special_files() -> Result {
        let directory = Temp::new()?;
        let path = directory.write("private", &[7; 32])?;
        assert_eq!(*read_secret(&path)?, [7; 32]);
        for length in [0, 1, 31, 33, 64, 4096] {
            std::fs::write(&path, vec![7; length])?;
            assert!(read_secret(&path).is_err());
        }
        std::fs::write(&path, [7; 32])?;
        for mode in [0o604, 0o640, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            assert!(read_secret(&path).is_err());
        }
        // Public pins may be shared read-only; private keys may not.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(read_public(&path)?, [7; 32]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let link = directory.0.join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(read_secret(&link).is_err());
        assert!(read_public(&link).is_err());
        assert!(read_secret(&directory.0).is_err());
        assert!(read_secret(std::path::Path::new("/dev/null")).is_err());
        let fifo = directory.0.join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        assert!(read_secret(&fifo).is_err());
        assert!(private_permissions(1000, 0o100600, 1000));
        assert!(!private_permissions(1001, 0o100600, 1000));
        assert!(!private_permissions(1000, 0o100640, 1000));
        Ok(())
    }

    #[test]
    fn member_pkcs8_is_unchanged_and_bounded_before_parsing() -> Result {
        let directory = Temp::new()?;
        let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
        let expected = identity::IdentityKey::from_pkcs8(&encoded)?.public_key();
        let path = directory.write("member", &encoded)?;
        assert_eq!(read_member(&path)?.public_key(), expected);
        for length in [0, 32, 4097] {
            std::fs::write(&path, vec![1; length])?;
            assert!(read_member(&path).is_err());
        }
        Ok(())
    }
}
