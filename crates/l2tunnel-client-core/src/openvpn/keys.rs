//! Explicit Linux key-file provisioning using opened-descriptor metadata.
use super::{KeyBundle, invalid};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// Load exactly 64 bytes from an owned, private regular file. Final symlinks,
/// special files and group/world permission bits are rejected before reading.
pub fn read(path: &Path) -> io::Result<KeyBundle> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "key file must be private regular file owned by effective user",
        ));
    }
    let mut bytes = Zeroizing::new([0; 65]);
    let mut reader = file.take(65);
    let mut length = 0;
    loop {
        let read = reader.read(&mut bytes[length..])?;
        if read == 0 {
            break;
        }
        length += read;
        if length == 65 {
            break;
        }
    }
    if length != 64 {
        return Err(invalid("key file must contain exactly 64 raw bytes"));
    }
    let mut bundle = Zeroizing::new([0; 64]);
    bundle.copy_from_slice(&bytes[..64]);
    KeyBundle::from_bytes(*bundle)
}
fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
/// Exclusively create independent admission and server-only cookie bundles.
/// Partial new files remain for inspection on failure. No secret is printed.
pub fn generate(admission: &Path, cookie: &Path) -> io::Result<()> {
    use ring::rand::SecureRandom;
    if admission == cookie {
        return Err(invalid("key output paths must differ"));
    }
    let random = ring::rand::SystemRandom::new();
    let mut first = Zeroizing::new([0; 64]);
    let mut second = Zeroizing::new([0; 64]);
    random
        .fill(&mut *first)
        .map_err(|_| io::Error::other("key generation failed"))?;
    random
        .fill(&mut *second)
        .map_err(|_| io::Error::other("key generation failed"))?;
    let a = KeyBundle::from_bytes(*first)?;
    let b = KeyBundle::from_bytes(*second)?;
    if a.overlaps(&b) {
        return Err(io::Error::other("independent key generation failed"));
    }
    let mut a_file = create(admission)?;
    a_file.write_all(&*first)?;
    a_file.sync_all()?;
    let mut b_file = create(cookie)?;
    b_file.write_all(&*second)?;
    b_file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "l2tunnel-keys-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn generation_is_private_independent_and_never_overwrites() -> io::Result<()> {
        let dir = Temp::new()?;
        let a = dir.0.join("a");
        let b = dir.0.join("b");
        generate(&a, &b)?;
        let first = read(&a)?;
        let second = read(&b)?;
        assert!(!first.overlaps(&second));
        assert_eq!(std::fs::metadata(&a)?.mode() & 0o077, 0);
        let before = std::fs::read(&a)?;
        assert!(generate(&a, &b).is_err());
        assert_eq!(std::fs::read(&a)?, before);
        assert!(generate(&a, &a).is_err());
        Ok(())
    }
    #[test]
    fn exact_lengths_modes_symlinks_and_special_files_are_rejected() -> io::Result<()> {
        let dir = Temp::new()?;
        let a = dir.0.join("a");
        let b = dir.0.join("b");
        generate(&a, &b)?;
        let original = std::fs::read(&a)?;
        for length in [0, 32, 63, 65, 4096] {
            let bytes = vec![5; length];
            std::fs::write(&a, &bytes)?;
            assert!(read(&a).is_err());
        }
        std::fs::write(&a, &original)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o640))?;
        assert!(read(&a).is_err());
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o600))?;
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&a, &link)?;
        assert!(read(&link).is_err());
        assert!(read(&dir.0).is_err());
        assert!(read(Path::new("/dev/null")).is_err());
        let fifo = dir.0.join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        assert!(read(&fifo).is_err());
        Ok(())
    }
    #[test]
    fn second_creation_failure_preserves_first_new_bundle() -> io::Result<()> {
        let dir = Temp::new()?;
        let a = dir.0.join("a");
        let b = dir.0.join("b");
        std::fs::write(&b, b"existing")?;
        assert!(generate(&a, &b).is_err());
        read(&a)?;
        assert_eq!(std::fs::read(&b)?, b"existing");
        Ok(())
    }
}
