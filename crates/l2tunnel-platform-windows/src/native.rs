use super::{Config, RING_CAPACITY, invalid, validate_dll_path, validate_packet, verify_dll};
use l2tunnel_device::{PacketDevice, PacketLayer, READ_BUFFER_BYTES};
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

/// Owned foreground Wintun L3 device and locked DLL backing its native session.
///
/// Opening may block and requires an elevated process. The caller must create it
/// on a blocking worker and hand ownership to the shared client/service runtime.
pub struct Device {
    // Field order keeps the DLL file lock alive until the dependency releases
    // its session, adapter, event and loaded library handles.
    device: SyncDevice,
    name: String,
    _dll_guard: File,
}

impl Device {
    /// Create a fresh, randomly named adapter with only its own address and MTU.
    ///
    /// The local DLL must reside in a trusted administrator-controlled directory.
    /// Its mandatory hash pin is verified while a read-only handle denies file
    /// writes/deletion. No driver uninstall, default route or DNS change occurs.
    pub fn open(config: &Config) -> io::Result<Self> {
        let dll = config.dll_path().canonicalize()?;
        validate_dll_path(&dll)?;
        // FILE_SHARE_READ permits the library loader to read the same file while
        // denying writes and deletion for the entire device lifetime.
        let mut dll_guard = OpenOptions::new().read(true).share_mode(1).open(&dll)?;
        if !dll_guard.metadata()?.is_file() {
            return Err(invalid("Wintun DLL must be a regular file"));
        }
        verify_dll(&mut dll_guard, config.dll_sha256())?;
        let dll = dll
            .to_str()
            .ok_or_else(|| invalid("Wintun DLL path must be valid Unicode"))?
            .to_owned();
        let mut nonce = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("cannot obtain random adapter identity"))?;
        let mut name = String::from("l2t-");
        for byte in nonce {
            write!(name, "{byte:02x}").map_err(io::Error::other)?;
        }
        let device = DeviceBuilder::new()
            .name(&name)
            .description(&name)
            .layer(Layer::L3)
            .wintun_file(dll)
            .wintun_log(false)
            .delete_driver(false)
            .ring_capacity(RING_CAPACITY)
            .mtu(config.mtu())
            .ipv4(config.address(), config.prefix(), None)
            .build_sync()?;
        if device.name()? != name {
            return Err(io::Error::other(
                "Wintun returned an unexpected adapter name",
            ));
        }
        Ok(Self {
            device,
            name,
            _dll_guard: dll_guard,
        })
    }

    /// Effective unique adapter name for local status and owned lab setup.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl PacketDevice for Device {
    type Error = io::Error;

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        if buffer.len() < READ_BUFFER_BYTES {
            return Err(invalid(
                "receive buffer must fit a complete maximum Wintun packet",
            ));
        }
        match self.device.try_recv(buffer) {
            Ok(size) => {
                let packet = buffer
                    .get(..size)
                    .ok_or_else(|| invalid("Wintun returned an invalid packet length"))?;
                validate_packet(packet)?;
                Ok(Some(size))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        validate_packet(packet)?;
        let sent = self.device.try_send(packet)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Wintun packet write",
            ));
        }
        Ok(())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // No blocking reader/thread is created here. Shutdown ends the session;
        // dependency Drop then closes/removes this created adapter and releases
        // its event/library handles even if shutdown itself reports an error.
        let _ = self.device.shutdown();
    }
}
