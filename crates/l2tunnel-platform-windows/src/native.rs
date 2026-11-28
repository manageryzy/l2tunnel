use super::{
    Config, RING_CAPACITY, TapConfig, invalid, validate_dll_path, validate_ethernet_frame,
    validate_packet, verify_dll,
};
use l2tunnel_device::{PacketDevice, PacketLayer, READ_BUFFER_BYTES};
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

/// Shared live MTU handle for an active Wintun device. Allows the service
/// runtime to read/update the Wintun interface MTU during live Internal MTU /
/// Capsule MTU switches (`docs/modules/live-tuning.md`).
#[derive(Clone, Default)]
pub struct MtuController {
    inner: Arc<Mutex<Option<Arc<SyncDevice>>>>,
}

impl MtuController {
    /// Create a new detached MTU controller; bound automatically when [`Device::open_with_mtu`] succeeds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the active Wintun adapter's current IPv4 MTU.
    pub fn get_mtu(&self) -> io::Result<u32> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("Wintun MTU lock poisoned"))?;
        let dev = guard.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Wintun adapter not open")
        })?;
        dev.mtu().map(u32::from)
    }

    /// Update the active Wintun adapter's IPv4 (and best-effort IPv6) MTU.
    pub fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        let mtu16 = u16::try_from(mtu)
            .ok()
            .filter(|&v| v >= 1280)
            .ok_or_else(|| invalid("Wintun MTU must be in 1280..=65535"))?;
        let guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("Wintun MTU lock poisoned"))?;
        let dev = guard.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Wintun adapter not open")
        })?;
        dev.set_mtu(mtu16)?;
        let _ = dev.set_mtu_v6(mtu16);
        Ok(())
    }

    /// Current Windows interface index (`IF_INDEX`) of the open Wintun adapter, if any.
    pub fn if_index(&self) -> Option<u32> {
        let guard = self.inner.lock().ok()?;
        guard.as_ref().and_then(|dev| dev.if_index().ok())
    }

    /// Current adapter alias/name of the open Wintun adapter, if any.
    pub fn name(&self) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        guard.as_ref().and_then(|dev| dev.name().ok())
    }

    fn bind(&self, device: Arc<SyncDevice>) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(device);
        }
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }
}

/// Owned foreground Wintun L3 device and locked DLL backing its native session.
///
/// Opening may block and requires an elevated process. The caller must create it
/// on a blocking worker and hand ownership to the shared client/service runtime.
pub struct Device {
    // Field order keeps the DLL file lock alive until the dependency releases
    // its session, adapter, event and loaded library handles.
    device: Arc<SyncDevice>,
    mtu_controller: Option<MtuController>,
    name: String,
    if_index: u32,
    _dll_guard: File,
}

impl Device {
    /// Create a fresh, randomly named adapter with only its own address and MTU.
    ///
    /// The local DLL must reside in a trusted administrator-controlled directory.
    /// Its mandatory hash pin is verified while a read-only handle denies file
    /// writes/deletion. No driver uninstall, default route or DNS change occurs.
    pub fn open(config: &Config) -> io::Result<Self> {
        Self::open_with_mtu(config, None)
    }

    /// Same as [`Self::open`], additionally binding a live [`MtuController`] so
    /// the shared service runtime can resize the adapter MTU during live tuning.
    pub fn open_with_mtu(
        config: &Config,
        mtu_controller: Option<MtuController>,
    ) -> io::Result<Self> {
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
        let device = Arc::new(
            DeviceBuilder::new()
                .name(&name)
                .description(&name)
                .layer(Layer::L3)
                .wintun_file(dll)
                .wintun_log(false)
                .delete_driver(false)
                .ring_capacity(RING_CAPACITY)
                .mtu(config.mtu())
                .ipv4(config.address(), config.prefix(), None)
                .build_sync()?,
        );
        if device.name()? != name {
            return Err(io::Error::other(
                "Wintun returned an unexpected adapter name",
            ));
        }
        let if_index = device.if_index()?;
        if let Some(ctrl) = &mtu_controller {
            ctrl.bind(device.clone());
        }
        Ok(Self {
            device,
            mtu_controller,
            name,
            if_index,
            _dll_guard: dll_guard,
        })
    }

    /// Effective unique adapter name for local status and owned lab setup.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Windows interface index (`IF_INDEX`) of this adapter.
    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Configure DNS servers on this owned Wintun interface.
    pub fn set_dns_servers(&self, servers: &[std::net::IpAddr]) -> io::Result<()> {
        self.device.set_dns_servers(servers)
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
        // Skip stray non-IP/padded frames from Windows NDIS rather than tearing
        // down the tunnel session (bounded loop so malformed bursts never spin).
        for _ in 0..16 {
            match self.device.try_recv(buffer) {
                Ok(size) => {
                    let Some(packet) = buffer.get(..size) else {
                        continue;
                    };
                    if validate_packet(packet).is_err() {
                        continue;
                    }
                    return Ok(Some(size));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if validate_packet(packet).is_err() {
            return Ok(());
        }
        match self.device.try_send(packet) {
            Ok(sent) if sent == packet.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Wintun packet write",
            )),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(ctrl) = &self.mtu_controller {
            ctrl.clear();
        }
        // No blocking reader/thread is created here. Shutdown ends the session;
        // dependency Drop then closes/removes this created adapter and releases
        // its event/library handles even if shutdown itself reports an error.
        let _ = self.device.shutdown();
    }
}

/// Owned Windows TAP L2 (Ethernet) device backed by the OpenVPN TAP-Windows6
/// (`tap0901`) driver through [`tun_rs`] (`CL-26`).
///
/// Requires the OpenVPN TAP-Windows6 driver (`tap0901`) to be installed on the
/// host and an elevated process. For driverless Windows L2 transport, use
/// VXLAN (`--vxlan-bind`/`--vxlan-peer`/`--vni`) instead.
pub struct TapDevice {
    device: Arc<SyncDevice>,
    mtu_controller: Option<MtuController>,
    name: String,
    if_index: u32,
    mac: [u8; 6],
}

impl TapDevice {
    /// Open or create a Windows TAP-Windows6 (`tap0901`) Ethernet adapter.
    pub fn open(config: &TapConfig) -> io::Result<Self> {
        Self::open_with_mtu(config, None)
    }

    /// Open a Windows TAP L2 adapter and bind an optional live [`MtuController`].
    pub fn open_with_mtu(
        config: &TapConfig,
        mtu_controller: Option<MtuController>,
    ) -> io::Result<Self> {
        let name = if let Some(explicit) = config.adapter_name() {
            explicit.to_owned()
        } else {
            let mut nonce = [0_u8; 8];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| io::Error::other("cannot obtain random TAP adapter identity"))?;
            let mut generated = String::from("l2tap-");
            for byte in nonce {
                write!(generated, "{byte:02x}").map_err(io::Error::other)?;
            }
            generated
        };
        let mut builder = DeviceBuilder::new()
            .name(&name)
            .layer(Layer::L2)
            .persist(config.persist())
            .reuse_dev(config.adapter_name().is_some())
            .mtu(config.mtu());
        if let Some((ip, prefix)) = config.address() {
            builder = builder.ipv4(ip, prefix, None);
        }
        if let Some(mac) = config.mac() {
            builder = builder.mac_addr(mac);
        }
        let device = Arc::new(builder.build_sync().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to open Windows TAP L2 adapter '{name}' (requires OpenVPN TAP-Windows6 'tap0901' driver and administrator privileges; or use --vxlan-bind/--vxlan-peer/--vni for driverless L2): {err}"
                ),
            )
        })?);
        let actual_name = device.name().unwrap_or(name);
        let if_index = device.if_index()?;
        let mac = device.mac_address().unwrap_or([0; 6]);
        if let Some(ctrl) = &mtu_controller {
            ctrl.bind(device.clone());
        }
        Ok(Self {
            device,
            mtu_controller,
            name: actual_name,
            if_index,
            mac,
        })
    }

    /// Effective Windows adapter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Windows interface index (`IF_INDEX`) of this TAP adapter.
    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Ethernet MAC address reported by the TAP adapter.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
}

impl PacketDevice for TapDevice {
    type Error = io::Error;

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        if buffer.len() < READ_BUFFER_BYTES {
            return Err(invalid(
                "receive buffer must fit a complete maximum TAP Ethernet frame",
            ));
        }
        for _ in 0..16 {
            match self.device.try_recv(buffer) {
                Ok(size) => {
                    let Some(frame) = buffer.get(..size) else {
                        continue;
                    };
                    if validate_ethernet_frame(frame).is_err() {
                        continue;
                    }
                    return Ok(Some(size));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn transmit(&mut self, frame: &[u8]) -> io::Result<()> {
        if validate_ethernet_frame(frame).is_err() {
            return Ok(());
        }
        match self.device.try_send(frame) {
            Ok(sent) if sent == frame.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial TAP Ethernet frame write",
            )),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for TapDevice {
    fn drop(&mut self) {
        if let Some(ctrl) = &self.mtu_controller {
            ctrl.clear();
        }
        let _ = self.device.shutdown();
    }
}
