//! Switchable catalog generation for live tuning (LT-01,
//! docs/modules/live-tuning.md).
//!
//! A client proposes switchable choices at connect: Swift FEC off or at
//! exact repair rates, device MTUs (largest inner packet) and path MTUs
//! (outer IP packet ceiling). Both ends derive the identical catalog from
//! their shared base descriptor and the proposal; every live switch then
//! still selects an exact pre-agreed catalog member.
//!
//! The generator is pure and deterministic: the same base and choices give
//! the same descriptors in the same canonical catalog order on every build.

use crate::record_configuration::{
    Catalog, CommonDirection, Descriptor, Error as ConfigError, NativeWindow, Profile,
};
use l2tunnel_management::Role;
use l2tunnel_swift::records;

/// Most entries a catalog may hold (the record-configuration bound).
pub const MAX_ENTRIES: usize = 64;
/// Most choices of each kind in one proposal.
pub const MAX_CHOICES: usize = 16;
/// Encoded proposal size bound: header plus three bounded lists.
pub const MAX_PROPOSAL_BYTES: usize = 4 + 1 + MAX_CHOICES * 8 + 2 * (1 + MAX_CHOICES * 2);

const MAGIC: [u8; 2] = *b"LT";
const VERSION: u8 = 1;

/// Swift FEC choice applied to both directions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Repair {
    /// No repair symbols; recovery is ARQ only.
    Off,
    /// Exact repair proportion `numerator / denominator`, never normalized.
    Rate {
        /// Repairs earned per `denominator` sources, at least 1.
        numerator: u32,
        /// In `1..=65536`, at least `numerator`.
        denominator: u32,
    },
}
impl Repair {
    fn valid(self) -> bool {
        match self {
            Self::Off => true,
            Self::Rate {
                numerator,
                denominator,
            } => numerator >= 1 && (1..=65_536).contains(&denominator) && numerator <= denominator,
        }
    }
    fn of(codec: &l2tunnel_swift::Config) -> Self {
        if codec.repair_numerator == 0 {
            Self::Off
        } else {
            Self::Rate {
                numerator: codec.repair_numerator,
                denominator: codec.repair_denominator,
            }
        }
    }
}

/// One client proposal: each list is a set of switchable values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Choices {
    /// FEC choices; empty keeps the base value only.
    pub repair: Vec<Repair>,
    /// Device MTUs (largest inner packet); empty keeps the base value only.
    pub device_mtu: Vec<u16>,
    /// Path MTUs (outer IP packet ceiling); empty keeps the base value only.
    pub path_mtu: Vec<u16>,
}

/// Values of one generated entry, as the UI controls show them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Setting {
    /// FEC choice (both directions).
    pub repair: Repair,
    /// Largest inner packet; the TUN device MTU follows it.
    pub device_mtu: u16,
    /// Outer IP packet ceiling.
    pub path_mtu: u16,
}

/// Server-side bounds on what a client may propose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Highest allowed repair proportion as `numerator / denominator`.
    pub max_repair: (u32, u32),
    /// Allowed device MTU range, inclusive.
    pub device_mtu: (u16, u16),
    /// Allowed path MTU range, inclusive.
    pub path_mtu: (u16, u16),
    /// Most entries in the generated catalog.
    pub max_entries: usize,
}
impl Limits {
    /// Defaults when the server profile sets none: anything the protocol
    /// accepts, up to the catalog bound (owner decision 5).
    pub const PROTOCOL: Self = Self {
        max_repair: (1, 1),
        device_mtu: (68, u16::MAX),
        path_mtu: (256, u16::MAX),
        max_entries: MAX_ENTRIES,
    };
}

/// Why a proposal or generation was refused; every variant names the reason
/// a refused connect reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The base descriptor is not a Swift profile, or its two directions
    /// differ in a field the generator would change.
    Base,
    /// A list has more than [`MAX_CHOICES`] values or repeats one.
    Choices,
    /// A repair proportion is malformed.
    Repair,
    /// A repair proportion exceeds the server's limit.
    RepairLimit,
    /// A device MTU is outside the server's range.
    DeviceMtuLimit,
    /// A path MTU is outside the server's range.
    PathMtuLimit,
    /// The combination has more entries than allowed.
    Entries,
    /// A path MTU leaves no room for the base carrier overhead.
    Overhead,
    /// The encoded proposal is malformed.
    Encoding,
    /// A generated descriptor or the catalog was refused.
    Configuration(ConfigError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Base => "the plan's base configuration is not a symmetric Swift profile",
            Self::Choices => "a choice list is too long or repeats a value",
            Self::Repair => "a repair rate is malformed",
            Self::RepairLimit => "a repair rate is above the server's limit",
            Self::DeviceMtuLimit => "a device MTU is outside the server's range",
            Self::PathMtuLimit => "a path MTU is outside the server's range",
            Self::Entries => "the choices combine into more catalog entries than allowed",
            Self::Overhead => "a path MTU is smaller than the carrier overhead allows",
            Self::Encoding => "malformed live-tuning proposal",
            Self::Configuration(_) => "a generated configuration is invalid",
        };
        formatter.write_str(text)
    }
}
impl std::error::Error for Error {}

/// Reason a server refused a proposal, carried as one stable nonzero code in
/// the authenticated verdict of handshake message 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The server takes no live-tuning proposals for this connection.
    NotOffered,
    /// See [`Error::Base`].
    Base,
    /// See [`Error::Choices`].
    Choices,
    /// See [`Error::Repair`].
    Repair,
    /// See [`Error::RepairLimit`].
    RepairLimit,
    /// See [`Error::DeviceMtuLimit`].
    DeviceMtuLimit,
    /// See [`Error::PathMtuLimit`].
    PathMtuLimit,
    /// See [`Error::Entries`].
    Entries,
    /// See [`Error::Overhead`].
    Overhead,
    /// See [`Error::Encoding`].
    Encoding,
    /// See [`Error::Configuration`].
    Configuration,
    /// The catalog needs more memory than the server allows.
    Memory,
    /// A code this build does not know (a newer server).
    Unknown(u8),
}
impl Refusal {
    const TABLE: [(Self, u8); 12] = [
        (Self::NotOffered, 1),
        (Self::Base, 2),
        (Self::Choices, 3),
        (Self::Repair, 4),
        (Self::RepairLimit, 5),
        (Self::DeviceMtuLimit, 6),
        (Self::PathMtuLimit, 7),
        (Self::Entries, 8),
        (Self::Overhead, 9),
        (Self::Encoding, 10),
        (Self::Configuration, 11),
        (Self::Memory, 12),
    ];
    /// Stable nonzero wire code.
    pub fn code(self) -> u8 {
        match self {
            Self::Unknown(code) => code,
            known => Self::TABLE
                .iter()
                .find(|(refusal, _)| *refusal == known)
                .map_or(u8::MAX, |(_, code)| *code),
        }
    }
    /// Stable machine-readable name, for status output.
    pub fn name(self) -> &'static str {
        match self {
            Self::NotOffered => "live_tuning_not_offered",
            Self::Base => "live_tuning_base",
            Self::Choices => "live_tuning_choices",
            Self::Repair => "live_tuning_repair",
            Self::RepairLimit => "live_tuning_repair_limit",
            Self::DeviceMtuLimit => "live_tuning_device_mtu_limit",
            Self::PathMtuLimit => "live_tuning_path_mtu_limit",
            Self::Entries => "live_tuning_entries",
            Self::Overhead => "live_tuning_overhead",
            Self::Encoding => "live_tuning_encoding",
            Self::Configuration => "live_tuning_configuration",
            Self::Memory => "live_tuning_memory",
            Self::Unknown(_) => "live_tuning_unknown",
        }
    }
    /// Reason for a nonzero wire code.
    pub fn from_code(code: u8) -> Self {
        Self::TABLE
            .iter()
            .find(|(_, known)| *known == code)
            .map_or(Self::Unknown(code), |(refusal, _)| *refusal)
    }
}
impl From<&Error> for Refusal {
    fn from(error: &Error) -> Self {
        match error {
            Error::Base => Self::Base,
            Error::Choices => Self::Choices,
            Error::Repair => Self::Repair,
            Error::RepairLimit => Self::RepairLimit,
            Error::DeviceMtuLimit => Self::DeviceMtuLimit,
            Error::PathMtuLimit => Self::PathMtuLimit,
            Error::Entries => Self::Entries,
            Error::Overhead => Self::Overhead,
            Error::Encoding => Self::Encoding,
            Error::Configuration(_) => Self::Configuration,
        }
    }
}
impl std::error::Error for Refusal {}
impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOffered => formatter.write_str("the server takes no live-tuning proposals"),
            Self::Base => Error::Base.fmt(formatter),
            Self::Choices => Error::Choices.fmt(formatter),
            Self::Repair => Error::Repair.fmt(formatter),
            Self::RepairLimit => Error::RepairLimit.fmt(formatter),
            Self::DeviceMtuLimit => Error::DeviceMtuLimit.fmt(formatter),
            Self::PathMtuLimit => Error::PathMtuLimit.fmt(formatter),
            Self::Entries => Error::Entries.fmt(formatter),
            Self::Overhead => Error::Overhead.fmt(formatter),
            Self::Encoding => Error::Encoding.fmt(formatter),
            Self::Configuration => formatter.write_str("a generated configuration is invalid"),
            Self::Memory => formatter
                .write_str("the switchable catalog needs more memory than the server allows"),
            Self::Unknown(code) => write!(formatter, "unknown live-tuning refusal code {code}"),
        }
    }
}

/// The plan's catalog extended by every combination of `choices` around its
/// initial entry, exactly as both ends derive it; the plan's own entries stay
/// switchable. Fails with the exact reason.
pub fn extend(base: &Catalog, choices: &Choices, limits: &Limits) -> Result<Catalog, Error> {
    let generated = generate(&base.initial(), choices, limits)?;
    let mut all = base.descriptors().to_vec();
    for descriptor in generated.descriptors() {
        if !all.contains(descriptor) {
            all.push(*descriptor);
        }
    }
    if all.len() > limits.max_entries.min(MAX_ENTRIES) {
        return Err(Error::Entries);
    }
    Catalog::new(base.initial(), &all).map_err(Error::Configuration)
}

/// Encode the server's verdict for handshake message 2: `[0]` accepts,
/// `[code]` refuses.
pub fn encode_verdict(verdict: Result<(), Refusal>) -> [u8; 1] {
    match verdict {
        Ok(()) => [0],
        Err(refusal) => [refusal.code().max(1)],
    }
}

/// Decode a verdict received in message 2. Anything but one byte is
/// [`Refusal::Encoding`].
pub fn decode_verdict(bytes: &[u8]) -> Result<(), Refusal> {
    match bytes {
        [0] => Ok(()),
        [code] => Err(Refusal::from_code(*code)),
        _ => Err(Refusal::Encoding),
    }
}

impl Choices {
    /// Check list bounds, duplicates and server limits.
    pub fn check(&self, limits: &Limits) -> Result<(), Error> {
        fn distinct<T: Ord + Copy>(values: &[T]) -> bool {
            let mut sorted = values.to_vec();
            sorted.sort_unstable();
            sorted.windows(2).all(|pair| pair[0] != pair[1])
        }
        if self.repair.len() > MAX_CHOICES
            || self.device_mtu.len() > MAX_CHOICES
            || self.path_mtu.len() > MAX_CHOICES
            || !distinct(&self.repair)
            || !distinct(&self.device_mtu)
            || !distinct(&self.path_mtu)
        {
            return Err(Error::Choices);
        }
        let (max_n, max_d) = limits.max_repair;
        for repair in &self.repair {
            if !repair.valid() {
                return Err(Error::Repair);
            }
            if let Repair::Rate {
                numerator,
                denominator,
            } = *repair
                && u64::from(numerator) * u64::from(max_d)
                    > u64::from(max_n) * u64::from(denominator)
            {
                return Err(Error::RepairLimit);
            }
        }
        let within = |value: u16, (low, high): (u16, u16)| (low..=high).contains(&value);
        if !self
            .device_mtu
            .iter()
            .all(|&m| within(m, limits.device_mtu))
        {
            return Err(Error::DeviceMtuLimit);
        }
        if !self.path_mtu.iter().all(|&m| within(m, limits.path_mtu)) {
            return Err(Error::PathMtuLimit);
        }
        Ok(())
    }

    /// Fixed wire form carried in handshake message 1: `LT`, version, a
    /// reserved zero byte, then three lists each prefixed by a count byte:
    /// repairs as (numerator u32, denominator u32) big-endian with Off as
    /// 0/0, device MTUs and path MTUs as u16 big-endian.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.repair.len() > MAX_CHOICES
            || self.device_mtu.len() > MAX_CHOICES
            || self.path_mtu.len() > MAX_CHOICES
        {
            return Err(Error::Choices);
        }
        let mut out = Vec::with_capacity(MAX_PROPOSAL_BYTES);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(0);
        out.push(self.repair.len() as u8);
        for repair in &self.repair {
            let (n, d) = match *repair {
                Repair::Off => (0, 0),
                Repair::Rate {
                    numerator,
                    denominator,
                } => (numerator, denominator),
            };
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&d.to_be_bytes());
        }
        for list in [&self.device_mtu, &self.path_mtu] {
            out.push(list.len() as u8);
            for value in list {
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Strict parse of [`Choices::encode`]; trailing or short input is refused.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let mut rest = input;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            if rest.len() < n {
                return Err(Error::Encoding);
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        if take(4)? != [MAGIC[0], MAGIC[1], VERSION, 0] {
            return Err(Error::Encoding);
        }
        let count = usize::from(take(1)?[0]);
        if count > MAX_CHOICES {
            return Err(Error::Encoding);
        }
        let mut repair = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = take(8)?;
            let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let d = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            repair.push(match (n, d) {
                (0, 0) => Repair::Off,
                (0, _) => return Err(Error::Encoding),
                (numerator, denominator) => Repair::Rate {
                    numerator,
                    denominator,
                },
            });
        }
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let count = usize::from(take(1)?[0]);
            if count > MAX_CHOICES {
                return Err(Error::Encoding);
            }
            for _ in 0..count {
                let bytes = take(2)?;
                list.push(u16::from_be_bytes([bytes[0], bytes[1]]));
            }
        }
        if !rest.is_empty() {
            return Err(Error::Encoding);
        }
        let [device_mtu, path_mtu] = lists;
        Ok(Self {
            repair,
            device_mtu,
            path_mtu,
        })
    }
}

/// Symmetric Swift fields of a base descriptor.
fn swift_base(base: &Descriptor) -> Result<records::Config, Error> {
    let Profile::Swift { forward, reverse } = *base.profile() else {
        return Err(Error::Base);
    };
    let same = forward.max_native == reverse.max_native
        && forward.codec.max_packet == reverse.codec.max_packet
        && forward.codec.datagram_bytes == reverse.codec.datagram_bytes
        && forward.codec.repair_numerator == reverse.codec.repair_numerator
        && forward.codec.repair_denominator == reverse.codec.repair_denominator;
    if !same {
        return Err(Error::Base);
    }
    Ok(forward)
}

/// The setting a descriptor represents, when it is a symmetric Swift profile.
pub fn setting(descriptor: &Descriptor) -> Result<Setting, Error> {
    let swift = swift_base(descriptor)?;
    Ok(Setting {
        repair: Repair::of(&swift.codec),
        device_mtu: u16::try_from(swift.max_native).map_err(|_| Error::Base)?,
        path_mtu: u16::try_from(descriptor.path_mtu()).map_err(|_| Error::Base)?,
    })
}

/// `base` with its FEC, inner size and path size replaced by `setting`; every
/// other field stays. The result is what the generator would produce for
/// `setting` around `base`.
pub fn tune(base: &Descriptor, setting: Setting) -> Result<Descriptor, Error> {
    apply(base, swift_base(base)?, setting)
}

fn apply(base: &Descriptor, swift: records::Config, setting: Setting) -> Result<Descriptor, Error> {
    // The carrier's bytes above the Swift datagram stay what the plan set.
    let overhead = base
        .path_mtu()
        .checked_sub(swift.codec.datagram_bytes)
        .ok_or(Error::Base)?;
    let device = usize::from(setting.device_mtu);
    let datagram = usize::from(setting.path_mtu)
        .checked_sub(overhead)
        .ok_or(Error::Overhead)?;
    // Each direction keeps its own other fields (channels, timers, window);
    // only the tuned fields change.
    let tune = |mut config: records::Config| -> Result<records::Config, Error> {
        config.max_native = device;
        config.codec.max_packet = device
            .checked_add(l2tunnel_swift::header::MAX_EXPANSION)
            .ok_or(Error::Overhead)?;
        config.codec.datagram_bytes = datagram;
        let needed = config.codec.max_packet + l2tunnel_swift::FRAME_PREFIX;
        config.codec.queue_bytes = config.codec.queue_bytes.max(needed);
        (
            config.codec.repair_numerator,
            config.codec.repair_denominator,
        ) = match setting.repair {
            Repair::Off => (0, swift.codec.repair_denominator),
            Repair::Rate {
                numerator,
                denominator,
            } => (numerator, denominator),
        };
        Ok(config)
    };
    let Profile::Swift { forward, reverse } = *base.profile() else {
        return Err(Error::Base);
    };
    Descriptor::new(
        usize::from(setting.path_mtu),
        base.duplex(),
        resized(base.direction(Role::Client).common(), device)?,
        resized(base.direction(Role::Server).common(), device)?,
        Profile::Swift {
            forward: tune(forward)?,
            reverse: tune(reverse)?,
        },
    )
    .map_err(Error::Configuration)
}

/// The common direction with its native packet bounds set to `device`;
/// the descriptor requires them to equal the Swift native maximum.
fn resized(common: &CommonDirection, device: usize) -> Result<CommonDirection, Error> {
    let mut pipeline = common.pipeline();
    pipeline.parse.max_packet_bytes = device;
    let window = match common.native_window() {
        NativeWindow::Delivery(mut window) => {
            let device = device as u64;
            window.max_packet_bytes = device;
            window.minimum_bytes = window.minimum_bytes.max(device);
            NativeWindow::Delivery(window)
        }
        other => other,
    };
    CommonDirection::new(
        common.traffic(),
        pipeline,
        common.bytes_per_second(),
        common.burst_bytes(),
        window,
    )
    .map_err(Error::Configuration)
}

/// The list with `own` added, sorted and without duplicates.
fn pick<T: Ord + Copy>(list: &[T], own: T) -> Vec<T> {
    let mut values = list.to_vec();
    values.push(own);
    values.sort_unstable();
    values.dedup();
    values
}

/// Every setting the choices allow, the base setting included, in sorted
/// order and without duplicates.
pub fn settings(base: &Descriptor, choices: &Choices) -> Result<Vec<Setting>, Error> {
    let own = setting(base)?;
    let repairs = pick(&choices.repair, own.repair);
    let devices = pick(&choices.device_mtu, own.device_mtu);
    let paths = pick(&choices.path_mtu, own.path_mtu);
    let total = repairs
        .len()
        .checked_mul(devices.len())
        .and_then(|n| n.checked_mul(paths.len()))
        .ok_or(Error::Entries)?;
    if total > MAX_ENTRIES {
        return Err(Error::Entries);
    }
    let mut all = Vec::with_capacity(total);
    for &repair in &repairs {
        for &device_mtu in &devices {
            for &path_mtu in &paths {
                all.push(Setting {
                    repair,
                    device_mtu,
                    path_mtu,
                });
            }
        }
    }
    Ok(all)
}

/// Check the proposal against the server's limits and derive the catalog;
/// the base descriptor stays the initial value.
pub fn generate(base: &Descriptor, choices: &Choices, limits: &Limits) -> Result<Catalog, Error> {
    choices.check(limits)?;
    let swift = swift_base(base)?;
    let all = settings(base, choices)?;
    if all.len() > limits.max_entries.min(MAX_ENTRIES) {
        return Err(Error::Entries);
    }
    let descriptors = all
        .into_iter()
        .map(|setting| apply(base, swift, setting))
        .collect::<Result<Vec<_>, _>>()?;
    Catalog::new(*base, &descriptors).map_err(Error::Configuration)
}

#[cfg(test)]
#[path = "live_tuning_tests.rs"]
mod tests;
