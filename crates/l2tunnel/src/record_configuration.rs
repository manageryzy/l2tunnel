//! Complete pure record policies; representation is not runtime capability.
//!
//! This additive CompleteV2 value preserves the existing Swift v1 module. It
//! opens no device, authenticates no label, reserves no engine and does not
//! install Active, native-credit or TCP-proxy protocols by naming their policy.

use crate::rolling_records;
use l2tunnel_aligned as aligned;
use l2tunnel_codec::{aligned_body, aligned_receiver};
use l2tunnel_core::{ConfigDigest, Duplex, Mapping, traffic};
use l2tunnel_fec as fec;
use l2tunnel_flow_control::delivery_window;
use l2tunnel_management::{Role, transaction};
use l2tunnel_pipeline as pipeline;
use l2tunnel_recovery::ArqConfig;
use l2tunnel_reliable::ReliableConfig;
use l2tunnel_swift::{self as swift, records};
use ring::digest;
use std::{fmt, time::Duration};

mod rolling;

/// Fixed magic/version/profile/duplex/reserved/MTU header size.
pub const HEADER_BYTES: usize = 16;
/// Every complete common directional field, encoded as 34 u64 words.
pub const COMMON_DIRECTION_BYTES: usize = 272;
/// Fixed largest complete record variant, including required zero padding.
pub const PROFILE_SLOT_BYTES: usize = 356;
/// One globally ordered common policy and record slot.
pub const DIRECTION_BYTES: usize = COMMON_DIRECTION_BYTES + PROFILE_SLOT_BYTES;
/// Exact anchor-free supported descriptor bytes.
pub const DESCRIPTOR_BYTES: usize = HEADER_BYTES + 2 * DIRECTION_BYTES;
/// Exact anchored CompleteV2 configuration bytes.
pub const CONFIGURATION_BYTES: usize = DESCRIPTOR_BYTES + 32;
/// Exact supported set bound, independent of runtime message/resource capacity.
pub const MAX_CATALOG_ENTRIES: usize = 64;
const CONFIG_DOMAIN: &[u8] = b"l2tunnel/record-transaction-config/v2\0";
const CATALOG_DOMAIN: &[u8] = b"l2tunnel/record-transaction-catalog/v2\0";
const SWIFT_BYTES: usize = 120;
const ALIGNED_BYTES: usize = 332;

/// Checked value, canonical grammar or bounded catalog failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact input/output length or internal fixed-layout arithmetic differs.
    Length,
    /// Unsupported magic, version, tag or reserved header byte.
    Prefix,
    /// An inactive branch or variant slot contains nonzero bytes.
    Padding,
    /// A canonical integer cannot fit the actual target field.
    Integer,
    /// A boolean or Duration nanosecond value is not canonical.
    Scalar,
    /// Complete IP packet ceiling is outside 256..=65535.
    PathMtu,
    /// Requested layer/TCP/QoS policy is internally inconsistent.
    Traffic,
    /// Existing common pipeline scalar validation refused the value.
    Pipeline,
    /// Exact directional service rate or burst is invalid.
    Rate,
    /// Native delivery-window scalar validation refused the value.
    Window,
    /// Complete actual record-family scalar validation refused the value.
    Profile,
    /// Channel, native-format or native-window bounds disagree across policies.
    Relation,
    /// Supported set is empty or exceeds 64 entries.
    CatalogSize,
    /// Supported descriptors have identical complete canonical bytes.
    Duplicate,
    /// The exact initial descriptor is absent from the supported catalog.
    Unlisted,
    /// Bounded catalog allocation failed without publishing a value.
    Allocation,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "complete record configuration: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Immutable public envelope label, without authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeDigest([u8; 32]);
impl EnvelopeDigest {
    /// Bind the caller's explicit exact label; no trust is inferred.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Exact unchanged label for the authenticated contract owner.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Domain-separated root of complete anchor-free descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogDigest([u8; 32]);
impl CatalogDigest {
    /// Exact catalog root; runtime authentication remains external.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Requested native delivery admission, separate from queue/recovery/TCP windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWindow {
    /// No selected external native delivery controller.
    Disabled,
    /// Full existing controller policy, not proof its receipt protocol is installed.
    Delivery(delivery_window::Config),
}

/// Complete selected common policy; execution capabilities are checked externally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommonDirection {
    traffic: traffic::TrafficPolicy,
    pipeline: pipeline::PipelineConfig,
    bytes_per_second: u64,
    burst_bytes: usize,
    native_window: NativeWindow,
}
impl CommonDirection {
    /// Validate the represented fields, without constructing any runtime owner.
    pub fn new(
        traffic: traffic::TrafficPolicy,
        pipeline: pipeline::PipelineConfig,
        bytes_per_second: u64,
        burst_bytes: usize,
        native_window: NativeWindow,
    ) -> Result<Self, Error> {
        let value = Self {
            traffic,
            pipeline,
            bytes_per_second,
            burst_bytes,
            native_window,
        };
        value.validate()?;
        Ok(value)
    }
    /// Requested TCP/QoS ownership, not an installed Active or proxy capability.
    pub const fn traffic(&self) -> traffic::TrafficPolicy {
        self.traffic
    }
    /// Complete classifier/flow/MUX/DRR/queue policy.
    pub const fn pipeline(&self) -> pipeline::PipelineConfig {
        self.pipeline
    }
    /// Complete-IP byte service rate, preserving exact non-kilobit values.
    pub const fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }
    /// Explicit shared full-wire burst ceiling.
    pub const fn burst_bytes(&self) -> usize {
        self.burst_bytes
    }
    /// Full requested delivery window, independent of actual receipt capability.
    pub const fn native_window(&self) -> NativeWindow {
        self.native_window
    }
    /// Pure scalar validation; never grants execution or negotiated authority.
    pub fn validate(&self) -> Result<(), Error> {
        self.traffic.validate().map_err(|_| Error::Traffic)?;
        self.pipeline.validate().map_err(|_| Error::Pipeline)?;
        let compatible = matches!(
            (self.traffic.layer, self.traffic.qos, self.pipeline.profile),
            (
                traffic::NetworkLayer::Tap,
                traffic::Qos::System,
                pipeline::Profile::TapSystem
            ) | (
                traffic::NetworkLayer::Tun,
                traffic::Qos::WeightedDeficit,
                pipeline::Profile::TunDrr(_)
            )
        );
        if !compatible {
            return Err(Error::Traffic);
        }
        if self.bytes_per_second == 0 || self.burst_bytes == 0 {
            return Err(Error::Rate);
        }
        if let NativeWindow::Delivery(window) = self.native_window {
            window.validate().map_err(|_| Error::Window)?;
        }
        Ok(())
    }
}

/// Actual same-family directional policies; no unimplemented algorithm placeholder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Exact bounded Copy policy stays allocation-free.
pub enum Profile {
    /// Existing actual Swift duplex engine configuration.
    Swift {
        /// Global client/initiator-to-server/responder records.
        forward: records::Config,
        /// Global reverse records.
        reverse: records::Config,
    },
    /// Existing actual Aligned duplex endpoint configuration.
    Aligned {
        /// Complete global forward data direction, including peer receiver limits.
        forward: aligned::Config,
        /// Complete global reverse data direction.
        reverse: aligned::Config,
    },
    /// Existing actual Packed duplex endpoint configuration.
    Packed {
        /// Complete global forward packed direction.
        forward: aligned::packed::Config,
        /// Complete global reverse packed direction.
        reverse: aligned::packed::Config,
    },
    /// Actual compact records over causal local/global rolling recovery.
    Rolling {
        /// Both complete directions, exact wire geometry and original native cap.
        config: rolling_records::Config,
        /// Exact authenticated coding stream, independent of native record IDs.
        stream: u32,
    },
    /// Explicit tag5 with complete physical-source copy selection.
    RollingCopies {
        /// Same actual directional recovery and codec owners.
        config: rolling_records::Config,
        /// Exact authenticated coding stream.
        stream: u32,
        /// Complete immutable directional source-copy policies.
        copies: rolling_records::CopyPolicies,
    },
}
/// Borrowed exact directional record policy; no engine or admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectionProfile<'a> {
    /// Complete existing Swift records, with rate in the common value.
    Swift(&'a records::Config),
    /// Complete existing Aligned data-direction policy.
    Aligned(&'a aligned::Config),
    /// Complete existing Packed data-direction policy.
    Packed(&'a aligned::packed::Config),
    /// Complete actual rolling direction and its authenticated shared binding.
    Rolling {
        /// Actual codec, recovery, scheduling and native policy.
        config: &'a rolling_records::DirectionConfig,
        /// Exact full-wire charge outside this directional record.
        overhead_bytes: usize,
        /// Original native custody cap, shared by both directions.
        native_stall_micros: u64,
        /// Exact coding stream, shared by both directions.
        stream: u32,
    },
}
impl DirectionProfile<'_> {
    /// Exact installed width; no modulo or opposite-direction substitution.
    pub fn channels(self) -> usize {
        match self {
            Self::Swift(config) => config.channels,
            Self::Aligned(config) => usize::from(config.receiver.channels),
            Self::Packed(config) => usize::from(config.base.receiver.channels),
            Self::Rolling { config, .. } => usize::from(config.receiver.channels),
        }
    }
    /// Original native maximum, separate from source and output packet maxima.
    pub fn max_native(self) -> usize {
        match self {
            Self::Swift(config) => config.max_native,
            Self::Aligned(config) => config.receiver.body.max_frame_bytes,
            Self::Packed(config) => config.base.receiver.body.max_frame_bytes,
            Self::Rolling { config, .. } => config.receiver.body.max_frame_bytes,
        }
    }
    fn layer(self) -> traffic::NetworkLayer {
        match self {
            Self::Swift(config) => match config.layer {
                records::Layer::Ethernet => traffic::NetworkLayer::Tap,
                records::Layer::Ip => traffic::NetworkLayer::Tun,
            },
            Self::Aligned(config) => native_layer(config.native_policy),
            Self::Packed(config) => native_layer(config.base.native_policy),
            Self::Rolling { config, .. } => native_layer(config.native_policy),
        }
    }
    fn validate(self) -> Result<(), Error> {
        match self {
            Self::Swift(config) => config.validate().map_err(|_| Error::Profile),
            Self::Aligned(config) => config.validate().map_err(|_| Error::Profile),
            Self::Packed(config) => config.validate().map_err(|_| Error::Profile),
            Self::Rolling { config, .. } => config.validate().map_err(|_| Error::Profile),
        }
    }
}
fn native_layer(policy: aligned::NativePolicy) -> traffic::NetworkLayer {
    match policy {
        aligned::NativePolicy::EthernetHeaders => traffic::NetworkLayer::Tap,
        aligned::NativePolicy::RawIp | aligned::NativePolicy::IpHeaders => {
            traffic::NetworkLayer::Tun
        }
    }
}
/// Common policy and exact family reference for one globally identified sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionView<'a> {
    common: &'a CommonDirection,
    profile: DirectionProfile<'a>,
}
impl<'a> DirectionView<'a> {
    /// Complete common value; actual capability checks must consume every field.
    pub const fn common(self) -> &'a CommonDirection {
        self.common
    }
    /// Exact full family policy, preserving distinct native/source/output geometry.
    pub const fn profile(self) -> DirectionProfile<'a> {
        self.profile
    }
    /// Exact directional width.
    pub fn channels(self) -> u16 {
        // Only a Descriptor can construct this view; it validated the actual
        // family's 64/256/255 width before publishing an immutable value.
        self.profile.channels() as u16
    }
    /// Largest original native packet for this direction.
    pub fn max_native(self) -> usize {
        self.profile.max_native()
    }
}
/// Role projection only; neither view is a mutable engine or capability token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalView<'a> {
    send: DirectionView<'a>,
    receive: DirectionView<'a>,
}
impl<'a> LocalView<'a> {
    /// Complete local outgoing direction.
    pub const fn send(self) -> DirectionView<'a> {
        self.send
    }
    /// Complete local incoming direction.
    pub const fn receive(self) -> DirectionView<'a> {
        self.receive
    }
}

/// Anchor-free complete mutable value, in global sender order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    path_mtu: usize,
    duplex: Duplex,
    forward: CommonDirection,
    reverse: CommonDirection,
    profile: Profile,
}
impl Descriptor {
    /// Validate both complete directions before a catalog or transaction may use them.
    pub fn new(
        path_mtu: usize,
        duplex: Duplex,
        forward: CommonDirection,
        reverse: CommonDirection,
        profile: Profile,
    ) -> Result<Self, Error> {
        let value = Self {
            path_mtu,
            duplex,
            forward,
            reverse,
            profile,
        };
        value.validate()?;
        Ok(value)
    }
    /// Exact complete-IP ceiling, without asserting selected-carrier fit.
    pub const fn path_mtu(&self) -> usize {
        self.path_mtu
    }
    /// Explicit physical lane arrangement; transactions cannot silently change it.
    pub const fn duplex(&self) -> Duplex {
        self.duplex
    }
    /// Complete globally ordered actual family pair.
    pub const fn profile(&self) -> &Profile {
        &self.profile
    }
    /// Select by the global authenticated sender, never by the reader's local role.
    pub fn direction(&self, sender: Role) -> DirectionView<'_> {
        let forward = sender == Role::Client;
        let profile = match &self.profile {
            Profile::Swift {
                forward: a,
                reverse: b,
            } => DirectionProfile::Swift(if forward { a } else { b }),
            Profile::Aligned {
                forward: a,
                reverse: b,
            } => DirectionProfile::Aligned(if forward { a } else { b }),
            Profile::Packed {
                forward: a,
                reverse: b,
            } => DirectionProfile::Packed(if forward { a } else { b }),
            Profile::Rolling { config, stream } | Profile::RollingCopies { config, stream, .. } => {
                DirectionProfile::Rolling {
                    config: if forward {
                        &config.forward
                    } else {
                        &config.reverse
                    },
                    overhead_bytes: if forward {
                        config.geometry.forward_overhead_bytes
                    } else {
                        config.geometry.reverse_overhead_bytes
                    },
                    native_stall_micros: config.native_stall_micros,
                    stream: *stream,
                }
            }
        };
        DirectionView {
            common: if forward {
                &self.forward
            } else {
                &self.reverse
            },
            profile,
        }
    }
    /// Preserve both global values while projecting their local send/receive order.
    pub fn local(&self, role: Role) -> LocalView<'_> {
        let peer = match role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        };
        LocalView {
            send: self.direction(role),
            receive: self.direction(peer),
        }
    }
    /// Old-policy fence width for the exact global sender.
    pub fn sender_channels(&self, sender: Role) -> u16 {
        self.direction(sender).channels()
    }
    /// Allocation-free represented-field validation, separate from runtime support.
    pub fn validate(&self) -> Result<(), Error> {
        if !(256..=65_535).contains(&self.path_mtu) {
            return Err(Error::PathMtu);
        }
        self.forward.validate()?;
        self.reverse.validate()?;
        let forward = self.direction(Role::Client);
        let reverse = self.direction(Role::Server);
        forward.profile.validate()?;
        reverse.profile.validate()?;
        match self.profile {
            Profile::Rolling { config, .. } => config.validate().map_err(|_| Error::Profile)?,
            Profile::RollingCopies { config, copies, .. } => {
                copies.validate(config).map_err(|_| Error::Profile)?
            }
            _ => {}
        }
        if let Profile::Swift { forward, reverse } = self.profile
            && (forward.layer != reverse.layer
                || forward.max_native == 0
                || forward.max_native != reverse.max_native)
        {
            return Err(Error::Relation);
        }
        for view in [forward, reverse] {
            let common = view.common;
            if view.channels() != common.pipeline.flows.channels
                || view.max_native() != common.pipeline.parse.max_packet_bytes
                || view.profile.layer() != common.traffic.layer
            {
                return Err(Error::Relation);
            }
            if let NativeWindow::Delivery(window) = common.native_window
                && window.max_packet_bytes != integer(view.max_native())?
            {
                return Err(Error::Relation);
            }
        }
        Ok(())
    }
    /// Encode exact canonical bytes; any error leaves caller output unchanged.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != DESCRIPTOR_BYTES {
            return Err(Error::Length);
        }
        output.copy_from_slice(&self.encoded()?);
        Ok(())
    }
    fn encoded(&self) -> Result<[u8; DESCRIPTOR_BYTES], Error> {
        self.validate()?;
        let mut bytes = [0; DESCRIPTOR_BYTES];
        let mut writer = Writer::new(&mut bytes);
        writer.bytes(b"L2RC")?;
        writer.byte(2)?;
        writer.byte(profile_tag(self.profile))?;
        writer.byte(match self.duplex {
            Duplex::Half => 1,
            Duplex::Full => 2,
        })?;
        writer.byte(0)?;
        writer.number(integer(self.path_mtu)?)?;
        encode_common(self.forward, writer.take(COMMON_DIRECTION_BYTES)?)?;
        encode_profile(
            self.direction(Role::Client).profile,
            writer.take(PROFILE_SLOT_BYTES)?,
        )?;
        encode_common(self.reverse, writer.take(COMMON_DIRECTION_BYTES)?)?;
        encode_profile(
            self.direction(Role::Server).profile,
            writer.take(PROFILE_SLOT_BYTES)?,
        )?;
        writer.finish()?;
        if let Profile::RollingCopies { copies, .. } = self.profile {
            for (offset, policy) in [
                (
                    HEADER_BYTES + COMMON_DIRECTION_BYTES + rolling::ACTIVE_BYTES,
                    copies.forward,
                ),
                (
                    HEADER_BYTES + DIRECTION_BYTES + COMMON_DIRECTION_BYTES + rolling::ACTIVE_BYTES,
                    copies.reverse,
                ),
            ] {
                rolling::encode_copy(policy, &mut bytes[offset..offset + 4])?;
            }
        }
        Ok(bytes)
    }
    /// Decode exact CompleteV2 bytes, requiring canonical re-encoding equality.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != DESCRIPTOR_BYTES {
            return Err(Error::Length);
        }
        let mut reader = Reader::new(input);
        if reader.take(4)? != b"L2RC" || reader.byte()? != 2 {
            return Err(Error::Prefix);
        }
        let tag = reader.byte()?;
        if !(1..=5).contains(&tag) {
            return Err(Error::Prefix);
        }
        let duplex = match reader.byte()? {
            1 => Duplex::Half,
            2 => Duplex::Full,
            _ => return Err(Error::Prefix),
        };
        if reader.byte()? != 0 {
            return Err(Error::Prefix);
        }
        let path_mtu = reader.number()?;
        let forward_common = reader.take(COMMON_DIRECTION_BYTES)?;
        let a = reader.take(PROFILE_SLOT_BYTES)?;
        let reverse_common = reader.take(COMMON_DIRECTION_BYTES)?;
        let b = reader.take(PROFILE_SLOT_BYTES)?;
        reader.finish()?;
        for common in [forward_common, reverse_common] {
            preflight_common_padding(common)?;
        }
        for slot in [a, b] {
            match tag {
                1 => padding(&slot[SWIFT_BYTES..])?,
                2 => padding(&slot[ALIGNED_BYTES..])?,
                4 => padding(&slot[rolling::ACTIVE_BYTES..])?,
                _ => {}
            }
        }
        let path_mtu = checked(path_mtu)?;
        let forward = decode_common(forward_common)?;
        let reverse = decode_common(reverse_common)?;
        let profile = match tag {
            1 => Profile::Swift {
                forward: decode_swift(a)?,
                reverse: decode_swift(b)?,
            },
            2 => Profile::Aligned {
                forward: decode_aligned(a)?,
                reverse: decode_aligned(b)?,
            },
            3 => Profile::Packed {
                forward: decode_packed(a)?,
                reverse: decode_packed(b)?,
            },
            4 => rolling::decode_pair(a, b)?,
            5 => rolling::decode_pair_with_copies(a, b)?,
            _ => return Err(Error::Prefix),
        };
        let value = Self::new(path_mtu, duplex, forward, reverse, profile)?;
        if value.encoded()?.as_slice() != input {
            return Err(Error::Scalar);
        }
        Ok(value)
    }
}
fn profile_tag(profile: Profile) -> u8 {
    match profile {
        Profile::Swift { .. } => 1,
        Profile::Aligned { .. } => 2,
        Profile::Packed { .. } => 3,
        Profile::Rolling { .. } => 4,
        Profile::RollingCopies { .. } => 5,
    }
}

/// Exact complete value anchored to the caller's immutable envelope label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Configuration {
    envelope: EnvelopeDigest,
    descriptor: Descriptor,
}
impl Configuration {
    /// Validate complete fields; the envelope is a label, not proof of trust.
    pub fn new(envelope: EnvelopeDigest, descriptor: Descriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            envelope,
            descriptor,
        })
    }
    /// Unchanged label for explicit authenticated contract binding.
    pub const fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Exact globally ordered complete mutable value.
    pub const fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    /// Check represented fields, without inspecting installed runtime capabilities.
    pub fn validate(&self) -> Result<(), Error> {
        self.descriptor.validate()
    }
    /// Encode exact fixed bytes; failure leaves caller output unchanged.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != CONFIGURATION_BYTES {
            return Err(Error::Length);
        }
        let descriptor = self.descriptor.encoded()?;
        output[..HEADER_BYTES].copy_from_slice(&descriptor[..HEADER_BYTES]);
        output[HEADER_BYTES..HEADER_BYTES + 32].copy_from_slice(self.envelope.as_bytes());
        output[HEADER_BYTES + 32..].copy_from_slice(&descriptor[HEADER_BYTES..]);
        Ok(())
    }
    /// Decode exact anchored bytes; never retry another version or drop fields.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != CONFIGURATION_BYTES {
            return Err(Error::Length);
        }
        let mut descriptor = [0; DESCRIPTOR_BYTES];
        descriptor[..HEADER_BYTES].copy_from_slice(&input[..HEADER_BYTES]);
        descriptor[HEADER_BYTES..].copy_from_slice(&input[HEADER_BYTES + 32..]);
        let mut envelope = [0; 32];
        envelope.copy_from_slice(&input[HEADER_BYTES..HEADER_BYTES + 32]);
        Self::new(
            EnvelopeDigest::new(envelope),
            Descriptor::decode(&descriptor)?,
        )
    }
    /// Maintained SHA-256 of the exact domain and complete canonical bytes.
    pub fn digest(&self) -> Result<ConfigDigest, Error> {
        let mut bytes = [0; CONFIGURATION_BYTES];
        self.encode_into(&mut bytes)?;
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(CONFIG_DOMAIN);
        context.update(&bytes);
        let mut result = [0; 32];
        result.copy_from_slice(context.finish().as_ref());
        Ok(ConfigDigest(result))
    }
}
impl transaction::Configuration for Configuration {
    const ENCODING: transaction::ConfigurationEncoding =
        transaction::ConfigurationEncoding::CompleteV2;
    const ENCODED_LEN: usize = CONFIGURATION_BYTES;
    const DIGEST_DOMAIN: &'static [u8] = CONFIG_DOMAIN;
    fn validate(&self) -> Result<(), transaction::Error> {
        Configuration::validate(self)
            .map_err(|_| transaction::Error::Configuration("invalid complete record value"))
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), transaction::Error> {
        Configuration::encode_into(self, output).map_err(|_| transaction::Error::Malformed)
    }
    fn decode(input: &[u8]) -> Result<Self, transaction::Error> {
        Configuration::decode(input).map_err(|_| transaction::Error::Malformed)
    }
    fn channels(&self) -> u16 {
        // Asymmetric consumers must select the explicit directional Peer API.
        self.descriptor.sender_channels(Role::Client)
    }
    fn sender_channels(&self, sender: Role) -> u16 {
        self.descriptor.sender_channels(sender)
    }
    fn duplex(&self) -> Duplex {
        self.descriptor.duplex
    }
}

/// Bounded sorted exact supported set, separate from runtime provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    initial: Descriptor,
    descriptors: Vec<Descriptor>,
    root: CatalogDigest,
}
impl Catalog {
    /// Validate all descriptors before the first fallible bounded reservation.
    pub fn new(initial: Descriptor, supported: &[Descriptor]) -> Result<Self, Error> {
        if !(1..=MAX_CATALOG_ENTRIES).contains(&supported.len()) {
            return Err(Error::CatalogSize);
        }
        let initial_bytes = initial.encoded()?;
        for descriptor in supported {
            descriptor.encoded()?;
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(supported.len())
            .map_err(|_| Error::Allocation)?;
        for descriptor in supported {
            encoded.push((descriptor.encoded()?, *descriptor));
        }
        encoded.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::Duplicate);
        }
        if !encoded.iter().any(|(bytes, _)| *bytes == initial_bytes) {
            return Err(Error::Unlisted);
        }
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(CATALOG_DOMAIN);
        context.update(
            &u16::try_from(encoded.len())
                .map_err(|_| Error::Integer)?
                .to_be_bytes(),
        );
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(encoded.len())
            .map_err(|_| Error::Allocation)?;
        for (bytes, descriptor) in encoded {
            context.update(&bytes);
            descriptors.push(descriptor);
        }
        let mut root = [0; 32];
        root.copy_from_slice(context.finish().as_ref());
        Ok(Self {
            initial,
            descriptors,
            root: CatalogDigest(root),
        })
    }
    /// Exact chosen initial member, independent of its sorted position.
    pub const fn initial(&self) -> Descriptor {
        self.initial
    }
    /// All complete members in canonical anchor-free byte order.
    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }
    /// Exact domain-separated root; authentication remains external.
    pub const fn root(&self) -> CatalogDigest {
        self.root
    }
    /// Bind each checked member to the exact envelope using bounded fallible storage.
    pub fn configurations(&self, envelope: EnvelopeDigest) -> Result<Vec<Configuration>, Error> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.descriptors.len())
            .map_err(|_| Error::Allocation)?;
        for descriptor in &self.descriptors {
            values.push(Configuration {
                envelope,
                descriptor: *descriptor,
            });
        }
        Ok(values)
    }
}

fn integer(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::Integer)
}
fn checked<T: TryFrom<u64>>(value: u64) -> Result<T, Error> {
    T::try_from(value).map_err(|_| Error::Integer)
}
fn padding(bytes: &[u8]) -> Result<(), Error> {
    if bytes.iter().any(|byte| *byte != 0) {
        Err(Error::Padding)
    } else {
        Ok(())
    }
}
struct Writer<'a> {
    output: &'a mut [u8],
    at: usize,
}
impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, at: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&mut [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Length)?;
        let result = self.output.get_mut(self.at..end).ok_or(Error::Length)?;
        self.at = end;
        Ok(result)
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.take(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.bytes(&[byte])
    }
    fn number(&mut self, number: u64) -> Result<(), Error> {
        self.bytes(&number.to_be_bytes())
    }
    fn size(&mut self, number: usize) -> Result<(), Error> {
        self.number(integer(number)?)
    }
    fn duration(&mut self, duration: Duration) -> Result<(), Error> {
        self.number(duration.as_secs())?;
        self.number(u64::from(duration.subsec_nanos()))
    }
    fn finish(self) -> Result<(), Error> {
        if self.at == self.output.len() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
}
struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Length)?;
        let bytes = self.input.get(self.at..end).ok_or(Error::Length)?;
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(*self.take(1)?.first().ok_or(Error::Length)?)
    }
    fn number(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Length)?,
        ))
    }
    fn size(&mut self) -> Result<usize, Error> {
        checked(self.number()?)
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Scalar),
        }
    }
    fn duration(&mut self) -> Result<Duration, Error> {
        let seconds = self.number()?;
        let nanos = self.number()?;
        if nanos >= 1_000_000_000 {
            return Err(Error::Scalar);
        }
        Ok(Duration::new(seconds, checked(nanos)?))
    }
    fn finish(self) -> Result<(), Error> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
}

fn encode_common(config: CommonDirection, output: &mut [u8]) -> Result<(), Error> {
    let pipeline = config.pipeline;
    let (tag, qos) = match pipeline.profile {
        pipeline::Profile::TapSystem => (1, [0; 4]),
        pipeline::Profile::TunDrr(qos) => (
            2,
            [
                u64::from(qos.base_quantum_bytes),
                u64::from(qos.max_weight),
                integer(qos.per_flow.bytes)?,
                integer(qos.per_flow.packets)?,
            ],
        ),
    };
    let window = match config.native_window {
        NativeWindow::Disabled => [0; 13],
        NativeWindow::Delivery(window) => [
            1,
            window.target_bandwidth_bps,
            window.bootstrap_rtt_micros,
            window.min_rtt_micros,
            window.max_rtt_micros,
            u64::from(window.headroom_percent),
            window.minimum_bytes,
            window.max_inflight_bytes,
            integer(window.max_records)?,
            window.max_packet_bytes,
            integer(window.metadata_limit_bytes)?,
            window.sample_ttl_micros,
            window.flush_timeout_micros,
        ],
    };
    let mut writer = Writer::new(output);
    for value in [
        match config.traffic.layer {
            traffic::NetworkLayer::Tap => 1,
            traffic::NetworkLayer::Tun => 2,
        },
        match config.traffic.tcp {
            traffic::TcpControl::System => 1,
            traffic::TcpControl::TunnelCredits => 2,
            traffic::TcpControl::SplitTcpProxy => 3,
        },
        match config.traffic.qos {
            traffic::Qos::System => 1,
            traffic::Qos::WeightedDeficit => 2,
        },
        tag,
        match pipeline.flows.mapping {
            Mapping::Crc32 => 1,
            Mapping::ConnectionRoundRobin => 2,
        },
        integer(pipeline.flows.capacity)?,
        u64::from(pipeline.flows.channels),
        pipeline.flows.idle_timeout.as_secs(),
        u64::from(pipeline.flows.idle_timeout.subsec_nanos()),
    ]
    .into_iter()
    .chain(qos)
    .chain([
        integer(pipeline.parse.max_packet_bytes)?,
        u64::from(pipeline.parse.max_vlan_tags),
        u64::from(pipeline.parse.max_ipv6_extensions),
        integer(pipeline.parse.max_ipv6_extension_bytes)?,
        integer(pipeline.queue.bytes)?,
        integer(pipeline.queue.packets)?,
        config.bytes_per_second,
        integer(config.burst_bytes)?,
    ])
    .chain(window)
    {
        writer.number(value)?;
    }
    writer.finish()
}
fn decode_common(input: &[u8]) -> Result<CommonDirection, Error> {
    let mut reader = Reader::new(input);
    let traffic = traffic::TrafficPolicy {
        layer: match reader.number()? {
            1 => traffic::NetworkLayer::Tap,
            2 => traffic::NetworkLayer::Tun,
            _ => return Err(Error::Prefix),
        },
        tcp: match reader.number()? {
            1 => traffic::TcpControl::System,
            2 => traffic::TcpControl::TunnelCredits,
            3 => traffic::TcpControl::SplitTcpProxy,
            _ => return Err(Error::Prefix),
        },
        qos: match reader.number()? {
            1 => traffic::Qos::System,
            2 => traffic::Qos::WeightedDeficit,
            _ => return Err(Error::Prefix),
        },
    };
    let tag = reader.number()?;
    let mapping = match reader.number()? {
        1 => Mapping::Crc32,
        2 => Mapping::ConnectionRoundRobin,
        _ => return Err(Error::Prefix),
    };
    let capacity = reader.size()?;
    let channels = checked(reader.number()?)?;
    let idle_timeout = reader.duration()?;
    let qos_bytes = reader.take(32)?;
    let profile = match tag {
        1 => {
            padding(qos_bytes)?;
            pipeline::Profile::TapSystem
        }
        2 => {
            let mut qos = Reader::new(qos_bytes);
            pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                base_quantum_bytes: checked(qos.number()?)?,
                max_weight: checked(qos.number()?)?,
                per_flow: pipeline::QueueLimits {
                    bytes: qos.size()?,
                    packets: qos.size()?,
                },
            })
        }
        _ => return Err(Error::Prefix),
    };
    let pipeline = pipeline::PipelineConfig {
        profile,
        flows: pipeline::FlowTableConfig {
            capacity,
            channels,
            mapping,
            idle_timeout,
        },
        parse: pipeline::ParseLimits {
            max_packet_bytes: reader.size()?,
            max_vlan_tags: checked(reader.number()?)?,
            max_ipv6_extensions: checked(reader.number()?)?,
            max_ipv6_extension_bytes: reader.size()?,
        },
        queue: pipeline::QueueLimits {
            bytes: reader.size()?,
            packets: reader.size()?,
        },
    };
    let bytes_per_second = reader.number()?;
    let burst_bytes = reader.size()?;
    let tag = reader.number()?;
    let fields = reader.take(96)?;
    let native_window = match tag {
        0 => {
            padding(fields)?;
            NativeWindow::Disabled
        }
        1 => {
            let mut fields = Reader::new(fields);
            NativeWindow::Delivery(delivery_window::Config {
                target_bandwidth_bps: fields.number()?,
                bootstrap_rtt_micros: fields.number()?,
                min_rtt_micros: fields.number()?,
                max_rtt_micros: fields.number()?,
                headroom_percent: checked(fields.number()?)?,
                minimum_bytes: fields.number()?,
                max_inflight_bytes: fields.number()?,
                max_records: fields.size()?,
                max_packet_bytes: fields.number()?,
                metadata_limit_bytes: fields.size()?,
                sample_ttl_micros: fields.number()?,
                flush_timeout_micros: fields.number()?,
            })
        }
        _ => return Err(Error::Prefix),
    };
    reader.finish()?;
    Ok(CommonDirection {
        traffic,
        pipeline,
        bytes_per_second,
        burst_bytes,
        native_window,
    })
}

fn preflight_common_padding(input: &[u8]) -> Result<(), Error> {
    let word = |index: usize| -> Result<u64, Error> {
        let bytes = input.get(index * 8..(index + 1) * 8).ok_or(Error::Length)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| Error::Length)?,
        ))
    };
    match word(3)? {
        1 => padding(input.get(9 * 8..13 * 8).ok_or(Error::Length)?)?,
        2 => {}
        _ => return Err(Error::Prefix),
    }
    match word(21)? {
        0 => padding(input.get(22 * 8..34 * 8).ok_or(Error::Length)?)?,
        1 => {}
        _ => return Err(Error::Prefix),
    }
    Ok(())
}

fn encode_profile(profile: DirectionProfile<'_>, output: &mut [u8]) -> Result<(), Error> {
    output.fill(0);
    match profile {
        DirectionProfile::Swift(config) => {
            encode_swift(*config, output.get_mut(..SWIFT_BYTES).ok_or(Error::Length)?)
        }
        DirectionProfile::Aligned(config) => encode_aligned(
            *config,
            output.get_mut(..ALIGNED_BYTES).ok_or(Error::Length)?,
        ),
        DirectionProfile::Packed(config) => {
            let mut writer = Writer::new(output);
            encode_aligned(config.base, writer.take(ALIGNED_BYTES)?)?;
            writer.number(config.hold_micros)?;
            writer.number(u64::from(config.max_units))?;
            writer.size(config.work_limit)?;
            writer.finish()
        }
        DirectionProfile::Rolling {
            config,
            overhead_bytes,
            native_stall_micros,
            stream,
        } => rolling::encode(*config, overhead_bytes, native_stall_micros, stream, output),
    }
}
fn encode_swift(config: records::Config, output: &mut [u8]) -> Result<(), Error> {
    let codec = config.codec;
    let mut writer = Writer::new(output);
    for value in [
        integer(config.channels)?,
        match config.layer {
            records::Layer::Ethernet => 1,
            records::Layer::Ip => 2,
        },
        integer(config.max_native)?,
        integer(codec.datagram_bytes)?,
        integer(codec.window)?,
        u64::from(codec.repair_numerator),
        u64::from(codec.repair_denominator),
        integer(codec.flow_sources)?,
        integer(codec.queue_bytes)?,
        integer(codec.max_packet)?,
        codec.flush_micros,
        codec.feedback_micros,
        codec.tail_micros,
        codec.min_rto_micros,
        codec.max_rto_micros,
    ] {
        writer.number(value)?;
    }
    writer.finish()
}
fn decode_swift(input: &[u8]) -> Result<records::Config, Error> {
    padding(input.get(SWIFT_BYTES..).ok_or(Error::Length)?)?;
    let mut reader = Reader::new(input.get(..SWIFT_BYTES).ok_or(Error::Length)?);
    let channels = reader.size()?;
    let layer = match reader.number()? {
        1 => records::Layer::Ethernet,
        2 => records::Layer::Ip,
        _ => return Err(Error::Prefix),
    };
    let max_native = reader.size()?;
    let codec = swift::Config {
        datagram_bytes: reader.size()?,
        window: reader.size()?,
        repair_numerator: checked(reader.number()?)?,
        repair_denominator: checked(reader.number()?)?,
        flow_sources: reader.size()?,
        queue_bytes: reader.size()?,
        max_packet: reader.size()?,
        flush_micros: reader.number()?,
        feedback_micros: reader.number()?,
        tail_micros: reader.number()?,
        min_rto_micros: reader.number()?,
        max_rto_micros: reader.number()?,
    };
    reader.finish()?;
    Ok(records::Config {
        codec,
        channels,
        layer,
        max_native,
    })
}

fn encode_aligned(config: aligned::Config, output: &mut [u8]) -> Result<(), Error> {
    let receiver = config.receiver;
    let body = receiver.body;
    let mut writer = Writer::new(output);
    writer.byte(match config.native_policy {
        aligned::NativePolicy::EthernetHeaders => 1,
        aligned::NativePolicy::RawIp => 2,
        aligned::NativePolicy::IpHeaders => 3,
    })?;
    for value in [
        body.max_frame_bytes,
        body.symbol_bytes,
        body.independent_short_frame_bytes,
    ] {
        writer.size(value)?;
    }
    for value in [
        body.elide_payload_length,
        body.predictive,
        body.timestamp_pair_dictionary,
    ] {
        writer.byte(u8::from(value))?;
    }
    for value in [
        u64::from(receiver.channels),
        receiver.first_record.0,
        receiver.first_source.0,
        u64::from(receiver.record_window),
        integer(receiver.source_window)?,
        integer(receiver.lookahead_records)?,
        integer(receiver.lookahead_bytes)?,
        integer(receiver.lookahead_fragments)?,
        integer(receiver.max_fragments_per_record)?,
        receiver.lifetime_ticks,
    ] {
        writer.number(value)?;
    }
    let recovery = config.recovery;
    let arq = recovery.arq;
    for value in [
        arq.max_source_bytes,
        arq.send_bytes,
        arq.receive_bytes,
        arq.send_records,
        arq.receive_records,
    ] {
        writer.size(value)?;
    }
    for value in [arq.initial_rto, arq.maximum_rto, arq.ack_delay] {
        writer.duration(value)?;
    }
    writer.number(u64::from(arq.max_retries))?;
    let fec = recovery.fec;
    for value in [
        integer(fec.block.max_sources)?,
        integer(fec.block.max_source_bytes)?,
        integer(fec.block.max_packet_bytes)?,
        fec.block.max_work_per_symbol,
        integer(fec.max_generations)?,
        integer(fec.max_symbols_per_generation)?,
        integer(fec.max_reserved_bytes)?,
        fec.max_lifetime_ticks,
        fec.generation_window,
        integer(recovery.repair_symbols)?,
    ] {
        writer.number(value)?;
    }
    writer.duration(recovery.flush_after)?;
    for value in [
        recovery.max_restored_packets,
        recovery.max_restored_bytes,
        recovery.outer_overhead_bytes,
        config.max_recovery_packet_bytes,
    ] {
        writer.size(value)?;
    }
    writer.finish()
}
fn read_aligned(reader: &mut Reader<'_>) -> Result<aligned::Config, Error> {
    let native_policy = match reader.byte()? {
        1 => aligned::NativePolicy::EthernetHeaders,
        2 => aligned::NativePolicy::RawIp,
        3 => aligned::NativePolicy::IpHeaders,
        _ => return Err(Error::Prefix),
    };
    let max_frame_bytes = reader.size()?;
    let symbol_bytes = reader.size()?;
    let independent_short_frame_bytes = reader.size()?;
    let body = aligned_body::Config {
        max_frame_bytes,
        symbol_bytes,
        independent_short_frame_bytes,
        elide_payload_length: reader.boolean()?,
        predictive: reader.boolean()?,
        timestamp_pair_dictionary: reader.boolean()?,
    };
    let receiver = aligned_receiver::Limits {
        body,
        channels: checked(reader.number()?)?,
        first_record: aligned_receiver::RecordId(reader.number()?),
        first_source: aligned_receiver::SourceId(reader.number()?),
        record_window: checked(reader.number()?)?,
        source_window: reader.size()?,
        lookahead_records: reader.size()?,
        lookahead_bytes: reader.size()?,
        lookahead_fragments: reader.size()?,
        max_fragments_per_record: reader.size()?,
        lifetime_ticks: reader.number()?,
    };
    let arq = ArqConfig {
        max_source_bytes: reader.size()?,
        send_bytes: reader.size()?,
        receive_bytes: reader.size()?,
        send_records: reader.size()?,
        receive_records: reader.size()?,
        initial_rto: reader.duration()?,
        maximum_rto: reader.duration()?,
        ack_delay: reader.duration()?,
        max_retries: checked(reader.number()?)?,
    };
    let fec = fec::DecoderConfig {
        block: fec::BlockConfig {
            max_sources: reader.size()?,
            max_source_bytes: reader.size()?,
            max_packet_bytes: reader.size()?,
            max_work_per_symbol: reader.number()?,
        },
        max_generations: reader.size()?,
        max_symbols_per_generation: reader.size()?,
        max_reserved_bytes: reader.size()?,
        max_lifetime_ticks: reader.number()?,
        generation_window: reader.number()?,
    };
    let recovery = ReliableConfig {
        arq,
        fec,
        repair_symbols: reader.size()?,
        flush_after: reader.duration()?,
        max_restored_packets: reader.size()?,
        max_restored_bytes: reader.size()?,
        outer_overhead_bytes: reader.size()?,
    };
    Ok(aligned::Config {
        native_policy,
        receiver,
        recovery,
        max_recovery_packet_bytes: reader.size()?,
    })
}
fn decode_aligned(input: &[u8]) -> Result<aligned::Config, Error> {
    padding(input.get(ALIGNED_BYTES..).ok_or(Error::Length)?)?;
    let mut reader = Reader::new(input.get(..ALIGNED_BYTES).ok_or(Error::Length)?);
    let config = read_aligned(&mut reader)?;
    reader.finish()?;
    Ok(config)
}
fn decode_packed(input: &[u8]) -> Result<aligned::packed::Config, Error> {
    let mut reader = Reader::new(input);
    let base = read_aligned(&mut reader)?;
    let value = aligned::packed::Config {
        base,
        hold_micros: reader.number()?,
        max_units: checked(reader.number()?)?,
        work_limit: reader.size()?,
    };
    reader.finish()?;
    Ok(value)
}

#[cfg(test)]
mod rolling_tests;
#[cfg(test)]
mod tests;
