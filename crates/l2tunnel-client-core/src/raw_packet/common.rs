//! Explicit carrier-only raw policy and fresh original PacketIo acquisition.
//! Common record/recovery policy remains in the complete authenticated catalog.
use super::*;
use std::sync::Arc;

/// Strict independent raw carrier policy; no ignored legacy recovery fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings(Document);
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u16,
    profile: String,
    forward: Endpoints,
    reverse: Option<Endpoints>,
    packet: Packet,
}
impl Settings {
    /// Parse the complete bounded carrier-only request without opening originals.
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("raw Common policy bound"));
        }
        let value: Document = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid strict raw Common carrier policy"))?;
        if value.version != 1 || value.profile != "raw-common-carrier-v1" {
            return Err(invalid("raw Common carrier profile/version"));
        }
        value
            .packet
            .policy()
            .record_geometry()
            .map_err(io::Error::other)?;
        raw_config(value.forward, value.packet)?;
        if let Some(reverse) = value.reverse {
            raw_config(reverse, value.packet)?;
            if reverse.local == value.forward.local || reverse.peer == value.forward.peer {
                return Err(invalid("raw Half originals require distinct tuples"));
            }
        }
        Ok(Self(value))
    }
    /// Exact maintained packet geometry/pacing/protection policy.
    pub fn packet_policy(&self) -> PacketPolicy {
        self.0.packet.policy()
    }
    /// Role-local first original tuple, without logical endpoint substitution.
    pub fn forward(&self) -> (SocketAddrV4, SocketAddrV4) {
        (self.0.forward.local, self.0.forward.peer)
    }
    /// Explicit Full/Half original-owner shape.
    pub fn duplex(&self) -> Duplex {
        if self.0.reverse.is_some() {
            Duplex::Half
        } else {
            Duplex::Full
        }
    }
    pub(crate) fn validate(
        &self,
        profile: &crate::secure_udp::common_transaction_profile::Profile,
        role: l2tunnel_security::Role,
    ) -> io::Result<()> {
        let connection = profile.connection();
        let us = connection.handshake_timeout.as_micros();
        if !(1000..=30_000_000).contains(&us)
            || !connection
                .handshake_timeout
                .subsec_nanos()
                .is_multiple_of(1000)
            || self.duplex() != connection.duplex
            || profile.raw_policy() != Some(self.packet_policy())
        {
            return Err(invalid("raw Common exact timeout/duplex/policy differs"));
        }
        let path = profile.settings().gate.path;
        let expected = match role {
            l2tunnel_security::Role::Initiator => (path.client, path.server),
            l2tunnel_security::Role::Responder => (path.server, path.client),
        };
        let actual = self.forward();
        if expected != (actual.0.into(), actual.1.into()) {
            return Err(invalid("raw first original differs from Common endpoint"));
        }
        profile.validate_raw_request()?;
        let first = raw_config(self.0.forward, self.0.packet)?;
        let second = self
            .0
            .reverse
            .map(|endpoints| raw_config(endpoints, self.0.packet))
            .transpose()?;
        self.phase(profile)?
            .preflight::<PacketOwner>(first, second)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }
    pub(crate) fn phase(
        &self,
        profile: &crate::secure_udp::common_transaction_profile::Profile,
    ) -> io::Result<PacketPhaseConfig> {
        let connection = profile.connection();
        Ok(PacketPhaseConfig {
            pair: PairConfig {
                session: l2tunnel_auth::SessionConfig {
                    layer: connection.layer,
                    digest: l2tunnel_core::ConfigDigest(profile.requested_configuration()?.0),
                },
                messages: MessageLimits::default(),
                driver: SwitchLimits::default(),
                timeout: connection.handshake_timeout,
            },
            packet: self.packet_policy(),
        })
    }
    pub(crate) fn open(
        &self,
        role: Role,
        deadline: Instant,
        opener: &PacketOpener,
    ) -> io::Result<RawInputs<PacketOwner>> {
        inputs_for(
            self.0.forward,
            self.0.reverse,
            self.0.packet,
            role,
            deadline,
            |config, role| (opener.open)(config, role),
        )
    }
}
/// A bounded trusted factory of fresh original PacketIo for explicit reconnect.
/// It never runs during Prepared validation and owns no background task.
#[derive(Clone)]
pub struct PacketOpener {
    open: Arc<Open>,
}
type Open = dyn Fn(RawConfig, Role) -> io::Result<PacketOwner> + Send + Sync;
impl PacketOpener {
    /// Retain the caller's actual nonblocking original opener. Trusted captures
    /// must be finite; dropping a partial setup releases every returned owner.
    pub fn new<I: PacketIo + Send + 'static>(
        open: impl Fn(RawConfig, Role) -> io::Result<I> + Send + Sync + 'static,
    ) -> Self {
        Self {
            open: Arc::new(move |config, role| {
                open(config, role).map(|io| PacketOwner(Box::new(io)))
            }),
        }
    }
}
pub(crate) struct PacketOwner(Box<dyn PacketIo + Send>);
impl PacketIo for PacketOwner {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.0.receive(output)
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0.send(packet)
    }
}
