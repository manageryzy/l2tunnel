//! Explicit shared-carrier authentication factories, without a private CLI path.
//!
//! Authentication readiness is distinct from native runtime readiness. The caller
//! transfers every returned tail to the one selected-carrier data/control reader.

#[cfg(all(test, unix))]
pub(crate) mod common_fixture;
#[cfg(unix)]
pub(crate) use crate::cli::secure_udp_frontend::{common_cli, common_runtime_cli};
#[cfg(not(unix))]
pub(crate) mod common_cli;
#[cfg(not(unix))]
pub(crate) mod common_runtime_cli;
/// Portable complete Common configuration values and explicit APIv4 observations.
pub mod common_status;
/// Explicit complete common record catalog and actual authentication handoff.
pub mod common_transaction_profile;
/// Explicit runtime credential owners and bounded manual key-file readers.
pub mod credentials;
pub(crate) mod datagram_profile;
/// Explicit maintained TCP/TLS and genuine QUIC Common transport policies.
pub mod maintained;
/// Load a provisioned native Common UDP client.
pub mod native_client;
/// Bounded performance telemetry shared by CLI and embedding frontends.
pub mod performance;

use l2tunnel_core::ConfigDigest;
use l2tunnel_cover as cover;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_runtime::secure_udp::{diagnostics, establish, member};
use l2tunnel_security as security;
use l2tunnel_udp_control as gate;
use ring::digest;
use std::{io, time::Duration};
use tokio::{net::UdpSocket, time::Instant};

/// Complete public appearance contract, in fixed global endpoint order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cover {
    /// Explicit selected layout; no default carrier is inferred.
    pub appearance: cover::Appearance,
    /// Initiating endpoint's fixed connection identifier.
    pub initiator_connection: cover::ConnectionId,
    /// Responding endpoint's fixed connection identifier.
    pub responder_connection: cover::ConnectionId,
    /// Initiating endpoint's RTP-like source identity.
    pub initiator_ssrc: cover::Ssrc,
    /// Responding endpoint's RTP-like source identity.
    pub responder_ssrc: cover::Ssrc,
    /// Explicit dynamic media payload type, without a codec claim.
    pub payload_type: u8,
    /// Maximum complete covered UDP payload.
    pub max_packet_bytes: usize,
    /// Maximum opaque protected bytes inside that cover.
    pub max_protected_bytes: usize,
}

impl Cover {
    /// Exact gate-accounting overhead: IP/UDP, bootstrap tag and handshake cover.
    /// Set the explicit gate contract to this value before constructing Settings.
    pub fn bootstrap_overhead(self, ipv6: bool) -> io::Result<usize> {
        let header = self
            .config(security::Role::Initiator)?
            .overhead(cover::Phase::Handshake, gate::GATE_BYTES + 1)
            .map_err(invalid)?;
        header
            .checked_add(1 + if ipv6 { 48 } else { 28 })
            .ok_or_else(|| invalid("bootstrap overhead overflow"))
    }

    fn config(self, role: security::Role) -> io::Result<cover::Config> {
        let initiator = role == security::Role::Initiator;
        let (local, peer, local_ssrc, peer_ssrc) = if initiator {
            (
                self.initiator_connection,
                self.responder_connection,
                self.initiator_ssrc,
                self.responder_ssrc,
            )
        } else {
            (
                self.responder_connection,
                self.initiator_connection,
                self.responder_ssrc,
                self.initiator_ssrc,
            )
        };
        cover::Config::new(
            self.appearance,
            cover::ConnectionIds { local, peer },
            cover::MediaConfig {
                local_ssrc,
                peer_ssrc,
                payload_type: self.payload_type,
            },
            cover::Limits {
                max_packet_bytes: self.max_packet_bytes,
                max_protected_bytes: self.max_protected_bytes,
            },
        )
        .map_err(invalid)
    }

    fn digest(self) -> io::Result<[u8; 32]> {
        self.config(security::Role::Initiator)?;
        self.config(security::Role::Responder)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-client/udp-cover/v1\0");
        hash.update(&[match self.appearance {
            cover::Appearance::QuicLike => 1,
            cover::Appearance::MediaLike => 2,
        }]);
        hash.update(&self.initiator_connection.0);
        hash.update(&self.responder_connection.0);
        hash.update(&self.initiator_ssrc.0.to_be_bytes());
        hash.update(&self.responder_ssrc.0.to_be_bytes());
        hash.update(&[self.payload_type]);
        hash_usize(&mut hash, self.max_packet_bytes)?;
        hash_usize(&mut hash, self.max_protected_bytes)?;
        Ok(finish(hash))
    }
}

/// Explicit joining proof/reply retry and input-work bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Membership {
    /// Retry interval for exact cached joining ciphertext.
    pub retry_interval: Duration,
    /// Complete joining transmissions including the original, in 1..=1024.
    pub max_attempts: u32,
    /// Positive input-work interval, at most one second.
    pub receive_interval: Duration,
    /// Input datagrams processed per interval, in 1..=1024.
    pub receive_packets_per_interval: u32,
}

impl Membership {
    fn validate(self) -> io::Result<()> {
        if self.retry_interval.is_zero()
            || self.retry_interval > Duration::from_secs(1)
            || self.receive_interval.is_zero()
            || self.receive_interval > Duration::from_secs(1)
            || !(1..=1024).contains(&self.max_attempts)
            || !(1..=1024).contains(&self.receive_packets_per_interval)
        {
            return Err(invalid("invalid member retry or input-work limits"));
        }
        Ok(())
    }

    fn runtime(self, context: identity::Context) -> member::Settings {
        member::Settings {
            context,
            retry_interval: self.retry_interval,
            max_attempts: self.max_attempts,
            receive_interval: self.receive_interval,
            receive_packets_per_interval: self.receive_packets_per_interval,
        }
    }
}

/// Public fixed-peer contract; all secrets remain separate owned inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Complete existing admission/ARQ/resource contract and fixed path.
    pub gate: gate::Config,
    /// Complete global explicit appearance contract.
    pub cover: Cover,
    /// Required Noise profile, with no peer-selected downgrade.
    pub profile: hs::Profile,
    /// Embedding data profile's canonical complete application digest.
    pub application: ConfigDigest,
    /// Explicit outer ownership binding; never a secret or certificate witness.
    pub outer: [u8; 32],
    /// Existing fixed client's Ed25519 member identity from trusted configuration.
    pub member: identity::MemberPublicKey,
    /// Explicit membership retry, deadline-service and input-work limits.
    pub membership: Membership,
    /// Bootstrap datagrams examined per gate interval, in 1..=4096.
    pub bootstrap_receive_packets_per_interval: u32,
}

impl Settings {
    /// Bind the complete selected public/resource contract in global role order.
    pub fn configuration(&self, peers: establish::Peers) -> io::Result<security::ConfigDigest> {
        self.membership.validate()?;
        if !(1..=4096).contains(&self.bootstrap_receive_packets_per_interval) {
            return Err(invalid("invalid bootstrap input-work bound"));
        }
        let carrier = self.cover.digest()?;
        let gate = self.gate.profile_digest().map_err(invalid)?;
        let ip_bytes = if self.gate.path.client.is_ipv4() {
            28
        } else {
            48
        };
        if self.gate.outer_overhead
            != self
                .cover
                .bootstrap_overhead(self.gate.path.client.is_ipv6())?
        {
            return Err(invalid(
                "gate overhead does not include the selected bootstrap cover",
            ));
        }
        let protected_bootstrap = self
            .gate
            .arq
            .max_source_bytes
            .checked_add(gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES + 1)
            .ok_or_else(|| invalid("bootstrap source geometry overflow"))?
            .max(gate::GATE_BYTES + 1);
        let bootstrap_header = self
            .cover
            .config(security::Role::Initiator)?
            .overhead(cover::Phase::Handshake, protected_bootstrap)
            .map_err(invalid)?;
        let bootstrap_packet = protected_bootstrap
            .checked_add(bootstrap_header)
            .ok_or_else(|| invalid("bootstrap packet geometry overflow"))?;
        if bootstrap_packet > self.cover.max_packet_bytes
            || bootstrap_packet
                .checked_add(ip_bytes)
                .is_none_or(|bytes| bytes > self.gate.path_mtu)
        {
            return Err(invalid(
                "actual bootstrap packet exceeds the configured path MTU",
            ));
        }
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-client/udp-configuration/v1\0");
        hash.update(&self.application.0);
        hash.update(&gate);
        // The reused gate's historical digest uses microseconds. Bind the exact
        // public Duration values too, so submicrosecond differences cannot alias.
        for duration in [
            self.gate.cookie_ttl,
            self.gate.handshake_timeout,
            self.gate.interval,
            self.gate.initial_rto,
            self.gate.maximum_rto,
            self.gate.arq.initial_rto,
            self.gate.arq.maximum_rto,
            self.gate.arq.ack_delay,
            self.membership.retry_interval,
            self.membership.receive_interval,
        ] {
            hash.update(&duration.as_nanos().to_be_bytes());
        }
        hash.update(&carrier);
        hash.update(&[match self.profile {
            hs::Profile::Ik => 1,
            hs::Profile::IkPsk2 => 2,
        }]);
        hash.update(&peers.initiator.0);
        hash.update(&peers.responder.0);
        hash.update(&self.member.0);
        hash.update(&self.outer);
        hash.update(&self.membership.max_attempts.to_be_bytes());
        hash.update(&self.membership.receive_packets_per_interval.to_be_bytes());
        hash.update(&self.bootstrap_receive_packets_per_interval.to_be_bytes());
        Ok(security::ConfigDigest(finish(hash)))
    }

    pub(crate) fn runtime(
        self,
        role: security::Role,
        peers: establish::Peers,
    ) -> io::Result<establish::Config> {
        let configuration = self.configuration(peers)?;
        let mut member = digest::Context::new(&digest::SHA256);
        member.update(b"l2tunnel/shared-client/member-policy/v1\0");
        member.update(&self.member.0);
        member.update(&peers.initiator.0);
        member.update(&peers.responder.0);
        Ok(establish::Config {
            gate: self.gate,
            cover: self.cover.config(role)?,
            profile: self.profile,
            binding: establish::Binding {
                configuration: configuration.0,
                carrier: self.cover.digest()?,
                outer: self.outer,
                member: finish(member),
            },
            receive_packets_per_interval: self.bootstrap_receive_packets_per_interval,
        })
    }
}

/// Completed authentication with requested/effective configuration and all owners.
/// This is not the service actor's native-runtime `Connected` observation.
pub struct Session {
    requested: Settings,
    effective: establish::Config,
    authenticated: member::Authenticated,
}

impl Session {
    /// Exact requested settings, with no secret material or silent fallback.
    pub fn requested(&self) -> Settings {
        self.requested
    }
    /// Validated role-specific bootstrap cover and binding derivation inputs.
    /// The exact authenticated prologue is separately exposed by `info()`.
    pub fn effective(&self) -> establish::Config {
        self.effective
    }
    /// Actual completed member identity and original endpoint observations.
    pub fn info(&self) -> member::Info {
        self.authenticated.info()
    }
    /// Transfer the original socket/root and both tails to the sole runtime reader.
    pub fn into_parts(self) -> member::Parts {
        self.authenticated.into_parts()
    }
}

/// Authenticate the actual fixed client on its original connected UDP socket.
pub async fn connect(
    socket: UdpSocket,
    settings: Settings,
    identity: establish::Identity,
    member: &identity::IdentityKey,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
) -> io::Result<Session> {
    connect_observed(
        socket,
        settings,
        identity,
        member,
        admission,
        deadline,
        entropy,
        &mut |_| {},
    )
    .await
}

/// Authenticate with shared bounded setup observations, preserving the original result.
#[allow(clippy::too_many_arguments)] // Preserve the established shared factory inputs with an additive observer.
pub async fn connect_observed(
    socket: UdpSocket,
    settings: Settings,
    identity: establish::Identity,
    member: &identity::IdentityKey,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Session> {
    observe(diagnostics::Observation::new(
        diagnostics::Stage::Configuration,
    ));
    if member.public_key() != settings.member {
        configuration_failure(observe);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured member differs from the supplied credential",
        ));
    }
    let peers = establish::Peers {
        initiator: identity.local.public_key(),
        responder: identity.peer,
    };
    let effective = settings
        .runtime(security::Role::Initiator, peers)
        .inspect_err(|_| configuration_failure(observe))?;
    connect_effective_observed(
        socket, settings, effective, identity, member, admission, deadline, entropy, observe,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_common_observed(
    socket: UdpSocket,
    profile: &common_transaction_profile::Profile,
    identity: establish::Identity,
    member: &identity::IdentityKey,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Session> {
    observe(diagnostics::Observation::new(
        diagnostics::Stage::Configuration,
    ));
    let settings = profile.settings();
    if member.public_key() != settings.member
        || identity.local.public_key() != profile.peers().initiator
        || identity.peer != profile.peers().responder
    {
        configuration_failure(observe);
        return Err(invalid(
            "Common client credentials differ from the configured trust",
        ));
    }
    let effective = profile
        .establish_config(security::Role::Initiator)
        .inspect_err(|_| configuration_failure(observe))?;
    connect_effective_observed(
        socket, settings, effective, identity, member, admission, deadline, entropy, observe,
    )
    .await
}

// Both factories consume an actual typed selection before the same Noise/member
// exchange. No public digest setter, copied Info or independent setup loop exists.
#[allow(clippy::too_many_arguments)]
async fn connect_effective_observed(
    socket: UdpSocket,
    settings: Settings,
    effective: establish::Config,
    identity: establish::Identity,
    member: &identity::IdentityKey,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> io::Result<Session> {
    let established = establish::connect_observed(
        socket, effective, identity, admission, deadline, entropy, observe,
    )
    .await
    .map_err(runtime_error)?;
    let context = proof_context(&established);
    let authenticated = member::connect_observed(
        established,
        member,
        settings.membership.runtime(context),
        observe,
    )
    .await?;
    Ok(Session {
        requested: settings,
        effective,
        authenticated,
    })
}

/// Reusable fixed-peer admission owner, preserving quarantine across attempts.
pub struct Server {
    settings: Settings,
    peers: establish::Peers,
    effective: establish::Config,
    admission: establish::ServerAdmission,
}

impl Server {
    /// Validate explicit public policy and retain the independently keyed cookie gate.
    pub fn new(
        settings: Settings,
        peers: establish::Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> io::Result<Self> {
        let effective = settings.runtime(security::Role::Responder, peers)?;
        Self::from_effective(settings, peers, effective, admission, cookie, origin)
    }
    pub(crate) fn new_common(
        profile: &common_transaction_profile::Profile,
        peers: establish::Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> io::Result<Self> {
        if peers != profile.peers() {
            return Err(invalid(
                "Common server credentials differ from configured pins",
            ));
        }
        Self::from_effective(
            profile.settings(),
            peers,
            profile.establish_config(security::Role::Responder)?,
            admission,
            cookie,
            origin,
        )
    }
    fn from_effective(
        settings: Settings,
        peers: establish::Peers,
        effective: establish::Config,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> io::Result<Self> {
        let admission =
            establish::ServerAdmission::new(effective, peers, admission, cookie, origin)
                .map_err(runtime_error)?;
        Ok(Self {
            settings,
            peers,
            effective,
            admission,
        })
    }

    /// Complete the same original socket's Noise and fixed-member proof.
    pub async fn accept(
        &mut self,
        socket: UdpSocket,
        identity: establish::Identity,
        deadline: Instant,
        entropy: &mut (impl hs::Entropy + Send),
    ) -> io::Result<Session> {
        self.accept_observed(socket, identity, deadline, entropy, &mut |_| {})
            .await
    }

    /// Accept with shared stage observations and cumulative retained gate accounting.
    pub async fn accept_observed(
        &mut self,
        socket: UdpSocket,
        identity: establish::Identity,
        deadline: Instant,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> io::Result<Session> {
        observe(diagnostics::Observation::new(
            diagnostics::Stage::Configuration,
        ));
        if identity.local.public_key() != self.peers.responder
            || identity.peer != self.peers.initiator
        {
            configuration_failure(observe);
            return Err(invalid(
                "server Noise credentials differ from configured pins",
            ));
        }
        let mut last_server_gate = None;
        let mut forward = |mut observation: diagnostics::Observation| {
            if observation.server_gate.is_some() {
                last_server_gate = observation.server_gate;
            } else {
                observation.server_gate = last_server_gate;
            }
            observe(observation);
        };
        let established = establish::accept_observed(
            socket,
            identity,
            &mut self.admission,
            deadline,
            entropy,
            &mut forward,
        )
        .await
        .map_err(runtime_error)?;
        let context = proof_context(&established);
        let members = identity::Allowlist::new(&[self.settings.member]).map_err(|error| {
            let mut observation = diagnostics::Observation::new(diagnostics::Stage::Membership);
            observation.reason = Some(diagnostics::Reason::Configuration);
            forward(observation);
            invalid(error)
        })?;
        let authenticated = member::accept_observed(
            established,
            members,
            self.settings.membership.runtime(context),
            &mut forward,
        )
        .await?;
        Ok(Session {
            requested: self.settings,
            effective: self.effective,
            authenticated,
        })
    }
}

fn configuration_failure(observe: &mut diagnostics::Observer<'_>) {
    let mut observation = diagnostics::Observation::new(diagnostics::Stage::Configuration);
    observation.reason = Some(diagnostics::Reason::Configuration);
    observe(observation);
}

fn proof_context(established: &establish::Established) -> identity::Context {
    identity::Context {
        session: established.root.binding().session,
        transcript: established.root.binding().transcript,
        configuration: established.authenticated.configuration,
        carrier: established.authenticated.carrier,
        outer: established.authenticated.outer,
        initiator_noise: identity::NoisePublicKey(established.peers.initiator.0),
        responder_noise: identity::NoisePublicKey(established.peers.responder.0),
    }
}

fn hash_usize(hash: &mut digest::Context, value: usize) -> io::Result<()> {
    hash.update(&u64::try_from(value).map_err(invalid)?.to_be_bytes());
    Ok(())
}

fn finish(hash: digest::Context) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(hash.finish().as_ref());
    value
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn runtime_error(error: establish::Error) -> io::Error {
    let kind = match error {
        establish::Error::Deadline => io::ErrorKind::TimedOut,
        establish::Error::Configuration(_) => io::ErrorKind::InvalidInput,
        establish::Error::Io(ref error) => error.kind(),
        _ => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
#[path = "secure_udp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "secure_udp_config_tests.rs"]
mod config_tests;
