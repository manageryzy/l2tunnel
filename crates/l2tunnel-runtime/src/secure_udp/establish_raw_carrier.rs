//! Genuine original raw authority through the existing admission/Noise loop.
use super::*;
use crate::secure_udp::raw_carrier_io::{RawAdapter, raw_error};
use l2tunnel_raw_io::{
    PacketIo,
    handoff::pairing::{
        PairInfo,
        packet::{PacketCarrier, PacketPolicy, RecordGeometry},
    },
};

/// Pure maintained bootstrap/cover/MTU preflight; this returns no proof or owner.
pub fn validate_requested(config: Config, peers: Peers, policy: PacketPolicy) -> Result<(), Error> {
    let geometry = policy.record_geometry().map_err(raw_error)?;
    if config.gate.path.client.is_ipv6()
        || config.gate.path.server.is_ipv6()
        || config.gate.path_mtu != geometry.path_mtu
        || config.cover.limits().max_packet_bytes > geometry.max_record_bytes
    {
        return Err(Error::Configuration("requested raw bootstrap geometry"));
    }
    setup_with_physical_overhead(config, peers, physical(geometry)?)?;
    Ok(())
}

/// Copied genuine observations; only RawOuter owns the actual original capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedRaw {
    role: hs::Role,
    info: l2tunnel_auth::SessionInfo,
    infos: [Option<l2tunnel_auth::SessionInfo>; 2],
    endpoints: [Option<(SocketAddr, SocketAddr)>; 2],
    duplex: l2tunnel_core::Duplex,
    profile: l2tunnel_core::ConfigDigest,
    transcript: [u8; 32],
    policy: PacketPolicy,
    policy_digest: [u8; 32],
    geometry: RecordGeometry,
    binding: [u8; 32],
    deadline: Instant,
}
impl AuthenticatedRaw {
    /// Actual authenticated first-lane TLS/member identities, not handoff authority.
    pub fn info(self) -> l2tunnel_auth::SessionInfo {
        self.info
    }
    /// Actual global role of the original factories.
    pub fn role(self) -> hs::Role {
        self.role
    }
    /// Actual complete accepted duplex policy; absent lanes remain absent.
    pub fn duplex(self) -> l2tunnel_core::Duplex {
        self.duplex
    }
    /// Ordered First/Second verified TLS identities.
    pub fn lane_infos(self) -> [Option<l2tunnel_auth::SessionInfo>; 2] {
        self.infos
    }
    /// Ordered global client/server endpoints of the actual occupied originals.
    pub fn lane_endpoints(self) -> [Option<(SocketAddr, SocketAddr)>; 2] {
        self.endpoints
    }
    /// Complete accepted original pair profile, without any transfer authority.
    pub fn profile(self) -> l2tunnel_core::ConfigDigest {
        self.profile
    }
    /// Accepted global original pairing transcript.
    pub fn transcript_digest(self) -> [u8; 32] {
        self.transcript
    }
    /// Actual complete original policy and its pre-TLS commitment.
    pub fn policy(self) -> PacketPolicy {
        self.policy
    }
    /// Original packet policy commitment, including the caller's pre-TLS base.
    pub fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }
    /// Exact maintained protected raw geometry.
    pub fn geometry(self) -> RecordGeometry {
        self.geometry
    }
    /// Global actual original-owner commitment; it contains no exported key.
    pub fn binding(self) -> [u8; 32] {
        self.binding
    }
    /// Original factory/packet transition cap, never renewed for inner setup.
    pub fn deadline(self) -> Instant {
        self.deadline
    }
    /// Pure consistency with the existing actual Noise prologue, never authority.
    pub fn expected_binding(
        self,
        config: Config,
        peers: Peers,
        session: hs::SessionId,
    ) -> Result<hs::Binding, Error> {
        validate_shape(self, config, self.role)?;
        session_binding(
            setup_with_physical_overhead(config, peers, physical(self.geometry)?)?,
            session.0,
        )
    }
}

/// Sole actual original raw capability; no constructor from public PairInfo exists.
pub struct RawOuter<I: PacketIo + Send + 'static> {
    carrier: PacketCarrier<I>,
    proof: AuthenticatedRaw,
}
impl<I: PacketIo + Send + 'static> RawOuter<I> {
    /// Consume the actual completed original TLS/member/packet transition owner.
    pub fn from_packet(mut carrier: PacketCarrier<I>) -> Result<Self, Error> {
        carrier.check_live().map_err(raw_error)?;
        let geometry = carrier.geometry().map_err(raw_error)?;
        let tuples = carrier.lane_endpoints().map_err(raw_error)?;
        let PairInfo {
            duplex,
            is_client,
            lanes: infos,
            profile,
            transcript_digest: transcript,
        } = carrier.info().clone();
        let role = if is_client {
            hs::Role::Initiator
        } else {
            hs::Role::Responder
        };
        let count = carrier.lane_count();
        let first = infos[0].ok_or(Error::Configuration("actual raw first identity absent"))?;
        let mut endpoints = [None, None];
        for index in 0..2 {
            match (infos[index], tuples[index], index < count) {
                (Some(info), Some((local, peer)), true) => {
                    if info.member != first.member
                        || info.server != first.server
                        || info.config.layer != first.config.layer
                        || (is_client && info.peer_member.is_some())
                        || (!is_client && info.peer_member != Some(info.member))
                    {
                        return Err(Error::Configuration(
                            "raw occupied lane authentication differs",
                        ));
                    }
                    endpoints[index] = Some(if is_client {
                        (local, peer)
                    } else {
                        (peer, local)
                    });
                }
                (None, None, false) => {}
                _ => return Err(Error::Configuration("raw actual lane shape differs")),
            }
        }
        let policy = carrier.policy();
        let policy_digest = carrier.policy_digest();
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/raw-common/actual-outer/v1\0");
        hash.update(&[if duplex == l2tunnel_core::Duplex::Full {
            1
        } else {
            2
        }]);
        hash.update(&profile.0);
        hash.update(&transcript);
        hash.update(&policy_digest);
        for value in [
            geometry.path_mtu,
            geometry.ip_tcp_bytes,
            geometry.record_overhead_bytes,
            geometry.max_record_bytes,
        ] {
            hash.update(&(value as u64).to_be_bytes());
        }
        for (info, tuple) in infos.into_iter().zip(endpoints) {
            if let (Some(info), Some((client, server))) = (info, tuple) {
                hash.update(&[1]);
                hash.update(&info.session_id);
                hash.update(&info.member.0);
                hash.update(&info.server.0);
                hash.update(&info.config.digest.0);
                hash.update(&[match info.config.layer {
                    l2tunnel_device::PacketLayer::Ethernet => 1,
                    l2tunnel_device::PacketLayer::Ip => 2,
                }]);
                super::carrier::bind_endpoint(&mut hash, client);
                super::carrier::bind_endpoint(&mut hash, server);
            } else {
                hash.update(&[0]);
            }
        }
        let mut binding = [0; 32];
        binding.copy_from_slice(hash.finish().as_ref());
        let proof = AuthenticatedRaw {
            role,
            info: first,
            infos,
            endpoints,
            duplex,
            profile,
            transcript,
            policy,
            policy_digest,
            geometry,
            binding,
            deadline: carrier.setup_deadline(),
        };
        before(Instant::now(), proof.deadline)?;
        Ok(Self { carrier, proof })
    }
    /// Observe genuine binding without transferring any original/raw/Noise owner.
    pub fn authenticated(&self) -> AuthenticatedRaw {
        self.proof
    }
    /// Retain an earlier caller-owned setup cap; never renew the actual factory cap.
    pub fn restrict_setup_deadline(mut self, deadline: Instant) -> Result<Self, Error> {
        self.proof.deadline = self.proof.deadline.min(deadline);
        before(Instant::now(), self.proof.deadline)?;
        Ok(self)
    }

    /// Actual initial-only maintained Noise, on the same original raw packet owner.
    pub async fn connect_initial(
        self,
        config: Config,
        identity: Identity,
        admission: gate::Secret,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<RawInitialEstablished<I>, Error> {
        validate_config(self.proof, config, hs::Role::Initiator)?;
        let adapter = RawAdapter::new(self.carrier)?;
        let mut report = Reporter::new(observe);
        let result = Box::pin(connect_inner(
            SocketBacking::Raw(adapter),
            config,
            identity,
            admission,
            self.proof.deadline,
            entropy,
            &mut report,
            None,
        ))
        .await;
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| RawInitialEstablished {
            state,
            outer: self.proof,
        })
    }
    /// Same cookie/quarantine/Noise state machine with an original retained cap.
    pub async fn accept_initial(
        self,
        identity: Identity,
        admission: &mut RawInitialServerAdmission,
        entropy: &mut (impl hs::Entropy + Send),
        observe: &mut diagnostics::Observer<'_>,
    ) -> Result<RawInitialEstablished<I>, Error> {
        validate_config(self.proof, admission.inner.config(), hs::Role::Responder)?;
        if admission.outer != self.proof.binding {
            return Err(Error::Configuration(
                "raw admission belongs to another actual outer",
            ));
        }
        let adapter = RawAdapter::new(self.carrier)?;
        let mut report = Reporter::new(observe);
        report.server(admission.inner.statistics());
        let result = Box::pin(accept_inner(
            SocketBacking::Raw(adapter),
            identity,
            &mut admission.inner,
            self.proof.deadline,
            entropy,
            &mut report,
            None,
        ))
        .await;
        report.server(admission.inner.statistics());
        if let Err(error) = &result {
            report.fail(diagnostics::establishment_reason(error));
        }
        result.map(|state| RawInitialEstablished {
            state,
            outer: self.proof,
        })
    }
}

/// Distinct retained actual raw admission, without selected refresh authority.
pub struct RawInitialServerAdmission {
    inner: ServerAdmission,
    outer: [u8; 32],
}
impl RawInitialServerAdmission {
    /// Preserve the same quarantine owner and explicit original setup clock.
    pub fn new<I: PacketIo + Send + 'static>(
        outer: &RawOuter<I>,
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        validate_config(outer.proof, config, hs::Role::Responder)?;
        Ok(Self {
            inner: ServerAdmission::with_physical_overhead(
                config,
                peers,
                admission,
                cookie,
                origin,
                physical(outer.proof.geometry)?,
            )?,
            outer: outer.proof.binding,
        })
    }
    /// Actual reusable admission counters; not authority.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.inner.statistics()
    }
    /// Exact retained effective setup configuration.
    pub fn config(&self) -> Config {
        self.inner.config()
    }
}

/// Opaque actual confirmed Noise plus original raw owner; membership is still required.
pub struct RawInitialEstablished<I: PacketIo + Send + 'static> {
    state: EstablishedState<RawAdapter<I>>,
    outer: AuthenticatedRaw,
}
impl<I: PacketIo + Send + 'static> RawInitialEstablished<I> {
    /// Actual confirmed Noise binding, without a root import path.
    pub fn binding(&self) -> security::SessionBinding {
        self.state.binding
    }
    /// Actual authenticated prologue, useful for the existing member context.
    pub fn authenticated(&self) -> hs::Binding {
        self.state.authenticated
    }
    /// Actual ordered Noise pins.
    pub fn peers(&self) -> Peers {
        self.state.peers
    }
    /// Actual selected complementary cover.
    pub fn cover(&self) -> cover::Config {
        self.state.cover
    }
    /// Genuine actual raw proof.
    pub fn outer(&self) -> AuthenticatedRaw {
        self.outer
    }
    /// Original common setup cap and actual Noise clock remain unchanged.
    pub fn deadline(&self) -> Instant {
        self.state.deadline
    }
    /// Actual original inner setup clock.
    pub fn clock_origin(&self) -> Instant {
        self.state.origin
    }
    pub(in crate::secure_udp) fn into_state(
        self,
    ) -> (EstablishedState<RawAdapter<I>>, AuthenticatedRaw) {
        (self.state, self.outer)
    }
}
fn physical(geometry: RecordGeometry) -> Result<usize, Error> {
    geometry
        .ip_tcp_bytes
        .checked_add(geometry.record_overhead_bytes)
        .ok_or(Error::Configuration("raw physical overhead"))
}
fn validate_config(proof: AuthenticatedRaw, config: Config, role: hs::Role) -> Result<(), Error> {
    before(Instant::now(), proof.deadline)?;
    validate_shape(proof, config, role)
}
fn validate_shape(proof: AuthenticatedRaw, config: Config, role: hs::Role) -> Result<(), Error> {
    let (client, server) =
        proof.endpoints[0].ok_or(Error::Configuration("actual raw first tuple absent"))?;
    if proof.role != role
        || config.binding.outer != proof.binding
        || config.gate.path.client != client
        || config.gate.path.server != server
        || config.gate.path_mtu != proof.geometry.path_mtu
        || config.cover.limits().max_packet_bytes > proof.geometry.max_record_bytes
    {
        return Err(Error::Configuration(
            "inner setup differs from actual raw proof/geometry",
        ));
    }
    Ok(())
}
