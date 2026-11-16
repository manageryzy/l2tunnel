//! Explicit common record selection authenticated by the existing same-socket factories.
use super::{Settings, establish, security};
use crate::{Compression, ConnectionConfig};
use l2tunnel::record_configuration::{self as common, Catalog, Configuration, EnvelopeDigest};
use l2tunnel_core::{ConfigDigest, Duplex, traffic::NetworkLayer};
use l2tunnel_device::PacketLayer;
use l2tunnel_management::{Role, transaction};
use l2tunnel_runtime::secure_udp::transport;
use ring::digest;
use std::io;

#[path = "common_transaction_profile_raw.rs"]
mod raw;

/// Complete common plan; settings() uses the maintained admission/Noise/member factories.
#[derive(Clone, Debug)]
pub struct Profile {
    connection: ConnectionConfig,
    peers: establish::Peers,
    settings: Settings,
    initiator: transport::Config,
    responder: transport::Config,
    catalog: Catalog,
    parameters: transport::TransactionSettings,
    envelope: EnvelopeDigest,
    initial: Configuration,
    data: ConfigDigest,
    carrier: Option<CarrierBinding>,
    raw: Option<raw::RawSelection>,
    requested_catalog: Option<Catalog>,
    proxy: Option<l2tunnel_runtime::proxy::Config>,
}

#[derive(Clone, Copy, Debug)]
struct CarrierBinding {
    outer: establish::carrier::AuthenticatedOuter,
    requested_configuration: security::ConfigDigest,
    requested_envelope: EnvelopeDigest,
    resources: [transport::Config; 2],
    configuration: security::ConfigDigest,
}
impl Profile {
    /// Bind every common descriptor and actual shared resource to retained own trust.
    /// Swift fields in the explicit resource templates are inactive in this selection.
    pub fn new(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
    ) -> io::Result<Self> {
        Self::new_selected(
            connection, settings, peers, initiator, responder, catalog, parameters, None, None,
        )
    }
    /// Explicit fixed TCP proxy on the initial Common record profile. The complete
    /// maintained proxy policy is bound before admission/Noise/member hashing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
    ) -> io::Result<Self> {
        let binding = l2tunnel_runtime::proxy::session_config(&proxy)?;
        if proxy.duplex != Duplex::Full
            || proxy.mux.channels != 1
            || proxy.runtime.layer != PacketLayer::Ip
            || connection.layer != PacketLayer::Ip
            || proxy.runtime.max_packet != connection.max_packet
            || catalog.descriptors().len() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Common proxy requires explicit fixed full-duplex one-channel TUN and one immutable descriptor",
            ));
        }
        let mut application = digest::Context::new(&digest::SHA256);
        application.update(b"l2tunnel/shared-client/common-proxy/v1\0");
        application.update(&settings.application.0);
        application.update(&binding.digest.0);
        settings.application = ConfigDigest(super::finish(application));
        Self::new_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            None,
            Some(proxy),
        )
    }
    /// The exact selected fixed policy, absent for all transparent Common plans.
    pub fn proxy_config(&self) -> Option<&l2tunnel_runtime::proxy::Config> {
        self.proxy.as_ref()
    }
    #[allow(clippy::too_many_arguments)]
    fn new_selected(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        raw_policy: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        proxy: Option<l2tunnel_runtime::proxy::Config>,
    ) -> io::Result<Self> {
        let base = connection.session()?;
        if initiator.rolling_fragments != responder.rolling_fragments {
            return Err(invalid(
                "both roles must select the same complete directional fragment policy",
            ));
        }
        if initiator.rolling_fragments.is_some()
            && !catalog.descriptors().iter().any(|descriptor| {
                matches!(
                    descriptor.profile(),
                    common::Profile::Rolling { .. } | common::Profile::RollingCopies { .. }
                )
            })
        {
            return Err(invalid(
                "fragment selection requires a Rolling catalog member",
            ));
        }
        if (raw_policy.is_none() && connection.duplex != Duplex::Full)
            || connection.compression != Compression::None
            || catalog.initial().duplex() != connection.duplex
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "common runtime requires full duplex and no outer compression",
            ));
        }
        for descriptor in catalog.descriptors() {
            for role in [Role::Client, Role::Server] {
                let selected = descriptor.direction(role).common().traffic().tcp;
                if (selected == l2tunnel_core::traffic::TcpControl::SplitTcpProxy)
                    != proxy.is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Common TCP ownership requires the matching explicit proxy plan",
                    ));
                }
            }
        }
        let initial = catalog.initial();
        let native = [Role::Client, Role::Server]
            .into_iter()
            .map(|role| initial.direction(role).max_native())
            .max()
            .ok_or_else(|| invalid("empty common native directions"))?;
        let layer = match connection.layer {
            PacketLayer::Ethernet => NetworkLayer::Tap,
            PacketLayer::Ip => NetworkLayer::Tun,
        };
        if proxy.is_none() && connection.max_packet != native {
            return Err(invalid("common native maximum differs from attachment"));
        }
        for descriptor in catalog.descriptors() {
            for role in [Role::Client, Role::Server] {
                let direction = descriptor.direction(role);
                let original = initial.direction(role);
                if direction.common().traffic().layer != layer
                    || direction.max_native() != original.max_native()
                    || descriptor.duplex() != connection.duplex
                {
                    return Err(invalid(
                        "common catalog changes immutable attachment/duplex",
                    ));
                }
            }
        }
        for resources in [initiator, responder] {
            resources.validate_common_resources(native)?;
            parameters.validate(resources)?;
            if resources.path_mtu != initial.path_mtu() {
                return Err(invalid("common initial MTU differs from template"));
            }
        }
        // H0 has a new domain. Its original trust/settings and anchor-free catalog
        // precede E, then complete C0 supplies D0; no self-reference exists.
        let seed = settings.application;
        let original = settings.configuration(peers)?;
        let mut envelope = digest::Context::new(&digest::SHA256);
        envelope.update(b"l2tunnel/shared-client/common-record-envelope/v1\0");
        envelope.update(&original.0);
        envelope.update(&base.digest.0);
        envelope.update(&connection.handshake_timeout.as_nanos().to_be_bytes());
        envelope.update(&initiator.common_resource_digest(native)?.0);
        envelope.update(&responder.common_resource_digest(native)?.0);
        envelope.update(catalog.root().as_bytes());
        for value in [
            parameters.protocol.retry_ms,
            parameters.protocol.phase_timeout_ms,
            parameters.protocol.reconcile_timeout_ms,
            parameters.max_operation_ms,
            u64::try_from(parameters.retained_bytes).map_err(io::Error::other)?,
        ] {
            envelope.update(&value.to_be_bytes());
        }
        let envelope = EnvelopeDigest::new(super::finish(envelope));
        let initial = Configuration::new(envelope, initial).map_err(io::Error::other)?;
        let data = transaction::configuration_digest(&initial).map_err(io::Error::other)?;
        let mut selection = digest::Context::new(&digest::SHA256);
        selection.update(b"l2tunnel/shared-client/common-record-selection/v1\0");
        selection.update(&seed.0);
        selection.update(envelope.as_bytes());
        selection.update(catalog.root().as_bytes());
        selection.update(&data.0);
        settings.application = ConfigDigest(super::finish(selection));
        let result = Self {
            connection,
            peers,
            settings,
            initiator,
            responder,
            catalog,
            parameters,
            envelope,
            initial,
            data,
            carrier: None,
            raw: None,
            requested_catalog: None,
            proxy,
        };
        if let Some(policy) = raw_policy {
            return result.select_raw(policy);
        }
        result.runtime_contract(security::Role::Initiator)?;
        result.runtime_contract(security::Role::Responder)?;
        Ok(result)
    }
    /// Exact requested directional ACK policies, unchanged by genuine outer binding.
    pub fn ack_coalescing(&self) -> [Option<l2tunnel::pipeline::ack_coalescing::Policy>; 2] {
        [self.initiator.ack_coalescing, self.responder.ack_coalescing]
    }
    /// Exact independent receive-wire policies, unchanged by genuine outer binding.
    pub fn rolling_ingress(&self) -> [Option<l2tunnel::rolling_records::IngressLimits>; 2] {
        [
            self.initiator.rolling_ingress,
            self.responder.rolling_ingress,
        ]
    }
    /// Exact paired authenticated raw ACK ingress limits.
    pub fn connection_ingress(&self) -> [Option<transport::ConnectionIngressLimits>; 2] {
        [
            self.initiator.connection_ingress,
            self.responder.connection_ingress,
        ]
    }
    /// Complete immutable requested fragment policy in global direction order.
    pub fn rolling_fragments(&self) -> Option<l2tunnel::record_engine::FragmentPolicy> {
        self.initiator.rolling_fragments
    }
    /// Exact shared native attachment contract.
    pub fn connection(&self) -> ConnectionConfig {
        self.connection
    }
    /// Retained ordered trusted Noise pins.
    pub fn peers(&self) -> establish::Peers {
        self.peers
    }
    /// Original requested settings, unchanged after actual outer binding.
    /// Bound factory callers must use establish_config() for effective geometry/H1.
    pub fn settings(&self) -> Settings {
        self.settings
    }
    /// Derive an effective plan only from a genuine completed outer proof.
    /// The original settings/catalog/resources remain retained and unchanged.
    pub fn bind_outer(&self, outer: establish::carrier::AuthenticatedOuter) -> io::Result<Self> {
        if self.proxy.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fixed Common proxy supports only its original protected UDP owner",
            ));
        }
        if self.carrier.is_some() || self.raw.is_some() {
            return Err(invalid("common profile already bound to an outer session"));
        }
        if outer.endpoints()
            != (
                self.settings.gate.path.client,
                self.settings.gate.path.server,
            )
            || outer.info().member.0 != self.settings.member.0
            || outer.info().config.layer != self.connection.layer
            || self.settings.cover.max_packet_bytes > outer.requested().max_record_bytes
        {
            return Err(invalid(
                "actual outer proof differs from requested common plan",
            ));
        }
        let role = outer_role(outer)?;
        let mut resources = [self.initiator, self.responder];
        for value in &mut resources {
            if let Some(policy) = value.rolling_fragments.as_mut() {
                policy.forward.framing.outer_overhead_bytes =
                    extra_byte(policy.forward.framing.outer_overhead_bytes)?;
                policy.reverse.framing.outer_overhead_bytes =
                    extra_byte(policy.reverse.framing.outer_overhead_bytes)?;
            }
            value.control.wire_overhead = extra_byte(value.control.wire_overhead)?;
            let streams = value
                .streams
                .as_mut()
                .ok_or_else(|| invalid("common carrier requires explicit streams"))?;
            for stream in &mut streams.streams {
                stream.delivery.wire_overhead = extra_byte(stream.delivery.wire_overhead)?;
            }
        }
        let requested_configuration = self.configuration()?;
        let mut binding = CarrierBinding {
            outer,
            requested_configuration,
            requested_envelope: self.envelope,
            resources,
            configuration: requested_configuration,
        };
        let mut result = self.clone();
        result.catalog = carrier_catalog(&self.catalog)?;
        result.requested_catalog = Some(self.catalog.clone());
        let contract = result.carrier_contract(binding, role)?;
        binding.configuration = contract.expected_configuration();
        result.envelope = contract.envelope();
        result.initial = contract.initial();
        result.data = contract.data_digest();
        result.carrier = Some(binding);
        result.establish_config(role)?;
        Ok(result)
    }
    /// Genuine completed outer observation, absent for the original UDP selection.
    pub fn carrier_binding(&self) -> Option<establish::carrier::AuthenticatedOuter> {
        self.carrier.map(|value| value.outer)
    }
    /// Original offline setup identity H0, before a fresh outer session is known.
    pub fn requested_configuration(&self) -> io::Result<security::ConfigDigest> {
        if let Some(raw) = self.raw {
            return Ok(raw.requested);
        }
        match self.carrier {
            Some(value) => Ok(value.requested_configuration),
            None => self.configuration(),
        }
    }
    /// Original offline common envelope E0, without a fabricated outer proof.
    pub fn requested_envelope(&self) -> EnvelopeDigest {
        if let Some(raw) = self.raw {
            return raw.envelope;
        }
        self.carrier
            .map_or(self.envelope, |value| value.requested_envelope)
    }
    /// Full original offline catalog, including its unchanged canonical root.
    pub fn requested_catalog(&self) -> &Catalog {
        self.requested_catalog.as_ref().unwrap_or(&self.catalog)
    }
    /// Exact role-specific factory input; copied observations create no authority.
    /// Bound profiles carry the actual extra opcode and effective setup identity.
    pub fn establish_config(&self, role: security::Role) -> io::Result<establish::Config> {
        let mut config = self.settings.runtime(role, self.peers)?;
        if self.raw.is_some() {
            return self.establish_raw(config, role);
        }
        if let Some(binding) = self.carrier {
            if role != outer_role(binding.outer)? {
                return Err(invalid(
                    "bound common profile belongs to the other local role",
                ));
            }
            config.gate.outer_overhead = extra_byte(config.gate.outer_overhead)?;
            config.binding.outer = binding.outer.binding();
            config.binding.configuration = binding.configuration.0;
            // Reuse the factory's actual extra-byte validation and prologue
            // derivation. This public session label is only a consistency input.
            binding
                .outer
                .expected_binding(config, self.peers, l2tunnel_handshake::SessionId([1; 16]))
                .map_err(io::Error::other)?;
        }
        Ok(config)
    }
    /// Complete transaction and combined-capacity requirements.
    pub fn parameters(&self) -> transport::TransactionSettings {
        self.parameters
    }
    /// Whole supported catalog, without pruning to fit storage.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    /// Immutable common envelope E, distinct from H0 and D0.
    pub fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Exact complete initial value, using effective E1 after carrier binding.
    pub fn initial(&self) -> Configuration {
        self.initial
    }
    /// Real initial management digest, using the effective initial value.
    pub fn data_digest(&self) -> ConfigDigest {
        self.data
    }
    /// Actual setup/Control digest consumed by the maintained authentication factories.
    pub fn configuration(&self) -> io::Result<security::ConfigDigest> {
        if let Some(raw) = self.raw {
            return Ok(raw.configuration);
        }
        match self.carrier {
            Some(value) => Ok(value.configuration),
            None => self.settings.configuration(self.peers),
        }
    }
    /// Transfer the exact selected role resources/catalog and setup identity.
    pub fn runtime_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        if self.raw.is_some() {
            return self.raw_contract(role);
        }
        if let Some(binding) = self.carrier {
            if role != outer_role(binding.outer)? {
                return Err(invalid(
                    "bound common profile belongs to the other local role",
                ));
            }
            return self.carrier_contract(binding, role);
        }
        let contract = transport::CommonTransactionContract::new(
            self.configuration()?,
            role,
            if role == security::Role::Initiator {
                self.initiator
            } else {
                self.responder
            },
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            self.envelope,
            self.catalog.clone(),
            self.parameters,
        )?;
        match &self.proxy {
            Some(proxy) => {
                let contract = contract
                    .with_proxy_binding(l2tunnel_runtime::proxy::session_config(proxy)?.digest)?;
                l2tunnel_runtime::proxy::common::validate(proxy, &contract)?;
                Ok(contract)
            }
            None => Ok(contract),
        }
    }
    fn carrier_contract(
        &self,
        binding: CarrierBinding,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        transport::CommonTransactionContract::new_on_carrier_paired(
            binding.requested_configuration,
            role,
            binding.resources,
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            binding.requested_envelope,
            self.catalog.clone(),
            self.parameters,
            binding.outer,
        )
    }
}
fn extra_byte(value: usize) -> io::Result<usize> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("common carrier opcode accounting overflow"))
}
fn carrier_catalog(catalog: &Catalog) -> io::Result<Catalog> {
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(catalog.descriptors().len())
        .map_err(io::Error::other)?;
    for descriptor in catalog.descriptors() {
        descriptors.push(carrier_descriptor(*descriptor)?);
    }
    Catalog::new(carrier_descriptor(catalog.initial())?, &descriptors).map_err(io::Error::other)
}
fn carrier_descriptor(descriptor: common::Descriptor) -> io::Result<common::Descriptor> {
    let mut profile = *descriptor.profile();
    match &mut profile {
        common::Profile::Swift { .. } => {}
        common::Profile::Aligned { forward, reverse } => {
            for value in [forward, reverse] {
                value.recovery.outer_overhead_bytes =
                    extra_byte(value.recovery.outer_overhead_bytes)?;
            }
        }
        common::Profile::Packed { forward, reverse } => {
            for value in [forward, reverse] {
                value.base.recovery.outer_overhead_bytes =
                    extra_byte(value.base.recovery.outer_overhead_bytes)?;
            }
        }
        common::Profile::AlignedCompact { forward, reverse } => {
            for value in [forward, reverse] {
                value.recovery = compact_extra_byte(value.recovery)?;
            }
        }
        common::Profile::PerConnectionCompact { forward, reverse } => {
            for value in [forward, reverse] {
                value.compact.recovery = compact_extra_byte(value.compact.recovery)?;
            }
        }
        common::Profile::PackedCompact { forward, reverse } => {
            for value in [forward, reverse] {
                value.base.recovery = compact_extra_byte(value.base.recovery)?;
            }
        }
        common::Profile::Rolling { config, .. } | common::Profile::RollingCopies { config, .. } => {
            config.geometry.forward_overhead_bytes =
                extra_byte(config.geometry.forward_overhead_bytes)?;
            config.geometry.reverse_overhead_bytes =
                extra_byte(config.geometry.reverse_overhead_bytes)?;
        }
    }
    common::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *descriptor.direction(Role::Client).common(),
        *descriptor.direction(Role::Server).common(),
        profile,
    )
    .map_err(io::Error::other)
}
// Retain the exact complete adaptive policy; only actual carrier framing changes.
fn compact_extra_byte(
    value: l2tunnel::reliable::CompactReliableConfig,
) -> io::Result<l2tunnel::reliable::CompactReliableConfig> {
    l2tunnel::reliable::CompactReliableConfig::new(
        value.arq(),
        extra_byte(value.outer_overhead_bytes())?,
    )
    .map_err(io::Error::other)
}
fn outer_role(outer: establish::carrier::AuthenticatedOuter) -> io::Result<security::Role> {
    match outer.info().peer_member {
        None => Ok(security::Role::Initiator),
        Some(member) if member == outer.info().member => Ok(security::Role::Responder),
        Some(_) => Err(invalid("actual outer member role differs")),
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "common_transaction_profile_tests.rs"]
mod tests;
