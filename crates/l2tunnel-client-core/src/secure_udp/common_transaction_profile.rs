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

#[path = "common_transaction_profile_compact.rs"]
mod compact;
#[path = "common_transaction_profile_maintained.rs"]
mod maintained;
#[path = "common_transaction_profile_raw.rs"]
mod raw;

/// Complete common plan; settings() uses the maintained admission/Noise/member factories.
#[derive(Clone, Debug)]
pub struct Profile {
    connection: ConnectionConfig,
    peers: establish::Peers,
    settings: Settings,
    application: ConfigDigest,
    initiator: transport::Config,
    responder: transport::Config,
    catalog: Catalog,
    parameters: transport::TransactionSettings,
    envelope: EnvelopeDigest,
    initial: Configuration,
    data: ConfigDigest,
    carrier: Option<CarrierBinding>,
    raw: Option<raw::RawSelection>,
    maintained: Option<Box<maintained::Selection>>,
    requested_catalog: Option<Catalog>,
    // Live-tuning catalog generated after setup (docs/modules/live-tuning.md);
    // the setup identity stays the base plan's.
    live_catalog: Option<Catalog>,
    // Client choices / server limits for live tuning at connect.
    tuning: super::live_tuning::Policy,
    proxy: Option<l2tunnel_runtime::proxy::Config>,
    proxy_retirement: bool,
    // Keep an absent optional policy from enlarging every carrier setup future.
    proxy_measured: Option<Box<l2tunnel_runtime::proxy::measured::Config>>,
    connection_reuse: bool,
    compact_wire: l2tunnel::secure_record::compact::Selection,
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
            None,
        )
    }
    /// Explicit compact v3 on the original UDP socket, selected before Noise/member
    /// authentication. The actual runtime validates the complete supported catalog.
    /// The explicit protection policy replaces the default full authentication tag.
    #[allow(clippy::too_many_arguments)]
    pub fn new_compact(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        selection: l2tunnel::secure_record::compact::Selection,
    ) -> io::Result<Self> {
        selection.validate().map_err(io::Error::other)?;
        Self::new_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            None,
            None,
            Some(selection),
        )
    }
    /// Exact establishment-bound final record protection used by every Common profile.
    pub const fn compact_wire(&self) -> l2tunnel::secure_record::compact::Selection {
        self.compact_wire
    }
    /// Explicit fixed TCP proxy on the initial Common record profile. The complete
    /// maintained proxy policy is bound before admission/Noise/member hashing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
    ) -> io::Result<Self> {
        Self::new_proxy_selected(
            connection, settings, peers, initiator, responder, catalog, parameters, proxy, false,
            None, None,
        )
    }
    /// Explicit retained graceful retirement, bound before Noise/member H0.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy_retained(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
    ) -> io::Result<Self> {
        Self::new_proxy_selected(
            connection, settings, peers, initiator, responder, catalog, parameters, proxy, true,
            None, None,
        )
    }
    /// Explicit complete measured policy with retained Common retirement.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy_measured_retained(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::measured::Config,
    ) -> io::Result<Self> {
        Self::new_proxy_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            proxy.fixed.clone(),
            true,
            Some(proxy),
            None,
        )
    }
    /// Build a complete proxy selection with its requested final wire before H0.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_proxy_selected(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
        retained: bool,
        measured: Option<l2tunnel_runtime::proxy::measured::Config>,
        wire: Option<l2tunnel::secure_record::compact::Selection>,
    ) -> io::Result<Self> {
        Self::new_proxy_selected_on(
            connection, settings, peers, initiator, responder, catalog, parameters, proxy,
            retained, measured, wire, None, None,
        )
    }
    /// Complete fixed or measured proxy policy on actual retained TLS/QUIC lanes.
    /// The proxy, carrier and record catalog all enter the pre-authentication digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy_maintained(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
        retained: bool,
        measured: Option<l2tunnel_runtime::proxy::measured::Config>,
        wire: Option<l2tunnel::secure_record::compact::Selection>,
        maintained: super::maintained::Settings,
    ) -> io::Result<Self> {
        Self::new_proxy_selected_on(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            proxy,
            retained,
            measured,
            wire,
            None,
            Some(maintained),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_proxy_selected_on(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
        retained: bool,
        measured: Option<l2tunnel_runtime::proxy::measured::Config>,
        wire: Option<l2tunnel::secure_record::compact::Selection>,
        raw: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        maintained: Option<super::maintained::Settings>,
    ) -> io::Result<Self> {
        let binding = l2tunnel_runtime::proxy::session_config(&proxy)?;
        #[cfg(unix)]
        l2tunnel_runtime::proxy::common::validate_catalog(&proxy, &catalog)?;
        if proxy.duplex != connection.duplex
            || proxy.runtime.layer != PacketLayer::Ip
            || connection.layer != PacketLayer::Ip
            || proxy.runtime.max_packet != connection.max_packet
            || catalog.descriptors().len() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Common proxy requires matching carrier duplex, TUN and one immutable descriptor",
            ));
        }
        if let Some(measured) = &measured {
            if !retained
                || l2tunnel_runtime::proxy::session_config(&measured.fixed)?.digest
                    != binding.digest
            {
                return Err(invalid(
                    "measured Common proxy requires matching fixed policy and retained close",
                ));
            }
            let digest = l2tunnel_runtime::proxy::measured::session_config(measured)?.digest;
            let mut application = digest::Context::new(&digest::SHA256);
            application.update(b"l2tunnel/shared-client/common-proxy-measured/v1\0");
            application.update(&settings.application.0);
            application.update(&digest.0);
            settings.application = ConfigDigest(super::finish(application));
        }
        if retained {
            let mut application = digest::Context::new(&digest::SHA256);
            application.update(b"l2tunnel/shared-client/common-proxy-retirement/v1\0");
            application.update(&settings.application.0);
            settings.application = ConfigDigest(super::finish(application));
        }
        let mut application = digest::Context::new(&digest::SHA256);
        application.update(b"l2tunnel/shared-client/common-proxy/v1\0");
        application.update(&settings.application.0);
        application.update(&binding.digest.0);
        settings.application = ConfigDigest(super::finish(application));
        let mut result = Self::new_selected_for(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            raw,
            Some(proxy),
            wire,
            maintained,
        )?;
        result.proxy_retirement = retained;
        result.proxy_measured = measured.map(Box::new);
        if result.maintained.is_none() && result.raw.is_none() {
            for role in [security::Role::Initiator, security::Role::Responder] {
                result.runtime_contract(role)?;
            }
        }
        Ok(result)
    }
    /// Exact selected measured policy, absent for fixed and transparent Common.
    pub fn proxy_measured_config(&self) -> Option<&l2tunnel_runtime::proxy::measured::Config> {
        self.proxy_measured.as_deref()
    }
    /// Explicit immutable close capability, bound to this plan's authenticated H0.
    pub const fn proxy_retirement(&self) -> bool {
        self.proxy_retirement
    }
    /// Explicit immutable same-owner reuse selection; old constructors remain fixed-cohort.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_connection_reuse(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
    ) -> io::Result<Self> {
        Self::select_reuse_application(&mut settings, parameters);
        let mut profile = Self::new(
            connection, settings, peers, initiator, responder, catalog, parameters,
        )?;
        profile.connection_reuse = true;
        for role in [security::Role::Initiator, security::Role::Responder] {
            profile.runtime_contract(role)?;
        }
        Ok(profile)
    }
    fn select_reuse_application(
        settings: &mut Settings,
        parameters: transport::TransactionSettings,
    ) {
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-client/slot-reuse/v1\0");
        hash.update(&settings.application.0);
        for value in [
            3,
            1,
            32,
            parameters.protocol.retry_ms,
            parameters.max_operation_ms,
        ] {
            hash.update(&value.to_be_bytes());
        }
        settings.application = ConfigDigest(super::finish(hash));
    }
    /// True only for the explicit immutable SlotReuseV1 contract selection.
    pub const fn connection_reuse(&self) -> bool {
        self.connection_reuse
    }
    /// Exact fixed base policy for either proxy family; absent for transparent Common.
    pub fn proxy_config(&self) -> Option<&l2tunnel_runtime::proxy::Config> {
        self.proxy.as_ref()
    }
    #[allow(clippy::too_many_arguments)]
    fn new_selected(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        raw_policy: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        proxy: Option<l2tunnel_runtime::proxy::Config>,
        compact_wire: Option<l2tunnel::secure_record::compact::Selection>,
    ) -> io::Result<Self> {
        Self::new_selected_for(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            raw_policy,
            proxy,
            compact_wire,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_selected_for(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        raw_policy: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        proxy: Option<l2tunnel_runtime::proxy::Config>,
        compact_wire: Option<l2tunnel::secure_record::compact::Selection>,
        maintained: Option<super::maintained::Settings>,
    ) -> io::Result<Self> {
        // Finish constructing the catalog before validating either role's
        // runtime inventory. Each operation holds large concrete profile values.
        let result = Self::build_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            raw_policy,
            proxy,
            compact_wire,
            maintained,
        )?;
        if let Some(settings) = maintained {
            return result.select_maintained(settings);
        }
        if let Some(policy) = raw_policy {
            return result.select_raw(policy);
        }
        result.runtime_contract(security::Role::Initiator)?;
        result.runtime_contract(security::Role::Responder)?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_selected(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        raw_policy: Option<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy>,
        proxy: Option<l2tunnel_runtime::proxy::Config>,
        compact_wire: Option<l2tunnel::secure_record::compact::Selection>,
        maintained: Option<super::maintained::Settings>,
    ) -> io::Result<Self> {
        let selected_proxy = proxy.is_some();
        let (compact_wire, [initiator, responder], catalog) = match compact_wire {
            Some(selection) => (selection, [initiator, responder], catalog),
            None => {
                let selection = compact::authenticated_selection(initiator, responder)?;
                let physical = if let Some(carrier) = maintained {
                    carrier.geometry.charged_overhead_bytes
                } else if let Some(policy) = raw_policy {
                    let final_geometry = policy
                        .final_record_geometry_with_tls_cover(
                            settings.cover.appearance == l2tunnel_cover::Appearance::TlsLike,
                        )
                        .map_err(io::Error::other)?;
                    final_geometry
                        .ip_tcp_bytes
                        .checked_add(final_geometry.record_overhead_bytes)
                        .ok_or_else(|| invalid("raw physical overhead overflow"))?
                } else if settings.gate.path.client.is_ipv6() {
                    48
                } else {
                    28
                };
                let (resources, catalog) = compact::rebase_parameters(
                    [initiator, responder],
                    catalog,
                    physical,
                    selection,
                )?;
                (selection, resources, catalog)
            }
        };
        let ([initiator, responder], catalog) = if selected_proxy {
            let physical = if let Some(carrier) = maintained {
                carrier.geometry.charged_overhead_bytes
            } else if let Some(policy) = raw_policy {
                let final_geometry = policy
                    .final_record_geometry_with_tls_cover(
                        settings.cover.appearance == l2tunnel_cover::Appearance::TlsLike,
                    )
                    .map_err(io::Error::other)?;
                final_geometry
                    .ip_tcp_bytes
                    .checked_add(final_geometry.record_overhead_bytes)
                    .ok_or_else(|| invalid("raw physical overhead overflow"))?
            } else if settings.gate.path.client.is_ipv6() {
                48
            } else {
                28
            };
            compact::rebase_parameters_with_data_overhead(
                [initiator, responder],
                catalog,
                physical,
                compact_wire
                    .data_overhead()
                    .max(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD),
            )?
        } else {
            ([initiator, responder], catalog)
        };
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
                    common::Profile::Rolling { .. }
                        | common::Profile::RollingCopies { .. }
                        | common::Profile::Research { .. }
                )
            })
        {
            return Err(invalid(
                "fragment selection requires a coded catalog member",
            ));
        }
        if (raw_policy.is_none() && maintained.is_none() && connection.duplex != Duplex::Full)
            || catalog.initial().duplex() != connection.duplex
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Common carrier and initial descriptor duplex differ",
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
        for role in [Role::Client, Role::Server] {
            let uses_lz4 = initial
                .direction(role)
                .native_policy()
                .is_some_and(l2tunnel::aligned::NativePolicy::uses_lz4);
            if uses_lz4 != (connection.compression == Compression::Lz4IfSmaller) {
                return Err(invalid(
                    "requested compression differs from the initial Common record policy",
                ));
            }
        }
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
        // The inner packet size may differ per entry (live-tuning decision
        // 8); the attachment layer and duplex may not. Native resources must
        // hold the largest entry.
        let mut largest = native;
        for descriptor in catalog.descriptors() {
            for role in [Role::Client, Role::Server] {
                let direction = descriptor.direction(role);
                largest = largest.max(direction.max_native());
                if direction.common().traffic().layer != layer
                    || descriptor.duplex() != connection.duplex
                {
                    return Err(invalid(
                        "common catalog changes immutable attachment/duplex",
                    ));
                }
            }
        }
        for resources in [initiator, responder] {
            resources.validate_common_resources(largest)?;
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
        Ok(Self {
            connection,
            peers,
            settings,
            application: seed,
            initiator,
            responder,
            catalog,
            parameters,
            envelope,
            initial,
            data,
            carrier: None,
            raw: None,
            maintained: None,
            requested_catalog: None,
            live_catalog: None,
            tuning: super::live_tuning::Policy::default(),
            proxy,
            proxy_retirement: false,
            proxy_measured: None,
            connection_reuse: false,
            compact_wire,
        })
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
        if self.proxy.is_some() || self.connection_reuse {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "explicit Common proxy supports only its original protected UDP owner",
            ));
        }
        if self.carrier.is_some() || self.raw.is_some() || self.maintained.is_some() {
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
        let resources = [self.initiator, self.responder];
        let requested_configuration = self.configuration()?;
        let mut binding = CarrierBinding {
            outer,
            requested_configuration,
            requested_envelope: self.envelope,
            resources,
            configuration: requested_configuration,
        };
        let mut result = self.clone();
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
        if let Some(value) = &self.maintained {
            return Ok(value.requested);
        }
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
        if let Some(value) = &self.maintained {
            return value.envelope;
        }
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
    /// Bound OpenVPN profiles retain the bootstrap opcode and effective setup
    /// identity; selected final Records geometry belongs to the runtime contract.
    pub fn establish_config(&self, role: security::Role) -> io::Result<establish::Config> {
        let mut config = self.settings.runtime(role, self.peers)?;
        if self.maintained.is_some() {
            return self.establish_maintained(config, role);
        }
        if self.raw.is_none() && self.carrier.is_none() {
            config.binding.configuration = self.compact_contract(role)?.expected_configuration().0;
        }
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
    /// This profile switching within `catalog`, the live-tuning catalog both
    /// ends generated from this plan and the authenticated proposal
    /// (docs/modules/live-tuning.md). The setup identity, envelope and
    /// initial entry stay this plan's; the runtime contract checks the rest.
    pub fn with_live_catalog(&self, catalog: Catalog) -> io::Result<Self> {
        if catalog.initial() != self.catalog.initial() {
            return Err(invalid("live-tuning catalog changes the initial entry"));
        }
        let mut result = self.clone();
        result.live_catalog = Some(catalog);
        Ok(result)
    }
    /// This profile with a live-tuning policy (client choices or server
    /// limits), read from the run options.
    pub fn with_tuning(mut self, policy: super::live_tuning::Policy) -> Self {
        self.tuning = policy;
        self
    }
    /// The live-tuning policy.
    pub fn tuning(&self) -> &super::live_tuning::Policy {
        &self.tuning
    }
    /// The live-tuning catalog in use, when the session was tuned.
    pub fn live_catalog(&self) -> Option<&Catalog> {
        self.live_catalog.as_ref()
    }
    fn apply_live_catalog(
        &self,
        contract: transport::CommonTransactionContract,
    ) -> io::Result<transport::CommonTransactionContract> {
        match &self.live_catalog {
            Some(catalog) => contract.with_live_catalog(catalog.clone()),
            None => Ok(contract),
        }
    }
    /// Whole supported catalog in effect, without pruning to fit storage:
    /// the live-tuning catalog when the session was tuned, else the plan's.
    pub fn catalog(&self) -> &Catalog {
        self.live_catalog.as_ref().unwrap_or(&self.catalog)
    }
    /// The plan's own catalog, which live tuning extends.
    pub fn plan_catalog(&self) -> &Catalog {
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
        if let Some(value) = &self.maintained {
            return Ok(value.configuration);
        }
        if let Some(raw) = self.raw {
            return Ok(raw.configuration);
        }
        if let Some(binding) = self.carrier {
            return Ok(binding.configuration);
        }
        Ok(self
            .compact_contract(security::Role::Initiator)?
            .expected_configuration())
    }
    /// Transfer the exact selected role resources/catalog and setup identity.
    pub fn runtime_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        if self.maintained.is_some() {
            return self.maintained_contract(role);
        }
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
        self.compact_contract(role)
    }
    fn compact_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        let selection = self.compact_wire;
        if self.raw.is_some() || self.carrier.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compact v3 currently requires the original UDP Common backend",
            ));
        }
        let contract = transport::CommonTransactionContract::new_compact_wire(
            self.settings.configuration(self.peers)?,
            role,
            [self.initiator, self.responder],
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            self.envelope,
            self.catalog.clone(),
            self.parameters,
            selection,
        )?;
        self.complete_proxy_contract(contract)
    }
    // Both callers already constructed their actual original carrier contract.
    // This metadata cannot upgrade an observation into member/root authority.
    fn complete_proxy_contract(
        &self,
        contract: transport::CommonTransactionContract,
    ) -> io::Result<transport::CommonTransactionContract> {
        let contract = self.apply_live_catalog(contract)?;
        match &self.proxy {
            Some(proxy) => {
                #[cfg(not(unix))]
                {
                    let _ = proxy;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Common proxy record adapter is unavailable on this platform",
                    ))
                }
                #[cfg(unix)]
                {
                    let digest = match &self.proxy_measured {
                        Some(measured) => {
                            l2tunnel_runtime::proxy::measured::session_config(measured)?.digest
                        }
                        None => l2tunnel_runtime::proxy::session_config(proxy)?.digest,
                    };
                    let mut contract = if self.raw.is_some() {
                        contract.with_proxy_raw_binding(digest)?
                    } else {
                        contract.with_proxy_binding(digest)?
                    };
                    if self.proxy_retirement {
                        contract = contract.with_proxy_retirement()?;
                    }
                    match &self.proxy_measured {
                        Some(measured) => {
                            l2tunnel_runtime::proxy::common::validate_measured(measured, &contract)?
                        }
                        None => l2tunnel_runtime::proxy::common::validate(proxy, &contract)?,
                    }
                    Ok(contract)
                }
            }
            None => {
                if self.connection_reuse {
                    contract.with_connection_reuse()
                } else {
                    Ok(contract)
                }
            }
        }
    }

    fn carrier_contract(
        &self,
        binding: CarrierBinding,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        let contract = transport::CommonTransactionContract::new_on_carrier_paired_compact(
            binding.requested_configuration,
            role,
            binding.resources,
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            binding.requested_envelope,
            self.catalog.clone(),
            self.parameters,
            binding.outer,
            self.compact_wire,
        )?;
        self.apply_live_catalog(contract)
    }
}
fn extra_byte(value: usize) -> io::Result<usize> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("common carrier opcode accounting overflow"))
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

#[cfg(all(test, unix))]
#[path = "common_transaction_profile_tests.rs"]
mod tests;
