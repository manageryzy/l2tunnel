//! Genuine original raw binding for the existing complete Common profile.
use super::*;
use l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy;
use l2tunnel_runtime::secure_udp::establish::raw_carrier::AuthenticatedRaw;

#[derive(Clone, Copy, Debug)]
pub(super) struct RawSelection {
    pub(super) policy: PacketPolicy,
    pub(super) base: security::ConfigDigest,
    pub(super) requested: security::ConfigDigest,
    pub(super) envelope: EnvelopeDigest,
    pub(super) configuration: security::ConfigDigest,
    pub(super) outer: Option<AuthenticatedRaw>,
}
impl Profile {
    pub(crate) fn requested_resources(&self, role: security::Role) -> transport::Config {
        if role == security::Role::Initiator {
            self.initiator
        } else {
            self.responder
        }
    }
    /// Explicit original raw Full/Half request; no original I/O or proof is created.
    /// The catalog/resources must already contain the exact maintained raw cost.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        packet: PacketPolicy,
    ) -> io::Result<Self> {
        Self::new_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            Some(packet),
            None,
            None,
        )
    }
    /// Select single final protection before the original raw TLS/member bootstrap.
    /// The raw phase remains protected until the actual accepted inner session
    /// transfers its material to the same original packet owner.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw_compact(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        packet: PacketPolicy,
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
            Some(packet),
            None,
            Some(selection),
        )
    }
    /// Explicit fixed proxy on the maintained original raw TCP carrier.
    /// Complete raw geometry is requested upfront; no descriptor/body is clamped.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy_raw(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
        packet: PacketPolicy,
    ) -> io::Result<Self> {
        let binding = l2tunnel_runtime::proxy::session_config(&proxy)?;
        let validation = {
            #[cfg(unix)]
            {
                l2tunnel_runtime::proxy::common::validate_catalog(&proxy, &catalog)
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Common proxy record adapter is unavailable on this platform",
                ))
            }
        };
        validation?;
        if connection.duplex != proxy.duplex
            || connection.layer != PacketLayer::Ip
            || proxy.runtime.layer != PacketLayer::Ip
            || proxy.runtime.max_packet != connection.max_packet
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw Common proxy requires matching duplex and fixed TUN policy",
            ));
        }
        let mut application = digest::Context::new(&digest::SHA256);
        application.update(b"l2tunnel/shared-client/common-proxy/v1\0");
        application.update(&settings.application.0);
        application.update(&binding.digest.0);
        settings.application = ConfigDigest(crate::secure_udp::finish(application));
        Self::new_selected(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            Some(packet),
            Some(proxy),
            None,
        )
    }
    /// Same fixed raw proxy with explicitly authenticated retained final ARQ debt.
    /// Existing v1/raw/native selections and defaults remain unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proxy_raw_retained(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        proxy: l2tunnel_runtime::proxy::Config,
        packet: PacketPolicy,
    ) -> io::Result<Self> {
        let mut application = digest::Context::new(&digest::SHA256);
        application.update(b"l2tunnel/shared-client/common-proxy-retirement/v1\0");
        application.update(&settings.application.0);
        settings.application = ConfigDigest(crate::secure_udp::finish(application));
        let mut result = Self::new_proxy_raw(
            connection, settings, peers, initiator, responder, catalog, parameters, proxy, packet,
        )?;
        result.proxy_retirement = true;
        Ok(result)
    }
    pub(super) fn select_raw(mut self, policy: PacketPolicy) -> io::Result<Self> {
        if self.settings.gate.path.client.is_ipv6() || self.settings.gate.path.server.is_ipv6() {
            return Err(invalid(
                "original raw Common currently requires explicit IPv4 tuples",
            ));
        }
        for role in [security::Role::Initiator, security::Role::Responder] {
            let config = raw_geometry(self.settings.runtime(role, self.peers)?, policy)?;
            establish::raw_carrier::validate_requested(config, self.peers, policy)
                .map_err(io::Error::other)?;
        }
        let base = self.settings.configuration(self.peers)?;
        let covers = [
            self.settings.cover.config(security::Role::Initiator)?,
            self.settings.cover.config(security::Role::Responder)?,
        ];
        let resources = [self.initiator, self.responder];
        transport::CommonTransactionContract::validate_raw_requested_compact(
            base,
            self.envelope,
            &self.catalog,
            resources,
            covers,
            self.parameters,
            policy,
            self.compact_wire,
        )?;
        let requested = transport::CommonTransactionContract::raw_requested_configuration_compact(
            base,
            self.envelope,
            &self.catalog,
            resources,
            covers,
            self.parameters,
            self.compact_wire,
        )?;
        self.raw = Some(Box::new(RawSelection {
            policy,
            base,
            requested: security::ConfigDigest(requested.0),
            envelope: self.envelope,
            configuration: security::ConfigDigest(requested.0),
            outer: None,
        }));
        Ok(self)
    }
    /// Explicit original raw policy, without any TLS/member or packet capability.
    pub fn raw_policy(&self) -> Option<PacketPolicy> {
        self.raw.as_deref().map(|v| v.policy)
    }
    /// Genuine completed raw proof, absent before actual original authentication.
    pub fn raw_binding(&self) -> Option<AuthenticatedRaw> {
        self.raw.as_deref().and_then(|v| v.outer)
    }
    /// Check both actual directional resource/catalog geometries without proof minting.
    pub fn validate_raw_request(&self) -> io::Result<()> {
        let raw = self
            .raw
            .as_deref()
            .ok_or_else(|| invalid("Common profile has no selected raw policy"))?;
        transport::CommonTransactionContract::validate_raw_requested_compact(
            raw.base,
            raw.envelope,
            self.requested_catalog(),
            [self.initiator, self.responder],
            [
                self.settings.cover.config(security::Role::Initiator)?,
                self.settings.cover.config(security::Role::Responder)?,
            ],
            self.parameters,
            raw.policy,
            self.compact_wire,
        )
    }
    /// Bind effective E1/H1 only to a genuine completed original PacketCarrier.
    pub fn bind_raw(&self, outer: AuthenticatedRaw) -> io::Result<Self> {
        let mut raw = *self
            .raw
            .as_deref()
            .ok_or_else(|| invalid("Common profile has no selected raw policy"))?;
        if raw.outer.is_some() || self.carrier.is_some() {
            return Err(invalid("Common profile already bound"));
        }
        let expected = (
            self.settings.gate.path.client,
            self.settings.gate.path.server,
        );
        if outer.lane_endpoints()[0] != Some(expected)
            || outer.info().member.0 != self.settings.member.0
            || outer.info().config.layer != self.connection.layer
            || outer.duplex() != self.connection.duplex
            || outer.policy() != raw.policy
        {
            return Err(invalid(
                "actual raw proof differs from requested Common identity/path/policy",
            ));
        }
        let role = raw_role(outer);
        let contract = self.make_raw_contract(raw, outer, role)?;
        let mut result = self.clone();
        result.requested_catalog = Some(Box::new(self.catalog.clone()));
        result.envelope = contract.envelope();
        result.initial = contract.initial();
        result.data = contract.data_digest();
        raw.outer = Some(outer);
        raw.configuration = contract.expected_configuration();
        result.raw = Some(Box::new(raw));
        result.establish_config(role)?;
        Ok(result)
    }
    pub(super) fn raw_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        let raw = *self
            .raw
            .as_deref()
            .ok_or_else(|| invalid("missing raw Common selection"))?;
        let outer = raw
            .outer
            .ok_or_else(|| invalid("raw Common requires genuine original authentication"))?;
        self.make_raw_contract(raw, outer, role)
    }
    fn make_raw_contract(
        &self,
        raw: RawSelection,
        outer: AuthenticatedRaw,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        let contract = transport::CommonTransactionContract::new_on_raw_paired_compact(
            raw.base,
            role,
            [self.initiator, self.responder],
            [
                self.settings.cover.config(security::Role::Initiator)?,
                self.settings.cover.config(security::Role::Responder)?,
            ],
            raw.envelope,
            self.catalog.clone(),
            self.parameters,
            outer,
            self.compact_wire,
        )?;
        self.complete_proxy_contract(contract)
    }
    pub(super) fn establish_raw(
        &self,
        mut config: establish::Config,
        role: security::Role,
    ) -> io::Result<establish::Config> {
        let raw = self
            .raw
            .as_deref()
            .ok_or_else(|| invalid("missing raw Common selection"))?;
        let outer = raw
            .outer
            .ok_or_else(|| invalid("raw setup requires genuine original authentication"))?;
        if role != raw_role(outer) {
            return Err(invalid("raw bound profile belongs to the other local role"));
        }
        config = raw_geometry(config, raw.policy)?;
        config.binding.outer = outer.binding();
        config.binding.configuration = raw.configuration.0;
        outer
            .expected_binding(config, self.peers, l2tunnel_handshake::SessionId([1; 16]))
            .map_err(io::Error::other)?;
        Ok(config)
    }
}
fn raw_role(outer: AuthenticatedRaw) -> security::Role {
    match outer.role() {
        l2tunnel_handshake::Role::Initiator => security::Role::Initiator,
        l2tunnel_handshake::Role::Responder => security::Role::Responder,
    }
}

fn raw_geometry(
    mut config: establish::Config,
    policy: PacketPolicy,
) -> io::Result<establish::Config> {
    let geometry = policy.record_geometry().map_err(io::Error::other)?;
    let physical = geometry
        .ip_tcp_bytes
        .checked_add(geometry.record_overhead_bytes)
        .ok_or_else(|| invalid("raw physical geometry overflow"))?;
    let extra = physical
        .checked_sub(28)
        .ok_or_else(|| invalid("raw IPv4 physical geometry"))?;
    config.gate.outer_overhead = config
        .gate
        .outer_overhead
        .checked_add(extra)
        .ok_or_else(|| invalid("raw bootstrap overhead overflow"))?;
    Ok(config)
}
