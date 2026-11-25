//! Complete requested Common policy and genuine maintained outer-session binding.
use super::*;
use l2tunnel_runtime::secure_udp::maintained::Authenticated;
#[derive(Clone, Copy, Debug)]
pub(super) struct Selection {
    pub(super) settings: super::super::maintained::Settings,
    base: security::ConfigDigest,
    pub(super) requested: security::ConfigDigest,
    pub(super) envelope: EnvelopeDigest,
    pub(super) configuration: security::ConfigDigest,
    outer: Option<Authenticated>,
}
impl Profile {
    /// Construct the mandatory final format with full-tag data authentication.
    /// Old input geometry is recomputed before the authenticated commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new_maintained(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        maintained: super::super::maintained::Settings,
    ) -> io::Result<Self> {
        Self::new_selected_for(
            connection,
            settings,
            peers,
            initiator,
            responder,
            catalog,
            parameters,
            None,
            None,
            None,
            Some(maintained),
        )
    }
    /// Explicit complete compact Common catalog over genuine maintained TLS/QUIC.
    /// The provided catalog/resources retain their exact selected geometry.
    #[allow(clippy::too_many_arguments)]
    pub fn new_maintained_compact(
        connection: ConnectionConfig,
        settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        maintained: super::super::maintained::Settings,
        selection: l2tunnel::secure_record::compact::Selection,
    ) -> io::Result<Self> {
        selection.validate().map_err(io::Error::other)?;
        Self::new_selected_for(
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
            Some(maintained),
        )
    }
    /// Explicit same-owner reuse on the supported Full/IP/PerConnection catalog.
    /// Runtime capability still requires the genuine authenticated maintained owner.
    #[allow(clippy::too_many_arguments)]
    pub fn new_maintained_compact_with_connection_reuse(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
        maintained: super::super::maintained::Settings,
        selection: l2tunnel::secure_record::compact::Selection,
    ) -> io::Result<Self> {
        if connection.layer != l2tunnel_device::PacketLayer::Ip
            || connection.duplex != l2tunnel_core::Duplex::Full
            || !catalog.descriptors().iter().any(|descriptor| {
                matches!(
                    descriptor.profile(),
                    l2tunnel::record_configuration::Profile::PerConnectionCompact { .. }
                )
            })
        {
            return Err(invalid(
                "maintained slot reuse requires Full native-IP PerConnection Common catalog",
            ));
        }
        Self::select_reuse_application(&mut settings, parameters);
        let mut profile = Self::new_maintained_compact(
            connection, settings, peers, initiator, responder, catalog, parameters, maintained,
            selection,
        )?;
        profile.connection_reuse = true;
        Ok(profile)
    }
    pub(super) fn select_maintained(
        mut self,
        settings: super::super::maintained::Settings,
    ) -> io::Result<Self> {
        let request = settings.request(self.connection)?;
        if self.settings.gate.path != settings.first {
            return Err(invalid("Common path differs from maintained first lane"));
        }
        let original = self.settings.configuration(self.peers)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-client/common-maintained-base/v1\0");
        hash.update(&original.0);
        for path in [Some(settings.first), settings.second] {
            hash.update(&[u8::from(path.is_some())]);
            if let Some(path) = path {
                for endpoint in [path.client, path.server] {
                    match endpoint {
                        std::net::SocketAddr::V4(value) => {
                            hash.update(&[4]);
                            hash.update(&value.ip().octets());
                        }
                        std::net::SocketAddr::V6(value) => {
                            hash.update(&[6]);
                            hash.update(&value.ip().octets());
                            hash.update(&value.flowinfo().to_be_bytes());
                            hash.update(&value.scope_id().to_be_bytes());
                        }
                    }
                    hash.update(&endpoint.port().to_be_bytes());
                }
            }
        }
        let base = security::ConfigDigest(super::super::finish(hash));
        let selection = self.compact_wire;
        let covers = self.maintained_covers()?;
        for role in [security::Role::Initiator, security::Role::Responder] {
            establish::maintained::validate_requested(
                bootstrap_geometry(self.settings.runtime(role, self.peers)?, request)?,
                self.peers,
                request,
            )
            .map_err(io::Error::other)?;
        }
        transport::CommonTransactionContract::validate_maintained_requested_compact(
            base,
            self.envelope,
            &self.catalog,
            [self.initiator, self.responder],
            covers,
            self.parameters,
            request,
            selection,
        )?;
        let requested =
            transport::CommonTransactionContract::maintained_requested_configuration_compact(
                base,
                self.envelope,
                &self.catalog,
                [self.initiator, self.responder],
                covers,
                self.parameters,
                request,
                selection,
            )?;
        self.maintained = Some(Box::new(Selection {
            settings,
            base,
            requested: security::ConfigDigest(requested.0),
            envelope: self.envelope,
            configuration: security::ConfigDigest(requested.0),
            outer: None,
        }));
        Ok(self)
    }
    fn maintained_covers(&self) -> io::Result<[l2tunnel_cover::Config; 2]> {
        Ok([
            self.settings.cover.config(security::Role::Initiator)?,
            self.settings.cover.config(security::Role::Responder)?,
        ])
    }
    /// Exact requested maintained policy; absence means another explicit carrier.
    pub fn maintained_settings(&self) -> Option<super::super::maintained::Settings> {
        self.maintained.as_ref().map(|v| v.settings)
    }
    /// Actual retained outer proof only after genuine authenticated factory completion.
    pub fn maintained_binding(&self) -> Option<Authenticated> {
        self.maintained.as_ref().and_then(|v| v.outer)
    }
    /// Complete Common digest used before the first TLS/member exchange.
    pub fn maintained_session(&self) -> io::Result<l2tunnel_auth::SessionConfig> {
        let value = self
            .maintained
            .as_ref()
            .ok_or_else(|| invalid("maintained selection absent"))?;
        Ok(l2tunnel_auth::SessionConfig {
            layer: self.connection.layer,
            digest: ConfigDigest(value.requested.0),
        })
    }
    /// Derive effective H1/E1 only from the actual retained original owners.
    pub fn bind_maintained(&self, outer: Authenticated) -> io::Result<Self> {
        let mut value = **self
            .maintained
            .as_ref()
            .ok_or_else(|| invalid("maintained selection absent"))?;
        if value.outer.is_some()
            || self.raw.is_some()
            || self.carrier.is_some()
            || outer.requested() != value.settings.request(self.connection)?
            || outer.common_configuration() != self.maintained_session()?
            || outer.endpoints()? != (value.settings.first.client, value.settings.first.server)
            || outer.info()?.member.0 != self.settings.member.0
        {
            return Err(invalid(
                "actual maintained proof differs from complete requested policy",
            ));
        }
        for (lane, path) in outer
            .lanes()
            .into_iter()
            .zip([Some(value.settings.first), value.settings.second])
        {
            if let (Some(lane), Some(path)) = (lane, path) {
                let endpoints = if lane.info.peer_member.is_none() {
                    (lane.local, lane.peer)
                } else {
                    (lane.peer, lane.local)
                };
                if endpoints != (path.client, path.server) {
                    return Err(invalid("actual maintained tuple differs"));
                }
            }
        }
        value.outer = Some(outer);
        let mut result = self.clone();
        result.maintained = Some(Box::new(value));
        let contract = result.maintained_contract(role(outer)?)?;
        result.requested_catalog = Some(Box::new(self.catalog.clone()));
        result.envelope = contract.envelope();
        result.initial = contract.initial();
        result.data = contract.data_digest();
        result
            .maintained
            .as_mut()
            .ok_or_else(|| invalid("maintained selection absent"))?
            .configuration = contract.expected_configuration();
        result.establish_config(role(outer)?)?;
        Ok(result)
    }
    pub(super) fn maintained_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        let value = self
            .maintained
            .as_ref()
            .ok_or_else(|| invalid("maintained selection absent"))?;
        let outer = value
            .outer
            .ok_or_else(|| invalid("maintained Common requires genuine outer authentication"))?;
        let contract = transport::CommonTransactionContract::new_on_maintained_paired_compact(
            value.base,
            role,
            [self.initiator, self.responder],
            self.maintained_covers()?,
            value.envelope,
            self.catalog.clone(),
            self.parameters,
            outer,
            self.compact_wire,
        )?;
        self.complete_proxy_contract(contract)
    }
    pub(super) fn establish_maintained(
        &self,
        mut config: establish::Config,
        local: security::Role,
    ) -> io::Result<establish::Config> {
        let value = self
            .maintained
            .as_ref()
            .ok_or_else(|| invalid("maintained selection absent"))?;
        let outer = value
            .outer
            .ok_or_else(|| invalid("maintained setup requires genuine original authentication"))?;
        if role(outer)? != local {
            return Err(invalid("maintained proof belongs to the other local role"));
        }
        config = bootstrap_geometry(config, value.settings.request(self.connection)?)?;
        config.binding.outer = outer.binding();
        config.binding.configuration = value.configuration.0;
        outer
            .expected_binding(config, self.peers, l2tunnel_handshake::SessionId([1; 16]))
            .map_err(io::Error::other)?;
        Ok(config)
    }
}
fn role(outer: Authenticated) -> io::Result<security::Role> {
    Ok(if outer.info()?.peer_member.is_none() {
        security::Role::Initiator
    } else {
        security::Role::Responder
    })
}

// Settings retains the generic gate's IP/UDP base charge. Select the maintained
// request's explicit bootstrap allowance only at its runtime setup boundary.
fn bootstrap_geometry(
    mut config: establish::Config,
    request: l2tunnel_runtime::secure_udp::maintained::Request,
) -> io::Result<establish::Config> {
    let ip_udp = if config.gate.path.client.is_ipv4() {
        28
    } else {
        48
    };
    let extra = request
        .geometry
        .bootstrap_overhead_bytes
        .checked_sub(ip_udp)
        .ok_or_else(|| invalid("maintained bootstrap allowance below base transport"))?;
    config.gate.outer_overhead = config
        .gate
        .outer_overhead
        .checked_add(extra)
        .ok_or_else(|| invalid("maintained bootstrap allowance overflow"))?;
    Ok(config)
}
