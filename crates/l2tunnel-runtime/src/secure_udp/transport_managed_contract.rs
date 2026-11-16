//! Explicit complete managed selection; labels do not manufacture initial authority.
use super::*;
use crate::secure_udp::establish::carrier::AuthenticatedOuter;
use l2tunnel_security::refresh::{Selection, SelectionSpec};

/// Exact opt-in fresh-key timing and copied-flight allowance; no default exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshKeyPolicy {
    /// Original accepted exchange cap in injected microseconds.
    pub exchange_micros: u64,
    /// Maximum key age from confirmed split import, also bounded by session expiry.
    pub key_micros: u64,
    /// Required receive-key overlap after actual local activation.
    pub overlap_micros: u64,
    /// First transmission plus exact copies for each original logical flight.
    pub max_flight_copies: u32,
}
impl FreshKeyPolicy {
    fn bind(self, hash: &mut digest::Context) {
        for value in [self.exchange_micros, self.key_micros, self.overlap_micros] {
            hash.update(&value.to_be_bytes());
        }
        hash.update(&self.max_flight_copies.to_be_bytes());
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Managed {
    pub(super) selection: Selection,
    pub(super) streams: control_owner::SettingsV2,
}

impl Config {
    /// Commit the actual selected v2 resource namespace without referencing H0.
    /// Local report cadence and inactive legacy Swift fields remain observations.
    pub fn managed_common_resource_digest(
        &self,
        max_native: usize,
        selected: control_owner::SettingsV2,
    ) -> io::Result<core::ConfigDigest> {
        self.validate_common_resources(max_native)?;
        let first = self
            .streams
            .ok_or_else(|| invalid("managed Common requires explicit streams"))?;
        if selected.streams[..3] != first.streams {
            return Err(invalid(
                "managed first three streams differ from resource template",
            ));
        }
        if streams::v2::HEADER_BYTES != streams::HEADER_BYTES {
            return Err(invalid("managed Control wrapper geometry differs"));
        }
        selected.validate(self.control, self.path_mtu, self.lifetime.lease)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/secure-udp-managed-common-resources/v1\0");
        // Reuse the full maintained shared inventory. This does not construct a
        // v1 owner; the additional version/map below selects actual v2 domains.
        hash.update(&self.common_resource_digest(max_native)?.0);
        hash.update(&[streams::v2::VERSION]);
        hash.update(&(streams::v2::HEADER_BYTES as u64).to_be_bytes());
        hash.update(&(security::refresh::PREFIX_BYTES as u64).to_be_bytes());
        hash.update(&[security::Protection::ChaCha20Poly1305 as u8]);
        let binding = delivery::Binding {
            session: mg::SessionId([1; 16]),
            lane: mg::LaneId(LANE),
            local_role: mg::Role::Client,
            control_epoch: self.control_epoch.0,
        };
        for (stream, entry) in streams::v2::ALL.into_iter().zip(selected.streams) {
            hash.update(&(stream as u64).to_be_bytes());
            hash.update(
                &streams::v2::delivery_binding(binding, stream)
                    .map_err(invalid)?
                    .control_epoch
                    .to_be_bytes(),
            );
            for value in [
                entry.delivery.wire_overhead as u64,
                entry.path_mtu as u64,
                entry.max_message_bytes as u64,
                entry.max_outbound_messages as u64,
                entry.max_outbound_bytes as u64,
                u64::from(entry.max_fragments),
                entry.max_reassembly_bytes as u64,
                entry.max_incomplete_messages as u64,
                entry.work_per_call as u64,
                entry.message_lifetime.as_secs(),
                u64::from(entry.message_lifetime.subsec_nanos()),
            ] {
                hash.update(&value.to_be_bytes());
            }
        }
        Ok(core::ConfigDigest(finish(hash)))
    }
}

impl CommonTransactionContract {
    /// Initial-only common protection on a genuine original outer carrier.
    /// This selects neither refresh capabilities nor periodic/fixed key timers.
    #[allow(clippy::too_many_arguments)]
    pub fn new_on_carrier(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedOuter,
    ) -> io::Result<Self> {
        let native = carrier_native(&catalog)?;
        let resource = resources.common_resource_digest(native)?;
        Self::initial_on_carrier(
            base_policy,
            role,
            resources,
            cover,
            ipv6,
            base_envelope,
            catalog,
            settings,
            outer,
            resource,
        )
    }

    /// Bind both endpoints' complete resources in fixed initiator/responder order.
    /// The selected local owner still uses its exact role-specific template.
    /// This explicit constructor supports asymmetric templates without deriving
    /// different setup digests at the two authenticated endpoints.
    #[allow(clippy::too_many_arguments)]
    pub fn new_on_carrier_paired(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedOuter,
    ) -> io::Result<Self> {
        let native = carrier_native(&catalog)?;
        let mut pair = digest::Context::new(&digest::SHA256);
        pair.update(b"l2tunnel/secure-udp-common-initial-carrier/paired-resources/v1\0");
        for local in resources {
            settings.validate(local)?;
            if local.path_mtu != outer.requested().path_mtu
                || covered_maximum(local, cover, false)? > outer.requested().max_record_bytes
            {
                return Err(invalid("paired resources exceed actual outer geometry"));
            }
            pair.update(&local.common_resource_digest(native)?.0);
        }
        let local = resources[match role {
            security::Role::Initiator => 0,
            security::Role::Responder => 1,
        }];
        let result = Self::initial_on_carrier(
            base_policy,
            role,
            local,
            cover,
            ipv6,
            base_envelope,
            catalog,
            settings,
            outer,
            core::ConfigDigest(finish(pair)),
        )?;
        let (peer_role, peer_resources) = match role {
            security::Role::Initiator => (security::Role::Responder, resources[1]),
            security::Role::Responder => (security::Role::Initiator, resources[0]),
        };
        // Validate the peer's complete catalog and message capacity without
        // assigning this local authenticated proof to an opposite-role owner.
        // This private temporary is discarded; only the genuine local result
        // can be returned to the caller or transferred into a runtime.
        Self::construct(
            result.expected_configuration(),
            peer_role,
            peer_resources,
            cover,
            ipv6,
            result.envelope(),
            result.catalog().clone(),
            settings,
            None,
            1,
            None,
        )?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn initial_on_carrier(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedOuter,
        resource: core::ConfigDigest,
    ) -> io::Result<Self> {
        let descriptor = catalog.initial();
        validate_carrier(outer, role, resources, ipv6, descriptor)?;
        settings.validate(resources)?;
        if covered_maximum(resources, cover, false)? > outer.requested().max_record_bytes {
            return Err(invalid(
                "initial record exceeds actual outer carrier capacity",
            ));
        }
        let mut envelope = digest::Context::new(&digest::SHA256);
        envelope.update(b"l2tunnel/secure-udp-common-initial-carrier/envelope/v1\0");
        envelope.update(base_envelope.as_bytes());
        envelope.update(&base_policy.0);
        envelope.update(&resource.0);
        envelope.update(catalog.root().as_bytes());
        envelope.update(&outer.binding());
        envelope.update(&outer.info().config.digest.0);
        bind_transaction(&mut envelope, settings)?;
        let envelope = common::EnvelopeDigest::new(finish(envelope));
        let initial = common::Configuration::new(envelope, descriptor).map_err(invalid)?;
        let mut bytes = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut bytes).map_err(invalid)?;
        let mut setup = digest::Context::new(&digest::SHA256);
        setup.update(b"l2tunnel/secure-udp-common-initial-carrier/setup/v1\0");
        setup.update(&base_policy.0);
        setup.update(envelope.as_bytes());
        setup.update(&bytes);
        setup.update(catalog.root().as_bytes());
        Self::construct(
            security::ConfigDigest(finish(setup)),
            role,
            resources,
            cover,
            ipv6,
            envelope,
            catalog,
            settings,
            None,
            1,
            Some(outer),
        )
    }

    /// Select managed v2 on the original UDP socket, with all policy explicit.
    /// `base_policy` and `base_envelope` precede this selection; neither is H0.
    #[allow(clippy::too_many_arguments)]
    pub fn new_managed(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        selected: control_owner::SettingsV2,
        fresh: FreshKeyPolicy,
    ) -> io::Result<Self> {
        Self::managed_contract(
            base_policy,
            role,
            resources,
            cover,
            ipv6,
            base_envelope,
            catalog,
            settings,
            selected,
            fresh,
            None,
        )
    }

    /// Bind a genuine completed outer carrier proof to the selected same-owner
    /// handoff. Copying this proof does not create socket or Noise authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new_managed_on_carrier(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        selected: control_owner::SettingsV2,
        fresh: FreshKeyPolicy,
        outer: AuthenticatedOuter,
    ) -> io::Result<Self> {
        Self::managed_contract(
            base_policy,
            role,
            resources,
            cover,
            ipv6,
            base_envelope,
            catalog,
            settings,
            selected,
            fresh,
            Some(outer),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn managed_contract(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        selected: control_owner::SettingsV2,
        fresh: FreshKeyPolicy,
        outer: Option<AuthenticatedOuter>,
    ) -> io::Result<Self> {
        let descriptor = catalog.initial();
        let max_native = [mg::Role::Client, mg::Role::Server]
            .into_iter()
            .map(|role| descriptor.direction(role).max_native())
            .max()
            .ok_or_else(|| invalid("managed native widths"))?;
        let resource = resources.managed_common_resource_digest(max_native, selected)?;
        settings.validate(resources)?;
        let mut control = digest::Context::new(&digest::SHA256);
        control.update(b"l2tunnel/secure-udp-managed-common/control/v1\0");
        control.update(&resource.0);
        control.update(&resources.control_epoch.0.to_be_bytes());
        let control_digest = security::ConfigDigest(finish(control));
        let mut envelope = digest::Context::new(&digest::SHA256);
        envelope.update(b"l2tunnel/secure-udp-managed-common/envelope/v1\0");
        envelope.update(base_envelope.as_bytes());
        envelope.update(&base_policy.0);
        envelope.update(catalog.root().as_bytes());
        envelope.update(&resource.0);
        envelope.update(&control_digest.0);
        bind_transaction(&mut envelope, settings)?;
        fresh.bind(&mut envelope);
        let extra = if let Some(outer) = outer {
            validate_carrier(outer, role, resources, ipv6, descriptor)?;
            envelope.update(&[1]);
            envelope.update(&outer.binding());
            envelope.update(&outer.info().config.digest.0);
            // The opaque binding includes the actual fresh session, fixed member,
            // server identity and globally ordered original endpoints.
            1
        } else {
            envelope.update(&[0]);
            0
        };
        let envelope = common::EnvelopeDigest::new(finish(envelope));
        let selection = Selection::new(SelectionSpec {
            lane: security::LaneId(LANE),
            limits: resources.security,
            protection: security::Protection::ChaCha20Poly1305,
            control_epoch: resources.control_epoch,
            control_digest,
            envelope_digest: security::ConfigDigest(*envelope.as_bytes()),
            exchange_micros: fresh.exchange_micros,
            key_micros: fresh.key_micros,
            overlap_micros: fresh.overlap_micros,
            max_flight_copies: fresh.max_flight_copies,
        })
        .map_err(invalid)?;
        let initial = common::Configuration::new(envelope, descriptor).map_err(invalid)?;
        let mut initial_bytes = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut initial_bytes).map_err(invalid)?;
        let mut setup = digest::Context::new(&digest::SHA256);
        setup.update(b"l2tunnel/secure-udp-managed-common/setup/v1\0");
        setup.update(&base_policy.0);
        setup.update(envelope.as_bytes());
        setup.update(&selection.canonical_bytes());
        setup.update(&initial_bytes);
        setup.update(catalog.root().as_bytes());
        let expected = security::ConfigDigest(finish(setup));
        let contract = Self::construct(
            expected,
            role,
            resources,
            cover,
            ipv6,
            envelope,
            catalog,
            settings,
            Some(Managed {
                selection,
                streams: selected,
            }),
            extra,
            outer,
        )?;
        if let Some(outer) = outer {
            let actual = covered_maximum(resources, cover, true)?;
            if actual > outer.requested().max_record_bytes {
                return Err(invalid(
                    "managed record exceeds actual outer carrier capacity",
                ));
            }
        }
        Ok(contract)
    }

    /// Fixed selected Control scope, independent of the mutable data scope/H0.
    pub fn fixed_control_scope(&self) -> Option<l2tunnel::secure_record::Scope> {
        self.refresh_selection().map(|selection| {
            let spec = selection.spec();
            l2tunnel::secure_record::Scope {
                epoch: spec.control_epoch,
                configuration: spec.control_digest,
            }
        })
    }
    /// Compare against a genuine handoff proof. Observations alone never create
    /// the Parts or confirmed initial authority needed by the runtime consumer.
    pub fn validate_outer(&self, actual: Option<AuthenticatedOuter>) -> io::Result<()> {
        let expected = self.outer;
        if actual != expected {
            return Err(invalid(
                "managed original outer proof differs from contract",
            ));
        }
        Ok(())
    }
}
fn covered_maximum(resources: Config, cover: cover::Config, managed: bool) -> io::Result<usize> {
    let protected = resources
        .security
        .max_body_bytes
        .checked_add(record::ROUTE_BYTES)
        .and_then(|value| {
            value.checked_add(if managed {
                security::refresh::PREFIX_BYTES
            } else {
                security::COMMON_PREFIX_BYTES
            })
        })
        .and_then(|value| value.checked_add(security::Protection::ChaCha20Poly1305.tag_bytes()))
        .ok_or_else(exhausted)?;
    if protected > cover.limits().max_protected_bytes {
        return Err(invalid(
            "managed security exceeds covered protected capacity",
        ));
    }
    protected
        .checked_add(
            cover
                .overhead(cover::Phase::Established, protected)
                .map_err(invalid)?,
        )
        .ok_or_else(exhausted)
}
fn bind_transaction(hash: &mut digest::Context, settings: TransactionSettings) -> io::Result<()> {
    for value in [
        settings.protocol.retry_ms,
        settings.protocol.phase_timeout_ms,
        settings.protocol.reconcile_timeout_ms,
        settings.max_operation_ms,
        u64::try_from(settings.retained_bytes).map_err(invalid)?,
    ] {
        hash.update(&value.to_be_bytes());
    }
    Ok(())
}
fn finish(hash: digest::Context) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(hash.finish().as_ref());
    bytes
}

#[cfg(test)]
#[path = "transport_managed_contract_tests.rs"]
mod tests;

pub(super) fn validate_carrier(
    outer: AuthenticatedOuter,
    role: security::Role,
    resources: Config,
    ipv6: bool,
    descriptor: common::Descriptor,
) -> io::Result<()> {
    let requested = outer.requested();
    if requested.path_mtu != resources.path_mtu
        || requested.outer_overhead_bytes != if ipv6 { 49 } else { 29 }
        || outer.endpoints().0.is_ipv6() != ipv6
        || outer.endpoints().1.is_ipv6() != ipv6
        || outer.info().config != requested.session_config().map_err(invalid)?
        || match role {
            security::Role::Initiator => outer.info().peer_member.is_some(),
            security::Role::Responder => outer.info().peer_member != Some(outer.info().member),
        }
        || outer.info().config.layer
            != match descriptor
                .direction(mg::Role::Client)
                .common()
                .traffic()
                .layer
            {
                core::traffic::NetworkLayer::Tap => PacketLayer::Ethernet,
                core::traffic::NetworkLayer::Tun => PacketLayer::Ip,
            }
    {
        return Err(invalid("selected original outer policy/geometry differs"));
    }
    Ok(())
}

fn carrier_native(catalog: &common::Catalog) -> io::Result<usize> {
    let descriptor = catalog.initial();
    [mg::Role::Client, mg::Role::Server]
        .into_iter()
        .map(|role| descriptor.direction(role).max_native())
        .max()
        .ok_or_else(|| invalid("carrier native widths"))
}
