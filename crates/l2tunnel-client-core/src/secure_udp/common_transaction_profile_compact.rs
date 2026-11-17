//! Explicit conversion of a complete unbound carrier plan before authentication.
use super::*;

impl Profile {
    /// Select compact final framing before establishment, preserving the complete
    /// proxy, measured, reuse and catalog policies. Only carrier byte charges are
    /// rebased; E, D0 and H0 are rebuilt from the original application commitment.
    /// Explicit storage and reassembly bounds are preserved and revalidated; a
    /// plan that cannot fit the selected geometry returns an error without clamping.
    /// No authenticated session or outer-carrier proof is converted by this API.
    pub fn with_compact_wire(
        self,
        selection: l2tunnel::secure_record::compact::Selection,
    ) -> io::Result<Self> {
        selection.validate().map_err(io::Error::other)?;
        if self.raw.is_some_and(|raw| raw.outer.is_some())
            || self.carrier.is_some()
            || self.maintained.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compact selection requires an unbound carrier profile",
            ));
        }
        let raw_policy = self.raw.map(|raw| raw.policy);
        let physical = if let Some(policy) = raw_policy {
            policy
                .record_geometry()
                .map_err(io::Error::other)?
                .ip_tcp_bytes
        } else if self.settings.gate.path.client.is_ipv6() {
            48
        } else {
            28
        };
        let (resources, catalog) = rebase_parameters(
            [self.initiator, self.responder],
            self.catalog,
            physical,
            selection,
        )?;
        let mut settings = self.settings;
        settings.application = self.application;
        let mut result = Self::new_selected(
            self.connection,
            settings,
            self.peers,
            resources[0],
            resources[1],
            catalog,
            self.parameters,
            raw_policy,
            self.proxy,
            Some(selection),
        )?;
        result.proxy_retirement = self.proxy_retirement;
        result.proxy_measured = self.proxy_measured;
        result.connection_reuse = self.connection_reuse;
        if result.raw_policy().is_some() {
            result.validate_raw_request()?;
        } else {
            for role in [security::Role::Initiator, security::Role::Responder] {
                result.runtime_contract(role)?;
            }
        }
        Ok(result)
    }
}
/// Preserve the full-tag authentication of Common configurations that predate
/// explicit short-check selection. The packet gap follows the existing key-use
/// limits; the finite failed-check bound is authenticated with the complete plan.
pub(super) fn authenticated_selection(
    initiator: transport::Config,
    responder: transport::Config,
) -> io::Result<l2tunnel::secure_record::compact::Selection> {
    let selection = l2tunnel::secure_record::compact::Selection {
        protection: security::compact::Protection::ChaCha20Poly1305,
        limits: security::compact::Selection {
            max_forward_packets: u32::try_from(
                initiator
                    .security
                    .packets_per_key
                    .min(responder.security.packets_per_key)
                    .min(i32::MAX as u64),
            )
            .map_err(io::Error::other)?,
            max_failed_checks: u32::MAX,
        },
    };
    selection.validate().map_err(io::Error::other)?;
    Ok(selection)
}

pub(super) fn rebase_parameters(
    resources: [transport::Config; 2],
    catalog: Catalog,
    physical: usize,
    selection: l2tunnel::secure_record::compact::Selection,
) -> io::Result<([transport::Config; 2], Catalog)> {
    rebase_parameters_with_data_overhead(resources, catalog, physical, selection.data_overhead())
}

pub(super) fn rebase_parameters_with_data_overhead(
    mut resources: [transport::Config; 2],
    catalog: Catalog,
    physical: usize,
    data_overhead: usize,
) -> io::Result<([transport::Config; 2], Catalog)> {
    let data = physical
        .checked_add(data_overhead)
        .ok_or_else(|| invalid("final data accounting overflow"))?;
    let control = physical
        .checked_add(l2tunnel::secure_record::compact::AUTHENTICATED_OVERHEAD)
        .ok_or_else(|| invalid("final control accounting overflow"))?;
    let stream_overhead = control
        .checked_add(l2tunnel_management::control_streams::HEADER_BYTES)
        .ok_or_else(|| invalid("final control stream accounting overflow"))?;
    for resource in &mut resources {
        resource.control.wire_overhead = control;
        if let Some(fragments) = resource.rolling_fragments.as_mut() {
            fragments.forward.framing.outer_overhead_bytes = data;
            fragments.reverse.framing.outer_overhead_bytes = data;
        }
        if let Some(streams) = resource.streams.as_mut() {
            for stream in &mut streams.streams {
                stream.delivery.wire_overhead = stream_overhead;
            }
        }
    }
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(catalog.descriptors().len())
        .map_err(io::Error::other)?;
    for descriptor in catalog.descriptors() {
        descriptors.push(rebase(*descriptor, data)?);
    }
    let catalog =
        Catalog::new(rebase(catalog.initial(), data)?, &descriptors).map_err(io::Error::other)?;
    Ok((resources, catalog))
}
fn reliable(
    config: l2tunnel::reliable::CompactReliableConfig,
    overhead: usize,
) -> io::Result<l2tunnel::reliable::CompactReliableConfig> {
    l2tunnel::reliable::CompactReliableConfig::new(config.arq(), overhead).map_err(io::Error::other)
}
fn rebase(descriptor: common::Descriptor, overhead: usize) -> io::Result<common::Descriptor> {
    let mut profile = *descriptor.profile();
    match &mut profile {
        common::Profile::Swift { .. } => {}
        common::Profile::Aligned { forward, reverse } => {
            for config in [forward, reverse] {
                config.recovery.outer_overhead_bytes = overhead;
            }
        }
        common::Profile::Packed { forward, reverse } => {
            for config in [forward, reverse] {
                config.base.recovery.outer_overhead_bytes = overhead;
            }
        }
        common::Profile::AlignedCompact { forward, reverse } => {
            for config in [forward, reverse] {
                config.recovery = reliable(config.recovery, overhead)?;
            }
        }
        common::Profile::PackedCompact { forward, reverse } => {
            for config in [forward, reverse] {
                config.base.recovery = reliable(config.base.recovery, overhead)?;
            }
        }
        common::Profile::PerConnectionCompact { forward, reverse } => {
            // The descriptor keeps its complete route capacity; selected endpoint
            // admission replaces this legacy route charge with the actual arm.
            let nested = overhead
                .checked_add(l2tunnel::connection_records::route::HEADER_BYTES)
                .ok_or_else(|| invalid("compact connection charge overflow"))?;
            for config in [forward, reverse] {
                config.compact.recovery = reliable(config.compact.recovery, nested)?;
            }
        }
        common::Profile::Rolling { config, .. } | common::Profile::RollingCopies { config, .. } => {
            config.geometry.forward_overhead_bytes = overhead;
            config.geometry.reverse_overhead_bytes = overhead;
        }
        common::Profile::Research { config, .. } => {
            config.geometry.forward_overhead_bytes = overhead;
            config.geometry.reverse_overhead_bytes = overhead;
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
