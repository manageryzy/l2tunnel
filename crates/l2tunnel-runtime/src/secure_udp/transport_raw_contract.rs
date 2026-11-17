//! Explicit genuine raw outer binding with a pre-TLS requested-policy DAG.
use super::*;
use establish::raw_carrier::AuthenticatedRaw;

impl CommonTransactionContract {
    /// Validate exact compact final geometry while retaining the complete
    /// bootstrap packet policy, covers and both endpoint resource inventories.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_raw_requested_compact(
        base: security::ConfigDigest,
        envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        policy: l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy,
        selection: record::compact::Selection,
    ) -> io::Result<()> {
        let geometry = policy.record_geometry().map_err(invalid)?;
        let physical = policy
            .final_record_geometry()
            .map_err(invalid)?
            .ip_tcp_bytes;
        let requested = Self::raw_requested_configuration_compact(
            base, envelope, catalog, resources, covers, settings, selection,
        )?;
        for (index, role) in [security::Role::Initiator, security::Role::Responder]
            .into_iter()
            .enumerate()
        {
            establish::raw_carrier::validate_cover_geometry(covers[index], policy)
                .map_err(invalid)?;
            if resources[index].path_mtu != geometry.path_mtu {
                return Err(invalid("requested raw complete record/MTU geometry"));
            }
            Self::construct_physical_selected(
                security::ConfigDigest(requested.0),
                role,
                resources[index],
                covers[index],
                false,
                envelope,
                catalog.clone(),
                settings,
                0,
                None,
                physical,
                None,
                catalog.initial().duplex(),
                selection,
            )?;
        }
        Ok(())
    }
    /// Base pre-TLS policy commitment retained inside the complete current request.
    /// This cannot select a final record format or grant TLS/raw/Noise authority.
    #[allow(clippy::too_many_arguments)]
    fn raw_requested_base_configuration(
        base_policy: security::ConfigDigest,
        base_envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
    ) -> io::Result<core::ConfigDigest> {
        let native = maximum_native(catalog)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/raw-common/requested/v1\0");
        hash.update(&base_policy.0);
        hash.update(base_envelope.as_bytes());
        hash.update(catalog.root().as_bytes());
        for resource in resources {
            settings.validate(resource)?;
            hash.update(&resource.common_resource_digest(native)?.0);
        }
        bind_covers(&mut hash, covers)?;
        bind_settings(&mut hash, settings)?;
        Ok(core::ConfigDigest(finish(hash)))
    }

    /// Complete pre-TLS request. The base commitment binds both resource inventories;
    /// the final domain additionally binds the carrier layout and data suite.
    #[allow(clippy::too_many_arguments)]
    pub fn raw_requested_configuration_compact(
        base_policy: security::ConfigDigest,
        base_envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        selection: record::compact::Selection,
    ) -> io::Result<core::ConfigDigest> {
        selection.validate().map_err(invalid)?;
        if resources[0].security != resources[1].security {
            return Err(invalid(
                "compact raw peers require matching security owner limits",
            ));
        }
        let original = Self::raw_requested_base_configuration(
            base_policy,
            base_envelope,
            catalog,
            resources,
            covers,
            settings,
        )?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/raw-common/compact-carrier-requested/v2\0");
        hash.update(&original.0);
        hash.update(b"l2tunnel/records/carrier-layout/raw-tcp-aad/v1\0");
        hash.update(&[match selection.protection {
            security::compact::Protection::Aes128Ccm4 => 1,
            security::compact::Protection::ChaCha20Crc32c => 2,
            security::compact::Protection::ChaCha20Poly1305 => 3,
            security::compact::Protection::HmacSha256 => 4,
        }]);
        hash.update(&selection.limits.max_forward_packets.to_be_bytes());
        hash.update(&selection.limits.max_failed_checks.to_be_bytes());
        Ok(core::ConfigDigest(finish(hash)))
    }
    /// Bind selected single-protection final Records to the genuine raw owner.
    /// Bootstrap capacity and identity still come from its completed TLS/member
    /// proof; runtime must activate the final framing on that same owner.
    #[allow(clippy::too_many_arguments)]
    pub fn new_on_raw_paired_compact(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedRaw,
        selection: record::compact::Selection,
    ) -> io::Result<Self> {
        if outer.duplex() != catalog.initial().duplex() {
            return Err(invalid("Common duplex differs from the actual raw pair"));
        }
        let expected_role = match role {
            security::Role::Initiator => l2tunnel_handshake::Role::Initiator,
            security::Role::Responder => l2tunnel_handshake::Role::Responder,
        };
        if outer.role() != expected_role {
            return Err(invalid("raw proof has another actual role"));
        }
        let requested = Self::raw_requested_configuration_compact(
            base_policy,
            base_envelope,
            &catalog,
            resources,
            covers,
            settings,
            selection,
        )?;
        if outer
            .policy()
            .configuration_digest(requested)
            .map_err(invalid)?
            != outer.policy_digest()
        {
            return Err(invalid(
                "actual original raw TLS policy did not bind complete Common request",
            ));
        }
        let geometry = outer.geometry();
        let physical = outer
            .policy()
            .final_record_geometry()
            .map_err(invalid)?
            .ip_tcp_bytes;
        let descriptor = catalog.initial();
        let layer = match descriptor
            .direction(mg::Role::Client)
            .common()
            .traffic()
            .layer
        {
            core::traffic::NetworkLayer::Tap => PacketLayer::Ethernet,
            core::traffic::NetworkLayer::Tun => PacketLayer::Ip,
        };
        if outer.info().config.layer != layer || descriptor.path_mtu() != geometry.path_mtu {
            return Err(invalid(
                "actual raw native layer/MTU differs from Common request",
            ));
        }
        for index in 0..2 {
            establish::raw_carrier::validate_cover_geometry(covers[index], outer.policy())
                .map_err(invalid)?;
            if resources[index].path_mtu != geometry.path_mtu {
                return Err(invalid(
                    "raw Common resources exceed actual complete record geometry",
                ));
            }
        }
        let mut envelope = digest::Context::new(&digest::SHA256);
        envelope.update(b"l2tunnel/raw-common/compact-carrier-envelope/v2\0");
        envelope.update(base_envelope.as_bytes());
        envelope.update(&requested.0);
        envelope.update(catalog.root().as_bytes());
        envelope.update(&outer.binding());
        let envelope = common::EnvelopeDigest::new(finish(envelope));
        let initial = common::Configuration::new(envelope, descriptor).map_err(invalid)?;
        let mut bytes = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut bytes).map_err(invalid)?;
        let mut setup = digest::Context::new(&digest::SHA256);
        setup.update(b"l2tunnel/raw-common/compact-carrier-setup/v2\0");
        setup.update(&requested.0);
        setup.update(envelope.as_bytes());
        setup.update(&bytes);
        setup.update(catalog.root().as_bytes());
        setup.update(&outer.binding());
        let expected = security::ConfigDigest(finish(setup));
        let local = match role {
            security::Role::Initiator => 0,
            security::Role::Responder => 1,
        };
        let peer_role = if local == 0 {
            security::Role::Responder
        } else {
            security::Role::Initiator
        };
        // Full peer preflight is validation only, never a counterfeit opposite-role proof.
        Self::construct_physical_selected(
            expected,
            peer_role,
            resources[1 - local],
            covers[1 - local],
            false,
            envelope,
            catalog.clone(),
            settings,
            0,
            None,
            physical,
            None,
            outer.duplex(),
            selection,
        )?;
        Self::construct_physical_selected(
            expected,
            role,
            resources[local],
            covers[local],
            false,
            envelope,
            catalog,
            settings,
            0,
            None,
            physical,
            Some(outer),
            outer.duplex(),
            selection,
        )
    }
    /// Require this exact genuine raw handoff proof. Public observations alone
    /// cannot create the RawInitialParts needed by the consuming runtime entry.
    pub fn validate_raw(&self, actual: AuthenticatedRaw) -> io::Result<()> {
        if self.raw != Some(actual) || self.outer.is_some() {
            return Err(invalid(
                "actual raw outer differs from selected Common contract",
            ));
        }
        Ok(())
    }
}
pub(super) fn maximum_native(catalog: &common::Catalog) -> io::Result<usize> {
    [mg::Role::Client, mg::Role::Server]
        .into_iter()
        .map(|role| catalog.initial().direction(role).max_native())
        .max()
        .ok_or_else(|| invalid("raw Common native policy absent"))
}
pub(super) fn bind_covers(
    hash: &mut digest::Context,
    covers: [cover::Config; 2],
) -> io::Result<()> {
    for (index, config) in covers.into_iter().enumerate() {
        hash.update(&[match config.appearance() {
            cover::Appearance::QuicLike => 1,
            cover::Appearance::MediaLike => 2,
        }]);
        for n in [
            config.limits().max_packet_bytes,
            config.limits().max_protected_bytes,
        ] {
            hash.update(&(n as u64).to_be_bytes());
        }
        for phase in [cover::Phase::Handshake, cover::Phase::Established] {
            let mut bytes = [0; 64];
            let length = config
                .encode(
                    cover::PacketMeta {
                        phase,
                        packet_number: cover::PacketNumber(0),
                        media_timestamp: cover::MediaTimestamp(0),
                    },
                    &[0],
                    &mut bytes,
                )
                .map_err(invalid)?;
            covers[1 - index]
                .decode(&bytes[..length])
                .map_err(invalid)?;
            hash.update(&(length as u64).to_be_bytes());
            hash.update(&bytes[..length]);
        }
    }
    Ok(())
}
pub(super) fn bind_settings(
    hash: &mut digest::Context,
    settings: TransactionSettings,
) -> io::Result<()> {
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
pub(super) fn finish(hash: digest::Context) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}
