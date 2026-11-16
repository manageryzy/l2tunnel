//! Explicit genuine raw outer binding with a pre-TLS requested-policy DAG.
use super::*;
use establish::raw_carrier::AuthenticatedRaw;

impl CommonTransactionContract {
    /// Validate a complete requested raw catalog/resources before opening originals.
    /// This pure check returns no contract, packet owner or authentication proof.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_raw_requested(
        base: security::ConfigDigest,
        envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        policy: l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy,
    ) -> io::Result<()> {
        Self::validate_raw_requested_selected(
            base, envelope, catalog, resources, covers, settings, policy, None,
        )
    }
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
        Self::validate_raw_requested_selected(
            base,
            envelope,
            catalog,
            resources,
            covers,
            settings,
            policy,
            Some(selection),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn validate_raw_requested_selected(
        base: security::ConfigDigest,
        envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        policy: l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy,
        selection: Option<record::compact::Selection>,
    ) -> io::Result<()> {
        let geometry = policy.record_geometry().map_err(invalid)?;
        let physical = if selection.is_some() {
            policy
                .final_record_geometry()
                .map_err(invalid)?
                .ip_tcp_bytes
        } else {
            geometry
                .ip_tcp_bytes
                .checked_add(geometry.record_overhead_bytes)
                .ok_or_else(exhausted)?
        };
        let requested = Self::raw_requested_selected(
            base, envelope, catalog, resources, covers, settings, selection,
        )?;
        for (index, role) in [security::Role::Initiator, security::Role::Responder]
            .into_iter()
            .enumerate()
        {
            if resources[index].path_mtu != geometry.path_mtu
                || covers[index].limits().max_packet_bytes > geometry.max_record_bytes
            {
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
                None,
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
    /// Pre-TLS original raw PairConfig.session.digest for this complete request.
    /// This is a public policy commitment, never TLS/raw/Noise authority.
    #[allow(clippy::too_many_arguments)]
    pub fn raw_requested_configuration(
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

    /// Complete pre-TLS compact request. The legacy commitment remains embedded
    /// unchanged; a distinct domain binds the final carrier layout and data suite.
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
        let original = Self::raw_requested_configuration(
            base_policy,
            base_envelope,
            catalog,
            resources,
            covers,
            settings,
        )?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/raw-common/compact-carrier-requested/v1\0");
        hash.update(&original.0);
        hash.update(b"l2tunnel/records/carrier-layout/raw-tcp-aad/v1\0");
        hash.update(&[match selection.protection {
            security::compact::Protection::Aes128Ccm4 => 1,
            security::compact::Protection::ChaCha20Crc32c => 2,
            security::compact::Protection::ChaCha20Poly1305 => {
                return Err(invalid("compact raw data check"));
            }
        }]);
        hash.update(&selection.limits.max_forward_packets.to_be_bytes());
        hash.update(&selection.limits.max_failed_checks.to_be_bytes());
        Ok(core::ConfigDigest(finish(hash)))
    }
    #[allow(clippy::too_many_arguments)]
    fn raw_requested_selected(
        base_policy: security::ConfigDigest,
        base_envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        selection: Option<record::compact::Selection>,
    ) -> io::Result<core::ConfigDigest> {
        match selection {
            Some(selection) => Self::raw_requested_configuration_compact(
                base_policy,
                base_envelope,
                catalog,
                resources,
                covers,
                settings,
                selection,
            ),
            None => Self::raw_requested_configuration(
                base_policy,
                base_envelope,
                catalog,
                resources,
                covers,
                settings,
            ),
        }
    }

    /// Bind both exact role policies to the genuine already completed raw owner.
    /// The complete requested catalog already uses its explicit raw geometry;
    /// this constructor never shrinks/rebases a descriptor or invents a TLS proof.
    #[allow(clippy::too_many_arguments)]
    pub fn new_on_raw_paired(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedRaw,
    ) -> io::Result<Self> {
        Self::new_on_raw_paired_selected(
            base_policy,
            role,
            resources,
            covers,
            base_envelope,
            catalog,
            settings,
            outer,
            None,
        )
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
        Self::new_on_raw_paired_selected(
            base_policy,
            role,
            resources,
            covers,
            base_envelope,
            catalog,
            settings,
            outer,
            Some(selection),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_on_raw_paired_selected(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: AuthenticatedRaw,
        selection: Option<record::compact::Selection>,
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
        let requested = Self::raw_requested_selected(
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
        let physical = if selection.is_some() {
            outer
                .policy()
                .final_record_geometry()
                .map_err(invalid)?
                .ip_tcp_bytes
        } else {
            geometry
                .ip_tcp_bytes
                .checked_add(geometry.record_overhead_bytes)
                .ok_or_else(exhausted)?
        };
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
            if resources[index].path_mtu != geometry.path_mtu
                || covers[index].limits().max_packet_bytes > geometry.max_record_bytes
            {
                return Err(invalid(
                    "raw Common resources exceed actual complete record geometry",
                ));
            }
        }
        let mut envelope = digest::Context::new(&digest::SHA256);
        if selection.is_some() {
            envelope.update(b"l2tunnel/raw-common/compact-carrier-envelope/v1\0");
        } else {
            envelope.update(b"l2tunnel/raw-common/envelope/v1\0");
        }
        envelope.update(base_envelope.as_bytes());
        envelope.update(&requested.0);
        envelope.update(catalog.root().as_bytes());
        envelope.update(&outer.binding());
        let envelope = common::EnvelopeDigest::new(finish(envelope));
        let initial = common::Configuration::new(envelope, descriptor).map_err(invalid)?;
        let mut bytes = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut bytes).map_err(invalid)?;
        let mut setup = digest::Context::new(&digest::SHA256);
        if selection.is_some() {
            setup.update(b"l2tunnel/raw-common/compact-carrier-setup/v1\0");
        } else {
            setup.update(b"l2tunnel/raw-common/setup/v1\0");
        }
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
            None,
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
            None,
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
        if self.raw != Some(actual) || self.outer.is_some() || self.managed.is_some() {
            return Err(invalid(
                "actual raw outer differs from selected Common contract",
            ));
        }
        Ok(())
    }
}
fn maximum_native(catalog: &common::Catalog) -> io::Result<usize> {
    [mg::Role::Client, mg::Role::Server]
        .into_iter()
        .map(|role| catalog.initial().direction(role).max_native())
        .max()
        .ok_or_else(|| invalid("raw Common native policy absent"))
}
fn bind_covers(hash: &mut digest::Context, covers: [cover::Config; 2]) -> io::Result<()> {
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
fn bind_settings(hash: &mut digest::Context, settings: TransactionSettings) -> io::Result<()> {
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
    let mut out = [0; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}
