//! Complete pre-authentication policy and actual maintained-connection binding.
use super::*;
use crate::secure_udp::maintained::{Authenticated, Request};

impl CommonTransactionContract {
    /// Complete initial-only Common selection authenticated by TLS/QUIC before
    /// handing its original connection(s) to the existing inner Noise protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn maintained_requested_configuration_compact(
        base: security::ConfigDigest,
        envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        request: Request,
        selection: record::compact::Selection,
    ) -> io::Result<core::ConfigDigest> {
        require_near8_socket_receipts(catalog)?;
        request.validate()?;
        selection.validate().map_err(invalid)?;
        if resources[0].security != resources[1].security
            || catalog.initial().duplex() != request.duplex
        {
            return Err(invalid("maintained Common security or duplex differs"));
        }
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/common-maintained/compact-requested/v2\0");
        hash.update(&base.0);
        hash.update(envelope.as_bytes());
        hash.update(catalog.root().as_bytes());
        hash.update(&request.digest()?.0);
        let native = raw::maximum_native(catalog)?;
        for resource in resources {
            settings.validate(resource)?;
            hash.update(&resource.common_resource_digest(native)?.0);
        }
        raw::bind_covers(&mut hash, covers)?;
        raw::bind_settings(&mut hash, settings)?;
        hash.update(&[match selection.protection {
            security::compact::Protection::Aes128Ccm4 => 1,
            security::compact::Protection::ChaCha20Crc32c => 2,
            security::compact::Protection::ChaCha20Poly1305 => 3,
            security::compact::Protection::HmacSha256 => 4,
        }]);
        hash.update(&selection.limits.max_forward_packets.to_be_bytes());
        hash.update(&selection.limits.max_failed_checks.to_be_bytes());
        Ok(core::ConfigDigest(raw::finish(hash)))
    }

    /// Pure full-catalog admission before opening any maintained connection.
    /// Configured overhead is never substituted for measured wire bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_maintained_requested_compact(
        base: security::ConfigDigest,
        envelope: common::EnvelopeDigest,
        catalog: &common::Catalog,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        settings: TransactionSettings,
        request: Request,
        selection: record::compact::Selection,
    ) -> io::Result<()> {
        let requested = Self::maintained_requested_configuration_compact(
            base, envelope, catalog, resources, covers, settings, request, selection,
        )?;
        for (index, role) in [security::Role::Initiator, security::Role::Responder]
            .into_iter()
            .enumerate()
        {
            let geometry = request.geometry;
            if resources[index].path_mtu != geometry.path_mtu
                || covers[index].limits().max_packet_bytes > geometry.max_record_bytes
                || resources[index]
                    .security
                    .max_body_bytes
                    .checked_add(selection.maximum_overhead())
                    .is_none_or(|maximum| maximum > geometry.max_record_bytes)
            {
                return Err(invalid("maintained requested record/bootstrap geometry"));
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
                geometry.charged_overhead_bytes,
                None,
                request.duplex,
                selection,
            )?;
        }
        Ok(())
    }

    /// Bind the unchanged complete catalog to genuine retained Full/Half owners.
    /// Both the pre-TLS Common request and actual fresh lane evidence are checked.
    #[allow(clippy::too_many_arguments)]
    pub fn new_on_maintained_paired_compact(
        base: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        covers: [cover::Config; 2],
        base_envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        outer: Authenticated,
        selection: record::compact::Selection,
    ) -> io::Result<Self> {
        let request = outer.requested();
        Self::validate_maintained_requested_compact(
            base,
            base_envelope,
            &catalog,
            resources,
            covers,
            settings,
            request,
            selection,
        )?;
        let requested = Self::maintained_requested_configuration_compact(
            base,
            base_envelope,
            &catalog,
            resources,
            covers,
            settings,
            request,
            selection,
        )?;
        let info = outer.info()?;
        let actual_role = if info.peer_member.is_none() {
            security::Role::Initiator
        } else {
            security::Role::Responder
        };
        let layer = match catalog
            .initial()
            .direction(mg::Role::Client)
            .common()
            .traffic()
            .layer
        {
            core::traffic::NetworkLayer::Tap => PacketLayer::Ethernet,
            core::traffic::NetworkLayer::Tun => PacketLayer::Ip,
        };
        if role != actual_role
            || outer.common_configuration()
                != (l2tunnel_auth::SessionConfig {
                    layer,
                    digest: requested,
                })
            || info.config.layer != layer
        {
            return Err(invalid(
                "actual maintained authentication did not bind complete Common request",
            ));
        }
        let mut envelope = digest::Context::new(&digest::SHA256);
        envelope.update(b"l2tunnel/common-maintained/compact-envelope/v1\0");
        envelope.update(base_envelope.as_bytes());
        envelope.update(&requested.0);
        envelope.update(catalog.root().as_bytes());
        envelope.update(&outer.binding());
        let envelope = common::EnvelopeDigest::new(raw::finish(envelope));
        let initial = common::Configuration::new(envelope, catalog.initial()).map_err(invalid)?;
        let mut bytes = [0; common::CONFIGURATION_BYTES];
        initial.encode_into(&mut bytes).map_err(invalid)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/common-maintained/compact-setup/v1\0");
        hash.update(&requested.0);
        hash.update(envelope.as_bytes());
        hash.update(&bytes);
        hash.update(catalog.root().as_bytes());
        hash.update(&outer.binding());
        let expected = security::ConfigDigest(raw::finish(hash));
        let local = usize::from(role == security::Role::Responder);
        let ipv6 = outer.endpoints()?.0.is_ipv6();
        let mut result = None;
        for (index, candidate_role) in [security::Role::Initiator, security::Role::Responder]
            .into_iter()
            .enumerate()
        {
            let candidate = Self::construct_physical_selected(
                expected,
                candidate_role,
                resources[index],
                covers[index],
                ipv6,
                envelope,
                catalog.clone(),
                settings,
                0,
                None,
                request.geometry.charged_overhead_bytes,
                None,
                request.duplex,
                selection,
            )?;
            if index == local {
                result = Some(candidate);
            }
        }
        let mut result = result.ok_or_else(|| invalid("maintained role"))?;
        result.maintained = Some(outer);
        Ok(result)
    }

    /// Actual opaque maintained proof. It cannot reconstruct the connection owner.
    pub fn maintained_outer(&self) -> Option<Authenticated> {
        self.maintained
    }

    /// Require the exact owner proof consumed by the selected runtime handoff.
    pub fn validate_maintained(&self, actual: Authenticated) -> io::Result<()> {
        if self.maintained != Some(actual) || self.raw.is_some() || self.outer.is_some() {
            return Err(invalid(
                "actual maintained owner differs from Common contract",
            ));
        }
        Ok(())
    }
}
