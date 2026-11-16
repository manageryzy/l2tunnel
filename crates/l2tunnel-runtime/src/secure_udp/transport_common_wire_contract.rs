//! Establishment-bound compact UDP selection; legacy contracts keep their bytes.
use super::*;

impl CommonTransactionContract {
    /// Select the compact final record wire before the actual Noise handshake.
    /// The returned H0 must be supplied to establishment; a copied public Info
    /// cannot install it. Both complete endpoint inventories and the full catalog
    /// are bound in initiator/responder order. Each supported record owner uses
    /// the selected encoding on the original UDP socket, including staged owners.
    #[allow(clippy::too_many_arguments)]
    pub fn new_compact_wire(
        base_policy: security::ConfigDigest,
        role: security::Role,
        resources: [Config; 2],
        cover: cover::Config,
        ipv6: bool,
        envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        selection: record::compact::Selection,
    ) -> io::Result<Self> {
        selection.validate().map_err(invalid)?;
        if resources[0].security != resources[1].security {
            return Err(invalid(
                "compact peers require matching security owner limits",
            ));
        }
        let native = [mg::Role::Client, mg::Role::Server]
            .into_iter()
            .map(|sender| catalog.initial().direction(sender).max_native())
            .max()
            .ok_or_else(|| invalid("compact native geometry"))?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/common-compact-wire/v1\0");
        hash.update(&base_policy.0);
        hash.update(envelope.as_bytes());
        hash.update(catalog.root().as_bytes());
        let initial = common::Configuration::new(envelope, catalog.initial()).map_err(invalid)?;
        hash.update(
            &transaction::configuration_digest(&initial)
                .map_err(invalid)?
                .0,
        );
        for local in resources {
            settings.validate(local)?;
            hash.update(&local.common_resource_digest(native)?.0);
        }
        hash.update(&[match selection.protection {
            security::compact::Protection::Aes128Ccm4 => 1,
            security::compact::Protection::ChaCha20Crc32c => 2,
            security::compact::Protection::ChaCha20Poly1305 => {
                return Err(invalid("compact data check"));
            }
        }]);
        hash.update(&selection.limits.max_forward_packets.to_be_bytes());
        hash.update(&selection.limits.max_failed_checks.to_be_bytes());
        hash.update(&[
            u8::from(ipv6),
            match cover.appearance() {
                cover::Appearance::QuicLike => 1,
                cover::Appearance::MediaLike => 2,
            },
        ]);
        for value in [
            cover.limits().max_packet_bytes,
            cover.limits().max_protected_bytes,
            settings.retained_bytes,
        ] {
            hash.update(&u64::try_from(value).map_err(invalid)?.to_be_bytes());
        }
        for value in [
            settings.protocol.retry_ms,
            settings.protocol.phase_timeout_ms,
            settings.protocol.reconcile_timeout_ms,
            settings.max_operation_ms,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let mut expected = [0; 32];
        expected.copy_from_slice(hash.finish().as_ref());
        let physical = if ipv6 { 48 } else { 28 };
        let make = |role, local| {
            Self::construct_physical_selected(
                security::ConfigDigest(expected),
                role,
                local,
                cover,
                ipv6,
                envelope,
                catalog.clone(),
                settings,
                None,
                0,
                None,
                physical,
                None,
                core::Duplex::Full,
                Some(selection),
            )
        };
        // Validate the actual opposite endpoint inventory without assigning it
        // any material or socket. Only the selected local contract is returned.
        let (local, peer, peer_role) = match role {
            security::Role::Initiator => (resources[0], resources[1], security::Role::Responder),
            security::Role::Responder => (resources[1], resources[0], security::Role::Initiator),
        };
        make(peer_role, peer)?;
        make(role, local)
    }

    /// Exact explicit final-wire selection; absence retains legacy framing.
    pub fn compact_wire(&self) -> Option<record::compact::Selection> {
        self.compact_wire
    }

    pub(crate) fn feedback_overhead_bytes(&self) -> io::Result<usize> {
        if self.compact_wire.is_some() {
            self.physical_overhead_bytes()?
                .checked_add(record::compact::AUTHENTICATED_OVERHEAD)
                .ok_or_else(exhausted)
        } else {
            Ok(self.geometry.forward_overhead_bytes)
        }
    }
}
