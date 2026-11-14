//! Explicit checked configuration handoff, without session or allocation authority.

use super::{Config, TransactionSettings};
use l2tunnel::swift_configuration::{
    CONFIGURATION_BYTES, Catalog, Configuration, Descriptor, EnvelopeDigest,
};
use l2tunnel_core::ConfigDigest;
use l2tunnel_cover as cover;
use l2tunnel_management::{self as mg, transaction};
use l2tunnel_security as security;
use std::{io, time::Duration};

/// Complete local construction plan for the explicitly selected generic backend.
///
/// H0 is retained separately from the real management digest D0. The embedding
/// facade must derive H0 from its complete authenticated settings and own trust
/// configuration. This value supplies no root, memory reservation, peer proof,
/// device, clock or permission to publish runtime readiness.
#[derive(Clone, Debug)]
pub struct TransactionContract {
    expected_configuration: security::ConfigDigest,
    role: security::Role,
    config: Config,
    cover: cover::Config,
    ipv6: bool,
    envelope: EnvelopeDigest,
    catalog: Catalog,
    initial: Configuration,
    data_digest: ConfigDigest,
    settings: TransactionSettings,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl TransactionContract {
    /// Validate every complete supported value before handing it to the runtime.
    #[allow(clippy::too_many_arguments)] // Frozen handoff names each independent authenticated input.
    pub fn new(
        expected_configuration: security::ConfigDigest,
        role: security::Role,
        config: Config,
        cover: cover::Config,
        ipv6: bool,
        envelope: EnvelopeDigest,
        catalog: Catalog,
        settings: TransactionSettings,
    ) -> io::Result<Self> {
        config.validate()?;
        settings.validate(config)?;
        if config.streams.is_none() {
            return Err(invalid(
                "generic transaction handoff requires explicit streams",
            ));
        }
        let (forward, reverse) = match role {
            security::Role::Initiator => (config.send, config.receive),
            security::Role::Responder => (config.receive, config.send),
        };
        let actual =
            Descriptor::new(config.path_mtu, forward, reverse).map_err(io::Error::other)?;
        if actual != catalog.initial() {
            return Err(invalid("initial catalog and actual role template differ"));
        }
        let initial = Configuration::new(envelope, actual).map_err(io::Error::other)?;
        let data_digest = transaction::configuration_digest(&initial).map_err(io::Error::other)?;
        let result = Self {
            expected_configuration,
            role,
            config,
            cover,
            ipv6,
            envelope,
            catalog,
            initial,
            data_digest,
            settings,
        };
        for descriptor in result.catalog.descriptors() {
            result.resolve_descriptor(*descriptor)?;
        }
        result.validate_control_capacity()?;
        Ok(result)
    }

    /// Exact expected Noise/member setup and immutable Control digest H0.
    pub fn expected_configuration(&self) -> security::ConfigDigest {
        self.expected_configuration
    }
    /// Explicit local security role; the actual session must match it.
    pub fn role(&self) -> security::Role {
        self.role
    }
    /// Exact initial local runtime template, including local report cadence.
    pub fn config(&self) -> Config {
        self.config
    }
    /// Exact role-local selected appearance and capacity contract.
    pub fn cover(&self) -> cover::Config {
        self.cover
    }
    /// Explicit IP-family geometry, to be checked against the actual socket.
    pub fn ipv6(&self) -> bool {
        self.ipv6
    }
    /// Full role-independent immutable envelope E.
    pub fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Entire exact finite catalog; it is never pruned to satisfy resources.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    /// Complete canonical initial User configuration C0.
    pub fn initial(&self) -> Configuration {
        self.initial
    }
    /// Real management digest of C0, distinct from the retained setup digest.
    pub fn data_digest(&self) -> ConfigDigest {
        self.data_digest
    }
    /// Exact shared generic transaction and combined-retention requirements.
    pub fn settings(&self) -> TransactionSettings {
        self.settings
    }

    /// Resolve only an exact supported complete C without rounding any field.
    pub fn resolve(&self, value: Configuration) -> io::Result<Config> {
        if value.envelope() != self.envelope
            || !self.catalog.descriptors().contains(&value.descriptor())
        {
            return Err(invalid(
                "configuration is outside the exact envelope/catalog",
            ));
        }
        self.resolve_descriptor(value.descriptor())
    }

    fn resolve_descriptor(&self, descriptor: Descriptor) -> io::Result<Config> {
        let (local, remote) = match self.role {
            security::Role::Initiator => (mg::Role::Client, mg::Role::Server),
            security::Role::Responder => (mg::Role::Server, mg::Role::Client),
        };
        let mut resolved = self.config;
        resolved.path_mtu = descriptor.path_mtu();
        resolved.send = descriptor.direction(local);
        resolved.receive = descriptor.direction(remote);
        if let Some(streams) = &mut resolved.streams {
            for stream in &mut streams.streams {
                stream.path_mtu = resolved.path_mtu;
            }
        }
        if resolved.immutable_contract_digest()? != self.config.immutable_contract_digest()? {
            return Err(invalid(
                "catalog changes immutable native/resource geometry",
            ));
        }
        resolved.validate_cover(self.cover, self.ipv6)?;
        Ok(resolved)
    }

    fn validate_control_capacity(&self) -> io::Result<()> {
        let maximum = |role| {
            self.catalog
                .descriptors()
                .iter()
                .map(|value| value.direction(role).records.channels)
                .max()
                .ok_or_else(|| invalid("empty transaction catalog"))
        };
        let prepare = maximum(mg::Role::Client)?
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(2 + CONFIGURATION_BYTES))
            .ok_or_else(|| invalid("PREPARE fields overflow"))?;
        let ready = maximum(mg::Role::Server)?
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or_else(|| invalid("READY fields overflow"))?;
        let message = prepare
            .max(ready)
            .checked_add(8)
            .and_then(|bytes| bytes.checked_add(mg::HEADER_LEN))
            .and_then(|bytes| bytes.checked_add(mg::session_control::HEADER_BYTES))
            .ok_or_else(|| invalid("complete transaction envelope overflow"))?;
        let selected = self
            .config
            .streams
            .ok_or_else(|| invalid("missing transaction stream"))?
            .streams[0];
        if selected.max_message_bytes < message {
            return Err(invalid(
                "transaction stream cannot carry complete catalog fences",
            ));
        }
        let binding = mg::control_streams::delivery_binding(
            mg::delivery::Binding {
                session: mg::SessionId([1; 16]),
                lane: mg::LaneId(0),
                local_role: match self.role {
                    security::Role::Initiator => mg::Role::Client,
                    security::Role::Responder => mg::Role::Server,
                },
                control_epoch: self.config.control_epoch.0,
            },
            mg::control_streams::Stream::Transaction,
        )
        .map_err(io::Error::other)?;
        // Exercise actual original+fragment custody rather than treating a scalar
        // bound as a reservation. This temporary owner is not a running session.
        let mut probe = mg::messages::Owner::new(
            selected,
            binding,
            Duration::ZERO,
            self.config.lifetime.lease,
        )
        .map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(message).map_err(io::Error::other)?;
        bytes.resize(message, 0);
        probe
            .submit(
                mg::messages::SubmissionId(1),
                &bytes,
                Duration::ZERO,
                selected.message_lifetime.min(self.config.lifetime.lease),
            )
            .map_err(|_| invalid("transaction storage cannot retain complete catalog fences"))?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "transport_contract_tests.rs"]
mod tests;
