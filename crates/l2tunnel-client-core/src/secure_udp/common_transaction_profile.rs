//! Explicit common record selection authenticated by the existing same-socket factories.
use super::{Settings, establish, security};
use crate::{Compression, ConnectionConfig};
use l2tunnel::record_configuration::{Catalog, Configuration, EnvelopeDigest};
use l2tunnel_core::{ConfigDigest, Duplex, traffic::NetworkLayer};
use l2tunnel_device::PacketLayer;
use l2tunnel_management::{Role, transaction};
use l2tunnel_runtime::secure_udp::transport;
use ring::digest;
use std::io;

/// Complete common plan; settings() uses the maintained admission/Noise/member factories.
#[derive(Clone, Debug)]
pub struct Profile {
    connection: ConnectionConfig,
    peers: establish::Peers,
    settings: Settings,
    initiator: transport::Config,
    responder: transport::Config,
    catalog: Catalog,
    parameters: transport::TransactionSettings,
    envelope: EnvelopeDigest,
    initial: Configuration,
    data: ConfigDigest,
}
impl Profile {
    /// Bind every common descriptor and actual shared resource to retained own trust.
    /// Swift fields in the explicit resource templates are inactive in this selection.
    pub fn new(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: transport::TransactionSettings,
    ) -> io::Result<Self> {
        let base = connection.session()?;
        if connection.duplex != Duplex::Full
            || connection.compression != Compression::None
            || catalog.initial().duplex() != Duplex::Full
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "common runtime requires full duplex and no outer compression",
            ));
        }
        let initial = catalog.initial();
        let native = [Role::Client, Role::Server]
            .into_iter()
            .map(|role| initial.direction(role).max_native())
            .max()
            .ok_or_else(|| invalid("empty common native directions"))?;
        let layer = match connection.layer {
            PacketLayer::Ethernet => NetworkLayer::Tap,
            PacketLayer::Ip => NetworkLayer::Tun,
        };
        if connection.max_packet != native {
            return Err(invalid("common native maximum differs from attachment"));
        }
        for descriptor in catalog.descriptors() {
            for role in [Role::Client, Role::Server] {
                let direction = descriptor.direction(role);
                let original = initial.direction(role);
                if direction.common().traffic().layer != layer
                    || direction.max_native() != original.max_native()
                    || descriptor.duplex() != Duplex::Full
                {
                    return Err(invalid(
                        "common catalog changes immutable attachment/duplex",
                    ));
                }
            }
        }
        for resources in [initiator, responder] {
            resources.validate_common_resources(native)?;
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
        let result = Self {
            connection,
            peers,
            settings,
            initiator,
            responder,
            catalog,
            parameters,
            envelope,
            initial,
            data,
        };
        result.runtime_contract(security::Role::Initiator)?;
        result.runtime_contract(security::Role::Responder)?;
        Ok(result)
    }
    /// Exact shared native attachment contract.
    pub fn connection(&self) -> ConnectionConfig {
        self.connection
    }
    /// Retained ordered trusted Noise pins.
    pub fn peers(&self) -> establish::Peers {
        self.peers
    }
    /// Exact settings for existing real connect/Server authentication factories.
    pub fn settings(&self) -> Settings {
        self.settings
    }
    /// Complete transaction and combined-capacity requirements.
    pub fn parameters(&self) -> transport::TransactionSettings {
        self.parameters
    }
    /// Whole supported catalog, without pruning to fit storage.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    /// Immutable common envelope E, distinct from H0 and D0.
    pub fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Exact complete common C0.
    pub fn initial(&self) -> Configuration {
        self.initial
    }
    /// Real initial management configuration digest D0.
    pub fn data_digest(&self) -> ConfigDigest {
        self.data
    }
    /// Actual setup/Control digest consumed by the maintained authentication factories.
    pub fn configuration(&self) -> io::Result<security::ConfigDigest> {
        self.settings.configuration(self.peers)
    }
    /// Transfer the retained exact role resources/catalog with independently recomputed H0.
    pub fn runtime_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::CommonTransactionContract> {
        transport::CommonTransactionContract::new(
            self.configuration()?,
            role,
            if role == security::Role::Initiator {
                self.initiator
            } else {
                self.responder
            },
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            self.envelope,
            self.catalog.clone(),
            self.parameters,
        )
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
