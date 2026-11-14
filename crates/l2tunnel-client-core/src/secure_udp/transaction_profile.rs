//! Complete authenticated plans for the explicitly selected generic transaction path.
//!
//! Construction validates configuration and trust binding without allocating
//! prepared engines, attaching a device or claiming runtime admission. The
//! actual driver must enforce the retained-byte ceiling before staging.

use super::{Settings, establish, security};
use crate::{Compression, ConnectionConfig};
use l2tunnel::swift_configuration::{Catalog, Configuration, Descriptor, EnvelopeDigest};
use l2tunnel_core::{ConfigDigest, Duplex};
use l2tunnel_device::PacketLayer;
use l2tunnel_management::{self as mg, transaction};
use l2tunnel_runtime::secure_udp::transport;
use l2tunnel_swift::records;
use ring::digest;
use std::io;
use std::time::Duration;

/// Shared immutable runtime contract; field encoding and client call syntax are unchanged.
pub use transport::TransactionSettings as Parameters;

/// Immutable complete catalog and authenticated setup/data digest construction.
#[derive(Clone, Debug)]
pub struct Profile {
    connection: ConnectionConfig,
    peers: establish::Peers,
    settings: Settings,
    initiator: transport::Config,
    responder: transport::Config,
    catalog: Catalog,
    parameters: Parameters,
    envelope: EnvelopeDigest,
    initial: Configuration,
    data: ConfigDigest,
}
impl Profile {
    /// Validate every supported value under both actual role templates before I/O.
    /// This creates a plan, not prepared-engine storage or a running connection.
    pub fn new(
        connection: ConnectionConfig,
        mut settings: Settings,
        peers: establish::Peers,
        initiator: transport::Config,
        responder: transport::Config,
        catalog: Catalog,
        parameters: Parameters,
    ) -> io::Result<Self> {
        let base = connection.session()?;
        if connection.duplex != Duplex::Full || connection.compression != Compression::None {
            return Err(invalid(
                "generic Swift plan requires full duplex and no compression",
            ));
        }
        initiator.validate()?;
        responder.validate()?;
        parameters.validate(initiator)?;
        parameters.validate(responder)?;
        if initiator.streams.is_none() || responder.streams.is_none() {
            return Err(invalid(
                "generic transaction plan requires explicit control streams",
            ));
        }
        if initiator.send != responder.receive || initiator.receive != responder.send {
            return Err(invalid("generic global directions are not complementary"));
        }
        let mut aligned = responder;
        aligned.send = initiator.send;
        aligned.receive = initiator.receive;
        aligned.wire.burst_bytes = initiator.wire.burst_bytes;
        if aligned.immutable_contract_digest()? != initiator.immutable_contract_digest()? {
            return Err(invalid("generic role templates differ in fixed resources"));
        }
        let actual = Descriptor::new(initiator.path_mtu, initiator.send, initiator.receive)
            .map_err(io::Error::other)?;
        if catalog.initial() != actual || initiator.path_mtu != responder.path_mtu {
            return Err(invalid(
                "catalog initial differs from actual role configuration",
            ));
        }
        let maximum_client = catalog
            .descriptors()
            .iter()
            .map(|value| value.forward().records.channels)
            .max()
            .ok_or_else(|| invalid("empty authenticated transaction catalog"))?;
        let maximum_server = catalog
            .descriptors()
            .iter()
            .map(|value| value.reverse().records.channels)
            .max()
            .ok_or_else(|| invalid("empty authenticated transaction catalog"))?;
        let prepare_fields = maximum_client
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(2))
            .and_then(|bytes| bytes.checked_add(l2tunnel::swift_configuration::CONFIGURATION_BYTES))
            .ok_or_else(|| invalid("complete PREPARE field size overflow"))?;
        let ready_fields = maximum_server
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or_else(|| invalid("complete READY field size overflow"))?;
        let prepare_bytes = prepare_fields
            .max(ready_fields)
            // Every actual management message includes its response-to prefix,
            // including an original PREPARE whose value is zero.
            .checked_add(8)
            .and_then(|bytes| bytes.checked_add(mg::HEADER_LEN))
            .and_then(|bytes| bytes.checked_add(mg::session_control::HEADER_BYTES))
            .ok_or_else(|| invalid("complete transaction envelope size overflow"))?;
        for template in [initiator, responder] {
            let streams = template
                .streams
                .ok_or_else(|| invalid("missing transaction stream"))?;
            if streams.streams[0].max_message_bytes < prepare_bytes {
                return Err(invalid(
                    "transaction stream cannot carry the complete catalog fence",
                ));
            }
            // Use the actual whole-message owner to check original plus fragment
            // custody. Its scalar validation permits intentionally tiny budgets,
            // which cannot qualify an always-admissible construction plan.
            let binding = mg::control_streams::delivery_binding(
                mg::delivery::Binding {
                    session: mg::SessionId([1; 16]),
                    lane: mg::LaneId(0),
                    local_role: mg::Role::Client,
                    control_epoch: template.control_epoch.0,
                },
                mg::control_streams::Stream::Transaction,
            )
            .map_err(io::Error::other)?;
            let selected = streams.streams[0];
            let mut probe = mg::messages::Owner::new(
                selected,
                binding,
                Duration::ZERO,
                template.lifetime.lease,
            )
            .map_err(io::Error::other)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(prepare_bytes)
                .map_err(io::Error::other)?;
            bytes.resize(prepare_bytes, 0);
            probe
                .submit(
                    mg::messages::SubmissionId(1),
                    &bytes,
                    Duration::ZERO,
                    selected.message_lifetime.min(template.lifetime.lease),
                )
                .map_err(|_| {
                    invalid("transaction storage cannot admit a complete catalog fence")
                })?;
        }
        for descriptor in catalog.descriptors() {
            for (role, template) in [
                (security::Role::Initiator, initiator),
                (security::Role::Responder, responder),
            ] {
                validate_runtime(connection, settings, role, template, *descriptor)?;
            }
        }
        // Hash the original complete public settings before deriving application
        // or H0. Catalog descriptors are anchor-free, so this graph is acyclic.
        let seed = settings.application;
        let original = settings.configuration(peers)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/shared-client/generic-swift-envelope/v1\0");
        hash.update(&original.0);
        hash.update(&base.digest.0);
        hash.update(&connection.handshake_timeout.as_nanos().to_be_bytes());
        hash.update(&initiator.immutable_contract_digest()?.0);
        hash.update(&responder.immutable_contract_digest()?.0);
        hash.update(catalog.root().as_bytes());
        for value in [
            parameters.protocol.retry_ms,
            parameters.protocol.phase_timeout_ms,
            parameters.protocol.reconcile_timeout_ms,
            parameters.max_operation_ms,
            u64::try_from(parameters.retained_bytes).map_err(io::Error::other)?,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let envelope = EnvelopeDigest::new(super::finish(hash));
        let initial = Configuration::new(envelope, catalog.initial()).map_err(io::Error::other)?;
        let data = transaction::configuration_digest(&initial).map_err(io::Error::other)?;
        let mut selection = digest::Context::new(&digest::SHA256);
        selection.update(b"l2tunnel/shared-client/generic-swift-selection/v1\0");
        selection.update(&seed.0);
        selection.update(envelope.as_bytes());
        selection.update(catalog.root().as_bytes());
        selection.update(&data.0);
        settings.application = ConfigDigest(super::finish(selection));
        // Validate the exact final contract used by the existing authentication factories.
        settings.configuration(peers)?;
        Ok(Self {
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
        })
    }
    /// Original native connection/attachment contract.
    pub fn connection(&self) -> ConnectionConfig {
        self.connection
    }
    /// Retained trusted fixed-peer pins used to construct this exact plan.
    pub fn peers(&self) -> establish::Peers {
        self.peers
    }
    /// Settings actually authenticated by the existing original-socket factories.
    pub fn settings(&self) -> Settings {
        self.settings
    }
    /// Complete immutable transaction and combined retention requirements.
    pub fn parameters(&self) -> Parameters {
        self.parameters
    }
    /// Exact finite supported catalog; this is not an arbitrary-policy resolver.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    /// Complete role-independent immutable envelope, before the H0 construction.
    pub fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Initial complete User configuration whose management digest is D0.
    pub fn initial(&self) -> Configuration {
        self.initial
    }
    /// Explicit initial User digest D0, separate from the setup/Control digest H0.
    pub fn data_digest(&self) -> ConfigDigest {
        self.data
    }
    /// Final setup/Control digest H0, with the retained trusted public pins.
    pub fn configuration(&self) -> io::Result<security::ConfigDigest> {
        self.settings.configuration(self.peers)
    }
    /// Recompute the actual setup digest from retained own trust and hand off
    /// the exact complete local role contract. This reserves no runtime storage.
    pub fn runtime_contract(
        &self,
        role: security::Role,
    ) -> io::Result<transport::TransactionContract> {
        transport::TransactionContract::new(
            self.configuration()?,
            role,
            match role {
                security::Role::Initiator => self.initiator,
                security::Role::Responder => self.responder,
            },
            self.settings.cover.config(role)?,
            self.settings.gate.path.client.is_ipv6(),
            self.envelope,
            self.catalog.clone(),
            self.parameters,
        )
    }
    /// Resolve only an exact supported complete value under this envelope.
    /// Actual multi-epoch allocation admission remains the driver's responsibility.
    pub fn runtime_for(
        &self,
        configuration: Configuration,
        role: security::Role,
    ) -> io::Result<transport::Config> {
        if configuration.envelope() != self.envelope
            || !self
                .catalog
                .descriptors()
                .contains(&configuration.descriptor())
        {
            return Err(invalid(
                "configuration is outside the authenticated exact catalog",
            ));
        }
        validate_runtime(
            self.connection,
            self.settings,
            role,
            match role {
                security::Role::Initiator => self.initiator,
                security::Role::Responder => self.responder,
            },
            configuration.descriptor(),
        )
    }
}

fn validate_runtime(
    connection: ConnectionConfig,
    session: Settings,
    role: security::Role,
    template: transport::Config,
    descriptor: Descriptor,
) -> io::Result<transport::Config> {
    let global = match role {
        security::Role::Initiator => mg::Role::Client,
        security::Role::Responder => mg::Role::Server,
    };
    let remote = match global {
        mg::Role::Client => mg::Role::Server,
        mg::Role::Server => mg::Role::Client,
    };
    let mut runtime = template;
    runtime.path_mtu = descriptor.path_mtu();
    runtime.send = descriptor.direction(global);
    runtime.receive = descriptor.direction(remote);
    if let Some(streams) = &mut runtime.streams {
        for stream in &mut streams.streams {
            stream.path_mtu = runtime.path_mtu;
        }
    }
    let layer = match connection.layer {
        PacketLayer::Ethernet => records::Layer::Ethernet,
        PacketLayer::Ip => records::Layer::Ip,
    };
    for direction in [runtime.send, runtime.receive] {
        if direction.records.layer != layer || direction.records.max_native != connection.max_packet
        {
            return Err(invalid(
                "catalog native format differs from the fixed attachment",
            ));
        }
    }
    if runtime.immutable_contract_digest()? != template.immutable_contract_digest()? {
        return Err(invalid(
            "catalog value changes fixed native/resource constraints",
        ));
    }
    runtime.validate_cover(
        session.cover.config(role)?,
        session.gate.path.client.is_ipv6(),
    )?;
    Ok(runtime)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "transaction_profile_tests.rs"]
mod tests;
