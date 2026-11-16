//! Explicit complete common selection; no public label establishes authentication.
use super::*;
use l2tunnel::{record_configuration as common, record_engine as engine};

#[path = "transport_managed_contract.rs"]
mod managed;
pub use managed::FreshKeyPolicy;
#[path = "transport_raw_contract.rs"]
mod raw;

/// Complete common policy/catalog handoff to the sole original-socket Driver.
#[derive(Clone, Debug)]
pub struct CommonTransactionContract {
    expected: security::ConfigDigest,
    role: security::Role,
    resources: Config,
    cover: cover::Config,
    ipv6: bool,
    envelope: common::EnvelopeDigest,
    catalog: common::Catalog,
    initial: common::Configuration,
    data: core::ConfigDigest,
    settings: TransactionSettings,
    geometry: engine::Geometry,
    managed: Option<managed::Managed>,
    extra_wire_bytes: usize,
    outer: Option<establish::carrier::AuthenticatedOuter>,
    raw: Option<establish::raw_carrier::AuthenticatedRaw>,
}

#[path = "transport_common_fragment_policy.rs"]
mod fragments;

pub(super) fn selected_fragment_policy(
    value: &common::Configuration,
    policy: Option<engine::FragmentPolicy>,
) -> Option<engine::FragmentPolicy> {
    if matches!(
        value.descriptor().profile(),
        common::Profile::Rolling { .. } | common::Profile::RollingCopies { .. }
    ) {
        policy
    } else {
        None
    }
}

impl Config {
    pub(super) fn validate_rolling_work(&self) -> io::Result<()> {
        if self.rolling_work.is_some_and(|work| {
            [work.field, work.copies, work.metadata]
                .into_iter()
                .any(|value| !(1..=l2tunnel_fec::rolling::MAX_STEP_WORK).contains(&value))
        }) {
            return Err(invalid(
                "rolling work requires positive bounded component caps",
            ));
        }
        Ok(())
    }
    /// Validate actual shared owners without consulting inactive Swift policies.
    /// Common C supplies native geometry, rates, burst, queues and record policy.
    pub fn validate_common_resources(&self, max_native: usize) -> io::Result<()> {
        self.validate_rolling_work()?;
        if let Some(policy) = self.rolling_fragments {
            fragments::validate(policy)?;
        }
        if let Some(limits) = self.connection_ingress {
            limits.plan(self.security.max_body_bytes)?;
        }
        if self
            .rolling_ingress
            .is_some_and(|limits| limits.slots == 0 || limits.capacity_bytes == 0)
        {
            return Err(invalid(
                "Rolling input custody requires positive explicit bounds",
            ));
        }
        if let Some(limits) = self.rolling_ingress {
            u64::try_from(limits.slots).map_err(invalid)?;
            u64::try_from(limits.capacity_bytes).map_err(invalid)?;
        }
        if let Some(policy) = self.ack_coalescing {
            use l2tunnel_pipeline::ack_coalescing::Selection;
            if policy.selection != Selection::Benchmark {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Common ACK ingress does not own TCP endpoints",
                ));
            }
            for value in [policy.interval, policy.max_hold] {
                let micros = u64::try_from(value.as_micros()).map_err(invalid)?;
                if Duration::from_micros(micros) != value {
                    return Err(invalid("ACK ingress timers require exact microseconds"));
                }
            }
        }
        if !(1..=65_535).contains(&max_native)
            || !(256..=65_535).contains(&self.path_mtu)
            || self.control_epoch.0 == 0
            || self.data_epoch.0 == 0
            || !(1..=1024).contains(&self.native.pending_packets)
            || !(max_native..=MAX_QUEUE).contains(&self.native.pending_bytes)
            || self.work.receive_interval.is_zero()
            || self.work.receive_interval > Duration::from_secs(1)
            || !(1..=4096).contains(&self.work.receive_packets)
            || [
                self.work.send_batch,
                self.work.native_read_batch,
                self.work.native_write_batch,
            ]
            .iter()
            .any(|value| !(1..=4096).contains(value))
            || !(1..=security::MAX_BODY_BYTES).contains(&self.security.max_body_bytes)
            || !(1..=security::MAX_PACKETS_PER_KEY).contains(&self.security.packets_per_key)
            || !(1..=security::MAX_BODY_BYTES_PER_KEY)
                .contains(&self.security.max_body_bytes_per_key)
            || self.security.max_body_bytes as u64 > self.security.max_body_bytes_per_key
            || self.control.recovery.max_source_bytes < control::HEADER_BYTES + mg::HEADER_LEN
        {
            return Err(invalid("common shared resource geometry"));
        }
        for value in [
            self.lifetime.lease,
            self.lifetime.ping_interval,
            self.lifetime.pong_timeout,
            self.native.stall_timeout,
            self.work.receive_interval,
        ]
        .into_iter()
        .chain(self.report_interval)
        {
            if value.as_micros() == 0 {
                return Err(invalid("common timer requires an effective microsecond"));
            }
            u64::try_from(value.as_micros()).map_err(invalid)?;
        }
        let base = delivery::Binding {
            session: mg::SessionId([1; 16]),
            lane: mg::LaneId(LANE),
            local_role: mg::Role::Client,
            control_epoch: self.control_epoch.0,
        };
        self.control
            .validate(base, Duration::ZERO, self.lifetime.lease)
            .map_err(invalid)?;
        let selected = self
            .streams
            .ok_or_else(|| invalid("common transactions require explicit streams"))?;
        selected.validate(self.control, self.path_mtu, self.lifetime.lease)?;
        for stream in streams::Stream::ALL {
            streams::delivery_binding(base, stream).map_err(invalid)?;
        }
        let source = self
            .control
            .recovery
            .max_source_bytes
            .checked_add(recovery::DATA_HEADER_BYTES)
            .and_then(|value| value.checked_add(streams::HEADER_BYTES))
            .ok_or_else(exhausted)?;
        if source > self.security.max_body_bytes {
            return Err(invalid("common control exceeds protected body capacity"));
        }
        Ok(())
    }

    /// Exact shared-owner inventory for the new common authentication domain.
    /// Inactive Swift directions/policy/wire burst are excluded; C binds actual data policy.
    pub fn common_resource_digest(&self, max_native: usize) -> io::Result<core::ConfigDigest> {
        self.validate_common_resources(max_native)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/secure-udp-common-resources/v1\0");
        let mut number = |value: u64| hash.update(&value.to_be_bytes());
        let a = self.control.recovery;
        for value in [
            self.path_mtu as u64,
            max_native as u64,
            self.security.max_body_bytes as u64,
            self.security.packets_per_key,
            self.security.max_body_bytes_per_key,
            self.control_epoch.0,
            self.data_epoch.0,
            self.work.receive_packets as u64,
            self.work.send_batch as u64,
            self.work.native_read_batch as u64,
            self.work.native_write_batch as u64,
            self.native.pending_packets as u64,
            self.native.pending_bytes as u64,
            a.max_source_bytes as u64,
            a.send_bytes as u64,
            a.receive_bytes as u64,
            a.send_records as u64,
            a.receive_records as u64,
            a.max_retries as u64,
            self.control.packets_per_interval as u64,
            self.control.bytes_per_interval as u64,
            self.control.wire_overhead as u64,
        ] {
            number(value);
        }
        for value in [
            self.work.receive_interval,
            self.native.stall_timeout,
            self.lifetime.lease,
            self.lifetime.ping_interval,
            self.lifetime.pong_timeout,
            self.control.interval,
            a.initial_rto,
            a.maximum_rto,
            a.ack_delay,
        ] {
            number(value.as_secs());
            number(u64::from(value.subsec_nanos()));
        }
        let selected = self
            .streams
            .ok_or_else(|| invalid("missing common streams"))?;
        number(u64::from(streams::VERSION));
        number(streams::HEADER_BYTES as u64);
        for (stream, entry) in streams::Stream::ALL.into_iter().zip(selected.streams) {
            number(stream as u64);
            number(
                streams::delivery_binding(
                    delivery::Binding {
                        session: mg::SessionId([1; 16]),
                        lane: mg::LaneId(LANE),
                        local_role: mg::Role::Client,
                        control_epoch: self.control_epoch.0,
                    },
                    stream,
                )
                .map_err(invalid)?
                .control_epoch,
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
                number(value);
            }
        }
        // Absence preserves every existing resource digest byte. Explicit rolling
        // service adds an authenticated extension including its scheduling geometry.
        if let Some(work) = self.rolling_work {
            hash.update(b"l2tunnel/common-resources/rolling-work/v1\0");
            for value in [work.field, work.copies, work.metadata, 2, 2] {
                hash.update(&(value as u64).to_be_bytes());
            }
        }
        if let Some(policy) = self.ack_coalescing {
            hash.update(b"l2tunnel/common-resources/ack-coalescing/v1\0");
            for value in [
                2,
                policy.interval.as_secs(),
                u64::from(policy.interval.subsec_nanos()),
                policy.max_hold.as_secs(),
                u64::from(policy.max_hold.subsec_nanos()),
                u64::try_from(policy.max_flows).map_err(invalid)?,
                u64::try_from(policy.max_ack_bytes).map_err(invalid)?,
            ] {
                hash.update(&value.to_be_bytes());
            }
        }
        if let Some(limits) = self.rolling_ingress {
            hash.update(b"l2tunnel/common-resources/rolling-ingress/v1\0");
            for value in [limits.slots, limits.capacity_bytes] {
                hash.update(&u64::try_from(value).map_err(invalid)?.to_be_bytes());
            }
        }
        if let Some(limits) = self.connection_ingress {
            hash.update(b"l2tunnel/common-resources/connection-ingress/v1\0");
            for value in [limits.slots, limits.capacity_bytes] {
                hash.update(&u64::try_from(value).map_err(invalid)?.to_be_bytes());
            }
        }
        if let Some(policy) = self.rolling_fragments {
            fragments::update_hash(policy, &mut hash)?;
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        Ok(core::ConfigDigest(bytes))
    }
}

impl CommonTransactionContract {
    /// Validate the exact common catalog and actual shared resources before I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
    ) -> io::Result<Self> {
        Self::construct(
            expected, role, resources, cover, ipv6, envelope, catalog, settings, None, 0, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn construct(
        expected: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        managed: Option<managed::Managed>,
        extra_wire_bytes: usize,
        outer: Option<establish::carrier::AuthenticatedOuter>,
    ) -> io::Result<Self> {
        let physical = (if ipv6 { 48usize } else { 28usize })
            .checked_add(extra_wire_bytes)
            .ok_or_else(exhausted)?;
        Self::construct_physical(
            expected,
            role,
            resources,
            cover,
            ipv6,
            envelope,
            catalog,
            settings,
            managed,
            extra_wire_bytes,
            outer,
            physical,
            None,
            core::Duplex::Full,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn construct_physical(
        expected: security::ConfigDigest,
        role: security::Role,
        resources: Config,
        cover: cover::Config,
        ipv6: bool,
        envelope: common::EnvelopeDigest,
        catalog: common::Catalog,
        settings: TransactionSettings,
        managed: Option<managed::Managed>,
        extra_wire_bytes: usize,
        outer: Option<establish::carrier::AuthenticatedOuter>,
        physical: usize,
        raw: Option<establish::raw_carrier::AuthenticatedRaw>,
        duplex: core::Duplex,
    ) -> io::Result<Self> {
        let initial = common::Configuration::new(envelope, catalog.initial()).map_err(invalid)?;
        if initial.descriptor().duplex() != duplex {
            if duplex == core::Duplex::Full {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "common selected runtime requires full duplex",
                ));
            }
            return Err(invalid(
                "common requested duplex differs from selected carrier",
            ));
        }
        let max_native = [mg::Role::Client, mg::Role::Server]
            .into_iter()
            .map(|sender| initial.descriptor().direction(sender).max_native())
            .max()
            .ok_or_else(|| invalid("common native widths"))?;
        resources.validate_common_resources(max_native)?;
        settings.validate(resources)?;
        if resources.path_mtu != initial.descriptor().path_mtu() {
            return Err(invalid("initial common MTU differs from resource template"));
        }
        let protected = resources
            .security
            .max_body_bytes
            .checked_add(record::ROUTE_BYTES)
            .and_then(|value| {
                value.checked_add(security::Protection::ChaCha20Poly1305.overhead_bytes())
            })
            .and_then(|value| {
                value.checked_add(if managed.is_some() {
                    security::refresh::PREFIX_BYTES - security::COMMON_PREFIX_BYTES
                } else {
                    0
                })
            })
            .ok_or_else(exhausted)?;
        if managed.is_some() && protected > cover.limits().max_protected_bytes {
            return Err(invalid(
                "managed security exceeds covered protected capacity",
            ));
        }
        let header = cover
            .overhead(cover::Phase::Established, protected)
            .map_err(invalid)?;
        if protected
            .checked_add(header)
            .is_none_or(|bytes| bytes > cover.limits().max_packet_bytes)
        {
            return Err(invalid("common security exceeds covered storage capacity"));
        }
        let overhead = record::ROUTE_BYTES
            + security::Protection::ChaCha20Poly1305.overhead_bytes()
            + header
            + physical
            + if managed.is_some() {
                security::refresh::PREFIX_BYTES - security::COMMON_PREFIX_BYTES
            } else {
                0
            };
        if resources.control.wire_overhead != overhead {
            return Err(invalid("common control wire charge differs"));
        }
        let geometry = engine::Geometry {
            forward_overhead_bytes: overhead,
            reverse_overhead_bytes: overhead,
        };
        let data = transaction::configuration_digest(&initial).map_err(invalid)?;
        let result = Self {
            expected,
            role,
            resources,
            cover,
            ipv6,
            envelope,
            catalog,
            initial,
            data,
            settings,
            geometry,
            managed,
            extra_wire_bytes,
            outer,
            raw,
        };
        for value in result.catalog.configurations(envelope).map_err(invalid)? {
            result.resolve(value)?;
        }
        result.validate_message_capacity()?;
        Ok(result)
    }
    /// Actual expected maintained setup/Control digest H0.
    pub fn expected_configuration(&self) -> security::ConfigDigest {
        self.expected
    }
    /// Extra outer carrier bytes, excluding the IP/UDP and record headers.
    pub fn extra_wire_bytes(&self) -> usize {
        self.extra_wire_bytes
    }
    /// Exact selected physical headers, independent of UDP/OpenVPN/raw naming.
    pub fn physical_overhead_bytes(&self) -> io::Result<usize> {
        if let Some(raw) = self.raw {
            let geometry = raw.geometry();
            geometry
                .ip_tcp_bytes
                .checked_add(geometry.record_overhead_bytes)
                .ok_or_else(exhausted)
        } else {
            (if self.ipv6 { 48usize } else { 28usize })
                .checked_add(self.extra_wire_bytes)
                .ok_or_else(exhausted)
        }
    }
    /// Genuine selected raw proof; copying it cannot create a handoff owner.
    pub fn raw_outer(&self) -> Option<establish::raw_carrier::AuthenticatedRaw> {
        self.raw
    }
    /// Actual explicit initial refresh selection, never an authentication proof.
    pub fn refresh_selection(&self) -> Option<security::refresh::Selection> {
        self.managed.map(|value| value.selection)
    }
    /// Exact complete selected v2 settings; absence preserves the old namespace.
    pub fn managed_streams(&self) -> Option<control_owner::SettingsV2> {
        self.managed.map(|value| value.streams)
    }
    /// Exact authenticated local role.
    pub fn role(&self) -> security::Role {
        self.role
    }
    /// Actual shared resources; template Swift policies remain inactive.
    pub fn resources(&self) -> Config {
        self.resources
    }
    /// Actual native attachment layer from the common value, never its Swift template.
    pub fn native_layer(&self) -> PacketLayer {
        match self
            .initial
            .descriptor()
            .direction(mg::Role::Client)
            .common()
            .traffic()
            .layer
        {
            core::traffic::NetworkLayer::Tap => PacketLayer::Ethernet,
            core::traffic::NetworkLayer::Tun => PacketLayer::Ip,
        }
    }
    /// Exact role-local appearance and storage capacity.
    pub fn cover(&self) -> cover::Config {
        self.cover
    }
    /// Actual underlay address family.
    pub fn ipv6(&self) -> bool {
        self.ipv6
    }
    /// Full common envelope E.
    pub fn envelope(&self) -> common::EnvelopeDigest {
        self.envelope
    }
    /// Entire retained supported catalog.
    pub fn catalog(&self) -> &common::Catalog {
        &self.catalog
    }
    /// Complete exact initial common value.
    pub fn initial(&self) -> common::Configuration {
        self.initial
    }
    /// Real common management digest D0.
    pub fn data_digest(&self) -> core::ConfigDigest {
        self.data
    }
    /// Original generic transaction/resource requirements.
    pub fn settings(&self) -> TransactionSettings {
        self.settings
    }
    /// Exact actual full-wire overhead of each direction.
    pub fn geometry(&self) -> engine::Geometry {
        self.geometry
    }
    /// Checked original native completion age policy.
    pub fn native_limits(&self) -> io::Result<engine::NativeLimits> {
        Ok(engine::NativeLimits {
            stall_micros: u64::try_from(self.resources.native.stall_timeout.as_micros())
                .map_err(invalid)?,
        })
    }
    /// Validate an exact catalog value without a Swift conversion or field clamp.
    pub fn resolve(&self, value: common::Configuration) -> io::Result<common::Configuration> {
        if value.envelope() != self.envelope
            || !self.catalog.descriptors().contains(value.descriptor())
            || value.descriptor().duplex() != self.initial.descriptor().duplex()
        {
            return Err(invalid("common value outside exact authenticated catalog"));
        }
        for sender in [mg::Role::Client, mg::Role::Server] {
            let old = self.initial.descriptor().direction(sender);
            let view = value.descriptor().direction(sender);
            if matches!(view.profile(), common::DirectionProfile::PerConnectionCompact(direction) if direction.unreliable.is_some())
                && self.resources.connection_ingress.is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "raw per-connection catalog requires explicit authenticated input custody",
                ));
            }
            if matches!(view.profile(), common::DirectionProfile::Rolling { .. })
                && self.resources.rolling_work.is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "rolling catalog requires explicit bounded scheduler work",
                ));
            }
            if view.max_native() != old.max_native()
                || view.common().traffic().layer != old.common().traffic().layer
            {
                return Err(invalid("common catalog changes immutable native format"));
            }
            let peer = if sender == mg::Role::Client {
                mg::Role::Server
            } else {
                mg::Role::Client
            };
            let maximum = maximum_body(view, value.descriptor().direction(peer))?;
            let (physical_body, wire) = if let Some(policy) =
                selected_fragment_policy(&value, self.resources.rolling_fragments)
            {
                fragments::physical_requirement(maximum, sender, policy)?
            } else {
                let overhead = if sender == mg::Role::Client {
                    self.geometry.forward_overhead_bytes
                } else {
                    self.geometry.reverse_overhead_bytes
                };
                (
                    maximum,
                    maximum.checked_add(overhead).ok_or_else(exhausted)?,
                )
            };
            if physical_body > self.resources.security.max_body_bytes
                || value.descriptor().path_mtu() < self.control_maximum()?
                || wire
                    .checked_add(self.reserve()?)
                    .is_none_or(|required| required > view.common().burst_bytes())
            {
                return Err(invalid("common data/control/burst geometry"));
            }
        }
        engine::storage::Plan::for_engine_with_fragmentation(
            value,
            engine::Context {
                session: 1,
                epoch: self.resources.data_epoch.0,
                role: mg_role(self.role),
            },
            self.geometry,
            self.native_limits()?,
            self.resources.ack_coalescing,
            self.resources.rolling_ingress,
            selected_fragment_policy(&value, self.resources.rolling_fragments),
        )
        .map_err(invalid)?;
        Ok(value)
    }
    pub(super) fn reserve(&self) -> io::Result<usize> {
        self.resources
            .control
            .recovery
            .max_source_bytes
            .checked_add(recovery::DATA_HEADER_BYTES + recovery::ACK_PACKET_BYTES)
            .and_then(|bytes| {
                bytes
                    .checked_add(2 * (self.geometry.forward_overhead_bytes + streams::HEADER_BYTES))
            })
            .ok_or_else(exhausted)
    }
    fn control_maximum(&self) -> io::Result<usize> {
        self.resources
            .control
            .recovery
            .max_source_bytes
            .checked_add(recovery::DATA_HEADER_BYTES + streams::HEADER_BYTES)
            .and_then(|bytes| bytes.checked_add(self.geometry.forward_overhead_bytes))
            .ok_or_else(exhausted)
    }
    fn validate_message_capacity(&self) -> io::Result<()> {
        let mut required = 0;
        for descriptor in self.catalog.descriptors() {
            required = required.max(
                transaction::maximum_prepare_bytes::<common::Configuration>(
                    descriptor.sender_channels(mg::Role::Client),
                )
                .map_err(invalid)?,
            );
            let ready = mg::HEADER_LEN
                .checked_add(8 + 2 + 8 * usize::from(descriptor.sender_channels(mg::Role::Server)))
                .ok_or_else(exhausted)?;
            required = required.max(ready);
        }
        let required = required
            .checked_add(control::HEADER_BYTES)
            .ok_or_else(exhausted)?;
        let entry = self
            .resources
            .streams
            .ok_or_else(|| invalid("common stream absent"))?
            .streams[0];
        let binding = delivery::Binding {
            session: mg::SessionId([1; 16]),
            lane: mg::LaneId(LANE),
            local_role: mg::Role::Client,
            control_epoch: self.resources.control_epoch.0,
        };
        let binding = if self.managed.is_some() {
            streams::v2::delivery_binding(binding, streams::Stream::Transaction)
        } else {
            streams::delivery_binding(binding, streams::Stream::Transaction)
        }
        .map_err(invalid)?;
        let mut owner = mg::messages::Owner::new(
            entry,
            binding,
            Duration::ZERO,
            self.resources.lifetime.lease,
        )
        .map_err(invalid)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(required)
            .map_err(io::Error::other)?;
        bytes.resize(required, 0);
        owner
            .submit(
                mg::messages::SubmissionId(1),
                &bytes,
                Duration::ZERO,
                entry.message_lifetime.min(self.resources.lifetime.lease),
            )
            .map_err(invalid)?;
        Ok(())
    }
}
pub(super) fn mg_role(role: security::Role) -> mg::Role {
    if role == security::Role::Initiator {
        mg::Role::Client
    } else {
        mg::Role::Server
    }
}
pub(super) fn maximum_body(
    view: common::DirectionView<'_>,
    opposite: common::DirectionView<'_>,
) -> io::Result<usize> {
    match view.profile() {
        common::DirectionProfile::Swift(config) => Ok(config.codec.datagram_bytes),
        common::DirectionProfile::Aligned(config) => {
            config.recovery.maximum_packet_bytes().map_err(invalid)
        }
        common::DirectionProfile::Packed(config) => {
            config.base.recovery.maximum_packet_bytes().map_err(invalid)
        }
        common::DirectionProfile::AlignedCompact(send) => {
            let common::DirectionProfile::AlignedCompact(receive) = opposite.profile() else {
                return Err(invalid("compact directional family mismatch"));
            };
            l2tunnel_reliable::storage::CompactPlan::for_duplex(send.recovery, receive.recovery)
                .map(|plan| plan.send_max_packet_bytes())
                .map_err(invalid)
        }
        common::DirectionProfile::PackedCompact(send) => {
            let common::DirectionProfile::PackedCompact(receive) = opposite.profile() else {
                return Err(invalid("packed compact directional family mismatch"));
            };
            l2tunnel_reliable::storage::CompactPlan::for_duplex(
                send.base.recovery,
                receive.base.recovery,
            )
            .map(|plan| plan.send_max_packet_bytes())
            .map_err(invalid)
        }
        common::DirectionProfile::PerConnectionCompact(send) => {
            let common::DirectionProfile::PerConnectionCompact(receive) = opposite.profile() else {
                return Err(invalid("connection directional family mismatch"));
            };
            common_connections::maximum_body(*send, *receive)
        }
        common::DirectionProfile::Rolling { config, .. } => Ok(config
            .maximum_packet_bytes()
            .map_err(invalid)?
            .max(l2tunnel_fec::rolling::scheduler::FEEDBACK_BYTES)),
    }
}
