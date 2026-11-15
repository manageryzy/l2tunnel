//! Explicit four-stream provisioning on the existing shared Control machinery.

use super::*;

/// Complete opt-in v2 stream settings; no v1/default field changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsV2 {
    /// Transaction, Liveness, DataFeedback and Lifecycle in that exact order.
    pub streams: [messages::Settings; 4],
}
impl SettingsV2 {
    pub(super) fn first_three(self) -> Settings {
        Settings {
            streams: [self.streams[0], self.streams[1], self.streams[2]],
        }
    }
    pub(super) fn from_parts(selected: Settings, lifecycle: messages::Settings) -> Self {
        Self {
            streams: [
                selected.streams[0],
                selected.streams[1],
                selected.streams[2],
                lifecycle,
            ],
        }
    }
    /// Preserve the original per-owner and global service bounds, with the same
    /// exact wrapper overhead. No quota is multiplied by the number of owners.
    pub fn validate(
        self,
        base: delivery::Settings,
        path_mtu: usize,
        lifetime: Duration,
    ) -> io::Result<()> {
        self.first_three().validate(base, path_mtu, lifetime)?;
        let lifecycle = self.streams[3];
        if lifecycle.delivery != self.streams[0].delivery || lifecycle.path_mtu != path_mtu {
            return Err(invalid(
                "v2 Lifecycle must preserve base quota and exact wrapper geometry",
            ));
        }
        envelope_limits(lifecycle.max_message_bytes)?;
        let chunk = base
            .recovery
            .max_source_bytes
            .checked_sub(1 + l2tunnel_codec::FRAGMENT_HEADER_BYTES)
            .filter(|chunk| *chunk > 0)
            .ok_or_else(|| invalid("Lifecycle fragment payload is empty"))?;
        if lifecycle.max_message_bytes.div_ceil(chunk) > usize::from(lifecycle.max_fragments) {
            return Err(invalid(
                "Lifecycle fragment bound cannot carry declared whole-message ceiling",
            ));
        }
        lifecycle
            .validate(
                streams::v2::delivery_binding(
                    delivery::Binding {
                        session: mg::SessionId([1; 16]),
                        lane: mg::LaneId(0),
                        local_role: mg::Role::Client,
                        control_epoch: 1,
                    },
                    streams::Stream::Lifecycle,
                )
                .map_err(invalid)?,
                Duration::ZERO,
                lifetime,
            )
            .map_err(invalid)?;
        Ok(())
    }
    /// Same complete packet geometry as v1, with a strict v2 discriminator.
    #[allow(dead_code)] // Selected fresh-DH Driver will consume this exact geometry; v1 remains selected today.
    pub(crate) fn max_packet_bytes(self, base: delivery::Settings) -> io::Result<usize> {
        self.first_three().max_packet_bytes(base)
    }
    /// All four actual complete message plans, including each ARQ/reassembly
    /// owner once. Wrapper/header storage remains separately charged.
    #[allow(dead_code)] // Real v2 plans are tested here; selected runtime admission follows with B.
    pub(crate) fn message_storage_plans(
        self,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
    ) -> io::Result<[messages::storage::Plan; 4]> {
        let make = |i: usize| {
            messages::storage::Plan::for_owner(
                self.streams[i],
                stream_binding(binding, streams::v2::ALL[i], streams::v2::VERSION)?,
                now,
                expires,
            )
            .map_err(invalid)
        };
        Ok([make(0)?, make(1)?, make(2)?, make(3)?])
    }
}

impl Owner {
    /// Provision all four actual reserved message owners and the checked wrapper
    /// before publishing one leased Control owner. There is no allocating fallback.
    #[allow(clippy::too_many_arguments)] // Exact original contexts and constructor-only storage budgets.
    #[allow(dead_code)] // Actual four-owner constructor is protocol-tested; no current Driver silently selects it.
    pub(crate) fn new_leased_reserved_messages_v2_with_wrapper_plan(
        base: delivery::Settings,
        selected: SettingsV2,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        limits: [messages::storage::Limits; 4],
        wrapper: wrapper_storage::Plan,
        wrapper_limit: wrapper_storage::Limits,
    ) -> io::Result<Self> {
        let raw = raw_packet_bytes(base)?;
        let (backend, max_packet) = Self::construct_streamed(
            base,
            selected.first_three(),
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            raw,
            Storage::ReservedMessagesV2 {
                messages: limits,
                wrapper: &wrapper,
                wrapper_limit,
            },
            &mut wrapper_storage::Allocation::default(),
            Some(selected.streams[3]),
        )?;
        Self {
            backend,
            binding,
            expires,
            now,
            max_packet,
            failed: false,
        }
        .into_leased(control_scope, data_scope)
    }

    /// Observe all four complete actual owner heaps, without truncating v2 into
    /// the legacy three-stream observation or claiming complete runtime admission.
    #[allow(dead_code)] // Selected fresh-DH status/accounting consumer follows separately.
    pub(crate) fn message_storage_usage_v2(&self) -> Option<[messages::storage::Usage; 4]> {
        let Backend::Streamed(streamed) = &self.backend else {
            return None;
        };
        streamed.lifecycle?;
        Some([
            streamed.owners[0].storage_usage()?,
            streamed.owners[1].storage_usage()?,
            streamed.owners[2].storage_usage()?,
            streamed.owners[3].storage_usage()?,
        ])
    }

    /// Submit one already encoded typed Lifecycle body under the fixed Control
    /// scope. The parser grants no refresh/Noise/key-install authority.
    #[allow(dead_code)] // Actual Lifecycle custody is tested; B supplies the real Records admission consumer.
    pub(crate) fn submit_lifecycle(
        &mut self,
        bytes: &[u8],
        now: Duration,
        original_deadline: Duration,
    ) -> io::Result<Option<Token>> {
        let Backend::Streamed(streamed) = &self.backend else {
            return Err(invalid("Lifecycle requires v2 Control"));
        };
        if streamed.lifecycle.is_none() {
            return Err(invalid("Lifecycle requires explicit v2"));
        }
        let scope = streamed.control_scope;
        streams::v2::Lifecycle::decode(bytes, sc::MAX_LIFECYCLE_BYTES).map_err(protocol)?;
        self.submit(
            scope,
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SessionRefreshV1,
                bytes,
            },
            now,
            original_deadline,
            false,
        )
    }
}
