//! Actual complete nested storage for Compact R0 codec owners.
use super::*;
use l2tunnel_codec::aligned_storage as codec;
use std::{alloc::Layout, mem::size_of};

/// Complete independent-direction Compact endpoint plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    pub(super) send: CompactConfig,
    pub(super) receive: CompactConfig,
    pub(super) send_packed: Option<packed::CompactConfig>,
    pub(super) receive_packed: Option<packed::CompactConfig>,
    pub(super) sender: usize,
    pub(super) receiver: codec::ReceiverPlan,
    pub(super) reliable: l2tunnel_reliable::storage::CompactPlan,
    packed_workspace_bytes: usize,
    pub(super) wrapper: usize,
    bytes: usize,
    pub(super) receiver_handoff_diagnostics: bool,
}
impl Plan {
    /// Plan actual ordinary owners; unsupported physical copies fail before allocation.
    pub fn for_duplex(send: CompactConfig, receive: CompactConfig) -> Result<Self, storage::Error> {
        send.validate().map_err(storage::Error::Endpoint)?;
        receive.validate().map_err(storage::Error::Endpoint)?;
        if send.copies.copies > 1 || receive.copies.copies > 1 {
            return Err(storage::Error::Endpoint(Error::UnsupportedCopies));
        }
        Self::build(send, receive, None, None)
    }
    /// Plan actual Packed owners; unsupported physical copies fail before allocation.
    pub fn for_packed_duplex(
        send: packed::CompactConfig,
        receive: packed::CompactConfig,
    ) -> Result<Self, storage::Error> {
        send.validate().map_err(storage::Error::Endpoint)?;
        receive.validate().map_err(storage::Error::Endpoint)?;
        if send.base.copies.copies > 1 || receive.base.copies.copies > 1 {
            return Err(storage::Error::Endpoint(Error::UnsupportedCopies));
        }
        Self::build(send.base, receive.base, Some(send), Some(receive))
    }
    fn build(
        send: CompactConfig,
        receive: CompactConfig,
        send_packed: Option<packed::CompactConfig>,
        receive_packed: Option<packed::CompactConfig>,
    ) -> Result<Self, storage::Error> {
        let (sender, cell) = if let Some(p) = send_packed {
            let plan = if send.native_policy.uses_ip_headers() {
                codec::PackedSenderPlan::for_ip_config(p.sender())
            } else {
                codec::PackedSenderPlan::for_config(p.sender())
            }
            .map_err(storage::Error::Codec)?;
            (
                plan.capacity_bytes(),
                size_of::<l2tunnel_codec::packed_sender::Sender>(),
            )
        } else {
            let plan = if send.native_policy.uses_ip_headers() {
                codec::SenderPlan::for_ip_config(sender_config(send.body()))
            } else {
                codec::SenderPlan::for_config(sender_config(send.body()))
            }
            .map_err(storage::Error::Codec)?;
            (plan.capacity_bytes(), size_of::<sender::Sender>())
        };
        let receiver = receive
            .native_policy
            .receiver_plan(receive.receiver)
            .map_err(storage::Error::Codec)?;
        let reliable =
            l2tunnel_reliable::storage::CompactPlan::for_duplex(send.recovery, receive.recovery)
                .map_err(storage::Error::Reliable)?;
        if reliable.send_max_packet_bytes() > send.max_recovery_packet_bytes
            || reliable.receive_max_packet_bytes() > receive.max_recovery_packet_bytes
        {
            return Err(storage::Error::Endpoint(Error::Configuration));
        }
        let packed_workspace_bytes = receive_packed.map_or(Ok(0), |p| {
            usize::from(p.max_units)
                .checked_mul(receive.receiver.body.symbol_bytes)
                .and_then(|symbols| symbols.checked_add(receive.body().packed_preview_bytes()))
                .ok_or(storage::Error::Layout)
        })?;
        let wrapper = storage::sum(&[
            cell,
            send.recovery.arq().bounds().max_source_bytes,
            receive.recovery.arq().bounds().max_source_bytes,
            packed_workspace_bytes,
        ])?;
        Layout::array::<u8>(wrapper).map_err(|_| storage::Error::Layout)?;
        let bytes = storage::sum(&[
            wrapper,
            sender,
            receiver.capacity_bytes(),
            reliable.capacity_bytes(),
        ])?;
        Ok(Self {
            send,
            receive,
            send_packed,
            receive_packed,
            sender,
            receiver,
            reliable,
            packed_workspace_bytes,
            wrapper,
            bytes,
            receiver_handoff_diagnostics: false,
        })
    }
    /// Prepay one exact ordered receiver-handoff observation, without changing recovery bounds.
    pub fn with_receiver_handoff_diagnostics(mut self) -> Result<Self, storage::Error> {
        if !self.receiver_handoff_diagnostics {
            let extra = Layout::array::<receiver_handoff::State>(1)
                .map_err(|_| storage::Error::Layout)?
                .size();
            self.wrapper = storage::sum(&[self.wrapper, extra])?;
            self.bytes = storage::sum(&[self.bytes, extra])?;
            self.receiver_handoff_diagnostics = true;
        }
        Ok(self)
    }
    /// Exact original sending policy.
    pub const fn send_config(&self) -> CompactConfig {
        self.send
    }
    /// Exact original receiving policy.
    pub const fn receive_config(&self) -> CompactConfig {
        self.receive
    }
    /// Exact Packed sending policy, absent for ordinary Aligned.
    pub const fn send_packed(&self) -> Option<packed::CompactConfig> {
        self.send_packed
    }
    /// Exact Packed receiving policy, absent for ordinary Aligned.
    pub const fn receive_packed(&self) -> Option<packed::CompactConfig> {
        self.receive_packed
    }
    /// Complete actual nested heap, excluding the inline Endpoint.
    pub const fn capacity_bytes(&self) -> usize {
        self.bytes
    }
    /// Actual selected Reliable subset, charged exactly once.
    pub const fn reliable_plan(&self) -> l2tunnel_reliable::storage::CompactPlan {
        self.reliable
    }
}

impl Endpoint {
    /// Reserve a symmetric genuine Compact R0 endpoint; physical custody is enabled.
    pub fn new_compact_reserved(
        config: CompactConfig,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::new_compact_duplex_reserved(config, config, context, limits)
    }
    /// Reserve one actual independently configured codec/recovery/native owner pair.
    pub fn new_compact_duplex_reserved(
        send: CompactConfig,
        receive: CompactConfig,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::assemble_compact(Plan::for_duplex(send, receive)?, context, limits)
    }
    /// Construct the exact ordinary Compact plan including its prepaid diagnostic sidecar.
    pub fn new_compact_reserved_with_plan(
        plan: Plan,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        if plan.send_packed.is_some() || plan.receive_packed.is_some() {
            return Err(storage::Error::Endpoint(Error::Configuration));
        }
        Self::assemble_compact(plan, context, limits)
    }
    pub(super) fn assemble_compact(
        plan: Plan,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        if context.session == 0 {
            return Err(storage::Error::Endpoint(Error::Configuration));
        }
        if plan.bytes > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.bytes,
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = storage::Allocation::for_wrapper(plan.wrapper);
        let send = plan.send;
        let receive = plan.receive;
        let direction = match context.role {
            EndpointRole::Initiator => receiver::Direction::InitiatorToResponder,
            EndpointRole::Responder => receiver::Direction::ResponderToInitiator,
        };
        let send_scope = receiver::Scope {
            session: context.session.to_be_bytes(),
            epoch: Epoch(context.epoch),
            direction,
        };
        let receive_scope = receiver::Scope {
            direction: match direction {
                receiver::Direction::InitiatorToResponder => {
                    receiver::Direction::ResponderToInitiator
                }
                receiver::Direction::ResponderToInitiator => {
                    receiver::Direction::InitiatorToResponder
                }
            },
            ..send_scope
        };
        let mut guard = storage::Construction::default();
        let (sender, sender_usage) = if let Some(p) = plan.send_packed {
            let mut cell = allocation.vec(1)?;
            let instance = if send.native_policy.uses_ip_headers() {
                l2tunnel_codec::packed_sender::Sender::new_reserved_ip_with_copies(
                    send_scope,
                    p.sender(),
                    codec::Limits {
                        capacity_bytes: plan.sender,
                    },
                    send.copies,
                )
            } else {
                l2tunnel_codec::packed_sender::Sender::new_reserved_with_copies(
                    send_scope,
                    p.sender(),
                    codec::Limits {
                        capacity_bytes: plan.sender,
                    },
                    send.copies,
                )
            }
            .map_err(storage::Error::Codec)?;
            let usage = instance.storage_usage().ok_or(storage::Error::Invariant)?;
            cell.push(instance);
            (packed::SenderOwner::Packed(cell), usage)
        } else {
            let mut cell = allocation.vec(1)?;
            let instance = if send.native_policy.uses_ip_headers() {
                sender::Sender::new_reserved_ip(
                    send_scope,
                    sender_config(send.body()),
                    codec::Limits {
                        capacity_bytes: plan.sender,
                    },
                )
            } else {
                sender::Sender::new_reserved(
                    send_scope,
                    sender_config(send.body()),
                    codec::Limits {
                        capacity_bytes: plan.sender,
                    },
                )
            }
            .map_err(storage::Error::Codec)?;
            let usage = instance.storage_usage().ok_or(storage::Error::Invariant)?;
            cell.push(instance);
            (packed::SenderOwner::Aligned(cell), usage)
        };
        guard.sender = Some(sender);
        let packing = plan.send_packed.map(|p| p.options());
        let receive_packing = plan.receive_packed.map(|p| p.options());
        guard.packed_symbols = allocation.bytes(plan.packed_workspace_bytes)?;
        guard.recovery = Some(
            Reliable::new_compact_duplex_reserved(
                send.recovery,
                receive.recovery,
                context,
                l2tunnel_reliable::storage::Limits {
                    capacity_bytes: plan.reliable.capacity_bytes(),
                },
            )
            .map_err(storage::Error::Reliable)?,
        );
        guard.receiver = Some(
            receive
                .native_policy
                .reserved_receiver(
                    receive_scope,
                    receive.receiver,
                    codec::Limits {
                        capacity_bytes: plan.receiver.capacity_bytes(),
                    },
                )
                .map_err(storage::Error::Codec)?,
        );
        guard.send_buffer = allocation.bytes(send.recovery.arq().bounds().max_source_bytes)?;
        guard.receive_buffer =
            allocation.bytes(receive.recovery.arq().bounds().max_source_bytes)?;
        let recovery_usage = guard
            .recovery
            .as_ref()
            .and_then(Reliable::storage_usage)
            .ok_or(storage::Error::Invariant)?;
        let receiver_usage = guard
            .receiver
            .as_ref()
            .and_then(receiver::Receiver::storage_usage)
            .ok_or(storage::Error::Invariant)?;
        guard.receiver_handoff = allocation.vec(usize::from(plan.receiver_handoff_diagnostics))?;
        if plan.receiver_handoff_diagnostics {
            guard.receiver_handoff.push(receiver_handoff::State::new(
                receive_scope,
                receive_packing.is_some(),
            ));
        }
        let (wrapper, wrapper_allocations) = allocation.actual();
        let bytes = storage::sum(&[
            wrapper,
            sender_usage.capacity_bytes,
            recovery_usage.capacity_bytes,
            receiver_usage.capacity_bytes,
        ])?;
        if wrapper != plan.wrapper
            || sender_usage.capacity_bytes != plan.sender
            || recovery_usage.capacity_bytes != plan.reliable.capacity_bytes()
            || receiver_usage.capacity_bytes != plan.receiver.capacity_bytes()
            || bytes != plan.bytes
        {
            return Err(storage::Error::Invariant);
        }
        let allocations = storage::sum(&[
            wrapper_allocations,
            sender_usage.allocations,
            recovery_usage.allocations,
            receiver_usage.allocations,
        ])?;
        let sender = guard.sender.take().ok_or(storage::Error::Invariant)?;
        let recovery = guard.recovery.take().ok_or(storage::Error::Invariant)?;
        let receiver = guard.receiver.take().ok_or(storage::Error::Invariant)?;
        let packed_symbols = std::mem::take(&mut guard.packed_symbols);
        let send_buffer = std::mem::take(&mut guard.send_buffer);
        let receive_buffer = std::mem::take(&mut guard.receive_buffer);
        let receiver_handoff = std::mem::take(&mut guard.receiver_handoff);
        guard.transferred(bytes);
        Ok(Self {
            config: send.body(),
            receive_config: receive.body(),
            receive_scope,
            send_scope,
            sender,
            packing,
            receive_packing,
            receive_unit: Some(receive.receiver.first_source),
            packed_symbols,
            recovery,
            receiver,
            send_buffer,
            receive_buffer,
            handoff: None,
            now: Duration::ZERO,
            failure: None,
            compact_wire: false,
            compact_data_overhead: 0,
            staged_wait: staged_wait::State::default(),
            receiver_handoff,
            usage: Some(storage::Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes: bytes,
                allocations,
            }),
        })
    }
}
