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
    pub(super) wrapper: usize,
    bytes: usize,
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
            let plan = if send.native_policy == NativePolicy::IpHeaders {
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
            let plan = if send.native_policy == NativePolicy::IpHeaders {
                codec::SenderPlan::for_ip_config(sender_config(send.body()))
            } else {
                codec::SenderPlan::for_config(sender_config(send.body()))
            }
            .map_err(storage::Error::Codec)?;
            (plan.capacity_bytes(), size_of::<sender::Sender>())
        };
        let receiver = if receive.native_policy == NativePolicy::IpHeaders {
            codec::ReceiverPlan::for_ip_limits(receive.receiver)
        } else {
            codec::ReceiverPlan::for_limits(receive.receiver)
        }
        .map_err(storage::Error::Codec)?;
        let reliable =
            l2tunnel_reliable::storage::CompactPlan::for_duplex(send.recovery, receive.recovery)
                .map_err(storage::Error::Reliable)?;
        if reliable.send_max_packet_bytes() > send.max_recovery_packet_bytes
            || reliable.receive_max_packet_bytes() > receive.max_recovery_packet_bytes
        {
            return Err(storage::Error::Endpoint(Error::Configuration));
        }
        let symbols = receive_packed.map_or(Ok(0), |p| {
            usize::from(p.max_units)
                .checked_mul(receive.receiver.body.symbol_bytes)
                .ok_or(storage::Error::Layout)
        })?;
        let wrapper = storage::sum(&[
            cell,
            send.recovery.arq().bounds().max_source_bytes,
            receive.recovery.arq().bounds().max_source_bytes,
            symbols,
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
            wrapper,
            bytes,
        })
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
            let instance = if send.native_policy == NativePolicy::IpHeaders {
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
            let instance = if send.native_policy == NativePolicy::IpHeaders {
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
        let symbols = receive_packing.map_or(0, |p| {
            usize::from(p.max_units) * receive.receiver.body.symbol_bytes
        });
        guard.packed_symbols = allocation.bytes(symbols)?;
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
            if receive.native_policy == NativePolicy::IpHeaders {
                receiver::Receiver::new_reserved_ip(
                    receive_scope,
                    receive.receiver,
                    codec::Limits {
                        capacity_bytes: plan.receiver.capacity_bytes(),
                    },
                )
            } else {
                receiver::Receiver::new_reserved(
                    receive_scope,
                    receive.receiver,
                    codec::Limits {
                        capacity_bytes: plan.receiver.capacity_bytes(),
                    },
                )
            }
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
            usage: Some(storage::Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes: bytes,
                allocations,
            }),
        })
    }
}
