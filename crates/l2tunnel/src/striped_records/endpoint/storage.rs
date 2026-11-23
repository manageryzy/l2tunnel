//! Complete retained heap for one local role and one negotiated epoch.
use super::*;
use crate::fec::striped_group::{ReceivePlan, TransmitPlan};
use std::alloc::Layout;

#[derive(Clone, Copy)]
pub(crate) struct StoragePlan {
    forward: Direction,
    reverse: Direction,
    role: Role,
    bytes: usize,
}

pub(super) fn fec_storage_error(error: fec::storage::Error) -> Error {
    match error {
        fec::storage::Error::Fec(error) => Error::Striped(error),
        fec::storage::Error::Layout => Error::Arithmetic,
        fec::storage::Error::Limit { .. } | fec::storage::Error::Allocation => {
            Error::Striped(fec::Error::Capacity)
        }
        fec::storage::Error::Invariant => Error::Invariant,
    }
}

impl StoragePlan {
    pub(crate) fn new(forward: Direction, reverse: Direction, role: Role) -> Result<Self, Error> {
        let (send, receive) = match role {
            Role::Client => (forward, reverse),
            Role::Server => (reverse, forward),
        };
        let codec_error = |e| Error::StripedNative(super::super::native::NativeError::Storage(e));
        let tx =
            TransmitPlan::for_window(send.profile, send.source_limit).map_err(fec_storage_error)?;
        let rx = ReceivePlan::for_window(
            receive.profile,
            receive.source_limit,
            receive.expanded_limit,
        )
        .map_err(fec_storage_error)?;
        let bytes = [
            send.packing_plan().map_err(codec_error)?.capacity_bytes(),
            send.packing
                .envelope()
                .max_source_bytes()
                .map_err(|_| Error::Configuration)?,
            receive
                .receiver_plan()
                .map_err(codec_error)?
                .capacity_bytes(),
            NativeReceiver::custody_planned_bytes(receive).map_err(Error::StripedNative)?,
            tx.capacity_bytes(),
            ScheduledSender::auxiliary_planned_bytes(send.profile, send.source_limit)
                .map_err(Error::Striped)?,
            rx.capacity_bytes(),
            ScheduledReceiver::auxiliary_planned_bytes(receive.source_limit)
                .map_err(Error::Striped)?,
            Guard::mixed_heap_bytes(receive.native_policy, receive.receiver),
            receive.profile.max_body_bytes,
            fec::striped_group::original_limit(send.profile).map_err(Error::Striped)?,
            Layout::array::<GenerationId>(receive.source_limit)
                .map_err(|_| Error::Arithmetic)?
                .size(),
            Index::<GenerationId, ()>::planned_bytes(receive.source_limit)
                .map_err(|_| Error::Arithmetic)?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, v| sum.checked_add(v).ok_or(Error::Arithmetic))?;
        Ok(Self {
            forward,
            reverse,
            role,
            bytes,
        })
    }
    pub(crate) fn heap_bytes(self) -> usize {
        self.bytes
    }
    pub(crate) fn construct(self, context: Context) -> Result<Endpoint, Error> {
        if context.role != self.role {
            return Err(Error::Configuration);
        }
        let endpoint = Endpoint::new(self.forward, self.reverse, context, Tick(0))?;
        if endpoint
            .heap_usage()
            .is_none_or(|(bytes, _)| bytes != self.bytes)
        {
            return Err(Error::Invariant);
        }
        Ok(endpoint)
    }
}

impl Endpoint {
    pub(crate) fn heap_usage(&self) -> Option<(usize, usize)> {
        let encoder = self.packing.heap_usage()?;
        let decoder = self.records.heap_usage()?;
        let tx = self.sender.custody_storage_usage()?;
        let rx = self.receiver.window().storage_usage();
        let parts = [
            encoder,
            decoder,
            (tx.capacity_bytes, tx.allocations),
            (rx.capacity_bytes, rx.allocations),
            (self.sender.auxiliary_capacity_bytes(), 2),
            (self.receiver.auxiliary_capacity_bytes(), 4),
            (self.guard.capacity_bytes(), self.guard.allocations()),
            (self.scratch.capacity(), 1),
            (self.split.capacity(), 1),
            (
                self.waiting
                    .capacity()
                    .checked_mul(size_of::<GenerationId>())?,
                1,
            ),
            (self.queued.capacity_bytes(), 1),
        ];
        parts
            .into_iter()
            .try_fold((0usize, 0usize), |(b, a), (bytes, allocations)| {
                Some((b.checked_add(bytes)?, a.checked_add(allocations)?))
            })
    }
}
