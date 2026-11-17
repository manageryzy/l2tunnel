//! Allocation-free queue observations on the actual maintained owner.
//! No allocation, clock, event retention, protocol mutation or provider internals.

/// Actual local adapter reservations for one trusted scheduling class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotSnapshot {
    /// Actual configured permits for this local scheduling class.
    pub capacity: usize,
    /// None exposes an inconsistent observation rather than inventing zero.
    pub used: Option<usize>,
}

/// Sampled observations from the actual authenticated QUIC owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSnapshot {
    /// User tickets currently retaining an actual class permit.
    pub user_slots: SlotSnapshot,
    /// Control tickets currently retaining an independent class permit.
    pub control_slots: SlotSnapshot,
    /// The exact configured value installed through TransportConfig, not heap use.
    pub outgoing_send_buffer_capacity: usize,
    /// Quinn's current maximum additional payload without evicting older payload.
    /// This is NOT capacity minus payload occupancy: pinned Quinn additionally
    /// subtracts a private Datagram metadata allowance and saturates at zero.
    pub available_payload_bytes: usize,
    /// The exact configured incoming queue bound, not current incoming occupancy.
    pub incoming_receive_buffer_capacity: usize,
    /// Public provider APIs do not expose exact queued incoming payload bytes.
    pub incoming_used_bytes: Option<usize>,
    /// Public provider APIs do not expose exact outgoing payload or heap usage.
    pub outgoing_used_bytes: Option<usize>,
    /// A permit count exceeded its configured capacity; used remains unknown.
    pub invalid_slot_observation: bool,
}

impl super::Carrier {
    /// Allocation-free observations only; no send, receive or authority changes.
    pub fn buffer_snapshot(&self) -> BufferSnapshot {
        let capacity = self.geometry.pending_per_class;
        let user = capacity.checked_sub(self.user.available_permits());
        let control = capacity.checked_sub(self.priority.available_permits());
        BufferSnapshot {
            user_slots: SlotSnapshot {
                capacity,
                used: user,
            },
            control_slots: SlotSnapshot {
                capacity,
                used: control,
            },
            outgoing_send_buffer_capacity: self.geometry.maintained_send_queue_bytes,
            available_payload_bytes: self.session.connection.datagram_send_buffer_space(),
            incoming_receive_buffer_capacity: self.geometry.maintained_queue_bytes,
            incoming_used_bytes: None,
            outgoing_used_bytes: None,
            invalid_slot_observation: user.is_none() || control.is_none(),
        }
    }
}
