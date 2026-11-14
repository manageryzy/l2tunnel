//! Checked known storage before any selected control/data workspace provisioning.
//! Setup tails, bridge copies, Peer/catalog and report owners remain incomplete.
use super::*;
use l2tunnel::swift_configuration::Configuration as C;
use l2tunnel_management::messages;

pub(super) struct Plan {
    pub(super) messages: [messages::storage::Plan; 3],
    pub(super) buffers: buffers::Plan<7>,
    pub(super) inputs: buffers::Plan<2>,
    pub(super) native: native_storage::Plan<Native>,
    pub(super) wrapper: control_owner::wrapper_storage::Plan,
    pub(super) external_bytes: usize,
    pub(super) required_bytes: usize,
}

impl Plan {
    pub(super) fn new(
        config: Config,
        cover: cover::Config,
        capacity: record::Capacity,
        binding: delivery::Binding,
        initial: C,
        role: mg::Role,
    ) -> io::Result<Self> {
        let selected = config
            .streams
            .ok_or_else(|| invalid("generic construction requires selected streams"))?;
        let messages =
            selected.message_storage_plans(binding, Duration::ZERO, config.lifetime.lease)?;
        let wrapper = control_owner::wrapper_storage::Plan::new(selected, config.control)?;
        let message_bytes = messages.iter().try_fold(0usize, |total, plan| {
            total
                .checked_add(plan.capacity_bytes())
                .ok_or_else(|| invalid("complete control storage layout overflow"))
        })?;
        let control_message = selected
            .streams
            .iter()
            .map(|settings| settings.max_message_bytes)
            .max()
            .ok_or_else(|| invalid("generic streams have no message storage"))?;
        let buffers = buffers::Buffers::plan(
            cover.limits().max_packet_bytes,
            capacity
                .seal_workspace_bytes
                .max(capacity.open_workspace_bytes),
            config.security.max_body_bytes,
            selected.max_packet_bytes(config.control)?,
            control_message,
            swift::control::MAX_FRAME,
        )?;
        let inputs = buffers::Inputs::plan(
            READ_BUFFER_BYTES,
            cover
                .limits()
                .max_packet_bytes
                .checked_add(1)
                .ok_or_else(exhausted)?,
        )?;
        let native = native_storage::Queue::<Native>::plan(
            config.native.pending_packets,
            config.native.pending_bytes,
            config.receive.records.max_native,
        )?;
        let external_bytes = external_capacity(
            buffers.capacity_bytes(),
            inputs.capacity_bytes(),
            native.capacity_bytes(),
            message_bytes,
            wrapper.capacity_bytes(),
        )?;
        let required_bytes = engines::Bank::required_capacity(initial, role, external_bytes)?;
        Ok(Self {
            messages,
            buffers,
            inputs,
            native,
            wrapper,
            external_bytes,
            required_bytes,
        })
    }

    /// The real provisioning closure is never called after a known budget refusal.
    pub(super) fn provision<T>(
        self,
        limit: usize,
        build: impl FnOnce(Self) -> io::Result<T>,
    ) -> io::Result<T> {
        if self.required_bytes > limit {
            return Err(io::Error::other(swift::storage::Error::Budget));
        }
        build(self)
    }
}

/// Same known-layout sum for checked plans and real provisioned capacities.
pub(super) fn external_capacity(
    buffers: usize,
    inputs: usize,
    native: usize,
    messages: usize,
    wrapper: usize,
) -> io::Result<usize> {
    // Set owns its inline layout. State is one real separately reserved cell;
    // Inputs move to the sole loop, retaining both their header and heaps.
    std::mem::size_of::<Driver>()
        .checked_add(std::mem::size_of::<transactions::State>())
        .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<swift::storage::Set>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<buffers::Inputs>()))
        .and_then(|bytes| bytes.checked_add(buffers))
        .and_then(|bytes| bytes.checked_add(inputs))
        .and_then(|bytes| bytes.checked_add(native))
        .and_then(|bytes| bytes.checked_add(wrapper))
        .and_then(|bytes| bytes.checked_add(messages))
        .ok_or_else(|| invalid("known generic construction layout overflow"))
}
