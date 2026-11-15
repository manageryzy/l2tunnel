//! Checked complete heap plans and actual fallible Pipeline construction.

use std::alloc::Layout;

use crate::backing::{
    ById, IdEntry, MetadataPool, MetadataQueue, MetadataSlot, StateEntry, States,
};
use crate::{
    Pipeline, PipelineConfig, PipelineError, Profile, QueueUsage, TUN_CLASSES, scheduler_config,
};

/// Complete retained Rust allocation-layout capacity, including idle slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete nested and wrapper heap capacity.
    pub capacity_bytes: usize,
}

/// Actual observed nested and wrapper capacities; not allocator RSS or stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Caller-supplied complete capacity limit.
    pub limit_bytes: usize,
    /// Actual retained allocation-layout capacities, each counted once.
    pub capacity_bytes: usize,
    /// Number of actual retained nonempty heap allocations.
    pub allocations: usize,
}

/// Constructor-only configuration, layout, limit or allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Authoritative complete Pipeline configuration rejection.
    Pipeline(PipelineError),
    /// Actual reserved flow-table constructor failure.
    Flow(l2tunnel_packet::storage::Error),
    /// Actual reserved MUX constructor failure.
    Mux(l2tunnel_mux::storage::Error),
    /// Actual reserved DRR constructor failure.
    Qos(l2tunnel_qos::storage::Error),
    /// Checked count, multiplication, sum or allocation layout overflow.
    Layout,
    /// Complete provisioned capacity exceeds the caller's limit.
    Limit {
        /// Complete required nested and wrapper bytes.
        required: usize,
        /// Supplied capacity bound.
        limit: usize,
    },
    /// An actual fallible reservation failed.
    Allocation,
    /// Actual backing capacity or inventory differs from the validated plan.
    Invariant,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Pipeline storage construction failed: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Complete allocation-free checked heap plan for one directional Pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: PipelineConfig,
    capacity_bytes: usize,
}

impl Plan {
    /// Validate the original complete policy, nested plans and actual layouts.
    pub fn for_pipeline(config: PipelineConfig) -> Result<Self, Error> {
        config.validate().map_err(Error::Pipeline)?;
        let flow = l2tunnel_packet::storage::Plan::for_config(config.flows).map_err(Error::Flow)?;
        let mux = mux_plan(config)?;
        let qos = match config.profile {
            Profile::TapSystem => 0,
            Profile::TunDrr(policy) => l2tunnel_qos::storage::Plan::for_scheduler(
                scheduler_config(config, policy),
                &TUN_CLASSES,
            )
            .map_err(Error::Qos)?
            .capacity_bytes(),
        };
        let capacity_bytes = [
            flow.capacity_bytes(),
            mux.capacity_bytes(),
            qos,
            array_bytes::<StateEntry>(config.flows.capacity)?,
            array_bytes::<IdEntry>(config.flows.capacity)?,
            array_bytes::<MetadataSlot>(config.queue.packets)?,
            array_bytes::<MetadataQueue>(usize::from(config.flows.channels))?,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(Error::Layout)
        })?;
        Ok(Self {
            config,
            capacity_bytes,
        })
    }

    /// Original complete policy; no limit or profile is silently reduced.
    pub fn config(&self) -> PipelineConfig {
        self.config
    }

    /// Complete nested and wrapper heap capacity, excluding inline Self.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

fn mux_plan(config: PipelineConfig) -> Result<l2tunnel_mux::storage::Plan, Error> {
    match config.profile {
        Profile::TapSystem => l2tunnel_mux::storage::Plan::for_queue(
            config.flows.channels,
            config.queue.bytes,
            config.queue.packets,
            config.parse.max_packet_bytes,
        ),
        Profile::TunDrr(_) => l2tunnel_mux::storage::Plan::for_handoff(
            config.flows.channels,
            config.queue.bytes,
            config.queue.packets,
        ),
    }
    .map_err(Error::Mux)
}

fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}

#[derive(Default)]
pub(crate) struct Allocation {
    attempts: usize,
    allocations: usize,
    #[cfg(test)]
    pub(crate) fail_at: Option<usize>,
}

impl Allocation {
    fn reserve<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        array_bytes::<T>(count)?;
        self.attempts = self.attempts.checked_add(1).ok_or(Error::Layout)?;
        #[cfg(test)]
        if self.fail_at == Some(self.attempts) {
            return Err(Error::Allocation);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if values.capacity() != count {
            return Err(Error::Invariant);
        }
        if count != 0 && std::mem::size_of::<T>() != 0 {
            self.allocations = self.allocations.checked_add(1).ok_or(Error::Layout)?;
        }
        Ok(values)
    }
}

impl Pipeline {
    /// Provision complete actual nested and wrapper storage before packet ingress.
    ///
    /// Planning and the complete limit check precede every selected allocation.
    /// Failure drops partial owners; it never falls back to legacy backing.
    pub fn new_reserved(config: PipelineConfig, limits: Limits) -> Result<Self, Error> {
        Self::new_reserved_with(config, limits, &mut Allocation::default())
    }

    pub(crate) fn new_reserved_with(
        config: PipelineConfig,
        limits: Limits,
        allocation: &mut Allocation,
    ) -> Result<Self, Error> {
        let plan = Plan::for_pipeline(config)?;
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let flow_plan =
            l2tunnel_packet::storage::Plan::for_config(config.flows).map_err(Error::Flow)?;
        let flows = l2tunnel_packet::FlowTable::with_plan(
            flow_plan,
            l2tunnel_packet::storage::Limits {
                capacity_bytes: flow_plan.capacity_bytes(),
            },
        )
        .map_err(Error::Flow)?;
        let mux_plan = mux_plan(config)?;
        let mux = l2tunnel_mux::Mux::with_plan(
            mux_plan,
            l2tunnel_mux::storage::Limits {
                capacity_bytes: mux_plan.capacity_bytes(),
            },
        )
        .map_err(Error::Mux)?;
        let qos = match config.profile {
            Profile::TapSystem => None,
            Profile::TunDrr(policy) => {
                let config = scheduler_config(config, policy);
                let plan = l2tunnel_qos::storage::Plan::for_scheduler(config, &TUN_CLASSES)
                    .map_err(Error::Qos)?;
                Some(
                    l2tunnel_qos::Scheduler::new_reserved(
                        config,
                        &TUN_CLASSES,
                        l2tunnel_qos::storage::Limits {
                            capacity_bytes: plan.capacity_bytes(),
                        },
                    )
                    .map_err(Error::Qos)?,
                )
            }
        };
        let states = allocation.reserve::<StateEntry>(config.flows.capacity)?;
        let by_id = allocation.reserve::<IdEntry>(config.flows.capacity)?;
        let mut metadata = allocation.reserve::<MetadataSlot>(config.queue.packets)?;
        for index in 0..config.queue.packets {
            metadata.push(MetadataSlot {
                value: None,
                next: (index + 1 < config.queue.packets).then_some(index + 1),
            });
        }
        let mut channel_metadata =
            allocation.reserve::<MetadataQueue>(usize::from(config.flows.channels))?;
        for _ in 0..config.flows.channels {
            channel_metadata.push(MetadataQueue::new(true));
        }
        let mut actual = Usage {
            limit_bytes: limits.capacity_bytes,
            capacity_bytes: [
                array_bytes::<StateEntry>(states.capacity())?,
                array_bytes::<IdEntry>(by_id.capacity())?,
                array_bytes::<MetadataSlot>(metadata.capacity())?,
                array_bytes::<MetadataQueue>(channel_metadata.capacity())?,
            ]
            .into_iter()
            .try_fold(0usize, |total, bytes| {
                total.checked_add(bytes).ok_or(Error::Layout)
            })?,
            allocations: allocation.allocations,
        };
        let flow_usage = flows.storage_usage().ok_or(Error::Invariant)?;
        let mux_usage = mux.storage_usage().ok_or(Error::Invariant)?;
        let qos_usage = match qos.as_ref() {
            Some(owner) => Some(owner.storage_usage().ok_or(Error::Invariant)?),
            None => None,
        };
        for (bytes, allocations) in [
            (flow_usage.capacity_bytes, flow_usage.allocations),
            (mux_usage.capacity_bytes, mux_usage.allocations),
            qos_usage.map_or((0, 0), |usage| (usage.capacity_bytes, usage.allocations)),
        ] {
            actual.capacity_bytes = actual
                .capacity_bytes
                .checked_add(bytes)
                .ok_or(Error::Layout)?;
            actual.allocations = actual
                .allocations
                .checked_add(allocations)
                .ok_or(Error::Layout)?;
        }
        if actual.capacity_bytes != plan.capacity_bytes {
            return Err(Error::Invariant);
        }
        Ok(Self {
            config,
            flows,
            states: States::Reserved(states),
            by_id: ById::Reserved(by_id),
            qos,
            mux,
            channel_metadata,
            metadata_pool: MetadataPool::Reserved {
                slots: metadata,
                free: Some(0),
                available: config.queue.packets,
            },
            usage: QueueUsage::default(),
            storage: Some(actual),
        })
    }

    /// Actual complete retained capacity, or None for an allocating legacy owner.
    pub fn storage_usage(&self) -> Option<Usage> {
        self.storage
    }
}
