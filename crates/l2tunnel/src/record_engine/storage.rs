//! Complete actual backing of one common Engine; external I/O stays separate.
use super::*;
use std::mem::size_of;

/// Explicit inline-plus-heap allowance for the complete Engine owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete actual owner capacity, without allocator/RSS/kernel overhead.
    pub capacity_bytes: usize,
}

/// Observed retained layouts, including all idle nested backing exactly once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original complete allowance.
    pub limit_bytes: usize,
    /// Actual inline Engine, including Pipeline and selected record headers.
    pub fixed_bytes: usize,
    /// Actual complete Pipeline heap.
    pub pipeline_bytes: usize,
    /// Actual selected record heap, excluding its already inline header.
    pub record_bytes: usize,
    /// Exact fixed plus nested heap layouts.
    pub capacity_bytes: usize,
    /// Explicit successful nonzero constructor reservations.
    pub allocations: usize,
}

/// Construction failures, distinct from live record processing errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing complete configuration, capabilities or geometry refused.
    Engine(super::Error),
    /// Actual complete common queue construction failed.
    Pipeline(pipeline::storage::Error),
    /// Actual single Swift backing failed.
    Swift(swift::storage::Error),
    /// Actual Aligned/Packed backing failed.
    Aligned(aligned::storage::Error),
    /// Actual complete codec/rolling/scratch backing refused.
    Rolling(rolling_records::Error),
    /// A complete layout or allocation count cannot be represented.
    Layout,
    /// Complete actual owner exceeds its explicit allowance.
    Limit {
        /// Required complete capacity.
        required: usize,
        /// Supplied complete allowance.
        limit: usize,
    },
    /// Actual nested observations disagree with the complete plan.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "common record storage: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)] // Bounded pure plans require no allocating indirection.
enum RecordPlan {
    Swift(swift::storage::Plan),
    Aligned(aligned::storage::Plan),
    Packed(aligned::storage::Plan),
    AlignedCompact(aligned::compact_storage::Plan),
    PackedCompact(aligned::compact_storage::Plan),
    Rolling(rolling_records::storage::Plan),
}
impl RecordPlan {
    fn for_engine(config: &configuration::Configuration, context: Context) -> Result<Self, Error> {
        if let configuration::Profile::Rolling { config, stream } = config.descriptor().profile() {
            return rolling_records::storage::Plan::for_endpoint(
                *config,
                context,
                *stream,
                Tick(0),
            )
            .map(Self::Rolling)
            .map_err(Error::Rolling);
        }
        if let configuration::Profile::RollingCopies {
            config,
            stream,
            copies,
        } = config.descriptor().profile()
        {
            return rolling_records::storage::Plan::for_endpoint_with_copies(
                *config,
                context,
                *stream,
                Tick(0),
                *copies,
            )
            .map(Self::Rolling)
            .map_err(Error::Rolling);
        }
        let local = config.descriptor().local(context.role);
        match (local.send().profile(), local.receive().profile()) {
            (
                configuration::DirectionProfile::Swift(send),
                configuration::DirectionProfile::Swift(receive),
            ) => swift::storage::Plan::for_engine(*send, *receive)
                .map(Self::Swift)
                .map_err(Error::Swift),
            (
                configuration::DirectionProfile::Aligned(send),
                configuration::DirectionProfile::Aligned(receive),
            ) => aligned::storage::Plan::for_duplex(*send, *receive)
                .map(Self::Aligned)
                .map_err(Error::Aligned),
            (
                configuration::DirectionProfile::Packed(send),
                configuration::DirectionProfile::Packed(receive),
            ) => aligned::storage::Plan::for_packed_duplex(*send, *receive)
                .map(Self::Packed)
                .map_err(Error::Aligned),
            (
                configuration::DirectionProfile::AlignedCompact(send),
                configuration::DirectionProfile::AlignedCompact(receive),
            ) => aligned::compact_storage::Plan::for_duplex(*send, *receive)
                .map(Self::AlignedCompact)
                .map_err(Error::Aligned),
            (
                configuration::DirectionProfile::PackedCompact(send),
                configuration::DirectionProfile::PackedCompact(receive),
            ) => aligned::compact_storage::Plan::for_packed_duplex(*send, *receive)
                .map(Self::PackedCompact)
                .map_err(Error::Aligned),
            _ => Err(Error::Engine(super::Error::Configuration)),
        }
    }
    fn heap_bytes(self) -> usize {
        match self {
            Self::Swift(plan) => plan.capacity_bytes(),
            Self::Aligned(plan) | Self::Packed(plan) => plan.capacity_bytes(),
            Self::AlignedCompact(plan) | Self::PackedCompact(plan) => plan.capacity_bytes(),
            Self::Rolling(plan) => plan.capacity_bytes(),
        }
    }
    fn construct(self, context: Context) -> Result<Owner, Error> {
        let recovery = owner::recovery_context(context);
        match self {
            Self::Swift(plan) => {
                let capacity_bytes = size_of::<swift::storage::Owned>()
                    .checked_add(plan.capacity_bytes())
                    .ok_or(Error::Layout)?;
                swift::storage::Owned::new(plan, swift::storage::Limits { capacity_bytes })
                    .map(Owner::Swift)
                    .map_err(Error::Swift)
            }
            Self::Aligned(plan) => aligned::Endpoint::new_duplex_reserved(
                plan.send_config(),
                plan.receive_config(),
                recovery,
                aligned::storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
            .map(Owner::Aligned)
            .map_err(Error::Aligned),
            Self::Packed(plan) => aligned::packed::Endpoint::new_duplex_reserved(
                plan.send_packed().ok_or(Error::Invariant)?,
                plan.receive_packed().ok_or(Error::Invariant)?,
                recovery,
                aligned::storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
            .map(Owner::Packed)
            .map_err(Error::Aligned),
            Self::AlignedCompact(plan) => aligned::Endpoint::new_compact_duplex_reserved(
                plan.send_config(),
                plan.receive_config(),
                recovery,
                aligned::storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
            .map(Owner::Aligned)
            .map_err(Error::Aligned),
            Self::PackedCompact(plan) => aligned::packed::Endpoint::new_compact_duplex_reserved(
                plan.send_packed().ok_or(Error::Invariant)?,
                plan.receive_packed().ok_or(Error::Invariant)?,
                recovery,
                aligned::storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
            .map(Owner::Packed)
            .map_err(Error::Aligned),
            Self::Rolling(plan) => rolling_records::Endpoint::new_reserved_with_copies(
                plan,
                rolling_records::storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )
            .map(Owner::Rolling)
            .map_err(Error::Rolling),
        }
    }
}

/// Validated complete immutable Engine policy and actual nested layouts.
#[derive(Clone, Copy)]
pub struct Plan {
    configuration: configuration::Configuration,
    context: Context,
    geometry: Geometry,
    native_limits: NativeLimits,
    parameters: Parameters,
    pipeline: pipeline::storage::Plan,
    record: RecordPlan,
    heap_bytes: usize,
    capacity_bytes: usize,
}
impl Plan {
    /// Validate actual capabilities/geometry and every nested layout without allocation.
    pub fn for_engine(
        configuration: configuration::Configuration,
        context: Context,
        geometry: Geometry,
        native_limits: NativeLimits,
    ) -> Result<Self, Error> {
        let parameters =
            parameters(&configuration, context, geometry, native_limits).map_err(Error::Engine)?;
        let local = configuration.descriptor().local(context.role);
        let pipeline = pipeline::storage::Plan::for_pipeline(local.send().common().pipeline())
            .map_err(Error::Pipeline)?;
        let record = RecordPlan::for_engine(&configuration, context)?;
        let heap_bytes = pipeline
            .capacity_bytes()
            .checked_add(record.heap_bytes())
            .ok_or(Error::Layout)?;
        let capacity_bytes = size_of::<Engine>()
            .checked_add(heap_bytes)
            .ok_or(Error::Layout)?;
        Ok(Self {
            configuration,
            context,
            geometry,
            native_limits,
            parameters,
            pipeline,
            record,
            heap_bytes,
            capacity_bytes,
        })
    }
    /// Exact complete canonical configuration, without clamping or omitted fields.
    pub const fn configuration(&self) -> &configuration::Configuration {
        &self.configuration
    }
    /// Exact trusted local origin labels, without authentication authority.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Exact full-wire directional overhead inputs.
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Exact external native custody policy.
    pub const fn native_limits(&self) -> NativeLimits {
        self.native_limits
    }
    /// Complete actual nested heap, excluding the outer inline Engine.
    pub const fn heap_bytes(&self) -> usize {
        self.heap_bytes
    }
    /// Complete actual inline-plus-heap owner capacity.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

impl Engine {
    /// Construct actual reserved queues and one actual reserved record owner.
    ///
    /// External packet I/O, buffers, pacing/duplex and authenticated control remain
    /// separate required owners. No allocating compatibility fallback is used.
    pub fn new_reserved(plan: Plan, limits: Limits) -> Result<Self, Error> {
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let pipeline = pipeline::Pipeline::new_reserved(
            plan.pipeline.config(),
            pipeline::storage::Limits {
                capacity_bytes: plan.pipeline.capacity_bytes(),
            },
        )
        .map_err(Error::Pipeline)?;
        let mut owner = plan.record.construct(plan.context)?;
        owner
            .enable_carrier_confirmation(&plan.configuration)
            .map_err(Error::Engine)?;
        let p = pipeline.storage_usage().ok_or(Error::Invariant)?;
        let (record_bytes, record_allocations) = owner.storage_heap().ok_or(Error::Invariant)?;
        if p.capacity_bytes != plan.pipeline.capacity_bytes()
            || record_bytes != plan.record.heap_bytes()
        {
            return Err(Error::Invariant);
        }
        let allocations = p
            .allocations
            .checked_add(record_allocations)
            .ok_or(Error::Layout)?;
        let usage = Usage {
            limit_bytes: limits.capacity_bytes,
            fixed_bytes: size_of::<Self>(),
            pipeline_bytes: p.capacity_bytes,
            record_bytes,
            capacity_bytes: plan.capacity_bytes,
            allocations,
        };
        Ok(Self::assemble(
            plan.configuration,
            plan.context,
            plan.native_limits,
            plan.parameters,
            pipeline,
            owner,
            Some(usage),
        ))
    }

    /// Actual complete retained backing, or None for explicit functional construction.
    pub const fn storage_usage(&self) -> Option<Usage> {
        self.usage
    }
}
