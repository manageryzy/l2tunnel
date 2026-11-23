//! Compact actual record units over the existing causal rolling byte scheduler.
//!
//! Callers retain authentication, replay, shared pacing, carrier handoff and
//! physical native completion authority. No runtime, socket or clock is created.
//! Actual functional/reserved composition stays separate from full mixed-Bank resources.

use crate::{codec, fec::rolling, record_engine};
use codec::{aligned_receiver as receiver, packed_envelope, packed_sender};
use rolling::scheduler;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// Local custody only; never authenticated, serialized or used as a nonce.
static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);
fn allocate_instance() -> Result<u64, Error> {
    NEXT_ENDPOINT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| Error::Arithmetic)
}

mod ack_lz4;
#[doc(hidden)]
pub mod compact_wire;
mod config;
use compact_wire::CompactRecovery;
mod copies;
mod deferred_feedback;
mod endpoint;
/// Bounded original lifetime observations for actual selected recovery owners.
pub mod expiry;
pub(crate) mod fin_order;
mod ingress;
mod native;
mod previewed;
#[doc(hidden)]
pub mod recovery;
mod repair_budget;
mod return_guard;
use recovery::RecoveryPolicy;
fn wire_charge(
    framing: Option<codec::FragmentConfig>,
    length: usize,
    overhead: usize,
) -> Result<(usize, usize), Error> {
    if let Some(mut framing) = framing {
        framing.outer_overhead_bytes = overhead;
        let geometry = framing.geometry(length).map_err(Error::Fragment)?;
        Ok((geometry.fragments(), geometry.wire_bytes()))
    } else {
        Ok((1, length.checked_add(overhead).ok_or(Error::Arithmetic)?))
    }
}
/// Exact backing of the actual codec, rolling schedulers and scratch owners.
pub mod storage;
#[cfg(test)]
mod tests;
/// Exact optional retained-operation refusal intervals.
pub mod waits;

pub use config::{
    Config, DirectionConfig, EffectiveRelease, GuardMode, NativeRelease, OutputFraming, ReturnGuard,
};
pub use copies::{COPY_POLICY_BYTES, CopyPolicies};
pub use endpoint::{Endpoint, OutputId, PreparedOutput, Statistics, Step};
pub use ingress::{IngressLimits, IngressStatus};
pub use l2tunnel_aligned::NativePolicy;
pub use l2tunnel_reliable::OutboundBudget;
pub use native::{DeliveryStatus, NativePreparation, NativeToken, PreparedNative};
/// Monotonic counters scoped to one receive-direction engine generation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeReorderStatus {
    /// Bounded holds opened on the first eligible ahead-of-prefix segment.
    pub starts: u64,
    /// Holds released by their immutable soft deadline.
    pub deadline_releases: u64,
    /// Episodes entering bypass after exceeding the byte span.
    pub span_releases: u64,
    /// Ahead-of-prefix payloads physically written during bypass.
    pub bypass_writes: u64,
    /// Holds closed by physically committed contiguous bytes before bypass.
    pub prefix_closes: u64,
    /// Bypass episodes closed when the delivery prefix reached their saved edge.
    pub bypass_prefix_closes: u64,
    /// Flows entering untracked delivery when the exact range ledger filled.
    pub range_overflows: u64,
}
pub use record_engine::{Context, Geometry, Tick};
pub use repair_budget::RepairBudgetStatus;
pub use return_guard::ReturnGuardStatus;

/// Explicit local admission, retained ownership or authoritative engine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Local complete geometry, policy, channel or origin is inconsistent.
    Configuration,
    /// The caller must retain and retry the same unadmitted input.
    Busy,
    /// A checked identity, timestamp or capacity cannot be represented.
    Arithmetic,
    /// Injected time moved backwards.
    Time,
    /// An original retained output or native custody deadline expired.
    Expired,
    /// Exact caller output capacity is required before consuming ownership.
    Output {
        /// Required complete capacity.
        required: usize,
    },
    /// Caller witness storage cannot contain the selected maximum.
    Witnesses {
        /// Required maximum witness count.
        required: usize,
    },
    /// No such exact pending local token is owned.
    Token,
    /// Recovered identity, source floor or output metadata disagrees.
    Identity,
    /// Received record kind violates the negotiated native interpretation.
    Policy,
    /// The maintained canonical fragment geometry refused the selected output.
    Fragment(codec::FragmentError),
    /// The maintained rolling owner returned this failure.
    Rolling(rolling::Error),
    /// The maintained timed packed sender returned this failure.
    Sender(packed_sender::Error),
    /// The maintained authenticated-unit receiver returned this failure.
    Receiver(receiver::Error),
    /// The maintained compact envelope returned this failure.
    Envelope(packed_envelope::Error),
    /// Actual fallible codec backing returned this failure.
    Storage(codec::aligned_storage::Error),
    /// Exact actual rolling scheduler backing refused construction or observation.
    RollingStorage(rolling::storage::Error),
    /// Actual bounded authenticated input custody refused admission or construction.
    Ingress(crate::native_storage::Error),
    /// Complete retained heap exceeds its original explicit allowance.
    Capacity {
        /// Complete actual requested heap capacity.
        required: usize,
        /// Original supplied allowance.
        limit: usize,
    },
    /// Actual nested/scratch capacities differ from the admitted complete plan.
    StorageInvariant,
    /// A real scratch reservation failed.
    Allocation,
}
impl Error {
    /// Whether unchanged caller-owned input can be retried after bounded service.
    pub fn is_backpressure(self) -> bool {
        matches!(
            self,
            Self::Busy
                | Self::Rolling(rolling::Error::Busy | rolling::Error::Capacity)
                | Self::Receiver(receiver::Error::Capacity | receiver::Error::RecordWindow)
        )
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rolling records: {self:?}")
    }
}
impl std::error::Error for Error {}

fn rolling_tick(now: Tick) -> rolling::Tick {
    rolling::Tick(now.0)
}
fn receiver_tick(now: Tick) -> receiver::Tick {
    receiver::Tick(now.0)
}
fn bytes(length: usize) -> Result<Vec<u8>, Error> {
    std::alloc::Layout::array::<u8>(length).map_err(|_| Error::Arithmetic)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    if bytes.capacity() != length {
        return Err(Error::Arithmetic);
    }
    bytes.resize(length, 0);
    Ok(bytes)
}
