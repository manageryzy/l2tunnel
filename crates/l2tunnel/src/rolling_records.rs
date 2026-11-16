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

#[doc(hidden)]
pub mod compact_wire;
mod config;
use compact_wire::CompactRecovery;
mod copies;
mod deferred_feedback;
mod endpoint;
mod ingress;
mod native;
#[doc(hidden)]
pub mod recovery;
use recovery::RecoveryPolicy;
/// Exact backing of the actual codec, rolling schedulers and scratch owners.
pub mod storage;
#[cfg(test)]
mod tests;

pub use config::{Config, DirectionConfig, OutputFraming};
pub use copies::{COPY_POLICY_BYTES, CopyPolicies};
pub use endpoint::{Endpoint, OutputId, PreparedOutput, Statistics, Step};
pub use ingress::{IngressLimits, IngressStatus};
pub use l2tunnel_aligned::NativePolicy;
pub use l2tunnel_reliable::OutboundBudget;
pub use native::{NativePreparation, NativeToken, PreparedNative};
pub use record_engine::{Context, Geometry, Tick};

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
