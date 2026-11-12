//! Canonical records and bounded actual-table ownership, without authentication.
//!
//! The owner stages authoritative demand counters and explicit probes, but exposes
//! no delivery-rate or RTT samples by itself. The optional pure measured
//! Controller owns that record path and actual table observations; runtime
//! dispatch remains separate work and parsing never establishes peer authority.

mod controller;
mod owner;
pub mod wire;

pub use controller::{
    AckRate, Controller, ControllerError, LocalPressure, MeasuredConfig, MeasuredPlan,
    ObservationConfig, ObservationMemory, ObservationStatus, ServiceLatency,
};
pub use owner::{
    Error, Ingress, MemoryBound, Micros, OutputId, Owner, OwnerConfig, OwnerStatus, Pending,
};
