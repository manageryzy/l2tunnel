//! Meter CSR: named read-only registers for every runtime meter.
//!
//! A register is a u64 at a path named after its owning Rust component,
//! for example `runtime.native_ingress.lane0.user.occupancy_bytes`. The
//! [`catalog`] fixes the v1 path vocabulary, [`Table`] holds one bounded
//! sorted snapshot, [`Wait`] and [`Gauge`] are the shared meter primitives,
//! and [`wire`] encodes remote read request/reply bodies.
//!
//! This crate has no clock, I/O, runtime or randomness. Callers inject
//! monotonic ticks. An absent path means the running profile does not report
//! that meter; it is never shown as zero.
//!
//! Design: `docs/modules/meter-csr.md`.

pub mod catalog;
pub mod path;
pub mod table;
pub mod wait;
pub mod wire;

pub use path::PathError;
pub use table::{Limits, Page, Table, TableError};
pub use wait::{Extent, Gauge, Histogram, Refusals, Wait, WaitSnapshot};
