//! Explicit research recovery with the maintained packed record/native body.
//!
//! Both directions contain the actual complete research policies. Authentication,
//! shared MUX/pacing and whole physical receipts remain with the enclosing owner.
//! No legacy scheduler or second recovery/codec state machine is constructed.

pub use crate::rolling_records::{
    Error, IngressLimits, IngressStatus, NativePolicy, NativePreparation, NativeToken,
    OutputFraming, OutputId, PreparedNative, PreparedOutput, Statistics, Step,
};
/// Complete codec and actual research policy for one global direction.
pub type DirectionConfig = crate::rolling_records::DirectionConfig<crate::fec::research::Config>;
/// Both complete research directions, geometry and original native cap.
pub type Config = crate::rolling_records::Config<crate::fec::research::Config>;
/// The same record body instantiated with the actual maintained research owners.
pub type Endpoint = crate::rolling_records::Endpoint<crate::fec::research::Config>;
/// Exact heap plans and observations for the actual selected owners.
pub mod storage {
    pub use crate::rolling_records::storage::{Limits, Usage};
    /// Complete research sender/receiver plus codec/scratch/ingress heap preflight.
    pub type Plan = crate::rolling_records::storage::Plan<crate::fec::research::Config>;
}
