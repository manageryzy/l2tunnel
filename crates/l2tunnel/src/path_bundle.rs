//! Point-to-point native packet striping. The runtime supplies authenticated
//! path bindings, a negotiated coding profile, actual handoff receipts and time.
mod receive;
mod transmit;

pub use receive::{ReceiveError, Receiver};
pub use transmit::{
    Error as TransmitError, MemberState, ReceiptEvidence, RecoveryStage, Transmitter,
};

#[cfg(test)]
mod receive_tests;
