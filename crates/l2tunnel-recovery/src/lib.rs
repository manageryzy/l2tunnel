//! Bounded real-payload selective repeat and explicit reliable-carrier forwarding.
//! FEC, fast recovery and Python wire/behavior parity remain separate work.
use std::time::Duration;

mod arq;
pub use arq::{
    ACK_PACKET_BYTES, ArqConfig, BufferSide, CarrierOnly, DATA_HEADER_BYTES, EndpointRole,
    PacketView, RecoveryContext, RecoveryError, Retained, SelectiveRepeat, SourceId, Statistics,
    inspect_packet,
};

/// Incremental recovery uses injected monotonic time and bounded caller buffers.
pub trait RecoveryEngine {
    /// Capacity, malformed feedback, generation or arithmetic failure.
    type Error;
    /// Admit a source; return its stable identity or backpressure.
    fn submit(&mut self, source: &[u8], now: Duration) -> Result<u64, Self::Error>;
    /// Consume an already authenticated received packet or feedback message.
    fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), Self::Error>;
    /// Emit at most one source/repair/feedback packet into bounded storage.
    fn poll(&mut self, now: Duration, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    /// Copy one recovered source into caller storage and return (source ID, length).
    /// Insufficient output capacity must leave the pending delivery unconsumed.
    fn poll_delivered(&mut self, output: &mut [u8]) -> Result<Option<(u64, usize)>, Self::Error>;
    /// Earliest required timer; None if there is no work.
    fn deadline(&self) -> Option<Duration>;
    /// Whether admitted work and receive delivery are drained. Selective repeat
    /// requires peer receipt; carrier-only proves local handoff, not peer receipt.
    fn drained(&self) -> bool;
}
