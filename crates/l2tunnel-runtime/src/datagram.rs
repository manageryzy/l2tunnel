//! Common runtime datagram I/O boundary; concrete adapters retain their owners.
use std::{future::Future, io};
use tokio::time::Instant;

/// Successful maintained handoff; neither variant proves remote device delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendBoundary {
    /// Complete protected UDP datagram accepted by the local OS socket.
    OsDatagramAccepted,
    /// Complete protected datagram accepted by QUIC's maintained send facility.
    /// This is congestion-controlled handoff, not a physical OS/NIC send proof.
    QuicDatagramAccepted,
}
/// Scalar receipt captured at actual adapter success, before actor/channel delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatagramSent {
    /// Original maintained handoff instant; never waiter wake/observer time.
    pub actual_at: Instant,
    /// Exact input payload accepted; excludes adapter-specific outer wire overhead.
    pub payload_bytes: usize,
    /// Explicit semantics of the originating adapter's maintained handoff.
    pub boundary: SendBoundary,
}
impl DatagramSent {
    /// Check exact input ownership and original time before forwarding completion.
    pub fn validate(
        self,
        expected: usize,
        boundary: SendBoundary,
        observed: Instant,
    ) -> io::Result<Instant> {
        if self.payload_bytes != expected || self.boundary != boundary || self.actual_at > observed
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram completion length, boundary or clock",
            ));
        }
        Ok(self.actual_at)
    }
}
/// Owned asynchronous carrier sender, returning its original successful boundary.
pub(crate) trait DatagramSend: Send + 'static {
    /// Immutable handoff semantics of this validated carrier adapter.
    const BOUNDARY: SendBoundary;
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<DatagramSent>> + Send;
}
/// Owned asynchronous carrier receiver; parser/protection remain in its adapter.
pub(crate) trait DatagramReceive: Send + 'static {
    fn receive(
        &mut self,
        output: &mut [u8],
    ) -> impl Future<Output = io::Result<Option<usize>>> + Send;
}
/// Actual authenticated carrier owners consumed by a runtime data/control pump.
pub(crate) struct DatagramParts<C, S, R> {
    pub session: [u8; 16],
    pub control: C,
    pub sender: S,
    pub receiver: R,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_payload_boundary_and_future_time_cannot_publish_completion() {
        let at = Instant::now();
        let receipt = DatagramSent {
            actual_at: at,
            payload_bytes: 7,
            boundary: SendBoundary::OsDatagramAccepted,
        };
        assert!(
            receipt
                .validate(6, SendBoundary::OsDatagramAccepted, at)
                .is_err()
        );
        assert!(
            receipt
                .validate(7, SendBoundary::QuicDatagramAccepted, at)
                .is_err()
        );
        assert!(
            DatagramSent {
                actual_at: at + std::time::Duration::from_millis(1),
                ..receipt
            }
            .validate(7, SendBoundary::OsDatagramAccepted, at)
            .is_err()
        );
        assert_eq!(
            receipt
                .validate(7, SendBoundary::OsDatagramAccepted, at)
                .ok(),
            Some(at)
        );
    }
}
