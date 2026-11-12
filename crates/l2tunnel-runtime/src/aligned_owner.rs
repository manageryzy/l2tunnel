//! Private selection of one authoritative codec/recovery owner in the shared actor.
use super::*;

#[derive(Clone, Copy)]
pub(crate) enum Selection {
    Aligned(Config),
    Packed(crate::packed::Config),
}
impl Selection {
    pub(super) fn base(self) -> Config {
        match self {
            Self::Aligned(c) => c,
            Self::Packed(c) => c.base(),
        }
    }
    pub(super) fn validate(self, runtime: RuntimeConfig, policy: DatagramPolicy) -> io::Result<()> {
        match self {
            Self::Aligned(c) => c.validate(runtime, policy),
            Self::Packed(c) => c.validate(runtime, policy),
        }
    }
    pub(super) fn control_magic(self) -> [u8; 4] {
        match self {
            Self::Aligned(_) => *b"L2A2",
            Self::Packed(_) => *b"L2P2",
        }
    }
    pub(super) fn burst_limit(self) -> usize {
        match self {
            Self::Aligned(_) => 0,
            Self::Packed(c) => c.protocol.work_limit,
        }
    }
    pub(super) fn unit_limit(self) -> usize {
        match self {
            Self::Aligned(_) => 1,
            Self::Packed(c) => usize::from(c.protocol.max_units),
        }
    }
    pub(super) fn endpoint(self, context: RecoveryContext) -> io::Result<Endpoint> {
        match self {
            Self::Aligned(c) => protocol::Endpoint::new(c.protocol, context)
                .map(Box::new)
                .map(Endpoint::Aligned),
            Self::Packed(c) => protocol::packed::Endpoint::new(c.protocol, context)
                .map(Box::new)
                .map(Endpoint::Packed),
        }
        .map_err(io::Error::other)
    }
}
pub(super) enum Endpoint {
    Aligned(Box<protocol::Endpoint>),
    Packed(Box<protocol::packed::Endpoint>),
}
// Both public endpoints have exactly the same admission/recovery/native lifecycle.
// This forwarding layer does not own a second queue, timer or retry state machine.
macro_rules! forward {
    ($(fn $name:ident(&mut self $(, $arg:ident: $ty:ty)*) -> $result:ty;)+) => {
        $(pub(super) fn $name(&mut self, $($arg: $ty),*) -> $result {
            match self { Self::Aligned(e) => e.$name($($arg),*), Self::Packed(e) => e.$name($($arg),*) }
        })+
    };
}
impl Endpoint {
    forward! {
        fn tick(&mut self, now: Duration) -> Result<(), protocol::Error>;
        fn enqueue_identified(&mut self, channel: protocol::ChannelId, bytes: &[u8], now: Duration) -> Result<protocol::RecordIdentity, protocol::Error>;
        fn outgoing_units(&mut self, packet: &[u8], output: &mut [protocol::UnitWitness]) -> Result<usize, protocol::Error>;
        fn receive_authenticated(&mut self, bytes: &[u8], now: Duration) -> Result<(), protocol::Error>;
        fn prepare(&mut self, channel: protocol::ChannelId, now: Duration, work: usize) -> Result<protocol::Prepared, protocol::Error>;
        fn commit_delivery(&mut self, now: Duration) -> Result<(), protocol::Error>;
        fn poll_data(&mut self, now: Duration, output: &mut [u8], budget: &mut l2tunnel_reliable::OutboundBudget) -> Result<Option<usize>, protocol::Error>;
        fn poll_feedback(&mut self, now: Duration, output: &mut [u8], budget: &mut l2tunnel_reliable::OutboundBudget) -> Result<Option<usize>, protocol::Error>;
    }
    pub(super) fn status(&self) -> protocol::Status {
        match self {
            Self::Aligned(e) => e.status(),
            Self::Packed(e) => e.status(),
        }
    }
    pub(super) fn pending(&self) -> Option<protocol::Delivery<'_>> {
        match self {
            Self::Aligned(e) => e.pending(),
            Self::Packed(e) => e.pending(),
        }
    }
    pub(super) fn inspect_peer(
        &self,
        bytes: &[u8],
    ) -> Result<l2tunnel_reliable::RecordKind, protocol::Error> {
        match self {
            Self::Aligned(e) => e.inspect_peer(bytes),
            Self::Packed(e) => e.inspect_peer(bytes),
        }
    }
    pub(super) fn packing_wake(&self) -> Option<Duration> {
        let status = self.status().packing?.packing;
        // A sealed source retains its original deadline as evidence. Repeated
        // immediate wakeups cannot create recovery capacity. Other deadlines are
        // still serviced by the original actor ticker and all normal I/O events.
        (!status.sealed)
            .then_some(status.deadline_micros)
            .flatten()
            .map(Duration::from_micros)
    }
}
