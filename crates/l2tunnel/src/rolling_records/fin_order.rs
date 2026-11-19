//! Preserve TCP sequence continuity and local half-close ordering during independent delivery.
use super::{DirectionConfig, Error, NativePolicy, RecoveryPolicy};
use l2tunnel_packet::{FlowKey, PacketKind, PacketLayer, ParseLimits, classify};

const FIN: u16 = 1;
const SYN: u16 = 2;
const RST: u16 = 4;
const ACK: u16 = 16;
const HALF_SPACE: u32 = 1 << 31;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Key {
    flow: FlowKey,
    high: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Fence {
    returning: Key,
    fin_end: u32,
}

struct Tcp {
    source: Key,
    destination: Key,
    flags: u16,
    seq: u32,
    payload: usize,
    ports: u32,
    end: u32,
    ack: u32,
}

enum Packet {
    Tcp(Tcp),
    Other,
    Unclassified,
}

fn packet(policy: NativePolicy, bytes: &[u8]) -> Packet {
    let layer = if policy.is_ip() {
        PacketLayer::Ip
    } else {
        PacketLayer::Ethernet
    };
    let Ok(parsed) = classify(layer, bytes, ParseLimits::default()) else {
        return Packet::Unclassified;
    };
    let (Some(ip), Some(transport)) = (parsed.ip, parsed.transport) else {
        use l2tunnel_packet::OpaqueReason;
        return match parsed.kind {
            PacketKind::Fragment
                if parsed
                    .ip
                    .is_some_and(|ip| matches!(ip.protocol, 6 | 0 | 43 | 44 | 51 | 60)) =>
            {
                Packet::Unclassified
            }
            PacketKind::Opaque(
                OpaqueReason::ExtensionLimit
                | OpaqueReason::VlanDepth
                | OpaqueReason::Ipv6JumbogramUnsupported,
            ) => Packet::Unclassified,
            _ => Packet::Other,
        };
    };
    let Some(flags) = transport.tcp_flags else {
        return Packet::Other;
    };
    let offset = parsed.ethernet.map_or(0, |e| e.header_bytes) + ip.header_bytes;
    let Some(header) = bytes.get(offset + 4..offset + 12) else {
        return Packet::Unclassified;
    };
    let seq = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let ack = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let from = (ip.source, transport.source_port);
    let to = (ip.destination, transport.destination_port);
    let end = seq
        .wrapping_add(transport.payload_bytes as u32)
        .wrapping_add(u32::from(flags & SYN != 0))
        .wrapping_add(u32::from(flags & FIN != 0));
    Packet::Tcp(Tcp {
        source: Key {
            flow: parsed.key,
            high: from >= to,
        },
        destination: Key {
            flow: parsed.key,
            high: to >= from,
        },
        flags,
        seq,
        payload: transport.payload_bytes,
        ports: u32::from(transport.source_port) << 16 | u32::from(transport.destination_port),
        end,
        ack,
    })
}

const WAYS: usize = 4;
const VERSION_MAX: u64 = (u64::MAX >> 11) - 1;

#[derive(Clone, Copy)]
struct Edge {
    key: Key,
    syn: Option<u32>,
    next: u32,
    proven: bool,
    later: Option<(u32, u32)>,
    last: u64,
}
#[derive(Clone, Copy, Default)]
struct VersionedEdge {
    edge: Option<Edge>,
    version: u64,
}
#[derive(Default)]
struct Bucket {
    slots: [VersionedEdge; WAYS],
    version: u64,
}

fn bump(version: &mut u64) {
    *version = version.saturating_add(1).min(VERSION_MAX);
}
fn after(a: u32, b: u32) -> bool {
    (1..HALF_SPACE).contains(&a.wrapping_sub(b))
}
fn overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    !after(a.0, b.1) && !after(b.0, a.1)
}
impl Edge {
    fn new(tcp: &Tcp, now: u64) -> Self {
        Self {
            key: tcp.source,
            syn: (tcp.flags & SYN != 0).then_some(tcp.seq),
            next: tcp.end,
            proven: tcp.flags & SYN != 0,
            later: None,
            last: now,
        }
    }
    fn permits(self, t: &Tcp, native_reorders: bool) -> bool {
        self.proven
            && t.seq.wrapping_sub(self.next) != HALF_SPACE
            && t.end.wrapping_sub(self.next) != HALF_SPACE
            && (native_reorders || !after(t.seq, self.next))
    }
    fn commit(&mut self, t: &Tcp, now: u64) {
        self.last = now;
        if t.seq.wrapping_sub(self.next) == HALF_SPACE
            || t.end.wrapping_sub(self.next) == HALF_SPACE
        {
            self.proven = false;
            self.later = None;
            return;
        }
        if after(t.seq, self.next) {
            // One remembered out-of-order interval is enough to unblock common
            // retransmit patterns. Additional disjoint far ranges confer no credit.
            let range = (t.seq, t.end);
            self.later = Some(match self.later {
                Some(r) if overlap(r, range) => (
                    if after(r.0, range.0) { range.0 } else { r.0 },
                    if after(r.1, range.1) { r.1 } else { range.1 },
                ),
                Some(r) if after(range.0, r.0) => r,
                _ => range,
            });
        } else if after(t.end, self.next) {
            self.next = t.end;
            self.proven = true;
            if let Some((start, end)) = self.later
                && !after(start, self.next)
            {
                if after(end, self.next) {
                    self.next = end
                }
                self.later = None;
            }
        }
    }
}

impl Guard {
    fn bucket(&self, t: &Tcp) -> usize {
        // Only chooses four candidate slots. Full directional key equality
        // decides every lookup, including address, VLAN and IP version.
        ((t.ports ^ t.ports.rotate_left(13)).wrapping_mul(0x9e37_79b9) >> 16) as usize
            % self.edges.len()
    }
    fn wait(&self, index: usize, version: u64) -> super::receiver::EarlyDecision {
        use super::receiver::EarlyDecision;
        if version >= VERSION_MAX {
            EarlyDecision::Ordered
        } else {
            EarlyDecision::Wait(((version + 1) << 11) | index as u64)
        }
    }
    pub(super) fn changed(&self, token: u64) -> bool {
        let n = (token & 2047) as usize;
        let v = token >> 11;
        let Some(bucket) = self.edges.get(n / (WAYS + 1)) else {
            return false;
        };
        let slot = n % (WAYS + 1);
        let current = if slot == WAYS {
            bucket.version
        } else {
            bucket.slots[slot].version
        };
        v != current + 1
    }
    pub(super) fn decision(
        &self,
        policy: NativePolicy,
        bytes: &[u8],
        now: u64,
    ) -> super::receiver::EarlyDecision {
        self.decide_packet(packet(policy, bytes), now, false, true)
    }

    /// Linux can SACK a complete future TCP segment. Keep handshake, close,
    /// uncertain flow identity, and feedback covering a local FIN ordered.
    pub(super) fn independent_ip_decision(
        &self,
        policy: NativePolicy,
        bytes: &[u8],
        now: u64,
        short: bool,
    ) -> super::receiver::EarlyDecision {
        self.decide_packet(packet(policy, bytes), now, true, short)
    }

    fn decide_packet(
        &self,
        packet: Packet,
        now: u64,
        native_reorders: bool,
        short: bool,
    ) -> super::receiver::EarlyDecision {
        use super::receiver::EarlyDecision;
        if self.active() && !self.fin_permits(&packet) {
            return EarlyDecision::Ordered;
        }
        match packet {
            Packet::Tcp(t)
                if t.flags & SYN != 0 || (native_reorders && t.flags & (FIN | RST) != 0) =>
            {
                EarlyDecision::Ordered
            }
            Packet::Tcp(t) if t.payload != 0 => {
                let idx = self.bucket(&t);
                let bucket = &self.edges[idx];
                let base = idx * (WAYS + 1);
                for (i, s) in bucket.slots.iter().enumerate() {
                    if let Some(edge) = s.edge
                        && edge.key == t.source
                    {
                        if now.saturating_sub(edge.last) < self.lifetime
                            && edge.permits(&t, native_reorders && t.flags & ACK != 0)
                        {
                            return EarlyDecision::Allow;
                        }
                        return self.wait(base + i, s.version);
                    }
                }
                self.wait(base + WAYS, bucket.version)
            }
            Packet::Unclassified => EarlyDecision::Ordered,
            _ if short => EarlyDecision::Allow,
            _ => EarlyDecision::Ordered,
        }
    }
    pub(super) fn native_commit(
        &mut self,
        policy: NativePolicy,
        bytes: &[u8],
        early: bool,
        now: u64,
    ) {
        let Packet::Tcp(t) = packet(policy, bytes) else {
            return;
        };
        if !early && !self.fences.is_empty() && t.flags & ACK != 0 {
            self.fences
                .retain(|f| f.returning != t.source || t.ack.wrapping_sub(f.fin_end) >= HALF_SPACE);
        }
        if self.edges.is_empty() || (t.payload == 0 && t.flags & (SYN | FIN | RST) == 0) {
            return;
        }
        let idx = self.bucket(&t);
        let b = &mut self.edges[idx];
        let existing = b
            .slots
            .iter()
            .position(|s| s.edge.is_some_and(|e| e.key == t.source));
        let place = existing.or_else(|| {
            b.slots.iter().position(|s| {
                s.edge
                    .is_none_or(|e| now.saturating_sub(e.last) >= self.lifetime)
            })
        });
        let Some(i) = place else { return };
        let s = &mut b.slots[i];
        let fresh = s.edge.is_none_or(|e| {
            e.key != t.source
                || now.saturating_sub(e.last) >= self.lifetime
                || (t.flags & SYN != 0 && e.syn != Some(t.seq))
        });
        if t.flags & RST != 0 {
            if existing.is_some() {
                s.edge = None;
                bump(&mut s.version);
                bump(&mut b.version);
            }
        } else if fresh {
            if !early {
                s.edge = Some(Edge::new(&t, now));
                bump(&mut s.version);
                bump(&mut b.version);
            }
        } else if let Some(e) = &mut s.edge {
            let before = (e.next, e.proven);
            e.commit(&t, now);
            if before != (e.next, e.proven) {
                bump(&mut s.version);
            }
        }
    }
}

pub(super) struct Guard {
    fences: Vec<Fence>,
    edges: Vec<Bucket>,
    lifetime: u64,
    // An untracked FIN must never evict another live fence. On overflow, only
    // colliding flows require ordered ACKs until this generation is retired.
    ordered_buckets: u64,
}

impl Guard {
    fn slots<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        if direction.scheduler.targeted()
            && (direction.native_policy.is_ip()
                || direction.receiver.body.independent_short_frame_bytes > 0)
        {
            usize::from(direction.receiver.channels).max(16)
        } else {
            0
        }
    }
    pub(super) fn planned_bytes<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        Self::slots(direction) * (size_of::<Fence>() + size_of::<Bucket>())
    }
    pub(super) fn new<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> Result<Self, Error> {
        let mut fences = Vec::new();
        fences
            .try_reserve_exact(Self::slots(direction))
            .map_err(|_| Error::Allocation)?;
        let mut edges = Vec::new();
        edges
            .try_reserve_exact(Self::slots(direction))
            .map_err(|_| Error::Allocation)?;
        edges.resize_with(Self::slots(direction), Bucket::default);
        Ok(Self {
            fences,
            edges,
            lifetime: direction.receiver.lifetime_ticks,
            ordered_buckets: 0,
        })
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        self.fences.capacity() * size_of::<Fence>() + self.edges.capacity() * size_of::<Bucket>()
    }
    pub(super) fn active(&self) -> bool {
        !self.fences.is_empty() || self.ordered_buckets != 0
    }
    pub(super) fn allocations(&self) -> usize {
        usize::from(self.fences.capacity() > 0) + usize::from(!self.edges.is_empty())
    }
    pub(super) fn tracks_payload(&self) -> bool {
        !self.edges.is_empty()
    }
    fn remember(&mut self, fence: Fence) {
        if !self.fences.contains(&fence) {
            if self.fences.len() < self.fences.capacity() {
                self.fences.push(fence);
            } else {
                self.ordered_buckets |= 1 << (fence.returning.flow.crc32() % 64);
            }
        }
    }
    pub(super) fn admitted(&mut self, policy: NativePolicy, bytes: &[u8]) {
        if self.fences.capacity() == 0 {
            return;
        }
        if let Packet::Tcp(tcp) = packet(policy, bytes)
            && tcp.flags & FIN != 0
        {
            self.remember(Fence {
                returning: tcp.destination,
                fin_end: tcp.end,
            });
        }
    }
    #[cfg(test)]
    pub(super) fn may_deliver_early(&self, policy: NativePolicy, bytes: &[u8]) -> bool {
        self.fin_permits(&packet(policy, bytes))
    }
    fn fin_permits(&self, packet: &Packet) -> bool {
        match packet {
            Packet::Tcp(tcp) if tcp.flags & ACK != 0 => {
                (self.ordered_buckets == 0
                    || self.ordered_buckets & (1 << (tcp.source.flow.crc32() % 64)) == 0)
                    && !self.fences.iter().any(|f| {
                        f.returning == tcp.source && tcp.ack.wrapping_sub(f.fin_end) <= HALF_SPACE
                    })
            }
            Packet::Unclassified => false,
            _ => true,
        }
    }
    #[cfg(test)]
    pub(super) fn ordered_commit(&mut self, policy: NativePolicy, bytes: &[u8]) {
        if !self.fences.is_empty()
            && let Packet::Tcp(tcp) = packet(policy, bytes)
            && tcp.flags & ACK != 0
        {
            self.fences.retain(|f| {
                f.returning != tcp.source || tcp.ack.wrapping_sub(f.fin_end) >= HALF_SPACE
            });
        }
    }
    pub(super) fn inherit(&mut self, previous: &Self) {
        if self.fences.capacity() == 0 {
            return;
        }
        self.ordered_buckets |= previous.ordered_buckets;
        for fence in &previous.fences {
            self.remember(*fence)
        }
    }
}
