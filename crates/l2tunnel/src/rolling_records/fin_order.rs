//! Prevent early native TCP delivery from acknowledging a local half-close across older data.
use super::{DirectionConfig, Error, NativePolicy, RecoveryPolicy};
use l2tunnel_packet::{FlowKey, PacketKind, PacketLayer, ParseLimits, classify};

const FIN: u16 = 1;
const SYN: u16 = 2;
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
        end,
        ack,
    })
}

pub(super) struct Guard {
    fences: Vec<Fence>,
    // An untracked FIN must never evict another live fence. On overflow, only
    // colliding flows require ordered ACKs until this generation is retired.
    ordered_buckets: u64,
}

impl Guard {
    fn slots<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        if direction.scheduler.targeted()
            && direction.receiver.body.independent_short_frame_bytes > 0
        {
            usize::from(direction.receiver.channels).max(16)
        } else {
            0
        }
    }
    pub(super) fn planned_bytes<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        Self::slots(direction) * size_of::<Fence>()
    }
    pub(super) fn new<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> Result<Self, Error> {
        let mut fences = Vec::new();
        fences
            .try_reserve_exact(Self::slots(direction))
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            fences,
            ordered_buckets: 0,
        })
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        self.fences.capacity() * size_of::<Fence>()
    }
    pub(super) fn active(&self) -> bool {
        !self.fences.is_empty() || self.ordered_buckets != 0
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
    pub(super) fn may_deliver_early(&self, policy: NativePolicy, bytes: &[u8]) -> bool {
        match packet(policy, bytes) {
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
