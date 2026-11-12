use super::*;
use l2tunnel_packet::{FlowTable, FlowTableConfig, Mapping};
use l2tunnel_qos::{ClassConfig, ClassId, FlowConfig, FlowId, Scheduler, SchedulerConfig};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Owner {
    Transparent(usize),
    Proxy(u64),
    Measurement(measured::Id),
    NativeTransparent,
    NativeProxy(u64),
}
#[derive(Clone, Copy, Debug)]
struct Meta {
    owner: Owner,
    channel: u16,
    serial: u64,
    admitted_at: Duration,
}
pub(super) struct Selected {
    pub owner: Owner,
    pub channel: u16,
    pub bytes: Vec<u8>,
}
pub(super) struct Rejected {
    pub pressure: bool,
    pub error: io::Error,
}
pub(super) struct Arbiter {
    flows: FlowTable,
    qos: Scheduler,
    meta: BTreeMap<u64, VecDeque<Meta>>,
    channels: Vec<VecDeque<(u64, u64)>>,
    next: u64,
    wire_charge: usize,
}
impl Arbiter {
    pub fn new(config: &Config, native: bool) -> io::Result<Self> {
        let policy = &config.mux;
        let bytes = if native {
            config.delivery.native_queue_bytes
        } else {
            policy.queue_bytes
        };
        let packets = if native {
            config.delivery.native_queue_packets
        } else {
            policy.queue_records
        };
        let maximum = if native {
            config.runtime.max_packet
        } else {
            config.max_user()? + 48
        };
        let qos = Scheduler::new(
            SchedulerConfig {
                base_quantum_bytes: policy.quantum_bytes,
                max_classes: 1,
                max_flows: policy.max_flow_bindings,
                max_packet_bytes: maximum,
                max_queued_bytes: bytes,
                max_queued_packets: packets,
                per_flow_bytes: if native { bytes } else { policy.per_flow_bytes },
                per_flow_packets: if native {
                    packets
                } else {
                    policy.per_flow_records
                },
            },
            &[ClassConfig {
                id: ClassId::new(0),
                weight: 1,
            }],
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            flows: FlowTable::new(FlowTableConfig {
                capacity: policy.max_flow_bindings,
                channels: policy.channels,
                mapping: Mapping::Crc32,
                idle_timeout: Duration::from_secs(60),
            })
            .map_err(io::Error::other)?,
            qos,
            meta: BTreeMap::new(),
            channels: vec![VecDeque::new(); policy.channels as usize],
            next: 0,
            wire_charge: if native { 0 } else { 48 },
        })
    }
    pub fn channel(&self, key: FlowKey, now: Duration) -> io::Result<u16> {
        Ok(self
            .flows
            .preview_assign(key, now)
            .map_err(io::Error::other)?
            .channel)
    }
    pub fn push(
        &mut self,
        key: FlowKey,
        weight: u16,
        body: Vec<u8>,
        owner: Owner,
        now: Duration,
    ) -> Result<(), Rejected> {
        let error = |_bytes: Vec<u8>, error, pressure| Rejected { error, pressure };
        let transaction = match self.flows.prepare_assign(key, now) {
            Ok(value) => value,
            Err(e) => return Err(error(body, io::Error::other(e), false)),
        };
        let binding = transaction.binding();
        let id = binding.id.0;
        let new = !self.meta.contains_key(&id);
        let Some(next) = self.next.checked_add(1) else {
            return Err(error(body, invalid("proxy scheduler ID exhausted"), false));
        };
        if new
            && let Err(e) = self.qos.register_flow(FlowConfig {
                id: FlowId::new(id),
                class: ClassId::new(0),
                weight: u32::from(weight),
            })
        {
            return Err(error(body, io::Error::other(e), false));
        }
        let mut charged = vec![0; self.wire_charge];
        charged.extend_from_slice(&body);
        if let Err(e) = self.qos.enqueue(FlowId::new(id), charged) {
            if new {
                let _ = self.qos.remove_flow(FlowId::new(id));
            }
            let pressure = matches!(
                e.kind,
                l2tunnel_qos::AdmissionErrorKind::GlobalBytes
                    | l2tunnel_qos::AdmissionErrorKind::GlobalPackets
                    | l2tunnel_qos::AdmissionErrorKind::FlowBytes
                    | l2tunnel_qos::AdmissionErrorKind::FlowPackets
            );
            return Err(error(
                body,
                io::Error::other(format!("proxy shared admission: {:?}", e.kind)),
                pressure,
            ));
        }
        transaction.commit();
        self.meta.entry(id).or_default().push_back(Meta {
            owner,
            channel: binding.channel,
            serial: self.next,
            admitted_at: now,
        });
        self.channels[binding.channel as usize].push_back((id, self.next));
        self.next = next;
        Ok(())
    }
    pub fn pop<F>(&mut self, mut eligible: F) -> io::Result<Option<Selected>>
    where
        F: FnMut(Owner, usize) -> bool,
    {
        let meta = &self.meta;
        let channels = &self.channels;
        let mut bad = false;
        let head = self
            .qos
            .peek_eligible(|id, n| {
                let Some(m) = meta.get(&id.value()).and_then(|q| q.front()) else {
                    bad = true;
                    return false;
                };
                channels[m.channel as usize].front() == Some(&(id.value(), m.serial))
                    && eligible(m.owner, n - self.wire_charge)
            })
            .map_err(io::Error::other)?;
        if bad {
            return Err(invalid("proxy scheduler metadata"));
        }
        let Some(head) = head else {
            return Ok(None);
        };
        let packet = self
            .qos
            .dequeue_peeked()
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("proxy scheduler selection lost"))?;
        let m = self
            .meta
            .get_mut(&head.flow.value())
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| invalid("proxy scheduler ownership"))?;
        if self.channels[m.channel as usize].pop_front() != Some((head.flow.value(), m.serial)) {
            return Err(invalid("proxy channel FIFO"));
        }
        Ok(Some(Selected {
            owner: m.owner,
            channel: m.channel,
            bytes: packet.payload[self.wire_charge..].to_vec(),
        }))
    }
    pub fn usage(&self) -> (usize, usize) {
        (self.qos.queued_bytes(), self.qos.queued_packets())
    }
    pub fn oldest_age(&self, now: Duration) -> io::Result<Duration> {
        self.meta
            .values()
            .filter_map(|q| q.front())
            .map(|m| {
                now.checked_sub(m.admitted_at)
                    .ok_or_else(|| invalid("proxy queue time regressed"))
            })
            .try_fold(Duration::ZERO, |a, b| Ok(a.max(b?)))
    }
}
