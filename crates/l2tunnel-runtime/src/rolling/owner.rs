use super::*;

struct Native {
    bytes: Vec<u8>,
    channel: u16,
    deadline: protocol::Tick,
    prepared: bool,
}
pub(super) struct LaneContext {
    pub session: [u8; 16],
    pub index: usize,
    pub initiator: bool,
}
pub(super) struct State {
    pub sender: Option<scheduler::Sender>,
    pub receiver: Option<scheduler::Receiver>,
    incoming_scope: protocol::Scope,
    fragmenter: Fragmenter,
    reassembly: Reassembler,
    reassembly_channel: Option<u16>,
    fragments: VecDeque<Vec<u8>>,
    native: VecDeque<Native>,
    record: Vec<u8>,
    codec: l2tunnel_codec::FrameCodec,
    pub outbound: Option<mpsc::Sender<Vec<u8>>>,
    pub feedback: watch::Sender<udp::Feedback>,
    pub admitted: u64,
    received: u64,
    delivered: u64,
    peer_delivered: u64,
    pub dropped_busy: u64,
}
impl State {
    pub fn new(
        context: LaneContext,
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        config: Config,
        feedback: watch::Sender<udp::Feedback>,
        outbound: Option<mpsc::Sender<Vec<u8>>>,
    ) -> io::Result<Self> {
        let LaneContext {
            session,
            index,
            initiator,
        } = context;
        let sends = policy.duplex == Duplex::Full || (index == 0) == initiator;
        let receives = policy.duplex == Duplex::Full || !sends;
        let scope = protocol::Scope {
            session,
            epoch: config.epoch,
            stream: config
                .stream
                .checked_add(index as u32)
                .ok_or_else(|| invalid("rolling stream exhausted"))?,
            direction: u8::from(!initiator),
        };
        let incoming_scope = protocol::Scope {
            direction: 1 - scope.direction,
            ..scope
        };
        let context = FragmentContext {
            session: SessionId(u64::from_be_bytes(
                session[..8]
                    .try_into()
                    .map_err(|_| invalid("rolling session width"))?,
            )),
            epoch: Epoch(config.epoch),
        };
        let codec = runtime.codec()?;
        let maximum = codec.max_encoded_len();
        let fragment_bytes = config.scheduler.recovery.max_payload - 2;
        let chunk = fragment_bytes - FRAGMENT_HEADER_BYTES;
        let count = u16::try_from(maximum.div_ceil(chunk))
            .map_err(|_| invalid("rolling fragment count"))?;
        Ok(Self {
            sender: sends
                .then(|| scheduler::Sender::new(config.scheduler, scope, protocol::Tick(0)))
                .transpose()
                .map_err(io::Error::other)?,
            receiver: receives
                .then(|| {
                    scheduler::Receiver::new(config.scheduler, incoming_scope, protocol::Tick(0))
                })
                .transpose()
                .map_err(io::Error::other)?,
            incoming_scope,
            fragmenter: Fragmenter::new(
                context,
                FragmentConfig {
                    path_mtu: fragment_bytes,
                    outer_overhead_bytes: 0,
                    max_message_bytes: maximum,
                    max_fragments: count,
                },
                MessageId(0),
            )
            .map_err(io::Error::other)?,
            reassembly: Reassembler::new(
                context,
                ReassemblyConfig {
                    max_message_bytes: maximum,
                    max_messages: 1,
                    max_fragment_payload_bytes: chunk as u16,
                    max_fragments_per_message: count,
                    max_total_fragments: usize::from(count),
                    max_reserved_bytes: maximum,
                    max_lifetime_ticks: ticks(policy.reassembly_timeout)?.0.max(1),
                    replay_window: 64,
                },
            )
            .map_err(io::Error::other)?,
            reassembly_channel: None,
            fragments: VecDeque::new(),
            native: VecDeque::new(),
            record: vec![0; maximum],
            codec,
            outbound,
            feedback,
            admitted: 0,
            received: 0,
            delivered: 0,
            peer_delivered: 0,
            dropped_busy: 0,
        })
    }
    pub fn control(&mut self, event: udp::ControlEvent, now: protocol::Tick) -> io::Result<()> {
        match event {
            udp::ControlEvent::Ack(bytes) => {
                self.sender
                    .as_mut()
                    .ok_or_else(|| invalid("rolling feedback on receive-only lane"))?
                    .receive_feedback_wire(&bytes, now)
                    .map_err(io::Error::other)?;
            }
            udp::ControlEvent::Credit(value) => {
                if value < self.peer_delivered || value > self.admitted {
                    return Err(invalid(
                        "rolling native credit regressed or exceeds admission",
                    ));
                }
                self.peer_delivered = value;
            }
        }
        Ok(())
    }
    pub fn data(&mut self, bytes: &[u8], now: protocol::Tick, config: Config) -> io::Result<()> {
        let scope = match protocol::wire::inspect(config.scheduler.recovery, bytes)
            .map_err(io::Error::other)?
        {
            protocol::wire::View::Source { scope, .. } => scope,
            protocol::wire::View::Repair(value) => value.scope,
        };
        if scope != self.incoming_scope {
            return Err(invalid("rolling full data scope mismatch"));
        }
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| invalid("rolling data on send-only lane"))?;
        match receiver.receive_wire(bytes, now) {
            Ok(_) => Ok(()),
            // Authenticated packets still pass full structural/domain validation.
            // A busy finite decoder is a drop, never a receipt or hidden queue.
            Err(protocol::Error::Busy) => add(&mut self.dropped_busy),
            Err(error) => Err(io::Error::other(error)),
        }
    }
    pub fn service(&mut self, now: protocol::Tick, config: Config) -> io::Result<()> {
        if !self
            .reassembly
            .expire(now.0)
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rolling original reassembly expiry",
            ));
        }
        if self
            .native
            .front()
            .is_some_and(|value| now >= value.deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rolling original native handoff expiry",
            ));
        }
        if let Some(sender) = &mut self.sender {
            sender.step(now, config.work).map_err(io::Error::other)?;
        }
        if let Some(receiver) = &mut self.receiver {
            // Capacity rejects only the candidate equation, preserving live state;
            // future systematic/tail equations may still resolve retained debt.
            receiver.step(now, config.work).map_err(io::Error::other)?;
        }
        Ok(())
    }
    pub fn admit(&mut self, item: &pipeline::Packet, runtime: RuntimeConfig) -> io::Result<bool> {
        if self.sender.is_none()
            || !self.fragments.is_empty()
            || self.admitted - self.peer_delivered >= runtime.queue_packets as u64
        {
            return Ok(false);
        }
        let encoded = self
            .codec
            .encode_vec(&item.payload)
            .map_err(io::Error::other)?;
        let batch = self
            .fragmenter
            .fragment(&encoded)
            .map_err(io::Error::other)?;
        for bytes in batch.fragments {
            let mut source = Vec::with_capacity(bytes.len() + 2);
            source.extend_from_slice(&item.metadata.binding.channel.to_be_bytes());
            source.extend_from_slice(&bytes);
            self.fragments.push_back(source);
        }
        add(&mut self.admitted)?;
        Ok(true)
    }
    pub fn submit(&mut self, now: protocol::Tick) -> io::Result<()> {
        if let Some(sender) = &mut self.sender
            && let Some(bytes) = self.fragments.front()
        {
            match sender.admit_source(bytes, now) {
                Ok(_) => {
                    self.fragments.pop_front();
                }
                Err(protocol::Error::Busy | protocol::Error::Capacity) => (),
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        Ok(())
    }
    pub fn reassemble(
        &mut self,
        runtime: RuntimeConfig,
        config: Config,
        now: protocol::Tick,
    ) -> io::Result<()> {
        let Some(receiver) = &mut self.receiver else {
            return Ok(());
        };
        if receiver.status().feedback_building {
            return Ok(());
        }
        // One pass accepts at most one decoded source, even when W sources resolve together.
        if self.native.len() >= runtime.queue_packets {
            return Ok(());
        }
        let Some((id, source)) = receiver.pending_source() else {
            return Ok(());
        };
        if source.len() <= 2 {
            return Err(invalid("rolling source lacks fragment channel"));
        }
        let channel = u16::from_be_bytes([source[0], source[1]]);
        if channel >= config.pipeline.flows.channels
            || self.reassembly_channel.is_some_and(|old| old != channel)
        {
            return Err(invalid("rolling native channel changed inside one frame"));
        }
        self.reassembly_channel = Some(channel);
        match self
            .reassembly
            .accept(&source[2..], now.0, &mut self.record)
            .map_err(io::Error::other)?
        {
            ReassemblyStatus::Pending { .. } => (),
            ReassemblyStatus::Duplicate { .. } => {
                return Err(invalid("rolling fragment replay under fresh source"));
            }
            ReassemblyStatus::Complete { message, length } => {
                if message.0 != self.received
                    || self.received - self.delivered >= runtime.queue_packets as u64
                    || (runtime.compression == super::super::Compression::None
                        && self.record.get(4) != Some(&0))
                {
                    return Err(invalid("rolling native sequence, credit or codec mismatch"));
                }
                let bytes = self
                    .codec
                    .decode_vec(&self.record[..length])
                    .map_err(io::Error::other)?;
                if !packet_valid(runtime.layer, &bytes) {
                    return Err(invalid("rolling invalid native packet"));
                }
                let deadline = protocol::Tick(
                    now.0
                        .checked_add(config.scheduler.recovery.handoff_ticks)
                        .ok_or_else(|| invalid("rolling native deadline overflow"))?,
                );
                self.native.push_back(Native {
                    bytes,
                    channel,
                    deadline,
                    prepared: false,
                });
                self.reassembly_channel = None;
                add(&mut self.received)?;
            }
        }
        receiver.confirm_handoff(id, now).map_err(io::Error::other)
    }
    pub fn deliver<D: PacketDevice<Error = io::Error>>(
        &mut self,
        device: &mut D,
        pipeline: &mut Pipeline,
        mut clock: impl FnMut() -> io::Result<protocol::Tick>,
    ) -> io::Result<()> {
        let Some(front) = self.native.front_mut() else {
            return Ok(());
        };
        let now = clock()?;
        if now >= front.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rolling original native expiry",
            ));
        }
        let delivered = self
            .delivered
            .checked_add(1)
            .ok_or_else(|| invalid("rolling native counter exhausted"))?;
        if !front.prepared {
            // A malformed inner packet or conflicting peer channel must fail
            // before native injection. Retain this prepared binding on WouldBlock.
            let key = pipeline
                .classify(&front.bytes)
                .map_err(io::Error::other)?
                .key;
            pipeline
                .learn(key, front.channel, 1, Duration::from_millis(now.0))
                .map_err(io::Error::other)?;
            front.prepared = true;
        }
        if clock()? >= front.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rolling native preparation exceeded original expiry",
            ));
        }
        let result = device.transmit(&front.bytes);
        if clock()? >= front.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "rolling native operation exceeded original expiry",
            ));
        }
        match result {
            Ok(()) => {
                self.native.pop_front();
                self.delivered = delivered;
                self.feedback
                    .send_modify(|feedback| feedback.credit = self.delivered);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
