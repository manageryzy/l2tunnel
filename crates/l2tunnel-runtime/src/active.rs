//! Fixed-bootstrap transparent active TUN on authenticated full/paired TCP links.
//! Native completion releases credit; endpoint TCP bytes/windows remain unchanged.
use super::{Compression, Duplex, Link, PacketDevice, PacketLayer, RuntimeConfig, invalid};
use l2tunnel_active::observation::{self, Observer as Measurements};
use l2tunnel_active::{
    Active, ActiveConfig, Capacity, Credit, Direction, ExternalDrain, Micros, RetirementPolicy,
    TargetConfig,
};
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::ConfigDigest;
use l2tunnel_flow_control::wire::WIRE_LEN;
use l2tunnel_packet::{FlowKey, classify};
use l2tunnel_pipeline::{
    FlowTableConfig, Mapping, ParseLimits, PipelineConfig, PipelineError, Profile, QueueLimits,
    TunQosConfig,
};
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};

pub(super) const HEADER_BYTES: usize = 40;
pub(super) const CONTROL_SLOTS: usize = 8;
pub(super) const WORK: usize = 32;
const MAX_WEIGHT: u32 = 1024;

/// Negotiated TUN policy with an explicit optional measured-growth profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Enable authenticated real demand/timing/native-delivery target feedback.
    pub adaptive: bool,
    /// Original authenticated bulk-lane arrangement.
    pub duplex: Duplex,
    /// Finite flow registrations per direction, with one MTU reserved per slot.
    pub max_flows: usize,
    /// CRC-affinity MUX channel count.
    pub channels: u16,
    /// Base per-flow byte quantum.
    pub base_quantum_bytes: u32,
    /// Trusted DSCP multipliers; the first admitted packet fixes a flow's weight.
    pub dscp_weights: [u32; 64],
    /// Maximum control/heartbeat records per second and initial burst per writer.
    pub control_packets_per_second: u32,
    /// Maximum idle writer heartbeat spacing when control allowance is available.
    pub heartbeat_interval: Duration,
    /// Complete record read/write/flush deadline; EOF always terminates the session.
    pub io_timeout: Duration,
    /// Idle age before requesting an authenticated drained flow retirement.
    pub idle_flow_timeout: Duration,
    /// Minimum spacing between finite immutable Final retries.
    pub retirement_retry: Duration,
    /// Total Final attempt allowance, including the initial barrier.
    pub retirement_max_attempts: u32,
}
impl Settings {
    /// Construct bounded static floor/regrant defaults for the native queue budget.
    pub fn new(runtime: RuntimeConfig, duplex: Duplex) -> io::Result<Self> {
        let value = Self {
            adaptive: false,
            duplex,
            max_flows: runtime.queue_packets.min(32),
            channels: 4,
            base_quantum_bytes: u32::try_from(runtime.max_packet).map_err(io::Error::other)?,
            dscp_weights: [1; 64],
            control_packets_per_second: 256,
            heartbeat_interval: Duration::from_secs(1),
            io_timeout: Duration::from_secs(30),
            idle_flow_timeout: Duration::from_secs(60),
            retirement_retry: Duration::from_secs(1),
            retirement_max_attempts: 8,
        };
        value.validate(runtime)?;
        Ok(value)
    }
    fn validate(self, runtime: RuntimeConfig) -> io::Result<()> {
        runtime.validate()?;
        if runtime.layer != PacketLayer::Ip
            || self.max_flows == 0
            || self.max_flows > runtime.queue_packets
            || self.max_flows > 1024
            || !(1..=256).contains(&self.channels)
            || self.base_quantum_bytes == 0
            || self.base_quantum_bytes > 65_535
            || self
                .dscp_weights
                .iter()
                .any(|weight| !(1..=MAX_WEIGHT).contains(weight))
            || !(2..=4096).contains(&self.control_packets_per_second)
            || self.heartbeat_interval < Duration::from_secs(1)
            || self.io_timeout > Duration::from_secs(120)
            || self.heartbeat_interval > self.io_timeout / 3
            || !(Duration::from_millis(1)..=Duration::from_secs(86_400))
                .contains(&self.idle_flow_timeout)
            || !(Duration::from_millis(1)..=Duration::from_secs(30))
                .contains(&self.retirement_retry)
            || !(1..=32).contains(&self.retirement_max_attempts)
            || self
                .retirement_retry
                .checked_mul(self.retirement_max_attempts)
                .is_none_or(|total| total > Duration::from_secs(120))
        {
            return Err(invalid("invalid static active-TUN settings"));
        }
        nanos(self.heartbeat_interval)?;
        nanos(self.io_timeout)?;
        let active = Active::new(
            self.engine_config(runtime, 0)?,
            Direction::Forward,
            Micros(0),
        )
        .map_err(io::Error::other)?;
        if self.adaptive {
            Measurements::new(self.observation_config(runtime)?, &active, Micros(0))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
    pub(super) fn observation_config(
        self,
        runtime: RuntimeConfig,
    ) -> io::Result<observation::Config> {
        let cap = Credit {
            bytes: u64::try_from(
                runtime
                    .max_packet
                    .checked_mul(runtime.queue_packets)
                    .ok_or_else(|| invalid("active observation cap overflow"))?,
            )
            .map_err(io::Error::other)?,
            records: runtime.queue_packets as u64,
        };
        let burst = self.control_packets_per_second / 2;
        let cycle = (self.max_flows as u64 + 2).div_ceil(u64::from(burst.max(1)));
        Ok(observation::Config {
            publication_micros: 100_000,
            demand_ttl_micros: cycle * 3_000_000,
            probe_interval_micros: cycle * 1_000_000,
            probe_timeout_micros: cycle * 2_000_000,
            measurement_ttl_micros: cycle * 3_000_000,
            rate_window_micros: 10_000,
            output_interval_micros: 1_000_000,
            output_burst: burst,
            peer_queue: cap,
            peer_retained: cap,
        })
    }
    pub(super) fn engine_config(
        self,
        runtime: RuntimeConfig,
        session: u128,
    ) -> io::Result<ActiveConfig> {
        let queue = QueueLimits {
            bytes: runtime
                .max_packet
                .checked_mul(runtime.queue_packets)
                .ok_or_else(|| invalid("active queue overflow"))?,
            packets: runtime.queue_packets,
        };
        let floor = Credit {
            bytes: u64::try_from(
                runtime
                    .max_packet
                    .checked_mul(self.max_flows)
                    .ok_or_else(|| invalid("active floor overflow"))?,
            )
            .map_err(io::Error::other)?,
            records: self.max_flows as u64,
        };
        let cap = Credit {
            bytes: queue.bytes as u64,
            records: queue.packets as u64,
        };
        Ok(ActiveConfig {
            session,
            epoch: 1,
            pipeline: PipelineConfig {
                profile: Profile::TunDrr(TunQosConfig {
                    base_quantum_bytes: self.base_quantum_bytes,
                    max_weight: MAX_WEIGHT,
                    per_flow: queue,
                }),
                flows: FlowTableConfig {
                    capacity: self.max_flows,
                    channels: self.channels,
                    mapping: Mapping::Crc32,
                    idle_timeout: self.idle_flow_timeout,
                },
                parse: ParseLimits {
                    max_packet_bytes: runtime.max_packet,
                    ..ParseLimits::default()
                },
                queue,
            },
            send_capacity: Capacity {
                credit: cap,
                max_flows: self.max_flows,
            },
            receive_capacity: Capacity {
                credit: cap,
                max_flows: self.max_flows,
            },
            target: TargetConfig {
                initial: floor,
                minimum: floor,
                session_cap: cap,
                per_flow_cap: cap,
                policy_cap: cap,
                queue_allowance_bytes: cap.bytes,
                max_flows: self.max_flows,
                ..TargetConfig::default()
            },
        })
    }
}
fn nanos(value: Duration) -> io::Result<u64> {
    u64::try_from(value.as_nanos()).map_err(|_| invalid("active duration overflow"))
}
pub(super) fn micros(value: Duration) -> io::Result<Micros> {
    Ok(Micros(
        u64::try_from(value.as_micros()).map_err(|_| invalid("active clock exhausted"))?,
    ))
}

/// Exact initial binding required on every authenticated physical lane.
pub fn session_config(runtime: RuntimeConfig, settings: Settings) -> io::Result<SessionConfig> {
    settings.validate(runtime)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/active-runtime/v3/retirement-observation/active-wire-v1/frame-v1\0");
    hash.update(&[
        u8::from(settings.adaptive),
        if settings.duplex == Duplex::Half {
            1
        } else {
            2
        },
        if runtime.compression == Compression::None {
            0
        } else {
            1
        },
    ]);
    for value in [
        runtime.max_packet as u64,
        runtime.queue_packets as u64,
        nanos(runtime.poll_interval)?,
        settings.max_flows as u64,
        u64::from(settings.channels),
        u64::from(settings.base_quantum_bytes),
        u64::from(settings.control_packets_per_second),
        nanos(settings.heartbeat_interval)?,
        nanos(settings.io_timeout)?,
        nanos(settings.idle_flow_timeout)?,
        nanos(settings.retirement_retry)?,
        u64::from(settings.retirement_max_attempts),
    ] {
        hash.update(&value.to_be_bytes());
    }
    for weight in settings.dscp_weights {
        hash.update(&weight.to_be_bytes());
    }
    // Bind derived policy values too: a future default change must not silently
    // negotiate a different controller under an unchanged settings digest.
    let target = settings.engine_config(runtime, 0)?.target;
    for value in [
        target.initial.bytes,
        target.initial.records,
        target.minimum.bytes,
        target.minimum.records,
        target.session_cap.bytes,
        target.session_cap.records,
        target.per_flow_cap.bytes,
        target.per_flow_cap.records,
        target.policy_cap.bytes,
        target.policy_cap.records,
        target.queue_allowance_bytes,
        target.queue_delay_target_micros,
        target.many_flow_step.bytes,
        target.many_flow_step.records,
        target.few_flow_threshold as u64,
        target.max_flows as u64,
        target.bootstrap_rtt_micros,
        target.recovery_rtts,
    ] {
        hash.update(&value.to_be_bytes());
    }
    if settings.adaptive {
        let observations = settings.observation_config(runtime)?;
        for value in [
            observations.publication_micros,
            observations.demand_ttl_micros,
            observations.probe_interval_micros,
            observations.probe_timeout_micros,
            observations.measurement_ttl_micros,
            observations.rate_window_micros,
            observations.output_interval_micros,
            u64::from(observations.output_burst),
            observations.peer_queue.bytes,
            observations.peer_queue.records,
            observations.peer_retained.bytes,
            observations.peer_retained.records,
        ] {
            hash.update(&value.to_be_bytes());
        }
    }
    Ok(SessionConfig {
        layer: PacketLayer::Ip,
        digest: ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("active digest size"))?,
        ),
    })
}

/// Coalesced local observation; physical flush and native delivery are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// False after the owning runtime ends, including cancellation or peer failure.
    pub running: bool,
    /// Real engine-owned logical and memory observations.
    pub engine: l2tunnel_active::Status,
    /// Original native packets accepted into the common DRR/MUX queue.
    pub admitted: u64,
    /// User records completely written and flushed to the authenticated bulk stream.
    pub flushed: u64,
    /// Actual successful local native writes followed by exact credit confirmation.
    pub delivered: u64,
    /// At most one native packet waiting for bounded pipeline admission.
    pub pending_native: bool,
    /// User records transferred to the bounded writer path, before actual flush.
    pub handed: u64,
    /// Credit-control records transferred to the bounded writer path.
    pub control_handed: u64,
    /// Credit-control records completely written and flushed to TLS.
    pub control_flushed: u64,
    /// Source flows whose exact FinalAck completed the frozen retirement.
    pub retired_flows: u64,
    /// Whether authenticated optional measured feedback is enabled.
    pub adaptive: bool,
    /// Latest fresh measured inputs; absent values never qualify growth.
    pub feedback: l2tunnel_flow_control::target::Feedback,
    /// Fresh remote flows with actual queued demand.
    pub demanding_flows: usize,
    /// Optional records transferred to the writer path.
    pub observation_handed: u64,
    /// Optional records actually flushed to TLS.
    pub observation_flushed: u64,
}
/// Read-only local observations; no reconfiguration or peer-control injection API.
#[derive(Clone)]
pub struct Observer {
    state: watch::Receiver<Option<Status>>,
}
impl Observer {
    /// Latest local state, or None before validated runtime initialization.
    pub fn status(&self) -> Option<Status> {
        *self.state.borrow()
    }
    /// Subscribe to coalesced changes without unbounded event retention.
    pub fn subscribe(&self) -> watch::Receiver<Option<Status>> {
        self.state.clone()
    }
}
/// Unique status owner passed to run; drops mark the latest observation stopped.
pub struct Reporter {
    updates: watch::Sender<Option<Status>>,
}
impl Drop for Reporter {
    fn drop(&mut self) {
        self.updates.send_modify(|snapshot| {
            if let Some(snapshot) = snapshot {
                snapshot.running = false;
            }
        });
    }
}
/// Allocate one bounded status snapshot, without starting a runtime or opening I/O.
pub fn observations() -> (Observer, Reporter) {
    let (updates, state) = watch::channel(None);
    (Observer { state }, Reporter { updates })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LaneMode {
    Mixed,
    Bulk,
    Control,
}
pub(super) struct Frame {
    pub(super) kind: u8,
    pub(super) channel: u16,
    pub(super) body: Vec<u8>,
}
pub(super) enum Event {
    Control(Vec<u8>),
    Data(u16, Vec<u8>),
    Observation(Vec<u8>),
    Management(Vec<u8>),
}

pub(super) fn header(
    frame: &Frame,
    sequence: u64,
    session: [u8; 16],
) -> io::Result<[u8; HEADER_BYTES]> {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"L2AC");
    bytes[4] = 1;
    bytes[5] = frame.kind;
    bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16..32].copy_from_slice(&session);
    bytes[32..36].copy_from_slice(
        &u32::try_from(frame.body.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    bytes[36..38].copy_from_slice(&frame.channel.to_be_bytes());
    Ok(bytes)
}
fn parse_header(
    bytes: &[u8; HEADER_BYTES],
    sequence: u64,
    session: [u8; 16],
    mode: LaneMode,
    maximum: usize,
    channels: u16,
) -> io::Result<(u8, u16, usize)> {
    parse_header_profile(bytes, sequence, session, mode, maximum, channels, false)
}
fn parse_header_profile(
    bytes: &[u8; HEADER_BYTES],
    sequence: u64,
    session: [u8; 16],
    mode: LaneMode,
    maximum: usize,
    channels: u16,
    management: bool,
) -> io::Result<(u8, u16, usize)> {
    let actual_sequence = u64::from_be_bytes(bytes[8..16].try_into().map_err(io::Error::other)?);
    let length = u32::from_be_bytes(bytes[32..36].try_into().map_err(io::Error::other)?) as usize;
    let channel = u16::from_be_bytes(bytes[36..38].try_into().map_err(io::Error::other)?);
    if &bytes[..4] != b"L2AC"
        || bytes[4] != 1
        || bytes[6..8] != [0; 2]
        || bytes[38..40] != [0; 2]
        || actual_sequence != sequence
        || bytes[16..32] != session
        || channel >= channels
    {
        return Err(invalid("active stream header/context/sequence"));
    }
    match (bytes[5], length, mode) {
        (1, WIRE_LEN, LaneMode::Mixed | LaneMode::Control) if channel == 0 => {}
        (2, length, LaneMode::Mixed | LaneMode::Bulk)
            if (WIRE_LEN + l2tunnel_codec::FRAME_HEADER_BYTES..=maximum).contains(&length) => {}
        (3, 0, _) if channel == 0 => {}
        (4, observation::WIRE_LEN, LaneMode::Mixed | LaneMode::Control) if channel == 0 => {}
        (5, length, LaneMode::Mixed | LaneMode::Control)
            if management
                && channel == 0
                && (l2tunnel_management::HEADER_LEN..=4096).contains(&length) => {}
        _ => return Err(invalid("active kind/lane/length")),
    }
    Ok((bytes[5], channel, length))
}
async fn read_lane(
    reader: impl AsyncRead + Unpin,
    mode: LaneMode,
    session: [u8; 16],
    maximum: usize,
    settings: Settings,
    control: mpsc::Sender<Event>,
    data: mpsc::Sender<Event>,
) -> io::Result<()> {
    read_lane_profile(
        reader,
        mode,
        session,
        maximum,
        ReadProfile {
            settings,
            management: false,
        },
        control,
        data,
    )
    .await
}
pub(super) struct ReadProfile {
    pub(super) settings: Settings,
    pub(super) management: bool,
}
pub(super) async fn read_lane_profile(
    mut reader: impl AsyncRead + Unpin,
    mode: LaneMode,
    session: [u8; 16],
    maximum: usize,
    profile: ReadProfile,
    control: mpsc::Sender<Event>,
    data: mpsc::Sender<Event>,
) -> io::Result<()> {
    let settings = profile.settings;
    let mut sequence = 0_u64;
    loop {
        let event = timeout(settings.io_timeout, async {
            let mut bytes = [0; HEADER_BYTES];
            reader.read_exact(&mut bytes).await?;
            let (kind, channel, length) = if profile.management {
                parse_header_profile(&bytes, sequence, session, mode, maximum, 256, true)?
            } else {
                parse_header(&bytes, sequence, session, mode, maximum, settings.channels)?
            };
            if kind == 4 && !settings.adaptive {
                return Err(invalid("unnegotiated active observation"));
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).await?;
            Ok::<_, io::Error>(match kind {
                1 => Some(Event::Control(body)),
                2 => Some(Event::Data(channel, body)),
                4 => Some(Event::Observation(body)),
                5 => Some(Event::Management(body)),
                _ => None,
            })
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "active read deadline"))??;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("active stream sequence exhausted"))?;
        if let Some(event) = event {
            let sender = if matches!(
                event,
                Event::Control(_) | Event::Observation(_) | Event::Management(_)
            ) {
                &control
            } else {
                &data
            };
            sender
                .send(event)
                .await
                .map_err(|_| invalid("active event consumer closed"))?;
        }
    }
}

async fn optional_recv(receiver: &mut Option<mpsc::Receiver<Frame>>) -> Option<Frame> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}
fn try_frame(receiver: &mut Option<mpsc::Receiver<Frame>>) -> Option<Frame> {
    receiver
        .as_mut()
        .and_then(|receiver| receiver.try_recv().ok())
}
fn mandatory_frame(
    controls: &mut Option<mpsc::Receiver<Frame>>,
    management: &mut Option<mpsc::Receiver<Frame>>,
    prefer_management: bool,
) -> Option<Frame> {
    if prefer_management {
        try_frame(management).or_else(|| try_frame(controls))
    } else {
        try_frame(controls).or_else(|| try_frame(management))
    }
}
pub(super) struct ControlWriter {
    pub(super) flushed: watch::Sender<u64>,
    pub(super) observations: Option<(mpsc::Receiver<Frame>, watch::Sender<u64>)>,
    pub(super) management: Option<(mpsc::Receiver<Frame>, watch::Sender<u64>)>,
}
impl From<watch::Sender<u64>> for ControlWriter {
    fn from(flushed: watch::Sender<u64>) -> Self {
        Self {
            flushed,
            observations: None,
            management: None,
        }
    }
}
pub(super) async fn write_lane(
    mut writer: impl AsyncWrite + Unpin,
    session: [u8; 16],
    settings: Settings,
    mut controls: Option<mpsc::Receiver<Frame>>,
    mut data: Option<mpsc::Receiver<Frame>>,
    flushed: Option<watch::Sender<u64>>,
    control: Option<ControlWriter>,
) -> io::Result<()> {
    let (
        control_flushed,
        mut observations,
        observation_flushed,
        mut management,
        management_flushed,
    ) = match control {
        Some(control) => {
            let (observations, observation_flushed) = control
                .observations
                .map_or((None, None), |(rx, tx)| (Some(rx), Some(tx)));
            let (management, management_flushed) = control
                .management
                .map_or((None, None), |(rx, tx)| (Some(rx), Some(tx)));
            (
                Some(control.flushed),
                observations,
                observation_flushed,
                management,
                management_flushed,
            )
        }
        None => (None, None, None, None, None),
    };
    let mut management_delivered = 0_u64;
    let mut prefer_management = false;
    let mut refill_at = Instant::now() + Duration::from_secs(1);
    let mut heartbeat = interval(settings.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    heartbeat.tick().await;
    let mut allowance = settings.control_packets_per_second;
    let mut sequence = 0_u64;
    let mut delivered = 0_u64;
    let mut controls_delivered = 0_u64;
    let mut observations_delivered = 0_u64;
    let mut optional_allowance = settings.control_packets_per_second / 2;
    let mut prefer_control = true;
    loop {
        // Service refill even when continuously ready data avoids the select path.
        if Instant::now() >= refill_at {
            allowance = settings.control_packets_per_second;
            optional_allowance = settings.control_packets_per_second / 2;
            refill_at = Instant::now() + Duration::from_secs(1);
        }
        let ready = if prefer_control && allowance > 0 {
            mandatory_frame(&mut controls, &mut management, prefer_management).or_else(|| {
                if optional_allowance > 0 {
                    try_frame(&mut observations)
                } else {
                    None
                }
            })
        } else {
            None
        }
        .or_else(|| try_frame(&mut data))
        .or_else(|| {
            if allowance > 0 {
                mandatory_frame(&mut controls, &mut management, prefer_management)
            } else {
                None
            }
        })
        .or_else(|| {
            if allowance > 0 && optional_allowance > 0 {
                try_frame(&mut observations)
            } else {
                None
            }
        });
        let frame = if let Some(frame) = ready {
            frame
        } else {
            tokio::select! {
                biased;
                frame = optional_recv(&mut controls), if allowance > 0 => frame.ok_or_else(|| invalid("active control producer closed"))?,
                frame = optional_recv(&mut management), if allowance > 0 => frame.ok_or_else(|| invalid("active management producer closed"))?,
                frame = optional_recv(&mut data) => frame.ok_or_else(|| invalid("active data producer closed"))?,
                frame = optional_recv(&mut observations), if allowance > 0 && optional_allowance > 0 => frame.ok_or_else(|| invalid("active observation producer closed"))?,
                _ = tokio::time::sleep_until(refill_at) => continue,
                _ = heartbeat.tick(), if allowance > 0 => Frame { kind: 3, channel: 0, body: Vec::new() },
            }
        };
        if frame.kind != 2 {
            allowance -= 1;
        }
        if frame.kind == 4 {
            optional_allowance -= 1;
        }
        if matches!(frame.kind, 1 | 5) {
            prefer_management = frame.kind == 1;
        }
        prefer_control = frame.kind == 2;
        let bytes = header(&frame, sequence, session)?;
        timeout(settings.io_timeout, async {
            writer.write_all(&bytes).await?;
            writer.write_all(&frame.body).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "active writer deadline"))??;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("active stream sequence exhausted"))?;
        if frame.kind == 2 {
            delivered = delivered
                .checked_add(1)
                .ok_or_else(|| invalid("active flush counter exhausted"))?;
            if let Some(flushed) = &flushed {
                flushed.send_replace(delivered);
            }
        } else if frame.kind == 1 {
            controls_delivered = controls_delivered
                .checked_add(1)
                .ok_or_else(|| invalid("active control flush counter exhausted"))?;
            if let Some(flushed) = &control_flushed {
                flushed.send_replace(controls_delivered);
            }
        } else if frame.kind == 5 {
            management_delivered = management_delivered
                .checked_add(1)
                .ok_or_else(|| invalid("management flush counter exhausted"))?;
            if let Some(flushed) = &management_flushed {
                flushed.send_replace(management_delivered);
            }
        } else if frame.kind == 4 {
            observations_delivered = observations_delivered
                .checked_add(1)
                .ok_or_else(|| invalid("active observation flush counter exhausted"))?;
            if let Some(flushed) = &observation_flushed {
                flushed.send_replace(observations_delivered);
            }
        }
    }
}

pub(super) fn logical_session(
    link: &Link,
    binding: SessionConfig,
    settings: Settings,
) -> io::Result<([u8; 16], Direction)> {
    let (authenticated, role, duplex) = link
        .managed_metadata
        .as_ref()
        .ok_or_else(|| invalid("missing authenticated active metadata"))?
        .snapshot();
    if authenticated != binding
        || duplex != settings.duplex
        || link.layer != PacketLayer::Ip
        || (duplex == Duplex::Half)
            != (link.reverse_reader.is_some() && link.reverse_writer.is_some())
    {
        return Err(invalid(
            "active link differs from authenticated configuration",
        ));
    }
    let direction = if role == super::managed::Role::Client {
        Direction::Forward
    } else {
        Direction::Reverse
    };
    let (forward, reverse) = if direction == Direction::Forward {
        (link.send_session, link.receive_session)
    } else {
        (link.receive_session, link.send_session)
    };
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/active-runtime/logical-session/v1\0");
    hash.update(&binding.digest.0);
    hash.update(&[if duplex == Duplex::Half { 1 } else { 2 }]);
    hash.update(&forward);
    hash.update(&reverse);
    Ok((
        hash.finish().as_ref()[..16]
            .try_into()
            .map_err(io::Error::other)?,
        direction,
    ))
}

pub(super) fn weight_for(packet: &[u8], settings: Settings) -> u32 {
    let dscp = match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet[1] >> 2,
        Some(6) => ((packet[0] & 15) << 2) | (packet[1] >> 6),
        _ => 0,
    };
    settings.dscp_weights[usize::from(dscp)]
}

#[derive(Default)]
pub(super) struct ExternalOutputs {
    pub(super) data: u64,
    pub(super) control: u64,
    pub(super) observation: u64,
}
impl ExternalOutputs {
    pub(super) fn drain(
        &self,
        data_flushed: u64,
        control_flushed: u64,
        observation_flushed: u64,
        queued: usize,
    ) -> io::Result<ExternalDrain> {
        let unflushed = self
            .data
            .checked_sub(data_flushed)
            .and_then(|data| {
                self.control
                    .checked_sub(control_flushed)
                    .and_then(|control| data.checked_add(control))
            })
            .and_then(|pending| {
                self.observation
                    .checked_sub(observation_flushed)
                    .and_then(|observation| pending.checked_add(observation))
            })
            .ok_or_else(|| invalid("active flush watermark exceeds transferred ownership"))?;
        let pending_outputs = usize::try_from(unflushed)
            .map_err(io::Error::other)?
            .checked_add(queued)
            .ok_or_else(|| invalid("active external output overflow"))?;
        Ok(ExternalDrain {
            pending_outputs,
            // This TCP-only adapter has no caller-owned ARQ/FEC/retry records.
            // Native Release proves peer consumption; kernel TCP retransmits the
            // same stream bytes and cannot create another application record.
            pending_recovery_records: 0,
        })
    }
}

/// Run fixed-bootstrap transparent TUN on the original authenticated TCP lanes.
/// Idle source flows retire only after external flush and exact peer FinalAck.
/// Optional measured target growth requires the authenticated adaptive setting.
/// This has no hot-switch endpoint.
/// All EOF/errors fail the link; cancellation drops every child socket task.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    mut link: Link,
    runtime: RuntimeConfig,
    settings: Settings,
    reporter: Option<Reporter>,
) -> io::Result<()> {
    let binding = session_config(runtime, settings)?;
    let (session, direction) = logical_session(&link, binding, settings)?;
    if device.layer() != PacketLayer::Ip {
        return Err(invalid("active runtime requires TUN IP"));
    }
    let config = settings.engine_config(runtime, u128::from_be_bytes(session))?;
    let mut engine = Active::new(config, direction, Micros(0)).map_err(io::Error::other)?;
    let mut measurements = settings
        .adaptive
        .then(|| {
            Measurements::new(settings.observation_config(runtime)?, &engine, Micros(0))
                .map_err(io::Error::other)
        })
        .transpose()?;
    let mut feedback = l2tunnel_flow_control::target::Feedback::default();
    let mut demanding_flows = 0;
    let codec = runtime.codec()?;
    let maximum = WIRE_LEN + codec.max_encoded_len();
    let (control_tx, mut control_rx) = mpsc::channel(CONTROL_SLOTS);
    let (data_tx, mut data_rx) = mpsc::channel(runtime.queue_packets);
    let (out_control, control_output) = mpsc::channel(CONTROL_SLOTS);
    let (out_data, data_output) = mpsc::channel(runtime.queue_packets);
    let (out_observation, observation_output) = mpsc::channel(CONTROL_SLOTS);
    let (flush_tx, flush_rx) = watch::channel(0);
    let (control_flush_tx, control_flush_rx) = watch::channel(0);
    let (observation_flush_tx, observation_flush_rx) = watch::channel(0);
    let control_writer = ControlWriter {
        flushed: control_flush_tx,
        observations: Some((observation_output, observation_flush_tx)),
        management: None,
    };
    let mut tasks = JoinSet::new();
    if settings.duplex == Duplex::Half {
        let reverse_reader = link
            .reverse_reader
            .take()
            .ok_or_else(|| invalid("missing control reader"))?;
        let reverse_writer = link
            .reverse_writer
            .take()
            .ok_or_else(|| invalid("missing control writer"))?;
        tasks.spawn(read_lane(
            link.reader,
            LaneMode::Bulk,
            session,
            maximum,
            settings,
            control_tx.clone(),
            data_tx.clone(),
        ));
        tasks.spawn(read_lane(
            reverse_reader,
            LaneMode::Control,
            session,
            maximum,
            settings,
            control_tx,
            data_tx,
        ));
        tasks.spawn(write_lane(
            link.writer,
            session,
            settings,
            None,
            Some(data_output),
            Some(flush_tx),
            None,
        ));
        tasks.spawn(write_lane(
            reverse_writer,
            session,
            settings,
            Some(control_output),
            None,
            None,
            Some(control_writer),
        ));
    } else {
        tasks.spawn(read_lane(
            link.reader,
            LaneMode::Mixed,
            session,
            maximum,
            settings,
            control_tx,
            data_tx,
        ));
        tasks.spawn(write_lane(
            link.writer,
            session,
            settings,
            Some(control_output),
            Some(data_output),
            Some(flush_tx),
            Some(control_writer),
        ));
    }
    let started = Instant::now();
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut native = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut pending = None::<Vec<u8>>;
    let mut weights = BTreeMap::<FlowKey, u32>::new();
    let mut admitted = 0_u64;
    let mut delivered = 0_u64;
    let mut external = ExternalOutputs::default();
    let mut retiring = None::<FlowKey>;
    let mut retired_flows = 0_u64;
    loop {
        let event = tokio::select! {
            Some(result) = tasks.join_next() => return match result {
                Ok(Err(error)) => Err(error), Err(error) => Err(io::Error::other(error)),
                Ok(Ok(())) => Err(invalid("active task ended unexpectedly")),
            },
            Some(event) = control_rx.recv() => Some(event),
            Some(event) = data_rx.recv() => Some(event),
            _ = ticker.tick() => None,
        };
        let now = micros(started.elapsed())?;
        if let Some(event) = event {
            match event {
                Event::Control(token) => engine
                    .receive_control(&token, now)
                    .map_err(io::Error::other)?,
                Event::Data(channel, body) => {
                    let token = body
                        .get(..WIRE_LEN)
                        .ok_or_else(|| invalid("active data token"))?;
                    let encoded = body
                        .get(WIRE_LEN..)
                        .ok_or_else(|| invalid("active data record"))?;
                    if runtime.compression == Compression::None && encoded.get(4) != Some(&0) {
                        return Err(invalid("active compression policy mismatch"));
                    }
                    let payload = codec.decode_vec(encoded).map_err(io::Error::other)?;
                    engine
                        .receive_data(token, channel, &payload, now)
                        .map_err(io::Error::other)?;
                }
                Event::Management(_) => return Err(invalid("unnegotiated management event")),
                Event::Observation(body) => measurements
                    .as_mut()
                    .ok_or_else(|| invalid("unnegotiated active observation event"))?
                    .receive(&engine, &body, now)
                    .map_err(io::Error::other)?,
            }
        }
        if retiring.is_some() && engine.status().pending_retirement.is_none() {
            let key = retiring
                .take()
                .ok_or_else(|| invalid("missing completed retirement key"))?;
            weights
                .remove(&key)
                .ok_or_else(|| invalid("missing retired flow weight"))?;
            retired_flows = retired_flows
                .checked_add(1)
                .ok_or_else(|| invalid("active retirement counter exhausted"))?;
        }
        let mut native_pressure = false;
        for _ in 0..WORK {
            let Some(delivery) = engine.delivery() else {
                break;
            };
            match device.transmit(delivery.payload) {
                Ok(()) => {
                    let record = delivery.record;
                    if settings.adaptive {
                        engine
                            .confirm_delivery_at(record, now)
                            .map_err(io::Error::other)?;
                    } else {
                        engine.confirm_delivery(record).map_err(io::Error::other)?;
                    }
                    delivered = delivered
                        .checked_add(1)
                        .ok_or_else(|| invalid("active delivered counter exhausted"))?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    native_pressure = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(measurements) = &mut measurements {
            // Suspend publication while an exact Final is pending. Incoming
            // observations still run, and any finite Pong remains serviceable.
            if retiring.is_none() {
                measurements.tick(&engine, now).map_err(io::Error::other)?;
            }
            let observed = measurements
                .feedback(&engine, now)
                .map_err(io::Error::other)?;
            feedback = observed.feedback;
            feedback.receiver_pressure = native_pressure;
            demanding_flows = observed.demanding.len();
            engine
                .update_targets(now, feedback, &observed.demanding)
                .map_err(io::Error::other)?;
        }
        for _ in 0..WORK {
            if pending.is_none() {
                match device.receive(&mut native) {
                    Ok(Some(length)) if length <= runtime.max_packet => {
                        pending = Some(native[..length].to_vec())
                    }
                    Ok(Some(_)) => {
                        return Err(invalid("active native packet exceeds configured maximum"));
                    }
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            let packet = pending
                .as_ref()
                .ok_or_else(|| invalid("missing pending native packet"))?;
            let key = classify(PacketLayer::Ip, packet, config.pipeline.parse)
                .map_err(io::Error::other)?
                .key;
            let weight = weights
                .get(&key)
                .copied()
                .unwrap_or_else(|| weight_for(packet, settings));
            match engine.enqueue_ip(packet, weight, now) {
                Ok(_) => {
                    weights.insert(key, weight);
                    pending = None;
                    admitted = admitted
                        .checked_add(1)
                        .ok_or_else(|| invalid("active admission counter exhausted"))?;
                }
                Err(
                    l2tunnel_active::Error::Pipeline(
                        PipelineError::Budget(_)
                        | PipelineError::Flow(l2tunnel_packet::FlowError::Capacity),
                    )
                    | l2tunnel_active::Error::FlowFrozen,
                ) => break,
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        for _ in 0..WORK {
            let Ok(permit) = out_control.try_reserve() else {
                break;
            };
            let Some(token) = engine.poll_control().map_err(io::Error::other)? else {
                break;
            };
            permit.send(Frame {
                kind: 1,
                channel: 0,
                body: token.to_vec(),
            });
            external.control = external
                .control
                .checked_add(1)
                .ok_or_else(|| invalid("active control handoff counter exhausted"))?;
        }
        for _ in 0..WORK {
            let Ok(permit) = out_data.try_reserve() else {
                break;
            };
            let Some(data) = engine.poll_data().map_err(io::Error::other)? else {
                break;
            };
            let encoded = codec.encode_vec(&data.payload).map_err(io::Error::other)?;
            let mut body = Vec::with_capacity(WIRE_LEN + encoded.len());
            body.extend_from_slice(&data.token);
            body.extend_from_slice(&encoded);
            permit.send(Frame {
                kind: 2,
                channel: data.channel,
                body,
            });
            external.data = external
                .data
                .checked_add(1)
                .ok_or_else(|| invalid("active data handoff counter exhausted"))?;
        }
        let control_flushed = *control_flush_rx.borrow();
        let data_flushed = *flush_rx.borrow();
        let observation_flushed = *observation_flush_rx.borrow();
        // All prior Opens must have entered the mandatory writer queue. That
        // queue has strict priority over observations on the same writer; a
        // selected Open completes before another record can start.
        if engine.status().pending_controls == 0
            && let Some(measurements) = &mut measurements
        {
            for _ in 0..WORK {
                let Ok(permit) = out_observation.try_reserve() else {
                    break;
                };
                let Some(body) = measurements.poll_output(now).map_err(io::Error::other)? else {
                    break;
                };
                permit.send(Frame {
                    kind: 4,
                    channel: 0,
                    body: body.to_vec(),
                });
                external.observation = external
                    .observation
                    .checked_add(1)
                    .ok_or_else(|| invalid("active observation handoff counter exhausted"))?;
            }
        }
        // A dequeued writer record remains external until its full TLS flush.
        if control_flushed == external.control {
            engine.poll_retirement(now).map_err(io::Error::other)?;
        }
        if retiring.is_none()
            && let Some(key) = engine.idle_candidate(now).map_err(io::Error::other)?
        {
            let pending_same_key = pending
                .as_ref()
                .map(|packet| {
                    classify(PacketLayer::Ip, packet, config.pipeline.parse)
                        .map(|packet| packet.key == key)
                })
                .transpose()
                .map_err(io::Error::other)?
                .unwrap_or(false);
            let queued = (out_data.max_capacity() - out_data.capacity())
                + (out_control.max_capacity() - out_control.capacity())
                + (out_observation.max_capacity() - out_observation.capacity())
                + measurements
                    .as_ref()
                    .map_or(0, Measurements::pending_outputs);
            let drain =
                external.drain(data_flushed, control_flushed, observation_flushed, queued)?;
            if !pending_same_key && drain.pending_outputs == 0 {
                match engine.request_idle_retirement(
                    &key,
                    now,
                    RetirementPolicy {
                        retry_micros: micros(settings.retirement_retry)?.0,
                        max_attempts: settings.retirement_max_attempts,
                    },
                    drain,
                ) {
                    Ok(_) => retiring = Some(key),
                    Err(l2tunnel_active::Error::Credit(
                        l2tunnel_flow_control::CreditError::OutstandingRecords,
                    )) => {}
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
        }
        if let Some(reporter) = &reporter {
            reporter.updates.send_replace(Some(Status {
                running: true,
                engine: engine.status(),
                admitted,
                flushed: *flush_rx.borrow(),
                delivered,
                pending_native: pending.is_some(),
                handed: external.data,
                control_handed: external.control,
                control_flushed,
                retired_flows,
                adaptive: settings.adaptive,
                feedback,
                demanding_flows,
                observation_handed: external.observation,
                observation_flushed,
            }));
        }
    }
}

#[cfg(test)]
#[path = "active_tests.rs"]
mod tests;
