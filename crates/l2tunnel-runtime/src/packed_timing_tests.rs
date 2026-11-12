//! Injected carrier timing tests only. Authentication is covered by real fixtures.
use super::*;
use tokio::{
    io::DuplexStream,
    sync::{mpsc, watch},
    task::JoinHandle,
};

struct Sender {
    blocked: watch::Receiver<bool>,
    emitted: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl crate::datagram::DatagramSend for Sender {
    const BOUNDARY: crate::datagram::SendBoundary =
        crate::datagram::SendBoundary::OsDatagramAccepted;
    async fn send(&mut self, bytes: &[u8]) -> io::Result<crate::datagram::DatagramSent> {
        while *self.blocked.borrow_and_update() {
            self.blocked
                .changed()
                .await
                .map_err(|_| invalid("test sender canceled"))?;
        }
        let mut packets = self
            .emitted
            .lock()
            .map_err(|_| invalid("test capture lock"))?;
        if packets.len() == 64 {
            return Err(invalid("test capture bound"));
        }
        packets.push(bytes.to_vec());
        Ok(crate::datagram::DatagramSent {
            actual_at: tokio::time::Instant::now(),
            payload_bytes: bytes.len(),
            boundary: crate::datagram::SendBoundary::OsDatagramAccepted,
        })
    }
}
struct Receiver(mpsc::Receiver<Vec<u8>>);
impl crate::datagram::DatagramReceive for Receiver {
    async fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let bytes = self
            .0
            .recv()
            .await
            .ok_or_else(|| invalid("test receiver ended"))?;
        if bytes.len() > output.len() {
            return Err(invalid("test receive bound"));
        }
        output[..bytes.len()].copy_from_slice(&bytes);
        Ok(Some(bytes.len()))
    }
}
struct Pump {
    task: Option<JoinHandle<io::Result<()>>>,
    emitted: Arc<Mutex<Vec<Vec<u8>>>>,
    input: mpsc::Sender<Vec<u8>>,
    _control: DuplexStream,
    _gate: watch::Sender<bool>,
}
impl Drop for Pump {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Pump {
    fn new(
        device: Device,
        rt: RuntimeConfig,
        transport: udp::Config,
        config: Config,
        blocked: bool,
    ) -> io::Result<Self> {
        let (control, peer) = tokio::io::duplex(8192);
        let (gate, changes) = watch::channel(blocked);
        let (input, receive) = mpsc::channel(16);
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let parts = vec![crate::datagram::DatagramParts {
            session: [65; 16],
            control,
            sender: Sender {
                blocked: changes,
                emitted: emitted.clone(),
            },
            receiver: Receiver(receive),
        }];
        Ok(Self {
            task: Some(tokio::spawn(aligned::run_parts(
                device,
                parts,
                true,
                rt,
                transport.policy()?,
                aligned::Selection::Packed(config),
            ))),
            emitted,
            input,
            _control: peer,
            _gate: gate,
        })
    }
    fn observations(&self) -> io::Result<Observations> {
        let seen = Observations::default();
        for packet in self
            .emitted
            .lock()
            .map_err(|_| invalid("test capture lock"))?
            .iter()
        {
            observe_packed(packet, &seen);
        }
        Ok(seen)
    }
    async fn cancel(mut self) -> TestResult {
        let task = self.task.take().ok_or("missing test task")?;
        task.abort();
        assert!(matches!(task.await,Err(error) if error.is_cancelled()));
        Ok(())
    }
}
async fn service() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn partial_source_wakes_before_the_later_native_poll_without_new_packets() -> TestResult {
    let mut rt = runtime(PacketLayer::Ip);
    rt.poll_interval = Duration::from_millis(100);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?
    .with_recovery(udp::RecoveryMode::Cauchy {
        sources: 1,
        repairs: 1,
        flush_after: Duration::from_millis(2),
    })?;
    let config = Config::for_udp(rt, transport, 4, options(), delivery(rt))?;
    let device = Device::new(rt.layer);
    device.change(|s| s.outgoing.push_back(packet(rt.layer, 1, 64)))?;
    let pump = Pump::new(device.clone(), rt, transport, config, false)?;
    service().await;
    assert_eq!(device.change(|s| s.admitted)?, 1);
    assert_eq!(
        pump.observations()?.packed_sources.load(Ordering::Relaxed),
        0
    );
    tokio::time::advance(Duration::from_micros(500)).await;
    service().await;
    assert_eq!(
        pump.observations()?.packed_sources.load(Ordering::Relaxed),
        0
    );
    tokio::time::advance(Duration::from_millis(3)).await;
    service().await;
    let seen = pump.observations()?;
    assert!(seen.packed_sources.load(Ordering::Relaxed) > 0);
    assert_eq!(seen.packed_max_units.load(Ordering::Relaxed), 1);
    assert_eq!(device.change(|s| s.admitted)?, 1);
    pump.cancel().await
}

#[tokio::test(start_paused = true)]
async fn sealed_output_pressure_does_not_spin_or_hide_earlier_native_expiry() -> TestResult {
    let mut rt = runtime(PacketLayer::Ip);
    rt.poll_interval = Duration::from_millis(5);
    let mut transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?
    .with_recovery(udp::RecoveryMode::Cauchy {
        sources: 1,
        repairs: 1,
        flush_after: Duration::from_millis(2),
    })?;
    transport.arq.send_records = 1;
    transport.arq.initial_rto = Duration::from_millis(5);
    transport.arq.maximum_rto = Duration::from_millis(5);
    transport.arq.max_retries = 0;
    transport.reassembly_timeout = Duration::from_millis(20);
    let config = Config::for_udp(
        rt,
        transport,
        // The injected peer below has one explicit channel binding. Keep this
        // timing fixture's common classifier on that same channel.
        1,
        Options {
            max_units: 1,
            ..options()
        },
        delivery(rt),
    )?;
    let device = Device::new(rt.layer);
    device.change(|s| {
        s.blocked = true;
        s.outgoing
            .extend((1..=6).map(|seed| packet(rt.layer, seed, 64)));
    })?;
    let mut pump = Pump::new(device.clone(), rt, transport, config, true)?;
    // The independent receive owner retains a native frame while physical
    // output remains full. Its original lifetime must still terminate the actor.
    let mut peer = protocol::Endpoint::new(
        config.protocol,
        l2tunnel_recovery::RecoveryContext {
            session: u128::from_be_bytes([65; 16]),
            epoch: 1,
            role: l2tunnel_recovery::EndpointRole::Responder,
        },
    )?;
    peer.enqueue_admitted(
        l2tunnel_aligned::ChannelId(0),
        &packet(rt.layer, 99, 64),
        Duration::ZERO,
    )?;
    let mut bytes = vec![0; peer.max_packet_bytes()];
    let mut budget = l2tunnel_reliable::OutboundBudget {
        packets: 1,
        wire_bytes: 4096,
    };
    let length = peer
        .poll_data(Duration::from_millis(2), &mut bytes, &mut budget)?
        .ok_or("missing remote source")?;
    pump.input.send(bytes[..length].to_vec()).await?;
    service().await;
    tokio::time::advance(Duration::from_millis(2)).await;
    service().await;
    let before = device.change(|s| s.writes)?;
    if pump.task.as_ref().is_some_and(|task| task.is_finished()) {
        let result = pump.task.take().ok_or("missing pump")?.await?;
        return Err(io::Error::other(format!(
            "actor ended before native pressure observation: {result:?}"
        ))
        .into());
    }
    assert!(before > 0);
    service().await;
    service().await;
    assert_eq!(
        device.change(|s| s.writes)?,
        before,
        "a sealed past packing deadline must not repeatedly wake the actor"
    );
    assert!(
        pump.emitted
            .lock()
            .map_err(|_| invalid("test capture lock"))?
            .is_empty()
    );
    tokio::time::advance(Duration::from_millis(25)).await;
    service().await;
    let task = pump.task.take().ok_or("missing pump")?;
    let result = task.await?;
    assert!(
        result
            .err()
            .ok_or("expected independent expiry")?
            .to_string()
            .contains("Expired")
    );
    assert!(device.change(|s| s.delivered.is_empty())?);
    Ok(())
}
