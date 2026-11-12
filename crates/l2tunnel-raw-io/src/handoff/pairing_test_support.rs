use super::*;
use std::{
    future::poll_fn,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::mpsc;
pub(super) type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Default)]
pub(super) struct Probe {
    pub blocked: AtomicBool,
    pub noise: AtomicBool,
    pub delay_ms: AtomicU64,
    pub received: AtomicUsize,
    pub sent: AtomicUsize,
    pub dropped: AtomicUsize,
    pub pending: Mutex<Option<Vec<u8>>>,
}
pub(super) struct PacketLink {
    pub incoming: mpsc::Receiver<Vec<u8>>,
    pub outgoing: mpsc::Sender<Vec<u8>>,
    pub probe: Arc<Probe>,
}
impl PacketIo for PacketLink {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        assert_eq!(out.len(), 65_536);
        self.probe.received.fetch_add(1, Ordering::SeqCst);
        let ms = self.probe.delay_ms.load(Ordering::SeqCst);
        if ms != 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
        if self.probe.noise.load(Ordering::SeqCst) {
            out[..12].fill(0);
            return Ok(Some(12));
        }
        match self.incoming.try_recv() {
            Ok(bytes) => {
                out[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.probe.blocked.load(Ordering::SeqCst) {
            let mut pending = self
                .probe
                .pending
                .lock()
                .map_err(|_| io::Error::other("fixture lock"))?;
            if let Some(old) = pending.as_ref() {
                assert_eq!(old, packet);
            } else {
                *pending = Some(packet.to_vec());
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.outgoing
            .try_send(packet.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        self.probe.sent.fetch_add(1, Ordering::SeqCst);
        self.probe
            .pending
            .lock()
            .map_err(|_| io::Error::other("fixture lock"))?
            .take();
        Ok(())
    }
}
impl Drop for PacketLink {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
pub(super) fn raw(client: bool, lane: u16) -> Config {
    let a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 91), 43001 + lane * 2);
    let b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 92), 43002 + lane * 2);
    Config {
        local: if client { a } else { b },
        peer: if client { b } else { a },
        mtu: 576,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 8,
        random_seed: if client {
            0x3131 + u64::from(lane)
        } else {
            0x4242 + u64::from(lane)
        },
        ack_delay_millis: 1,
        keepalive_millis: 1000,
        idle_timeout_millis: 30_000,
    }
}
pub(super) fn config() -> PairConfig {
    PairConfig {
        session: SessionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            digest: ConfigDigest([0x61; 32]),
        },
        messages: MessageLimits::default(),
        driver: SwitchLimits::default(),
        timeout: Duration::from_secs(10),
    }
}
pub(super) fn fixture() -> R<(ClientTls, ServerTls, MemberKey, MemberAllowlist)> {
    let cert = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowed = MemberAllowlist::new(&[member.public_key()])?;
    Ok((
        ClientTls::from_der_roots(&chain)?,
        ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        member,
        allowed,
    ))
}
pub(super) fn inputs(
    half: bool,
) -> (
    RawInputs<PacketLink>,
    RawInputs<PacketLink>,
    Vec<Arc<Probe>>,
) {
    let mut probes = Vec::new();
    let mut lane = |index| {
        let (at, br) = mpsc::channel(64);
        let (bt, ar) = mpsc::channel(64);
        let a = Arc::new(Probe::default());
        let b = Arc::new(Probe::default());
        probes.push(a.clone());
        probes.push(b.clone());
        (
            RawInput {
                config: raw(true, index),
                io: PacketLink {
                    incoming: ar,
                    outgoing: at,
                    probe: a,
                },
            },
            RawInput {
                config: raw(false, index),
                io: PacketLink {
                    incoming: br,
                    outgoing: bt,
                    probe: b,
                },
            },
        )
    };
    let (a, b) = lane(0);
    if half {
        let (c, d) = lane(1);
        (
            RawInputs::Half {
                forward: a,
                reverse: c,
            },
            RawInputs::Half {
                forward: b,
                reverse: d,
            },
            probes,
        )
    } else {
        (RawInputs::Full(a), RawInputs::Full(b), probes)
    }
}
pub(super) async fn paired(
    half: bool,
) -> R<(
    PairedRaw<PacketLink>,
    PairedRaw<PacketLink>,
    Vec<Arc<Probe>>,
)> {
    let (c, s, m, allowed) = fixture()?;
    let (a, b, probes) = inputs(half);
    let mut a = begin_pair_client(a, &c, "tunnel.test", &m, config())?;
    let mut b = begin_pair_server(b, &s, &allowed, config())?;
    let (mut ar, mut br) = (None, None);
    // Ready transfers each still-live original driver to PairedRaw. Service it
    // while the other peer finishes; Ready is deliberately not all-peer Armed.
    poll_fn(|cx| {
        for (setup, owner) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(ready) = owner {
                if let Poll::Ready(Err(e)) = PairedRaw::poll_progress(ready, cx) {
                    return Poll::Ready(Err(e));
                }
            } else if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                *owner = Some(result?);
            }
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok((
        ar.ok_or("client absent")?,
        br.ok_or("server absent")?,
        probes,
    ))
}
pub(super) async fn transfer(
    a: &mut PairedRaw<PacketLink>,
    b: &mut PairedRaw<PacketLink>,
    lane: PairLane,
    bytes: &[u8],
) -> R {
    a.stage_message(lane, bytes)?;
    poll_fn(|cx| {
        if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if b.message(lane) == Some(bytes)
            && a.status().messages[lane.index()].is_some_and(|m| !m.send_pending)
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok(())
}
