//! Bounded test-only path impairment. Production code has no registry or fault mode.
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::UdpSocket;

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Impaired,
    DropCloseAcks(usize),
    ReplayTlsAfter(Duration),
}
struct Plan {
    mode: Mode,
    observer: Observer,
}
#[derive(Clone, Default)]
pub(crate) struct Observer(Arc<Observation>);
#[derive(Default)]
struct Observation {
    quiesced: AtomicBool,
    held: AtomicBool,
    quiescence_observed: AtomicBool,
    recovery_drained: AtomicBool,
    dropped: AtomicUsize,
    dropped_user: AtomicUsize,
}
impl Observer {
    /// Stop introducing new faults only on this explicitly selected test path.
    pub fn quiesce(&self) {
        self.0.recovery_drained.store(false, Ordering::Release);
        self.0.quiesced.store(true, Ordering::Release);
    }
    pub fn dropped_user(&self) -> usize {
        self.0.dropped_user.load(Ordering::Acquire)
    }
    pub fn dropped(&self) -> usize {
        self.0.dropped.load(Ordering::Acquire)
    }
    pub fn drained(&self) -> bool {
        self.0.quiescence_observed.load(Ordering::Acquire)
            && self.0.recovery_drained.load(Ordering::Acquire)
            && !self.0.held.load(Ordering::Acquire)
    }
}
static PLANS: OnceLock<Mutex<BTreeMap<SocketAddr, Plan>>> = OnceLock::new();
static DROPPED: OnceLock<Mutex<BTreeMap<SocketAddr, usize>>> = OnceLock::new();
pub(crate) fn dropped(address: SocketAddr) -> io::Result<usize> {
    Ok(DROPPED
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| io::Error::other("test drop registry"))?
        .remove(&address)
        .unwrap_or(0))
}
pub(crate) fn install(address: SocketAddr, mode: Mode) -> io::Result<()> {
    install_observed(address, mode).map(|_| ())
}
pub(crate) fn install_observed(address: SocketAddr, mode: Mode) -> io::Result<Observer> {
    let mut plans = PLANS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| io::Error::other("test registry poisoned"))?;
    if matches!(mode, Mode::DropCloseAcks(_)) {
        let mut counts = DROPPED
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| io::Error::other("test drop registry"))?;
        if counts.len() >= 32 {
            return Err(io::Error::other("test drop count bound"));
        }
        counts.insert(address, 0);
    }
    if plans.len() >= 32 || plans.contains_key(&address) {
        return Err(io::Error::other("test plan bound/conflict"));
    }
    let observer = Observer::default();
    plans.insert(
        address,
        Plan {
            mode,
            observer: observer.clone(),
        },
    );
    Ok(observer)
}
// Dynamic bounded test gate for proving independent-lane ordering. It discards
// only already-budgeted test datagrams and leaves maintained retransmission intact.
static BLOCKED_TLS: OnceLock<Mutex<BTreeMap<SocketAddr, usize>>> = OnceLock::new();
pub(crate) fn block_tls(address: SocketAddr, blocked: bool) -> io::Result<usize> {
    let mut entries = BLOCKED_TLS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| io::Error::other("test TLS gate"))?;
    if blocked {
        if entries.len() >= 32 || entries.contains_key(&address) {
            return Err(io::Error::other("test TLS gate bound/conflict"));
        }
        entries.insert(address, 0);
        Ok(0)
    } else {
        Ok(entries.remove(&address).unwrap_or(0))
    }
}
pub(crate) struct Path {
    mode: Option<Mode>,
    observer: Observer,
    count: usize,
    held: Option<(Duration, Vec<u8>)>,
    old_tls: Option<Vec<u8>>,
    final_acks: usize,
}
impl Path {
    pub fn take(address: SocketAddr) -> io::Result<Self> {
        let plan = PLANS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| io::Error::other("test registry poisoned"))?
            .remove(&address);
        Ok(Self {
            mode: plan.as_ref().map(|p| p.mode),
            observer: plan.map_or_else(Observer::default, |p| p.observer),
            count: 0,
            held: None,
            old_tls: None,
            final_acks: 0,
        })
    }
    pub fn flush(
        &mut self,
        socket: &UdpSocket,
        peer: SocketAddr,
        now: Duration,
    ) -> io::Result<u64> {
        if self.observer.0.quiesced.load(Ordering::Acquire) {
            self.observer
                .0
                .quiescence_observed
                .store(true, Ordering::Release);
        }
        if let Some((due, bytes)) = &self.held
            && now >= *due
        {
            match socket.try_send_to(bytes, peer) {
                Ok(length) if length == bytes.len() => {
                    self.held = None;
                    self.observer.0.held.store(false, Ordering::Release);
                    return Ok(1);
                }
                Ok(_) => return Err(io::Error::other("partial impaired UDP")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(0)
    }
    /// Report actual actor recovery/bridge/output ownership after servicing it.
    pub fn observe_recovery_drain(&self, drained: bool) {
        if self.observer.0.quiesced.load(Ordering::Acquire) {
            self.observer
                .0
                .recovery_drained
                .store(drained, Ordering::Release);
        }
    }
    pub fn drained(&self) -> bool {
        self.held.is_none()
    }
    pub fn send(
        &mut self,
        socket: &UdpSocket,
        bytes: &[u8],
        peer: SocketAddr,
        now: Duration,
        closing: bool,
    ) -> io::Result<u64> {
        if matches!(bytes.first(), Some(32 | 40))
            && let Some(count) = BLOCKED_TLS
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .map_err(|_| io::Error::other("test TLS gate"))?
                .get_mut(&socket.local_addr()?)
        {
            *count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("test TLS gate count"))?;
            return Ok(0);
        }
        if let Some(Mode::DropCloseAcks(limit)) = self.mode
            && closing
            && bytes.first() == Some(&40)
            && self.final_acks < limit
        {
            self.final_acks += 1;
            if let Some(count) = DROPPED
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .map_err(|_| io::Error::other("test drop registry"))?
                .get_mut(&socket.local_addr()?)
            {
                *count += 1;
            }
            return Ok(0);
        }
        self.count += 1;
        if matches!(self.mode, Some(Mode::Impaired))
            && !self.observer.0.quiesced.load(Ordering::Acquire)
        {
            if self.count.is_multiple_of(7) {
                self.observer.0.dropped.fetch_add(1, Ordering::Release);
                // Same existing USER/control prefix split as the socket driver.
                if bytes.first() == Some(&0x48) {
                    self.observer.0.dropped_user.fetch_add(1, Ordering::Release);
                }
                return Ok(0);
            }
            if self.count.is_multiple_of(9) && self.held.is_none() {
                self.held = Some((now + Duration::from_millis(12), bytes.to_vec()));
                self.observer.0.held.store(true, Ordering::Release);
                return Ok(0);
            }
        }
        let tls = matches!(bytes.first(), Some(32 | 40));
        let replay = matches!(self.mode, Some(Mode::ReplayTlsAfter(at)) if now >= at) && tls;
        let actual = if replay {
            self.old_tls.as_deref().unwrap_or(bytes)
        } else {
            bytes
        };
        let length = socket.try_send_to(actual, peer)?;
        if length != actual.len() {
            return Err(io::Error::other("partial test UDP"));
        }
        if tls && self.old_tls.is_none() {
            self.old_tls = Some(bytes.to_vec());
        }
        let mut sent = 1;
        if matches!(self.mode, Some(Mode::Impaired))
            && !self.observer.0.quiesced.load(Ordering::Acquire)
            && self.count.is_multiple_of(11)
        {
            match socket.try_send_to(bytes, peer) {
                Ok(length) if length == bytes.len() => sent += 1,
                Ok(_) => return Err(io::Error::other("partial duplicate UDP")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn close_ack_loss_starts_before_tls_completion() -> io::Result<()> {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        install(a.local_addr()?, Mode::DropCloseAcks(usize::MAX))?;
        let mut path = Path::take(a.local_addr()?)?;
        // The fixture starts at close initiation. TLS may still be consuming its
        // last decrypted message while the carrier emits its recovery ACK.
        assert_eq!(
            path.send(&a, &[40], b.local_addr()?, Duration::ZERO, true)?,
            0
        );
        assert_eq!(dropped(a.local_addr()?)?, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), b.recv_from(&mut [0; 1]))
                .await
                .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod quiescence_tests {
    use super::*;
    #[tokio::test]
    async fn quiescence_requires_driver_observation_and_releases_preexisting_held_output()
    -> io::Result<()> {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        tokio::time::timeout(Duration::from_secs(1), a.writable())
            .await
            .map_err(io::Error::other)??;
        let observer = install_observed(a.local_addr()?, Mode::Impaired)?;
        let mut path = Path::take(a.local_addr()?)?;
        for ordinal in 1..=9 {
            let sent = path.send(&a, &[0x48], b.local_addr()?, Duration::ZERO, false)?;
            if ordinal == 7 || ordinal == 9 {
                assert_eq!(sent, 0);
            }
        }
        assert!(!path.drained());
        observer.quiesce();
        assert!(
            !observer.drained(),
            "request alone is not actor observation"
        );
        assert_eq!(path.flush(&a, b.local_addr()?, Duration::ZERO)?, 0);
        assert!(
            !observer.drained(),
            "quiescence cannot discard a held packet"
        );
        assert_eq!(
            path.flush(&a, b.local_addr()?, Duration::from_millis(12))?,
            1
        );
        assert!(
            !observer.drained(),
            "released path alone is not recovery drain"
        );
        path.observe_recovery_drain(false);
        assert!(!observer.drained());
        path.observe_recovery_drain(true);
        assert!(observer.drained());
        for _ in 10..=14 {
            assert_eq!(
                path.send(
                    &a,
                    &[0x48],
                    b.local_addr()?,
                    Duration::from_millis(12),
                    false
                )?,
                1
            );
        }
        Ok(())
    }
}
