//! Bounded test-only path impairment. Production code has no registry or fault mode.
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::net::UdpSocket;

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Impaired,
    DropCloseAcks(usize),
    ReplayTlsAfter(Duration),
}
static PLANS: OnceLock<Mutex<BTreeMap<SocketAddr, Mode>>> = OnceLock::new();
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
    if plans.len() >= 32 || plans.insert(address, mode).is_some() {
        return Err(io::Error::other("test plan bound/conflict"));
    }
    Ok(())
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
    count: usize,
    held: Option<(Duration, Vec<u8>)>,
    old_tls: Option<Vec<u8>>,
    final_acks: usize,
}
impl Path {
    pub fn take(address: SocketAddr) -> io::Result<Self> {
        let mode = PLANS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| io::Error::other("test registry poisoned"))?
            .remove(&address);
        Ok(Self {
            mode,
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
        if let Some((due, bytes)) = &self.held
            && now >= *due
        {
            match socket.try_send_to(bytes, peer) {
                Ok(length) if length == bytes.len() => {
                    self.held = None;
                    return Ok(1);
                }
                Ok(_) => return Err(io::Error::other("partial impaired UDP")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(0)
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
        if matches!(self.mode, Some(Mode::Impaired)) {
            if self.count.is_multiple_of(7) {
                return Ok(0);
            }
            if self.count.is_multiple_of(9) && self.held.is_none() {
                self.held = Some((now + Duration::from_millis(12), bytes.to_vec()));
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
        if matches!(self.mode, Some(Mode::Impaired)) && self.count.is_multiple_of(11) {
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
