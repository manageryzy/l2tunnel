//! Fixed authenticated phase grammar. No copied value is an ownership capability.
use super::packet::Error;

pub(super) const HEADER: usize = 48;
pub(super) const CONTROL: usize = 128;
pub(super) const HELLO: usize = 280;
pub(super) const COMMIT: usize = 104;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Kind {
    Hello = 1,
    Commit = 2,
    CommitAck = 3,
    Data = 4,
    Feedback = 5,
    Ping = 6,
    Pong = 7,
    Window = 8,
}
impl Kind {
    fn parse(n: u8) -> Result<Self, Error> {
        match n {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Commit),
            3 => Ok(Self::CommitAck),
            4 => Ok(Self::Data),
            5 => Ok(Self::Feedback),
            6 => Ok(Self::Ping),
            7 => Ok(Self::Pong),
            8 => Ok(Self::Window),
            _ => Err(Error::Format),
        }
    }
    pub(super) fn control(self) -> bool {
        !matches!(self, Self::Data | Self::Feedback)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Header {
    pub kind: Kind,
    pub transaction: [u8; 16],
    pub offset: u64,
    pub retired: u64,
    pub right_edge: u64,
    pub body: u16,
}
impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes[0] != 1 || bytes[2..4] != [0; 2] || bytes[46..48] != [0; 2]
        {
            return Err(Error::Format);
        }
        let body = u16::from_be_bytes([bytes[44], bytes[45]]);
        if bytes.len() != HEADER + usize::from(body) {
            return Err(Error::Format);
        }
        let kind = Kind::parse(bytes[1])?;
        let n = usize::from(body);
        if match kind {
            Kind::Hello => n != HELLO,
            Kind::Commit | Kind::CommitAck => n != COMMIT,
            Kind::Data | Kind::Feedback => n == 0,
            Kind::Ping | Kind::Pong => n != 8,
            Kind::Window => n != 0,
        } {
            return Err(Error::Format);
        }
        Ok(Self {
            kind,
            transaction: array(&bytes[4..20])?,
            offset: u64_at(bytes, 20)?,
            retired: u64_at(bytes, 28)?,
            right_edge: u64_at(bytes, 36)?,
            body,
        })
    }
    pub fn encode(self, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() != usize::from(self.body) {
            return Err(Error::Format);
        }
        let mut out = vec![0; HEADER + body.len()];
        out[0] = 1;
        out[1] = self.kind as u8;
        out[4..20].copy_from_slice(&self.transaction);
        out[20..28].copy_from_slice(&self.offset.to_be_bytes());
        out[28..36].copy_from_slice(&self.retired.to_be_bytes());
        out[36..44].copy_from_slice(&self.right_edge.to_be_bytes());
        out[44..46].copy_from_slice(&self.body.to_be_bytes());
        out[HEADER..].copy_from_slice(body);
        Self::parse(&out)?;
        Ok(out)
    }
}
pub(super) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Format)
}
fn u64_at(bytes: &[u8], i: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(array(
        bytes.get(i..i + 8).ok_or(Error::Format)?,
    )?))
}
fn u32_at(bytes: &[u8], i: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(
        bytes.get(i..i + 4).ok_or(Error::Format)?,
    )?))
}
pub(super) fn control(
    kind: u8,
    lane: usize,
    tx: [u8; 16],
    pair: [u8; 32],
    policy: [u8; 32],
    stage: [u8; 32],
) -> [u8; CONTROL] {
    let mut out = [0; CONTROL];
    out[..4].copy_from_slice(b"L2RT");
    out[4..8].copy_from_slice(&[1, kind, lane as u8, 0]);
    out[8..24].copy_from_slice(&tx);
    out[24..56].copy_from_slice(&pair);
    out[56..88].copy_from_slice(&policy);
    out[88..120].copy_from_slice(&stage);
    out
}
pub(super) fn set_hash(domain: &[u8], records: &[[u8; CONTROL]]) -> [u8; 32] {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(domain);
    for record in records {
        hash.update(record);
    }
    let mut out = [0; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LaneProof {
    pub lane: u8,
    pub bulk: u8,
    pub role: u8,
    pub options: u8,
    pub session: [u8; 16],
    pub written: u64,
    pub read: u64,
    pub una: u32,
    pub next: u32,
    pub receive: u32,
    pub ack: u32,
    pub window: u16,
    pub scale: u8,
    pub peer_scale: u8,
    pub peer_window: u32,
    pub mss: u16,
    pub available: u32,
    pub counters: [u8; 32],
}
impl LaneProof {
    pub fn encode(self) -> [u8; 104] {
        let mut out = [0; 104];
        out[..4].copy_from_slice(&[self.lane, self.bulk, self.role, self.options]);
        out[4..20].copy_from_slice(&self.session);
        out[20..28].copy_from_slice(&self.written.to_be_bytes());
        out[28..36].copy_from_slice(&self.read.to_be_bytes());
        for (i, n) in [self.una, self.next, self.receive, self.ack]
            .into_iter()
            .enumerate()
        {
            out[36 + i * 4..40 + i * 4].copy_from_slice(&n.to_be_bytes());
        }
        out[52..54].copy_from_slice(&self.window.to_be_bytes());
        out[54] = self.scale;
        out[55] = self.peer_scale;
        out[56..60].copy_from_slice(&self.peer_window.to_be_bytes());
        out[60..62].copy_from_slice(&self.mss.to_be_bytes());
        out[64..68].copy_from_slice(&self.available.to_be_bytes());
        out[72..104].copy_from_slice(&self.counters);
        out
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 104
            || bytes[62..64] != [0; 2]
            || bytes[68..72] != [0; 4]
            || bytes[0] > 1
            || bytes[1] > 2
            || !(1..=2).contains(&bytes[2])
            || bytes[3] & !1 != 0
            || bytes[54] > 14
            || (bytes[55] > 14 && bytes[55] != 255)
        {
            return Err(Error::Format);
        }
        let p = Self {
            lane: bytes[0],
            bulk: bytes[1],
            role: bytes[2],
            options: bytes[3],
            session: array(&bytes[4..20])?,
            written: u64_at(bytes, 20)?,
            read: u64_at(bytes, 28)?,
            una: u32_at(bytes, 36)?,
            next: u32_at(bytes, 40)?,
            receive: u32_at(bytes, 44)?,
            ack: u32_at(bytes, 48)?,
            window: u16::from_be_bytes([bytes[52], bytes[53]]),
            scale: bytes[54],
            peer_scale: bytes[55],
            peer_window: u32_at(bytes, 56)?,
            mss: u16::from_be_bytes([bytes[60], bytes[61]]),
            available: u32_at(bytes, 64)?,
            counters: array(&bytes[72..104])?,
        };
        if p.written == 0
            || p.read == 0
            || p.written >= 1 << 31
            || p.read >= 1 << 31
            || p.una != p.next
            || p.ack != p.receive
            || p.mss == 0
            || p.available != u32::MAX - p.next
        {
            return Err(Error::Proof);
        }
        Ok(p)
    }
    pub fn complementary(self, other: Self) -> Result<(), Error> {
        if self.lane != other.lane
            || self.bulk != other.bulk
            || self.role == other.role
            || self.session != other.session
            || self.written != other.read
            || self.read != other.written
            || self.next != other.receive
            || self.receive != other.next
            || self.peer_window != (u32::from(other.window) << other.scale)
            || other.peer_window != (u32::from(self.window) << self.scale)
            || self.options != other.options
            || self.scale
                != if other.peer_scale == 255 {
                    0
                } else {
                    other.peer_scale
                }
            || other.scale
                != if self.peer_scale == 255 {
                    0
                } else {
                    self.peer_scale
                }
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Hello {
    pub count: usize,
    pub pair: [u8; 32],
    pub armed: [u8; 32],
    pub lanes: [Option<LaneProof>; 2],
}
impl Hello {
    pub fn encode(&self) -> Result<[u8; HELLO], Error> {
        if !(1..=2).contains(&self.count) {
            return Err(Error::Format);
        }
        let mut out = [0; HELLO];
        out[..4].copy_from_slice(&[1, if self.count == 1 { 1 } else { 2 }, self.count as u8, 0]);
        out[8..40].copy_from_slice(&self.pair);
        out[40..72].copy_from_slice(&self.armed);
        for i in 0..self.count {
            out[72 + i * 104..176 + i * 104]
                .copy_from_slice(&self.lanes[i].ok_or(Error::Proof)?.encode());
        }
        Self::parse(&out)?;
        Ok(out)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HELLO
            || bytes[0] != 1
            || !(1..=2).contains(&bytes[2])
            || bytes[1] != bytes[2]
            || bytes[3..8] != [0; 5]
        {
            return Err(Error::Format);
        }
        let count = usize::from(bytes[2]);
        let mut lanes = [None, None];
        for (i, slot) in lanes.iter_mut().enumerate().take(count) {
            let p = LaneProof::parse(&bytes[72 + i * 104..176 + i * 104])?;
            if p.lane != i as u8 || p.bulk != if count == 1 { 0 } else { i as u8 + 1 } {
                return Err(Error::Proof);
            }
            *slot = Some(p);
        }
        if count == 1 && bytes[176..] != [0; 104] {
            return Err(Error::Format);
        }
        Ok(Self {
            count,
            pair: array(&bytes[8..40])?,
            armed: array(&bytes[40..72])?,
            lanes,
        })
    }
}
pub(super) fn commit(
    kind: Kind,
    count: usize,
    proof: [u8; 32],
    pair: [u8; 32],
    policy: [u8; 32],
) -> [u8; COMMIT] {
    let mut out = [0; COMMIT];
    out[..4].copy_from_slice(&[1, kind as u8, count as u8, 0]);
    out[8..40].copy_from_slice(&proof);
    out[40..72].copy_from_slice(&pair);
    out[72..].copy_from_slice(&policy);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_header_and_truncation() -> Result<(), Error> {
        let h = Header {
            kind: Kind::Data,
            transaction: [7; 16],
            offset: 13,
            retired: 5,
            right_edge: 1005,
            body: 3,
        };
        let encoded = h.encode(b"abc")?;
        assert_eq!(Header::parse(&encoded)?, h);
        for n in 0..encoded.len() {
            assert!(Header::parse(&encoded[..n]).is_err());
        }
        for i in [0, 2, 3, 46, 47] {
            let mut bad = encoded.clone();
            bad[i] ^= 2;
            assert!(Header::parse(&bad).is_err());
        }
        assert_eq!(&encoded[20..28], &13u64.to_be_bytes());
        Ok(())
    }
    #[test]
    fn hello_proofs_strict_and_complementary() -> Result<(), Error> {
        let a = LaneProof {
            lane: 0,
            bulk: 0,
            role: 1,
            options: 0,
            session: [1; 16],
            written: 123,
            read: 234,
            una: 1000,
            next: 1000,
            receive: 2000,
            ack: 2000,
            window: 16384,
            scale: 0,
            peer_scale: 0,
            peer_window: 16384,
            mss: 536,
            available: u32::MAX - 1000,
            counters: [9; 32],
        };
        let b = LaneProof {
            role: 2,
            written: 234,
            read: 123,
            una: 2000,
            next: 2000,
            receive: 1000,
            ack: 1000,
            available: u32::MAX - 2000,
            ..a
        };
        a.complementary(b)?;
        let h = Hello {
            count: 1,
            pair: [2; 32],
            armed: [3; 32],
            lanes: [Some(a), None],
        };
        let mut bytes = h.encode()?;
        assert_eq!(Hello::parse(&bytes)?, h);
        bytes[279] = 1;
        assert!(Hello::parse(&bytes).is_err());
        assert!(a.complementary(LaneProof { read: 122, ..b }).is_err());
        Ok(())
    }
}
