use super::*;

pub(super) const USER_HEADER: usize = 24;
pub(super) const CONTROL_MAX: usize = 72;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Credit {
    pub bytes: u64,
    pub packets: u64,
}
impl Credit {
    pub fn add(self, bytes: usize) -> io::Result<Self> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(bytes as u64)
                .ok_or_else(|| invalid("proxy byte counter exhausted"))?,
            packets: self
                .packets
                .checked_add(1)
                .ok_or_else(|| invalid("proxy packet counter exhausted"))?,
        })
    }
    pub fn contains(self, other: Self) -> bool {
        self.bytes >= other.bytes && self.packets >= other.packets
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Fence {
    pub records: u64,
    pub transparent: Credit,
    pub flows: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Start {
    pub digest: [u8; 32],
    pub session: [u8; 16],
    pub originator: bool,
    pub duplex: Duplex,
    pub lane: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ControlFrame {
    Start(Start),
    Ready(Start),
    Credit(Credit),
    Ping(u64),
    Pong(u64),
    Quiesce,
    Barrier(Fence),
    Ack(Fence),
}
fn number(input: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_be_bytes(
        input
            .get(offset..offset + 8)
            .ok_or_else(|| invalid("truncated proxy field"))?
            .try_into()
            .map_err(io::Error::other)?,
    ))
}
impl ControlFrame {
    pub fn encode(self) -> Vec<u8> {
        let (kind, length) = match self {
            Self::Start(_) => (1, 56),
            Self::Ready(_) => (2, 56),
            Self::Credit(_) => (3, 16),
            Self::Ping(_) => (4, 8),
            Self::Pong(_) => (5, 8),
            Self::Quiesce => (6, 8),
            Self::Barrier(_) => (7, 32),
            Self::Ack(_) => (8, 32),
        };
        let mut b = vec![0; 16 + length];
        b[..8].copy_from_slice(b"LTPCTRL1");
        b[8] = kind;
        b[12..16].copy_from_slice(&(length as u32).to_be_bytes());
        let body = &mut b[16..];
        match self {
            Self::Start(s) | Self::Ready(s) => {
                body[..32].copy_from_slice(&s.digest);
                body[32..48].copy_from_slice(&s.session);
                body[48] = if s.originator { 1 } else { 2 };
                body[49] = if s.duplex == Duplex::Full { 1 } else { 2 };
                body[50] = s.lane;
            }
            Self::Credit(c) => {
                body[..8].copy_from_slice(&c.bytes.to_be_bytes());
                body[8..].copy_from_slice(&c.packets.to_be_bytes());
            }
            Self::Ping(n) | Self::Pong(n) => body.copy_from_slice(&n.to_be_bytes()),
            Self::Quiesce => {}
            Self::Barrier(f) | Self::Ack(f) => {
                for (i, n) in [
                    f.records,
                    f.transparent.bytes,
                    f.transparent.packets,
                    f.flows,
                ]
                .into_iter()
                .enumerate()
                {
                    body[i * 8..(i + 1) * 8].copy_from_slice(&n.to_be_bytes());
                }
            }
        }
        b
    }
    pub fn decode(b: &[u8]) -> io::Result<Self> {
        if b.len() < 16
            || b.len() > CONTROL_MAX
            || b[..8] != *b"LTPCTRL1"
            || b[9..12] != [0; 3]
            || u32::from_be_bytes(b[12..16].try_into().map_err(io::Error::other)?) as usize
                != b.len() - 16
        {
            return Err(invalid("proxy control header"));
        }
        let body = &b[16..];
        match b[8] {
            k @ (1 | 2) if body.len() == 56 => {
                if !matches!(body[48], 1 | 2)
                    || !matches!(body[49], 1 | 2)
                    || body[50] > 1
                    || body[51..] != [0; 5]
                {
                    return Err(invalid("proxy startup fields"));
                }
                let s = Start {
                    digest: body[..32].try_into().map_err(io::Error::other)?,
                    session: body[32..48].try_into().map_err(io::Error::other)?,
                    originator: body[48] == 1,
                    duplex: if body[49] == 1 {
                        Duplex::Full
                    } else {
                        Duplex::Half
                    },
                    lane: body[50],
                };
                if s.session == [0; 16] || (s.duplex == Duplex::Full && s.lane != 0) {
                    return Err(invalid("proxy startup session"));
                }
                Ok(if k == 1 {
                    Self::Start(s)
                } else {
                    Self::Ready(s)
                })
            }
            3 if body.len() == 16 => Ok(Self::Credit(Credit {
                bytes: number(body, 0)?,
                packets: number(body, 8)?,
            })),
            k @ (4 | 5) if body.len() == 8 => {
                let n = number(body, 0)?;
                if n == 0 {
                    return Err(invalid("zero proxy heartbeat"));
                }
                Ok(if k == 4 { Self::Ping(n) } else { Self::Pong(n) })
            }
            6 if body == [0; 8] => Ok(Self::Quiesce),
            k @ (7 | 8) if body.len() == 32 => {
                let f = Fence {
                    records: number(body, 0)?,
                    transparent: Credit {
                        bytes: number(body, 8)?,
                        packets: number(body, 16)?,
                    },
                    flows: number(body, 24)?,
                };
                Ok(if k == 7 {
                    Self::Barrier(f)
                } else {
                    Self::Ack(f)
                })
            }
            _ => Err(invalid("proxy control kind or exact length")),
        }
    }
}
pub(super) struct User<'a> {
    pub measurement: bool,
    pub channel: u16,
    pub flow: u64,
    pub body: &'a [u8],
}
pub(super) fn user(channel: u16, flow: u64, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![0; USER_HEADER];
    out[..4].copy_from_slice(b"LTPW");
    out[4] = 1;
    out[5] = u8::from(flow != 0);
    out[8..10].copy_from_slice(&channel.to_be_bytes());
    out[12..20].copy_from_slice(&flow.to_be_bytes());
    out[20..24].copy_from_slice(
        &u32::try_from(body.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    Ok(out)
}
pub(super) fn decode_user<'a>(input: &'a [u8], config: &Config) -> io::Result<User<'a>> {
    if input.len() < USER_HEADER
        || input.len() > config.max_user()?
        || input[..4] != *b"LTPW"
        || input[4] != 1
        || input[5] > 1
        || input[6..8] != [0; 2]
        || input[10..12] != [0; 2]
        || u32::from_be_bytes(input[20..24].try_into().map_err(io::Error::other)?) as usize
            != input.len() - USER_HEADER
    {
        return Err(invalid("proxy user envelope"));
    }
    let channel = u16::from_be_bytes(input[8..10].try_into().map_err(io::Error::other)?);
    let flow = number(input, 12)?;
    if channel >= config.mux.channels
        || ((flow == 0) != (input[5] == 0))
        || flow > config.relay.max_flows as u64
    {
        return Err(invalid("proxy user channel or flow"));
    }
    Ok(User {
        measurement: false,
        channel,
        flow,
        body: &input[USER_HEADER..],
    })
}
pub(super) fn decode_profile<'a>(
    input: &'a [u8],
    config: &Config,
    measured: bool,
) -> io::Result<User<'a>> {
    if !measured {
        return decode_user(input, config);
    }
    let value = super::measured::envelope::decode_fixed(config, input)?;
    Ok(User {
        measurement: value.kind == super::measured::envelope::Kind::Measurement,
        channel: value.channel,
        flow: value.flow,
        body: value.body,
    })
}
