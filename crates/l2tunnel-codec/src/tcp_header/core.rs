//! One bounded layout/delta/checksum core for legacy L2 and explicit native IP.
use super::{Decoded, Error, HeaderProfile, RecordKind, capacity, checksum, raw};

pub(super) const MAX_HEADER: usize = super::MAX_IP_HEADER_BYTES;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Format {
    Ethernet,
    Ip,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Layout {
    ip: usize,
    tcp: usize,
    header: usize,
    ipv4: bool,
    timestamp: Option<usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Context {
    bytes: [u8; MAX_HEADER],
    len: usize,
    layout: Layout,
}
impl Context {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub(crate) fn view(&self) -> View<'_> {
        View {
            bytes: self.bytes(),
            layout: self.layout,
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    bytes: &'a [u8],
    layout: Layout,
}
impl View<'_> {
    pub(crate) fn header_bytes(self) -> usize {
        self.layout.header
    }
    pub(crate) fn payload_length(self) -> Result<usize, Error> {
        declared_length(self.bytes, self.layout)?
            .checked_sub(self.layout.header)
            .ok_or(Error::InvalidRecord)
    }
    pub(crate) fn ipid(self) -> Option<u16> {
        self.layout
            .ipv4
            .then(|| word16(self.bytes, self.layout.ip + 4))
    }
    pub(crate) fn sequence(self) -> u32 {
        word32(self.bytes, self.layout.tcp + 4)
    }
    pub(crate) fn ack(self) -> u32 {
        word32(self.bytes, self.layout.tcp + 8)
    }
    pub(crate) fn timestamps(self) -> Option<(u32, u32)> {
        self.layout
            .timestamp
            .map(|offset| (word32(self.bytes, offset), word32(self.bytes, offset + 4)))
    }
    pub(crate) fn prediction_mask(self, payload: usize) -> u8 {
        u8::from(self.layout.ipv4) | if payload == 0 { 0 } else { 2 }
    }
    pub(crate) fn packet<'p>(self, packet: &'p [u8]) -> Option<View<'p>> {
        let format = if self.layout.ip == 14 {
            Format::Ethernet
        } else {
            Format::Ip
        };
        let layout = layout(packet, format, true)?;
        (layout == self.layout).then_some(View {
            bytes: packet,
            layout,
        })
    }
}
fn word16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn word32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn options(bytes: &[u8], start: usize, end: usize, tcp: bool) -> Option<Option<usize>> {
    let mut position = start;
    let mut timestamp = None;
    while position < end {
        match bytes[position] {
            0 => break,
            1 => position += 1,
            kind => {
                let length = usize::from(*bytes.get(position + 1)?);
                let next = position.checked_add(length)?;
                if length < 2 || next > end {
                    return None;
                }
                if tcp && kind == 8 {
                    if length != 10 || timestamp.is_some() {
                        return None;
                    }
                    timestamp = Some(position + 2);
                }
                position = next;
            }
        }
    }
    Some(timestamp)
}
fn declared_length(bytes: &[u8], l: Layout) -> Result<usize, Error> {
    if l.ipv4 {
        usize::from(word16(bytes, l.ip + 2))
            .checked_add(l.ip)
            .ok_or(Error::LengthOverflow)
    } else {
        usize::from(word16(bytes, 4))
            .checked_add(40)
            .ok_or(Error::LengthOverflow)
    }
}
fn layout(bytes: &[u8], format: Format, complete: bool) -> Option<Layout> {
    let l = if format == Format::Ethernet {
        if bytes.len() < 66
            || bytes[12..15] != [8, 0, 0x45]
            || bytes[23] != 6
            || bytes[46] >> 4 != 8
            || bytes[54..58] != [1, 1, 8, 10]
            || word16(bytes, 20) & 0x3fff != 0
        {
            return None;
        }
        Layout {
            ip: 14,
            tcp: 34,
            header: 66,
            ipv4: true,
            timestamp: Some(58),
        }
    } else {
        let (tcp, ipv4) = match bytes.first().map(|byte| byte >> 4) {
            Some(4) => {
                if bytes.len() < 20 || bytes[9] != 6 || word16(bytes, 6) & 0x3fff != 0 {
                    return None;
                }
                let ihl = usize::from(bytes[0] & 15) * 4;
                if !(20..=60).contains(&ihl) || bytes.len() < ihl {
                    return None;
                }
                options(bytes, 20, ihl, false)?;
                (ihl, true)
            }
            Some(6) => {
                if bytes.len() < 40 || bytes[6] != 6 || word16(bytes, 4) == 0 {
                    return None;
                }
                (40, false)
            }
            _ => return None,
        };
        if bytes.len() < tcp + 20 {
            return None;
        }
        let tcp_bytes = usize::from(bytes[tcp + 12] >> 4) * 4;
        let header = tcp.checked_add(tcp_bytes)?;
        if !(20..=60).contains(&tcp_bytes) || bytes.len() < header || header > MAX_HEADER {
            return None;
        }
        let timestamp = options(bytes, tcp + 20, header, true)?;
        Layout {
            ip: 0,
            tcp,
            header,
            ipv4,
            timestamp,
        }
    };
    let length = declared_length(bytes, l).ok()?;
    if length < l.header || complete && length != bytes.len() {
        return None;
    }
    Some(l)
}
pub(crate) fn view(bytes: &[u8], format: Format) -> Result<View<'_>, Error> {
    let layout = layout(bytes, format, false).ok_or(Error::InvalidRecord)?;
    Ok(View { bytes, layout })
}
pub(crate) fn context(bytes: &[u8], format: Format) -> Result<Context, Error> {
    let l = layout(bytes, format, false)
        .filter(|l| l.header == bytes.len())
        .ok_or(Error::InvalidRecord)?;
    let mut result = Context {
        bytes: [0; MAX_HEADER],
        len: bytes.len(),
        layout: l,
    };
    result.bytes[..bytes.len()].copy_from_slice(bytes);
    Ok(result)
}
fn field(l: Layout, bit: usize) -> Option<(usize, usize)> {
    match bit {
        0 => l.ipv4.then_some((l.ip + 4, 2)),
        1 => Some((l.tcp + 4, 4)),
        2 => Some((l.tcp + 8, 4)),
        3 => Some((l.tcp + 13, 1)),
        4 => Some((l.tcp + 14, 2)),
        5 => Some((l.tcp + 18, 2)),
        6 => l.timestamp.map(|offset| (offset, 4)),
        7 => l.timestamp.map(|offset| (offset + 4, 4)),
        _ => None,
    }
}
fn number(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |n, byte| (n << 8) | u64::from(*byte))
}
fn fields(context: &Context) -> [u64; 8] {
    std::array::from_fn(|bit| {
        field(context.layout, bit).map_or(0, |(start, width)| {
            number(&context.bytes[start..start + width])
        })
    })
}
pub(super) fn restore(
    context: &Context,
    values: &[u64; 8],
    payload: &[u8],
) -> Result<Context, Error> {
    let mut result = *context;
    let l = context.layout;
    for (bit, value) in values.iter().enumerate() {
        if let Some((start, width)) = field(l, bit) {
            result.bytes[start..start + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
        } else if *value != 0 {
            return Err(Error::InvalidRecord);
        }
    }
    let total = l
        .header
        .checked_add(payload.len())
        .ok_or(Error::LengthOverflow)?;
    let tcp_length = total.checked_sub(l.tcp).ok_or(Error::LengthOverflow)?;
    let tcp_u16 = u16::try_from(tcp_length).map_err(|_| Error::LengthOverflow)?;
    if l.ipv4 {
        let length = u16::try_from(total - l.ip).map_err(|_| Error::LengthOverflow)?;
        result.bytes[l.ip + 2..l.ip + 4].copy_from_slice(&length.to_be_bytes());
        result.bytes[l.ip + 10..l.ip + 12].fill(0);
        let value = checksum(&[&result.bytes[l.ip..l.tcp]]);
        result.bytes[l.ip + 10..l.ip + 12].copy_from_slice(&value.to_be_bytes());
    } else {
        let length = u16::try_from(total - 40).map_err(|_| Error::LengthOverflow)?;
        result.bytes[4..6].copy_from_slice(&length.to_be_bytes());
    }
    result.bytes[l.tcp + 16..l.tcp + 18].fill(0);
    let value = if l.ipv4 {
        let mut pseudo = [0; 12];
        pseudo[..8].copy_from_slice(&result.bytes[l.ip + 12..l.ip + 20]);
        pseudo[9] = 6;
        pseudo[10..].copy_from_slice(&tcp_u16.to_be_bytes());
        checksum(&[&pseudo, &result.bytes[l.tcp..l.header], payload])
    } else {
        let mut pseudo = [0; 40];
        pseudo[..32].copy_from_slice(&result.bytes[8..40]);
        pseudo[32..36].copy_from_slice(&(u32::from(tcp_u16)).to_be_bytes());
        pseudo[39] = 6;
        checksum(&[&pseudo, &result.bytes[l.tcp..l.header], payload])
    };
    result.bytes[l.tcp + 16..l.tcp + 18].copy_from_slice(&value.to_be_bytes());
    Ok(result)
}
fn push(output: &mut [u8], cursor: &mut usize, byte: u8) -> Result<(), Error> {
    *output.get_mut(*cursor).ok_or(Error::LengthOverflow)? = byte;
    *cursor += 1;
    Ok(())
}
fn varint(input: &[u8], cursor: &mut usize) -> Result<u64, Error> {
    let mut value = 0;
    for shift in [0, 7, 14, 21, 28] {
        let byte = *input.get(*cursor).ok_or(Error::Truncated)?;
        *cursor += 1;
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(Error::DeltaOverflow)
}
pub(super) struct Encoded {
    pub written: usize,
    pub next: Option<Context>,
}
pub(super) fn encode(
    profile: HeaderProfile,
    maximum: usize,
    format: Format,
    previous: Option<Context>,
    packet: &[u8],
    output: &mut [u8],
) -> Result<Encoded, Error> {
    if packet.len() > maximum {
        return Err(Error::FrameTooLarge);
    }
    let Some(l) = layout(packet, format, true) else {
        return Ok(Encoded {
            written: raw(packet, output)?,
            next: previous,
        });
    };
    let header = context(&packet[..l.header], format)?;
    let values = fields(&header);
    let payload = &packet[l.header..];
    if restore(&header, &values, payload)? != header {
        return Ok(Encoded {
            written: raw(packet, output)?,
            next: previous,
        });
    }
    let needs_context = match previous {
        None => true,
        Some(old) => old.layout != l || restore(&old, &values, payload)? != header,
    };
    let mut prefix = [0; MAX_HEADER + 47];
    let mut cursor = 0;
    if needs_context {
        prefix[0] = if format == Format::Ethernet { 0 } else { 8 };
        prefix[1..3].copy_from_slice(&(l.header as u16).to_be_bytes());
        prefix[3..3 + l.header].copy_from_slice(header.bytes());
        cursor = 3 + l.header;
    }
    let timestamp = profile == HeaderProfile::TcpTimestamp;
    prefix[cursor] = if format == Format::Ip {
        9
    } else if timestamp {
        1
    } else {
        3
    };
    prefix[cursor + 1..cursor + 3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cursor += 3;
    if timestamp {
        for (bit, value) in values.iter().enumerate() {
            let (_, width) = field(l, bit).ok_or(Error::InvalidRecord)?;
            prefix[cursor..cursor + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
            cursor += width;
        }
    } else {
        let mask_offset = cursor;
        cursor += 1;
        let old = if needs_context {
            values
        } else {
            fields(&previous.ok_or(Error::MissingContext)?)
        };
        for (bit, value) in values.iter().enumerate() {
            let Some((_, width)) = field(l, bit) else {
                continue;
            };
            let mask = (1_u64 << (width * 8)) - 1;
            let mut difference = value.wrapping_sub(old[bit]) & mask;
            if difference == 0 {
                continue;
            }
            prefix[mask_offset] |= 1 << bit;
            while difference >= 128 {
                push(&mut prefix, &mut cursor, (difference as u8 & 127) | 128)?;
                difference >>= 7;
            }
            push(&mut prefix, &mut cursor, difference as u8)?;
        }
    }
    let needed = cursor
        .checked_add(payload.len())
        .ok_or(Error::LengthOverflow)?;
    capacity(output, needed)?;
    output[..cursor].copy_from_slice(&prefix[..cursor]);
    output[cursor..needed].copy_from_slice(payload);
    Ok(Encoded {
        written: needed,
        next: if needs_context || !timestamp {
            Some(header)
        } else {
            previous
        },
    })
}
pub(super) struct DecodedState {
    pub event: Decoded,
    pub next: Option<Context>,
}
pub(super) fn decode(
    maximum: usize,
    format: Format,
    previous: Option<Context>,
    input: &[u8],
    output: &mut [u8],
) -> Result<DecodedState, Error> {
    if input.len() < 3 {
        return Err(Error::Truncated);
    }
    let size = usize::from(word16(input, 1));
    let tag = input[0];
    if tag == if format == Format::Ethernet { 0 } else { 8 } {
        if format == Format::Ethernet && size != 66
            || format == Format::Ip && !(40..=MAX_HEADER).contains(&size)
        {
            return Err(Error::InvalidRecord);
        }
        let end = 3usize.checked_add(size).ok_or(Error::LengthOverflow)?;
        let body = input.get(3..end).ok_or(Error::Truncated)?;
        let header = context(body, format)?;
        let l = header.layout;
        if declared_length(body, l)? > maximum || l.ipv4 && checksum(&[&body[l.ip..l.tcp]]) != 0 {
            return Err(Error::InvalidRecord);
        }
        return Ok(DecodedState {
            event: Decoded::Context { consumed: end },
            next: Some(header),
        });
    }
    if tag == 2 {
        if size > maximum {
            return Err(Error::FrameTooLarge);
        }
        let end = 3 + size;
        let body = input.get(3..end).ok_or(Error::Truncated)?;
        capacity(output, size)?;
        output[..size].copy_from_slice(body);
        return Ok(DecodedState {
            event: Decoded::Frame {
                consumed: end,
                written: size,
                kind: RecordKind::Raw,
            },
            next: previous,
        });
    }
    let timestamp = format == Format::Ethernet && tag == 1;
    if !timestamp && tag != if format == Format::Ethernet { 3 } else { 9 } {
        return Err(Error::InvalidRecord);
    }
    let header = previous.ok_or(Error::MissingContext)?;
    let l = header.layout;
    let written = l
        .header
        .checked_add(size)
        .filter(|n| *n <= maximum)
        .ok_or(Error::FrameTooLarge)?;
    let mut values = fields(&header);
    let mut cursor = 3;
    if timestamp {
        for (bit, value) in values.iter_mut().enumerate() {
            let (_, width) = field(l, bit).ok_or(Error::InvalidRecord)?;
            *value = number(input.get(cursor..cursor + width).ok_or(Error::Truncated)?);
            cursor += width;
        }
    } else {
        let mask = *input.get(cursor).ok_or(Error::Truncated)?;
        cursor += 1;
        for (bit, value) in values.iter_mut().enumerate() {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let (_, width) = field(l, bit).ok_or(Error::InvalidRecord)?;
            let difference = varint(input, &mut cursor)?;
            *value = (*value + difference) & ((1_u64 << (width * 8)) - 1);
        }
    }
    let end = cursor.checked_add(size).ok_or(Error::LengthOverflow)?;
    let payload = input.get(cursor..end).ok_or(Error::Truncated)?;
    capacity(output, written)?;
    let restored = restore(&header, &values, payload)?;
    output[..l.header].copy_from_slice(restored.bytes());
    output[l.header..written].copy_from_slice(payload);
    Ok(DecodedState {
        event: Decoded::Frame {
            consumed: end,
            written,
            kind: if timestamp {
                RecordKind::Timestamp
            } else {
                RecordKind::Delta
            },
        },
        next: if timestamp { previous } else { Some(restored) },
    })
}
