//! Exact inner header compression for ordered channels.
//!
//! A channel is a lossless ordered stream, so both ends see the same packets
//! in the same order and can keep identical per-connection contexts without
//! any feedback. A TCP/IPv4 packet whose header is predictable from the
//! previous packet of its connection is sent as a few changed fields; its
//! length and both checksums are reconstructed. Everything else is sent
//! literally.
//!
//! The compressor decodes every candidate itself and falls back to the
//! literal form unless the result is identical, so the output of
//! [`Decompressor::decompress`] is always byte-for-byte the original packet,
//! including packets with wrong checksums, padding or unusual options.
use super::Error;

/// Connection contexts per channel.
pub const SLOTS: usize = 8;
/// Largest growth of a record over its packet.
pub const MAX_EXPANSION: usize = 1;

const ETHERNET: usize = 14;
const IPV4: usize = 20;
const MAX_HEADER: usize = ETHERNET + IPV4 + 60;
const LITERAL: u8 = 0;
const LITERAL_STORE: u8 = 1;
const DELTA: u8 = 2;
const F_ID: u8 = 1;
const F_SEQ: u8 = 2;
const F_ACK: u8 = 4;
const F_CONTROL: u8 = 8;
const F_TSVAL: u8 = 16;
const F_TSECR: u8 = 32;
const TIMESTAMPS: [u8; 4] = [1, 1, 8, 10];

#[derive(Clone, Copy)]
struct Context {
    header: [u8; MAX_HEADER],
    /// Header bytes in use; zero marks an empty slot.
    length: usize,
    /// TCP payload bytes of the packet that set this context.
    payload: u32,
}
const EMPTY: Context = Context {
    header: [0; MAX_HEADER],
    length: 0,
    payload: 0,
};

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn short(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Header length of a packet this profile can describe: an optional Ethernet
/// header with the IPv4 type, an unfragmented option-free IPv4 header whose
/// total length covers exactly the rest, and a TCP header that fits.
fn layout(link: usize, packet: &[u8]) -> Option<usize> {
    let ip = packet.get(link..)?;
    if ip.len() < IPV4 + 20
        || ip.len() > usize::from(u16::MAX)
        || (link == ETHERNET && short(packet, 12) != 0x0800)
        || ip[0] != 0x45
        || ip[9] != 6
        || short(ip, 6) & 0x3FFF != 0
        || usize::from(short(ip, 2)) != ip.len()
    {
        return None;
    }
    let offset = usize::from(ip[IPV4 + 12] >> 4) * 4;
    (offset >= 20 && ip.len() >= IPV4 + offset).then_some(link + IPV4 + offset)
}

fn has_timestamps(link: usize, header: &[u8]) -> bool {
    header.len() == link + IPV4 + 32 && header[link + IPV4 + 20..link + IPV4 + 24] == TIMESTAMPS
}

/// Addresses and ports identify the connection a context belongs to.
fn same_connection(link: usize, a: &[u8], b: &[u8]) -> bool {
    a[link + 12..link + 24] == b[link + 12..link + 24]
}

fn sum(mut total: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        total += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        total = (total & 0xFFFF) + (total >> 16);
    }
    if let [last] = chunks.remainder() {
        total += u32::from(*last) << 8;
        total = (total & 0xFFFF) + (total >> 16);
    }
    total
}
fn finish(total: u32) -> [u8; 2] {
    let folded = (total & 0xFFFF) + (total >> 16);
    (!(folded as u16)).to_be_bytes()
}

fn put_varint(output: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    if input.len() < count {
        return Err(Error::Malformed);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
fn take_varint(input: &mut &[u8]) -> Result<u32, Error> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = take(input, 1)?[0];
        let bits = u32::from(byte & 0x7F);
        if shift == 28 && bits > 0x0F {
            return Err(Error::Malformed);
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::Malformed)
}

/// Write the packet described by `fields` relative to `context` followed by
/// `payload`. Shared by both ends so they cannot disagree.
fn rebuild(
    link: usize,
    context: &Context,
    flags: u8,
    fields: &mut &[u8],
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    let length = context.length;
    let total = length - link + payload.len();
    let total = u16::try_from(total).map_err(|_| Error::Malformed)?;
    output.clear();
    output.extend_from_slice(&context.header[..length]);
    let (ip, tcp) = (link, link + IPV4);
    output[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
    let id = if flags & F_ID != 0 {
        short(take(fields, 2)?, 0)
    } else {
        short(&context.header, ip + 4).wrapping_add(1)
    };
    output[ip + 4..ip + 6].copy_from_slice(&id.to_be_bytes());
    let mut sequence = word(&context.header, tcp + 4).wrapping_add(context.payload);
    if flags & F_SEQ != 0 {
        sequence = sequence.wrapping_add(take_varint(fields)?);
    }
    output[tcp + 4..tcp + 8].copy_from_slice(&sequence.to_be_bytes());
    if flags & F_ACK != 0 {
        let value = word(&context.header, tcp + 8).wrapping_add(take_varint(fields)?);
        output[tcp + 8..tcp + 12].copy_from_slice(&value.to_be_bytes());
    }
    if flags & F_CONTROL != 0 {
        let control = take(fields, 4)?;
        // The data offset fixes the header length the context already has.
        if control[0] >> 4 != context.header[tcp + 12] >> 4 {
            return Err(Error::Malformed);
        }
        output[tcp + 12..tcp + 16].copy_from_slice(control);
    }
    if flags & (F_TSVAL | F_TSECR) != 0 && !has_timestamps(link, &context.header[..length]) {
        return Err(Error::Malformed);
    }
    if flags & F_TSVAL != 0 {
        let value = word(&context.header, tcp + 24).wrapping_add(take_varint(fields)?);
        output[tcp + 24..tcp + 28].copy_from_slice(&value.to_be_bytes());
    }
    if flags & F_TSECR != 0 {
        let value = word(&context.header, tcp + 28).wrapping_add(take_varint(fields)?);
        output[tcp + 28..tcp + 32].copy_from_slice(&value.to_be_bytes());
    }
    output[ip + 10..ip + 12].fill(0);
    let checksum = finish(sum(0, &output[ip..tcp]));
    output[ip + 10..ip + 12].copy_from_slice(&checksum);
    output[tcp + 16..tcp + 18].fill(0);
    let segment = u32::from(total) - IPV4 as u32;
    let pseudo = sum(sum(0, &output[ip + 12..ip + 20]), &[0, 6]) + segment;
    // The header has even length, so the payload starts on a word boundary.
    let checksum = finish(sum(sum(pseudo, &output[tcp..length]), payload));
    output[tcp + 16..tcp + 18].copy_from_slice(&checksum);
    output.extend_from_slice(payload);
    Ok(())
}

fn remember(context: &mut Context, packet: &[u8], length: usize) {
    context.header[..length].copy_from_slice(&packet[..length]);
    context.length = length;
    context.payload = (packet.len() - length) as u32;
}

/// Sending side of one channel.
pub struct Compressor {
    link: usize,
    slots: [Context; SLOTS],
    next: usize,
    scratch: Vec<u8>,
    saved: u64,
}

impl Compressor {
    /// `ethernet` selects frames with an Ethernet header, otherwise raw IP.
    pub fn new(ethernet: bool) -> Self {
        Self {
            link: if ethernet { ETHERNET } else { 0 },
            slots: [EMPTY; SLOTS],
            next: 0,
            scratch: Vec::new(),
            saved: 0,
        }
    }
    /// Bytes removed so far, net of the record tags added to literal packets.
    pub fn saved(&self) -> u64 {
        self.saved
    }
    /// Write the record for `packet` into `record` (cleared first). The record
    /// is at most [`MAX_EXPANSION`] bytes longer than the packet. Records must
    /// reach the peer's [`Decompressor`] in exactly this order.
    pub fn compress(&mut self, packet: &[u8], record: &mut Vec<u8>) {
        record.clear();
        let link = self.link;
        let Some(length) = layout(link, packet) else {
            record.push(LITERAL);
            record.extend_from_slice(packet);
            return;
        };
        let found = self.slots.iter().position(|context| {
            context.length != 0 && same_connection(link, &context.header, packet)
        });
        if let Some(slot) = found
            && self.delta(slot, packet, length, record)
        {
            remember(&mut self.slots[slot], packet, length);
            self.saved += (packet.len() - record.len()) as u64;
            return;
        }
        let slot = found.unwrap_or_else(|| {
            let slot = self.next;
            self.next = (self.next + 1) % SLOTS;
            slot
        });
        record.clear();
        record.push(LITERAL_STORE | (slot as u8) << 2);
        record.extend_from_slice(packet);
        remember(&mut self.slots[slot], packet, length);
    }
    /// Try the delta form; keep it only if decoding it restores the packet.
    fn delta(&mut self, slot: usize, packet: &[u8], length: usize, record: &mut Vec<u8>) -> bool {
        let context = &self.slots[slot];
        if context.length != length {
            return false;
        }
        let (link, previous) = (self.link, &context.header);
        let (ip, tcp) = (link, link + IPV4);
        let mut flags = 0;
        record.clear();
        record.push(DELTA | (slot as u8) << 2);
        record.push(0);
        let id = short(packet, ip + 4);
        if id != short(previous, ip + 4).wrapping_add(1) {
            flags |= F_ID;
            record.extend_from_slice(&id.to_be_bytes());
        }
        let expected = word(previous, tcp + 4).wrapping_add(context.payload);
        let sequence = word(packet, tcp + 4);
        if sequence != expected {
            flags |= F_SEQ;
            put_varint(record, sequence.wrapping_sub(expected));
        }
        let mut field = |flag: u8, at: usize, record: &mut Vec<u8>| {
            let (old, new) = (word(previous, at), word(packet, at));
            if old != new {
                flags |= flag;
                put_varint(record, new.wrapping_sub(old));
            }
        };
        field(F_ACK, tcp + 8, record);
        if packet[tcp + 12..tcp + 16] != previous[tcp + 12..tcp + 16] {
            flags |= F_CONTROL;
            record.extend_from_slice(&packet[tcp + 12..tcp + 16]);
        }
        if has_timestamps(link, &previous[..length]) {
            let mut field = |flag: u8, at: usize, record: &mut Vec<u8>| {
                let (old, new) = (word(previous, at), word(packet, at));
                if old != new {
                    flags |= flag;
                    put_varint(record, new.wrapping_sub(old));
                }
            };
            field(F_TSVAL, tcp + 24, record);
            field(F_TSECR, tcp + 28, record);
        }
        record[1] = flags;
        let payload = &packet[length..];
        let mut fields = &record[2..];
        let exact = rebuild(
            link,
            context,
            flags,
            &mut fields,
            payload,
            &mut self.scratch,
        )
        .is_ok()
            && fields.is_empty()
            && self.scratch == packet;
        if exact {
            record.extend_from_slice(payload);
        }
        exact
    }
}

/// Receiving side of one channel.
pub struct Decompressor {
    link: usize,
    slots: [Context; SLOTS],
}

impl Decompressor {
    /// `ethernet` must match the peer's [`Compressor`].
    pub fn new(ethernet: bool) -> Self {
        Self {
            link: if ethernet { ETHERNET } else { 0 },
            slots: [EMPTY; SLOTS],
        }
    }
    /// Restore the packet of one record into `packet` (cleared first). A
    /// record no compressor could have produced, or a packet longer than
    /// `max_packet`, is rejected and leaves every context unchanged.
    pub fn decompress(
        &mut self,
        record: &[u8],
        max_packet: usize,
        packet: &mut Vec<u8>,
    ) -> Result<(), Error> {
        packet.clear();
        let (&tag, body) = record.split_first().ok_or(Error::Malformed)?;
        let slot = usize::from(tag >> 2);
        if slot >= SLOTS || body.is_empty() {
            return Err(Error::Malformed);
        }
        match tag & 3 {
            LITERAL if slot == 0 && body.len() <= max_packet => {
                packet.extend_from_slice(body);
                Ok(())
            }
            LITERAL_STORE if body.len() <= max_packet => {
                let length = layout(self.link, body).ok_or(Error::Malformed)?;
                packet.extend_from_slice(body);
                remember(&mut self.slots[slot], body, length);
                Ok(())
            }
            DELTA => {
                let context = self.slots[slot];
                let (&flags, mut rest) = body.split_first().ok_or(Error::Malformed)?;
                if context.length == 0 || flags & !(F_TSECR * 2 - 1) != 0 {
                    return Err(Error::Malformed);
                }
                // Fields are consumed first; what remains is the payload.
                let mut probe = Vec::new();
                let mut fields = rest;
                rebuild(self.link, &context, flags, &mut fields, &[], &mut probe)?;
                let consumed = rest.len() - fields.len();
                let mut fields = take(&mut rest, consumed)?;
                if context.length + rest.len() > max_packet {
                    return Err(Error::Malformed);
                }
                rebuild(self.link, &context, flags, &mut fields, rest, packet)?;
                let length = context.length;
                remember(&mut self.slots[slot], packet, length);
                Ok(())
            }
            _ => Err(Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Random(u64);
    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// A valid Ethernet/IPv4/TCP frame with Linux-style timestamp options.
    fn segment(
        port: u16,
        id: u16,
        sequence: u32,
        ack: u32,
        ts: (u32, u32),
        data: usize,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 66 + data];
        frame[..12].copy_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&[8, 0]);
        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&((52 + data) as u16).to_be_bytes());
        frame[ip + 4..ip + 6].copy_from_slice(&id.to_be_bytes());
        frame[ip + 6] = 0x40;
        frame[ip + 8] = 64;
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
        let tcp = 34;
        frame[tcp..tcp + 2].copy_from_slice(&port.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&24_500u16.to_be_bytes());
        frame[tcp + 4..tcp + 8].copy_from_slice(&sequence.to_be_bytes());
        frame[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
        frame[tcp + 12] = 0x80;
        frame[tcp + 13] = 0x10;
        frame[tcp + 14..tcp + 16].copy_from_slice(&502u16.to_be_bytes());
        frame[tcp + 20..tcp + 24].copy_from_slice(&TIMESTAMPS);
        frame[tcp + 24..tcp + 28].copy_from_slice(&ts.0.to_be_bytes());
        frame[tcp + 28..tcp + 32].copy_from_slice(&ts.1.to_be_bytes());
        for (index, byte) in frame[66..].iter_mut().enumerate() {
            *byte = (index as u32 ^ sequence) as u8;
        }
        checksums(&mut frame);
        frame
    }
    fn checksums(frame: &mut [u8]) {
        let (ip, tcp) = (14, 34);
        frame[ip + 10..ip + 12].fill(0);
        let value = finish(sum(0, &frame[ip..tcp]));
        frame[ip + 10..ip + 12].copy_from_slice(&value);
        frame[tcp + 16..tcp + 18].fill(0);
        let segment = (frame.len() - tcp) as u32;
        let pseudo = sum(sum(0, &frame[ip + 12..ip + 20]), &[0, 6]) + segment;
        let value = finish(sum(pseudo, &frame[tcp..]));
        frame[tcp + 16..tcp + 18].copy_from_slice(&value);
    }

    struct Pair {
        compressor: Compressor,
        decompressor: Decompressor,
        record: Vec<u8>,
        packet: Vec<u8>,
    }
    impl Pair {
        fn new(ethernet: bool) -> Self {
            Self {
                compressor: Compressor::new(ethernet),
                decompressor: Decompressor::new(ethernet),
                record: Vec::new(),
                packet: Vec::new(),
            }
        }
        /// Round-trip one packet and return its record length.
        fn pass(&mut self, packet: &[u8]) -> usize {
            self.compressor.compress(packet, &mut self.record);
            assert!(self.record.len() <= packet.len() + MAX_EXPANSION);
            let result = self
                .decompressor
                .decompress(&self.record, 65_535, &mut self.packet);
            assert_eq!(
                result,
                Ok(()),
                "record {:?}",
                &self.record[..self.record.len().min(16)]
            );
            assert_eq!(self.packet, packet, "packet was not restored exactly");
            self.record.len()
        }
    }

    #[test]
    fn bulk_data_and_acknowledgement_streams_shrink_to_a_few_bytes() {
        let mut pair = Pair::new(true);
        let (mut sequence, mut total, mut original) = (1_000u32, 0, 0);
        assert_eq!(
            pair.pass(&segment(40_000, 7, sequence, 9, (100, 50), 1448)),
            1515
        );
        for index in 1..2_000u32 {
            sequence = sequence.wrapping_add(1448);
            let ts = (100 + index / 2, 50 + index / 3);
            let frame = segment(40_000, 7 + index as u16, sequence, 9, ts, 1448);
            let record = pair.pass(&frame);
            assert!(record <= 1448 + 4, "data record {record}");
            total += record;
            original += frame.len();
        }
        // On average about three bytes replace the 66-byte header.
        assert!(total * 1000 < original * 959, "{total} of {original}");
        assert_eq!(pair.compressor.saved(), (original - total) as u64);
        // The reverse direction: pure acknowledgements advancing by two segments.
        let mut pair = Pair::new(true);
        let mut acknowledged = 5_000u32;
        pair.pass(&segment(24_500, 1, 77, acknowledged, (9, 9), 0));
        for index in 1..500u32 {
            acknowledged = acknowledged.wrapping_add(2896);
            let frame = segment(
                24_500,
                1 + index as u16,
                77,
                acknowledged,
                (9 + index, 9 + index),
                0,
            );
            assert!(pair.pass(&frame) <= 6, "acknowledgement record");
        }
    }

    #[test]
    fn every_irregular_packet_is_restored_exactly() {
        let mut pair = Pair::new(true);
        let base = segment(40_000, 7, 1_000, 9, (100, 50), 100);
        pair.pass(&base);
        let mut variants: Vec<Vec<u8>> = Vec::new();
        let mut edit = |change: &dyn Fn(&mut Vec<u8>), fix: bool| {
            let mut frame = segment(40_000, 8, 1_100, 9, (100, 50), 100);
            change(&mut frame);
            if fix {
                checksums(&mut frame);
            }
            variants.push(frame);
        };
        edit(&|frame| frame[14 + 4] = 0xAA, true); // identification jump
        edit(
            &|frame| frame[34 + 4..34 + 8].copy_from_slice(&5u32.to_be_bytes()),
            true,
        ); // retransmission
        edit(&|frame| frame[34 + 13] = 0x19, true); // FIN and PSH
        edit(&|frame| frame[34 + 14] = 9, true); // window
        edit(&|frame| frame[14 + 8] = 3, true); // TTL: literal
        edit(&|frame| frame[5] = 9, true); // MAC: literal
        edit(&|frame| frame[34 + 18] = 1, true); // urgent pointer: literal
        edit(&|frame| frame[34 + 16] ^= 0x55, false); // wrong TCP checksum
        edit(&|frame| frame[14 + 10] ^= 0x55, false); // wrong IP checksum
        edit(&|frame| frame.push(0), false); // trailer beyond the IP length
        edit(&|frame| frame[14 + 6] = 0x20, true); // fragment
        edit(&|frame| frame[14 + 9] = 17, true); // UDP
        edit(&|frame| frame[12] = 0x86, true); // not IPv4
        edit(&|frame| frame[14] = 0x46, true); // IP options claimed
        edit(&|frame| frame[34 + 12] = 0xF0, true); // data offset beyond the frame
        edit(&|frame| frame.truncate(40), false);
        edit(&|frame| frame[34 + 21] = 3, true); // different option layout
        for frame in &variants {
            pair.pass(frame);
            // The stream continues correctly after each of them.
            pair.pass(&segment(40_000, 9, 1_200, 9, (101, 50), 100));
        }
        for tiny in [&[0u8][..], &[0x45], &[0xFF; 13], &[0; 14]] {
            assert_eq!(pair.pass(tiny), tiny.len() + 1);
        }
        // Raw IP uses the same profile without the Ethernet header.
        let mut raw = Pair::new(false);
        let first = segment(40_000, 7, 1_000, 9, (100, 50), 500);
        let second = segment(40_000, 8, 1_500, 9, (100, 50), 500);
        assert_eq!(raw.pass(&first[14..]), first.len() - 14 + 1);
        assert!(raw.pass(&second[14..]) <= 502);
        // Odd payload lengths exercise the checksum tail.
        for data in [0, 1, 2, 3, 1447] {
            raw.pass(&segment(40_000, 9, 2_000, 9, (100, 50), data)[14..]);
        }
    }

    #[test]
    fn many_connections_share_and_recycle_the_slots() {
        let mut pair = Pair::new(true);
        let mut random = Random(11);
        let mut state = [(0u16, 0u32); 24];
        let mut compressed = 0;
        for round in 0..4_000u32 {
            // Mostly the same few connections, sometimes any of 24.
            let pick = if round.is_multiple_of(10) {
                random.next() % 24
            } else {
                random.next() % 6
            } as usize;
            let (id, sequence) = &mut state[pick];
            let data = (random.next() % 1449) as usize;
            let frame = segment(
                40_000 + pick as u16,
                *id,
                *sequence,
                round / 7,
                (round, round / 2),
                data,
            );
            *id = id.wrapping_add(1);
            *sequence = sequence.wrapping_add(data as u32);
            if pair.pass(&frame) < frame.len() {
                compressed += 1;
            }
        }
        assert!(
            compressed > 3_000,
            "only {compressed} records used a context"
        );
    }

    #[test]
    fn random_header_mutations_never_break_exactness() {
        let mut pair = Pair::new(true);
        let mut random = Random(2026);
        let mut frame = segment(40_000, 1, 1, 1, (1, 1), 64);
        for _ in 0..20_000 {
            let mut next = frame.clone();
            for _ in 0..random.next() % 3 {
                let at = (random.next() % 66) as usize;
                next[at] = random.next() as u8;
            }
            if !random.next().is_multiple_of(4) {
                checksums(&mut next);
            }
            pair.pass(&next);
            if random.next().is_multiple_of(3) {
                frame = next;
            }
        }
    }

    #[test]
    fn records_no_compressor_produces_are_rejected_without_state_change() {
        let mut pair = Pair::new(true);
        let first = segment(40_000, 7, 1_000, 9, (100, 50), 10);
        pair.pass(&first);
        let mut packet = Vec::new();
        let bad: [&[u8]; 12] = [
            &[],
            &[LITERAL],
            &[LITERAL | 4, 1, 2],
            &[LITERAL_STORE, 1, 2, 3],
            &[3, 0],
            &[DELTA | 7 << 2, 0, 1],
            &[DELTA | 5 << 2, 0],
            &[DELTA, 0x40],
            &[DELTA, F_ID, 1],
            &[DELTA, F_SEQ, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            &[DELTA, F_SEQ, 0x80, 0x80, 0x80, 0x80, 0x10],
            &[DELTA, F_CONTROL, 0x50, 0, 0, 0],
        ];
        for record in bad {
            let result = pair.decompressor.decompress(record, 1600, &mut packet);
            assert_eq!(result, Err(Error::Malformed), "{record:?}");
        }
        // Size limits apply to the restored packet.
        let mut record = vec![DELTA, 0];
        record.extend_from_slice(&[0; 1600]);
        assert_eq!(
            pair.decompressor.decompress(&record, 1600, &mut packet),
            Err(Error::Malformed)
        );
        let mut literal = vec![LITERAL];
        literal.extend_from_slice(&[0; 1601]);
        assert_eq!(
            pair.decompressor.decompress(&literal, 1600, &mut packet),
            Err(Error::Malformed)
        );
        // None of that disturbed the context.
        pair.pass(&segment(40_000, 8, 1_010, 9, (100, 50), 10));
        // Timestamp fields without a timestamp context are refused.
        let mut plain = Pair::new(true);
        let mut frame = segment(40_000, 7, 1, 1, (1, 1), 0);
        frame[34 + 20] = 0;
        checksums(&mut frame);
        plain.pass(&frame);
        let result = plain
            .decompressor
            .decompress(&[DELTA, F_TSVAL, 1], 1600, &mut packet);
        assert_eq!(result, Err(Error::Malformed));
    }
}
