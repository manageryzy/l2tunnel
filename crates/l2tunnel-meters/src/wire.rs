//! Remote meter read request/reply bodies for the `Meters` control stream.
//!
//! These are message bodies only. Authentication, fragmentation, reliable
//! delivery and deadlines belong to the management control-stream custody
//! that carries them. All integers are big-endian.
//!
//! | Offset | Bytes | Field |
//! |---:|---:|---|
//! | 0 | 1 | Version 1 |
//! | 1 | 1 | Kind: request=1, reply=2, refusal=3 |
//! | 2 | 2 | Reserved, zero |
//! | 4 | 4 | Request ID |
//!
//! Request: `limit` u16 (1..=256), `prefix_len` u8, `cursor_len` u8 (0 = no
//! cursor), then prefix and cursor bytes.
//!
//! Reply: `flags` u8 (bit 0 = more follow), reserved u8, `count` u16,
//! `generation` u64, then per entry: `shared` u8 (bytes shared with the
//! previous path), `suffix_len` u8, suffix, `value` u64. Paths are strictly
//! increasing; the last path is the cursor for the next page.
//!
//! Refusal: `code` u8, three reserved zero bytes.

use std::collections::TryReserveError;

pub use crate::path::MAX_PREFIX_BYTES;
use crate::path::{self, MAX_PATH_BYTES};
use crate::table::Table;

/// Body version.
pub const VERSION: u8 = 1;
/// Minimum interval between remote reads per session.
pub const MIN_INTERVAL_MS: u64 = 250;
/// Remote reads in flight per session.
pub const MAX_IN_FLIGHT: usize = 1;
/// Largest reply body.
pub const MAX_REPLY_BYTES: usize = 16 * 1024;
/// Most entries in one reply.
pub const MAX_PAGE_ENTRIES: u16 = 256;
/// Request deadline.
pub const DEADLINE_MS: u64 = 2_000;
/// Largest request body.
pub const MAX_REQUEST_BYTES: usize = HEADER + 4 + MAX_PREFIX_BYTES + MAX_PATH_BYTES;

const HEADER: usize = 8;
const REPLY_FIXED: usize = HEADER + 12;
const ENTRY_FIXED: usize = 2 + 8;

const KIND_REQUEST: u8 = 1;
const KIND_REPLY: u8 = 2;
const KIND_REFUSAL: u8 = 3;

/// Decode or encode failure. Never changes session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Truncated, trailing bytes, nonzero reserved fields or unknown kind.
    Malformed,
    /// Unsupported body version.
    Version,
    /// A field outside the v1 limits.
    Limits,
    /// A path, prefix or cursor is invalid.
    Path,
    /// Reply paths are not strictly increasing or lie outside the prefix.
    Order,
    /// Output allocation failed.
    Allocation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed meter body",
            Self::Version => "unsupported meter body version",
            Self::Limits => "meter body outside limits",
            Self::Path => "invalid meter path",
            Self::Order => "meter reply out of order or outside prefix",
            Self::Allocation => "meter body allocation failed",
        })
    }
}

impl std::error::Error for Error {}

impl From<TryReserveError> for Error {
    fn from(_: TryReserveError) -> Self {
        Self::Allocation
    }
}

/// Refusal codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Code {
    /// The request did not decode.
    Malformed = 1,
    /// The request is outside the v1 limits.
    Limits = 2,
    /// Faster than [`MIN_INTERVAL_MS`] or a read already in progress.
    Busy = 3,
    /// No running session owns meters.
    NotRunning = 4,
    /// The answering side does not serve meters.
    Unsupported = 5,
}

impl Code {
    fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            1 => Self::Malformed,
            2 => Self::Limits,
            3 => Self::Busy,
            4 => Self::NotRunning,
            5 => Self::Unsupported,
            _ => return Err(Error::Malformed),
        })
    }

    /// Stable name used by the local API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "peer_malformed",
            Self::Limits => "peer_limits",
            Self::Busy => "busy",
            Self::NotRunning => "peer_not_running",
            Self::Unsupported => "peer_unsupported",
        }
    }
}

/// One read request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    /// Correlates the reply.
    pub id: u32,
    /// Most entries wanted, 1..=[`MAX_PAGE_ENTRIES`].
    pub limit: u16,
    /// Whole-segment prefix; empty reads everything.
    pub prefix: &'a str,
    /// Last path of the previous page.
    pub cursor: Option<&'a str>,
}

/// One decoded reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    /// Request ID answered.
    pub id: u32,
    /// Session generation of the values.
    pub generation: u64,
    /// More matching entries follow the last one.
    pub more: bool,
    /// Entries in path order.
    pub entries: Vec<(String, u64)>,
}

/// One decoded refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refusal {
    /// Request ID refused.
    pub id: u32,
    /// Why.
    pub code: Code,
}

/// Any decoded body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message<'a> {
    /// A read request.
    Request(Request<'a>),
    /// A reply.
    Reply(Reply),
    /// A refusal.
    Refusal(Refusal),
}

fn header(out: &mut Vec<u8>, kind: u8, id: u32) {
    out.extend_from_slice(&[VERSION, kind, 0, 0]);
    out.extend_from_slice(&id.to_be_bytes());
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    if input.len() < count {
        return Err(Error::Malformed);
    }
    let (head, rest) = input.split_at(count);
    *input = rest;
    Ok(head)
}

fn byte(input: &mut &[u8]) -> Result<u8, Error> {
    Ok(take(input, 1)?[0])
}

fn u16_at(input: &mut &[u8]) -> Result<u16, Error> {
    let bytes = take(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn u32_at(input: &mut &[u8]) -> Result<u32, Error> {
    let bytes = take(input, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(input: &mut &[u8]) -> Result<u64, Error> {
    let bytes = take(input, 8)?;
    let mut array = [0; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(array))
}

fn text<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a str, Error> {
    std::str::from_utf8(take(input, count)?).map_err(|_| Error::Path)
}

impl<'a> Request<'a> {
    /// Check the v1 limits and path rules.
    pub fn validate(&self) -> Result<(), Error> {
        if self.limit == 0 || self.limit > MAX_PAGE_ENTRIES {
            return Err(Error::Limits);
        }
        path::validate_prefix(self.prefix).map_err(|_| Error::Path)?;
        if let Some(cursor) = self.cursor {
            path::validate(cursor).map_err(|_| Error::Path)?;
            if !path::under(self.prefix, cursor) {
                return Err(Error::Order);
            }
        }
        Ok(())
    }

    /// Encode into `out`, replacing its contents. `out` is unchanged on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        let cursor = self.cursor.unwrap_or("");
        let total = HEADER + 4 + self.prefix.len() + cursor.len();
        let mut body = Vec::new();
        body.try_reserve_exact(total)?;
        header(&mut body, KIND_REQUEST, self.id);
        body.extend_from_slice(&self.limit.to_be_bytes());
        // Both lengths fit u8: validated against MAX_PREFIX_BYTES/MAX_PATH_BYTES.
        body.push(self.prefix.len() as u8);
        body.push(cursor.len() as u8);
        body.extend_from_slice(self.prefix.as_bytes());
        body.extend_from_slice(cursor.as_bytes());
        *out = body;
        Ok(())
    }

    fn decode_body(id: u32, mut input: &'a [u8]) -> Result<Self, Error> {
        let limit = u16_at(&mut input)?;
        let prefix_len = usize::from(byte(&mut input)?);
        let cursor_len = usize::from(byte(&mut input)?);
        if prefix_len > MAX_PREFIX_BYTES || cursor_len > MAX_PATH_BYTES {
            return Err(Error::Limits);
        }
        let prefix = text(&mut input, prefix_len)?;
        let cursor = text(&mut input, cursor_len)?;
        if !input.is_empty() {
            return Err(Error::Malformed);
        }
        let request = Self {
            id,
            limit,
            prefix,
            cursor: (!cursor.is_empty()).then_some(cursor),
        };
        request.validate()?;
        Ok(request)
    }
}

impl Reply {
    /// Whether this reply is consistent with `request`: same ID, every path
    /// under its prefix, after its cursor and strictly increasing, at most
    /// its limit, and a cursor to continue when more follow.
    pub fn check(&self, request: &Request<'_>) -> Result<(), Error> {
        if self.id != request.id || self.entries.len() > usize::from(request.limit) {
            return Err(Error::Order);
        }
        if self.more && self.entries.is_empty() {
            return Err(Error::Order);
        }
        let mut previous = request.cursor;
        for (path, _) in &self.entries {
            if !path::under(request.prefix, path)
                || previous.is_some_and(|last| path.as_str() <= last)
            {
                return Err(Error::Order);
            }
            previous = Some(path);
        }
        Ok(())
    }

    fn decode_body(id: u32, mut input: &[u8]) -> Result<Self, Error> {
        let flags = byte(&mut input)?;
        if flags & !1 != 0 || byte(&mut input)? != 0 {
            return Err(Error::Malformed);
        }
        let count = u16_at(&mut input)?;
        if count > MAX_PAGE_ENTRIES {
            return Err(Error::Limits);
        }
        let generation = u64_at(&mut input)?;
        let mut entries: Vec<(String, u64)> = Vec::new();
        entries.try_reserve_exact(usize::from(count))?;
        let mut previous = String::new();
        for _ in 0..count {
            let shared = usize::from(byte(&mut input)?);
            let suffix_len = usize::from(byte(&mut input)?);
            if shared > previous.len() || shared + suffix_len > MAX_PATH_BYTES {
                return Err(Error::Limits);
            }
            let suffix = text(&mut input, suffix_len)?;
            if !previous.is_char_boundary(shared) {
                return Err(Error::Path);
            }
            let mut current = String::new();
            current.try_reserve_exact(shared + suffix_len)?;
            current.push_str(&previous[..shared]);
            current.push_str(suffix);
            path::validate(&current).map_err(|_| Error::Path)?;
            if !entries.is_empty() && current <= previous {
                return Err(Error::Order);
            }
            let value = u64_at(&mut input)?;
            previous.clone_from(&current);
            entries.push((current, value));
        }
        if !input.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id,
            generation,
            more: flags & 1 == 1,
            entries,
        })
    }
}

impl Refusal {
    /// Encode into `out`, replacing its contents.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut body = Vec::new();
        body.try_reserve_exact(HEADER + 4)?;
        header(&mut body, KIND_REFUSAL, self.id);
        body.extend_from_slice(&[self.code as u8, 0, 0, 0]);
        *out = body;
        Ok(())
    }

    fn decode_body(id: u32, mut input: &[u8]) -> Result<Self, Error> {
        let code = Code::from_byte(byte(&mut input)?)?;
        if take(&mut input, 3)? != [0, 0, 0] || !input.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { id, code })
    }
}

impl<'a> Message<'a> {
    /// Decode one complete body.
    pub fn decode(mut input: &'a [u8]) -> Result<Self, Error> {
        if input.len() > MAX_REPLY_BYTES {
            return Err(Error::Limits);
        }
        let version = byte(&mut input)?;
        let kind = byte(&mut input)?;
        if take(&mut input, 2)? != [0, 0] {
            return Err(Error::Malformed);
        }
        if version != VERSION {
            return Err(Error::Version);
        }
        let id = u32_at(&mut input)?;
        match kind {
            KIND_REQUEST => Request::decode_body(id, input).map(Self::Request),
            KIND_REPLY => Reply::decode_body(id, input).map(Self::Reply),
            KIND_REFUSAL => Refusal::decode_body(id, input).map(Self::Refusal),
            _ => Err(Error::Malformed),
        }
    }

    /// Request ID of a body that at least carries a complete header, so a
    /// malformed request can still be refused by ID.
    pub fn id_of(input: &[u8]) -> Option<u32> {
        let bytes = input.get(4..8)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Answer `request` from a sealed `table` into `out`, replacing its contents.
/// Entries stop at the request limit or the reply byte cap, whichever comes
/// first; `more` is set when matching entries remain.
pub fn answer(
    table: &Table,
    generation: u64,
    request: &Request<'_>,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    answer_bounded(table, generation, request, MAX_REPLY_BYTES, out)
}

/// Answer `request` from a sealed `table` into `out`, capping the encoded body
/// at `max_bytes.min(MAX_REPLY_BYTES)` so streams with a smaller message bound
/// page cleanly without overflowing.
pub fn answer_bounded(
    table: &Table,
    generation: u64,
    request: &Request<'_>,
    max_bytes: usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    request.validate()?;
    if !table.is_sealed() {
        return Err(Error::Order);
    }
    let cap = max_bytes.min(MAX_REPLY_BYTES);
    if cap < REPLY_FIXED {
        return Err(Error::Limits);
    }
    let mut body = Vec::new();
    body.try_reserve_exact(cap)?;
    header(&mut body, KIND_REPLY, request.id);
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&generation.to_be_bytes());
    let mut count: u16 = 0;
    let mut more = false;
    let mut previous = "";
    for (current, value) in table.matching(request.prefix, request.cursor) {
        let shared = previous
            .bytes()
            .zip(current.bytes())
            .take_while(|(left, right)| left == right)
            .count();
        let suffix = &current[shared..];
        if count == request.limit || body.len() + ENTRY_FIXED + suffix.len() > cap {
            more = true;
            break;
        }
        // Path lengths are at most MAX_PATH_BYTES, so both fit u8.
        body.push(shared as u8);
        body.push(suffix.len() as u8);
        body.extend_from_slice(suffix.as_bytes());
        body.extend_from_slice(&value.to_be_bytes());
        count += 1;
        previous = current;
    }
    body[HEADER] = u8::from(more);
    body[HEADER + 2..HEADER + 4].copy_from_slice(&count.to_be_bytes());
    debug_assert!(body.len() >= REPLY_FIXED);
    *out = body;
    Ok(())
}

/// Per-session admission of remote reads by an injected millisecond clock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateGate {
    last: Option<u64>,
}

impl RateGate {
    /// Admit a read at `now_ms` if at least [`MIN_INTERVAL_MS`] passed since
    /// the last admitted one. A clock regression is refused.
    pub fn admit(&mut self, now_ms: u64) -> bool {
        let ready = self.last.is_none_or(|last| {
            now_ms
                .checked_sub(last)
                .is_some_and(|gap| gap >= MIN_INTERVAL_MS)
        });
        if ready {
            self.last = Some(now_ms);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::Limits;

    type Outcome = Result<(), Box<dyn std::error::Error>>;

    fn table(count: usize) -> Result<Table, Box<dyn std::error::Error>> {
        let mut table = Table::new(Limits::for_entries(count + 2, 96))?;
        for index in 0..count {
            table.put(
                format_args!("runtime.native_ingress.lane{index}.user.wait.physical_receipt_pending.completed_episodes"),
                index as u64,
            )?;
        }
        table.put_str("meta.version", 1)?;
        table.seal()?;
        Ok(table)
    }

    fn reply(body: &[u8]) -> Result<Reply, Box<dyn std::error::Error>> {
        match Message::decode(body)? {
            Message::Reply(reply) => Ok(reply),
            other => Err(format!("unexpected {other:?}").into()),
        }
    }

    #[test]
    fn exact_request_bytes() -> Outcome {
        let request = Request {
            id: 0x0102_0304,
            limit: 256,
            prefix: "mux",
            cursor: Some("mux.ch1"),
        };
        let mut out = Vec::new();
        request.encode(&mut out)?;
        assert_eq!(
            out,
            [
                &[1, 1, 0, 0, 1, 2, 3, 4, 1, 0, 3, 7][..],
                b"mux",
                b"mux.ch1"
            ]
            .concat()
        );
        assert_eq!(Message::decode(&out)?, Message::Request(request));
        Ok(())
    }

    #[test]
    fn exact_reply_bytes_with_shared_prefix() -> Outcome {
        let mut table = Table::new(Limits::for_entries(4, 16))?;
        table.put_str("a.b", 1)?;
        table.put_str("a.c", 2)?;
        table.seal()?;
        let request = Request {
            id: 9,
            limit: 10,
            prefix: "a",
            cursor: None,
        };
        let mut out = Vec::new();
        answer(&table, 7, &request, &mut out)?;
        let mut expected = vec![1, 2, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7];
        expected.extend_from_slice(&[0, 3, b'a', b'.', b'b', 0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[2, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(out, expected);
        let decoded = reply(&out)?;
        decoded.check(&request)?;
        assert_eq!(
            decoded.entries,
            vec![("a.b".to_string(), 1), ("a.c".to_string(), 2)]
        );
        assert_eq!(decoded.generation, 7);
        assert!(!decoded.more);
        Ok(())
    }

    #[test]
    fn paging_covers_everything_once_within_the_byte_cap() -> Outcome {
        let table = table(600)?;
        let prefix = "runtime.native_ingress";
        let mut cursor: Option<String> = None;
        let mut seen = 0;
        loop {
            let request = Request {
                id: seen as u32,
                limit: MAX_PAGE_ENTRIES,
                prefix,
                cursor: cursor.as_deref(),
            };
            let mut out = Vec::new();
            answer(&table, 1, &request, &mut out)?;
            assert!(out.len() <= MAX_REPLY_BYTES);
            let page = reply(&out)?;
            page.check(&request)?;
            seen += page.entries.len();
            if !page.more {
                break;
            }
            cursor = page.entries.last().map(|(path, _)| path.clone());
        }
        assert_eq!(seen, 600);
        Ok(())
    }

    #[test]
    fn malformed_and_limit_failures() -> Outcome {
        let mut out = Vec::new();
        let bad = Request {
            id: 1,
            limit: 0,
            prefix: "",
            cursor: None,
        };
        assert_eq!(bad.encode(&mut out), Err(Error::Limits));
        let over = Request { limit: 257, ..bad };
        assert_eq!(over.encode(&mut out), Err(Error::Limits));
        let outside = Request {
            limit: 1,
            prefix: "mux",
            cursor: Some("quic.connection"),
            ..bad
        };
        assert_eq!(outside.encode(&mut out), Err(Error::Order));
        assert!(out.is_empty());
        let good = Request {
            id: 5,
            limit: 1,
            prefix: "mux",
            cursor: None,
        };
        good.encode(&mut out)?;
        let mut trailing = out.clone();
        trailing.push(0);
        assert_eq!(Message::decode(&trailing), Err(Error::Malformed));
        let mut version = out.clone();
        version[0] = 2;
        assert_eq!(Message::decode(&version), Err(Error::Version));
        let mut reserved = out.clone();
        reserved[2] = 1;
        assert_eq!(Message::decode(&reserved), Err(Error::Malformed));
        let mut kind = out.clone();
        kind[1] = 9;
        assert_eq!(Message::decode(&kind), Err(Error::Malformed));
        let mut path = out.clone();
        path[12] = b'M';
        assert_eq!(Message::decode(&path), Err(Error::Path));
        for cut in 0..out.len() {
            assert!(Message::decode(&out[..cut]).is_err());
        }
        assert_eq!(Message::id_of(&out), Some(5));
        assert_eq!(
            Message::decode(&vec![0; MAX_REPLY_BYTES + 1]),
            Err(Error::Limits)
        );
        Ok(())
    }

    #[test]
    fn replies_must_be_ordered_and_consistent() -> Outcome {
        // Two entries where the second does not increase.
        let mut body = vec![1, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1];
        body.extend_from_slice(&[0, 3, b'a', b'.', b'c', 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[2, 1, b'b', 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(Message::decode(&body), Err(Error::Order));
        // Shared length beyond the previous path.
        let mut shared = vec![1, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        shared.extend_from_slice(&[4, 1, b'x', 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(Message::decode(&shared), Err(Error::Limits));
        let request = Request {
            id: 1,
            limit: 1,
            prefix: "a",
            cursor: None,
        };
        let wrong = Reply {
            id: 1,
            generation: 0,
            more: true,
            entries: Vec::new(),
        };
        assert_eq!(wrong.check(&request), Err(Error::Order));
        let outside = Reply {
            more: false,
            entries: vec![("b".into(), 1)],
            ..wrong.clone()
        };
        assert_eq!(outside.check(&request), Err(Error::Order));
        Ok(())
    }

    #[test]
    fn refusal_round_trip_and_rate_gate() -> Outcome {
        let mut out = Vec::new();
        Refusal {
            id: 3,
            code: Code::Busy,
        }
        .encode(&mut out)?;
        assert_eq!(out, [1, 3, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0]);
        assert_eq!(
            Message::decode(&out)?,
            Message::Refusal(Refusal {
                id: 3,
                code: Code::Busy
            })
        );
        out[8] = 0;
        assert_eq!(Message::decode(&out), Err(Error::Malformed));
        let mut gate = RateGate::default();
        assert!(gate.admit(1_000));
        assert!(!gate.admit(1_249));
        assert!(gate.admit(1_250));
        assert!(!gate.admit(1_000));
        Ok(())
    }

    #[test]
    fn answer_bounded_pages_within_custom_byte_cap() -> Outcome {
        let mut table = Table::new(Limits::for_entries(16, 48))?;
        for i in 0_u32..8 {
            table.put(format_args!("runtime.meter.k{i:02}"), u64::from(i) + 1)?;
        }
        table.seal()?;
        let cap = 96;
        let mut collected = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        let mut out = Vec::new();
        loop {
            let req = Request {
                id: pages as u32 + 1,
                limit: 256,
                prefix: "runtime.meter",
                cursor: cursor.as_deref(),
            };
            answer_bounded(&table, 7, &req, cap, &mut out)?;
            assert!(out.len() <= cap, "encoded {} > {cap}", out.len());
            let Message::Reply(reply) = Message::decode(&out)? else {
                return Err("expected reply".into());
            };
            reply.check(&req)?;
            assert_eq!(reply.generation, 7);
            assert!(!reply.entries.is_empty());
            collected.extend(reply.entries.iter().cloned());
            pages += 1;
            if !reply.more {
                break;
            }
            cursor = reply.entries.last().map(|(path, _)| path.clone());
        }
        assert!(pages >= 2, "expected multiple pages under {cap}-byte cap");
        assert_eq!(collected.len(), 8);
        assert_eq!(collected[0], ("runtime.meter.k00".into(), 1));
        assert_eq!(collected[7], ("runtime.meter.k07".into(), 8));
        Ok(())
    }
}
