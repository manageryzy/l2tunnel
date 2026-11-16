//! Exact legacy symbol batches. Structure is not authentication or receipt authority.
use super::{
    Config, Error, Scope, SourceId, Term,
    batch::{Kind, Packing},
    wire,
};

/// Versioned batch envelope bytes, before each inner record's two-byte length.
pub const HEADER_BYTES: usize = 8;
/// Batch format version. Existing L2LS version-one records are unchanged.
pub const VERSION: u8 = 1;

/// A completely validated borrowed batch; every item is still a maintained v1 record.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    kind: Kind,
    scope: Scope,
    count: usize,
    body: &'a [u8],
}
impl<'a> View<'a> {
    /// Source, repair or single retry packet class.
    pub fn kind(self) -> Kind {
        self.kind
    }
    /// Common domain observed in all inner records, not an authentication grant.
    pub fn scope(self) -> Scope {
        self.scope
    }
    /// Exact represented record count.
    pub fn count(self) -> usize {
        self.count
    }
    /// Iterate the already validated record boundaries without allocating.
    pub fn records(self) -> Records<'a> {
        Records { body: self.body }
    }
}
/// Exact borrowed inner-record iterator.
pub struct Records<'a> {
    body: &'a [u8],
}
impl<'a> Iterator for Records<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.body.get(..2)?;
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let record = self.body.get(2..2 + length)?;
        self.body = self.body.get(2 + length..)?;
        Some(record)
    }
}
pub(super) fn header(kind: Kind, count: usize) -> Result<[u8; HEADER_BYTES], Error> {
    if count == 0 || count > 255 {
        return Err(Error::Length);
    }
    let mut bytes = [0u8; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"L2LB");
    bytes[4] = VERSION;
    bytes[5] = kind.code();
    bytes[6..8].copy_from_slice(&(count as u16).to_be_bytes());
    Ok(bytes)
}
/// Validate the entire bounded batch and every canonical inner record before iteration.
/// Parsing uses fixed scratch for at most 255 terms/IDs, and grants no peer authority.
pub fn inspect<'a>(config: Config, packing: Packing, bytes: &'a [u8]) -> Result<View<'a>, Error> {
    packing.validate(config)?;
    if bytes.len() < HEADER_BYTES
        || bytes.len() > packing.max_packet_bytes
        || bytes.get(..4) != Some(b"L2LB".as_slice())
        || bytes[4] != VERSION
    {
        return Err(Error::Format);
    }
    let kind = Kind::from_code(bytes[5])?;
    let count = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    let maximum = match kind {
        Kind::Source => packing.source_batch,
        Kind::Repair => packing.repair_batch,
        Kind::Retry => 1,
    };
    if count == 0 || count > usize::from(maximum) {
        return Err(Error::Length);
    }
    let mut body = &bytes[HEADER_BYTES..];
    let mut scope = None;
    let mut previous = None;
    let mut terms = [Term {
        source: SourceId(0),
        coefficient: 0,
    }; 255];
    let mut ids = [SourceId(0); 255];
    for _ in 0..count {
        let prefix = body.get(..2).ok_or(Error::Length)?;
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let record = body.get(2..2 + length).ok_or(Error::Length)?;
        let (domain, identity) = match wire::inspect(config, record, &mut terms, &mut ids)? {
            wire::View::Source { scope, id, .. } if kind != Kind::Repair => {
                (scope, u64::from(id.0))
            }
            wire::View::Repair(repair) if kind == Kind::Repair => {
                (repair.equation.scope, repair.equation.id.0)
            }
            _ => return Err(Error::Format),
        };
        if scope.is_some_and(|old| old != domain) || previous.is_some_and(|old| identity <= old) {
            return Err(Error::Identity);
        }
        scope = Some(domain);
        previous = Some(identity);
        body = &body[2 + length..];
    }
    if !body.is_empty() {
        return Err(Error::Length);
    }
    Ok(View {
        kind,
        scope: scope.ok_or(Error::Identity)?,
        count,
        body: &bytes[HEADER_BYTES..],
    })
}
