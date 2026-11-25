//! A bounded, sorted register table with one fallible reservation.

use std::collections::TryReserveError;
use std::fmt::{self, Write as _};

use crate::path::{self, PathError};

/// Capacity of one table, fixed at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum number of registers.
    pub entries: usize,
    /// Maximum total path bytes.
    pub path_bytes: usize,
}

impl Limits {
    /// Limits for `entries` registers of average path length `average`.
    pub const fn for_entries(entries: usize, average: usize) -> Self {
        Self {
            entries,
            path_bytes: entries.saturating_mul(average),
        }
    }
}

/// Why a register could not be stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    /// The path is invalid.
    Path(PathError),
    /// The entry or path-byte capacity is exhausted.
    Full,
    /// The same path was written twice before [`Table::seal`].
    Duplicate,
    /// A read was attempted before [`Table::seal`].
    Unsealed,
}

impl fmt::Display for TableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => error.fmt(formatter),
            Self::Full => formatter.write_str("meter table capacity exhausted"),
            Self::Duplicate => formatter.write_str("duplicate meter path"),
            Self::Unsealed => formatter.write_str("meter table read before seal"),
        }
    }
}

impl std::error::Error for TableError {}

impl From<PathError> for TableError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    start: u32,
    len: u8,
    value: u64,
}

/// Registers with paths stored in one arena. After construction neither
/// writes nor reads allocate.
#[derive(Debug)]
pub struct Table {
    arena: String,
    entries: Vec<Entry>,
    limits: Limits,
    sealed: bool,
}

/// One page of a prefix read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<'a> {
    /// Matching registers in path order.
    pub entries: Vec<(&'a str, u64)>,
    /// Whether more matching registers follow the last returned one. The last
    /// returned path is the cursor for the next page.
    pub more: bool,
}

impl Table {
    /// Reserve a table. Fails instead of aborting on allocation failure.
    pub fn new(limits: Limits) -> Result<Self, TryReserveError> {
        let mut arena = String::new();
        arena.try_reserve_exact(limits.path_bytes)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(limits.entries)?;
        Ok(Self {
            arena,
            entries,
            limits,
            sealed: false,
        })
    }

    /// Fallible copy with the same limits.
    pub fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut copy = Self::new(self.limits)?;
        copy.arena.push_str(&self.arena);
        copy.entries.extend_from_slice(&self.entries);
        copy.sealed = self.sealed;
        Ok(copy)
    }

    /// Fallible copy reserving exactly the space in use.
    pub fn try_compact(&self) -> Result<Self, TryReserveError> {
        let mut copy = Self::new(Limits {
            entries: self.entries.len(),
            path_bytes: self.arena.len(),
        })?;
        copy.arena.push_str(&self.arena);
        copy.entries.extend_from_slice(&self.entries);
        copy.sealed = self.sealed;
        Ok(copy)
    }

    /// Replace this table's contents with `other`'s, reusing the reservation.
    pub fn copy_from(&mut self, other: &Self) -> Result<(), TableError> {
        if other.arena.len() > self.limits.path_bytes || other.entries.len() > self.limits.entries {
            return Err(TableError::Full);
        }
        self.clear();
        self.arena.push_str(&other.arena);
        self.entries.extend_from_slice(&other.entries);
        self.sealed = other.sealed;
        Ok(())
    }

    /// Capacity fixed at construction.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Reserved heap bytes.
    pub fn heap_bytes(&self) -> usize {
        self.arena
            .capacity()
            .saturating_add(self.entries.capacity() * std::mem::size_of::<Entry>())
    }

    /// Remove every register; the reservation is kept.
    pub fn clear(&mut self) {
        self.arena.clear();
        self.entries.clear();
        self.sealed = false;
    }

    /// Number of registers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no register.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether [`Table::seal`] completed since the last write.
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Store one register whose path is formatted from `path`. On any error
    /// the table is unchanged.
    pub fn put(&mut self, path: fmt::Arguments<'_>, value: u64) -> Result<(), TableError> {
        if self.entries.len() >= self.limits.entries {
            return Err(TableError::Full);
        }
        let start = self.arena.len();
        let mut bounded = Bounded {
            arena: &mut self.arena,
            limit: self.limits.path_bytes,
            overflow: false,
        };
        if bounded.write_fmt(path).is_err() || bounded.overflow {
            let overflow = bounded.overflow;
            self.arena.truncate(start);
            return Err(if overflow {
                TableError::Full
            } else {
                TableError::Path(PathError::InvalidByte)
            });
        }
        let written = &self.arena[start..];
        if let Err(error) = path::validate(written) {
            self.arena.truncate(start);
            return Err(error.into());
        }
        let (Ok(start32), Ok(len)) = (u32::try_from(start), u8::try_from(written.len())) else {
            self.arena.truncate(start);
            return Err(TableError::Full);
        };
        self.entries.push(Entry {
            start: start32,
            len,
            value,
        });
        self.sealed = false;
        Ok(())
    }

    /// Store one register with a literal path.
    pub fn put_str(&mut self, path: &str, value: u64) -> Result<(), TableError> {
        self.put(format_args!("{path}"), value)
    }

    /// Sort by path and reject duplicates. Required before reads.
    pub fn seal(&mut self) -> Result<(), TableError> {
        let arena = &self.arena;
        self.entries
            .sort_unstable_by(|left, right| text(arena, left).cmp(text(arena, right)));
        if self
            .entries
            .windows(2)
            .any(|pair| text(arena, &pair[0]) == text(arena, &pair[1]))
        {
            return Err(TableError::Duplicate);
        }
        self.sealed = true;
        Ok(())
    }

    /// All registers in path order (insertion order before sealing).
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.entries
            .iter()
            .map(|entry| (text(&self.arena, entry), entry.value))
    }

    /// Exact lookup in a sealed table.
    pub fn get(&self, path: &str) -> Option<u64> {
        if !self.sealed {
            return None;
        }
        self.entries
            .binary_search_by(|entry| text(&self.arena, entry).cmp(path))
            .ok()
            .map(|index| self.entries[index].value)
    }

    /// Registers under `prefix` strictly after `after`, at most `limit`.
    ///
    /// Matching paths are contiguous in path order because `.` sorts before
    /// every segment byte.
    pub fn page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<'_>, TableError> {
        if !self.sealed {
            return Err(TableError::Unsealed);
        }
        let mut entries = Vec::new();
        let mut more = false;
        for (path, value) in self.matching(prefix, after) {
            if entries.len() == limit {
                more = true;
                break;
            }
            entries.push((path, value));
        }
        Ok(Page { entries, more })
    }

    /// Iterator over registers under `prefix` strictly after `after`, in path
    /// order. Requires a sealed table; an unsealed table yields nothing.
    pub fn matching<'s, 'q>(
        &'s self,
        prefix: &'q str,
        after: Option<&'q str>,
    ) -> impl Iterator<Item = (&'s str, u64)> + use<'s, 'q> {
        let begin = if self.sealed {
            let floor = |entry: &Entry| text(&self.arena, entry) < prefix;
            let start = self.entries.partition_point(floor);
            match after {
                Some(cursor) => start.max(
                    self.entries
                        .partition_point(|entry| text(&self.arena, entry) <= cursor),
                ),
                None => start,
            }
        } else {
            self.entries.len()
        };
        self.entries[begin..]
            .iter()
            .map(|entry| (text(&self.arena, entry), entry.value))
            .take_while(move |(path, _)| path::under(prefix, path))
    }
}

fn text<'a>(arena: &'a str, entry: &Entry) -> &'a str {
    let start = entry.start as usize;
    &arena[start..start + usize::from(entry.len)]
}

struct Bounded<'a> {
    arena: &'a mut String,
    limit: usize,
    overflow: bool,
}

impl fmt::Write for Bounded<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.arena.len().saturating_add(text.len()) > self.limit {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.arena.push_str(text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Outcome = Result<(), Box<dyn std::error::Error>>;

    fn table() -> Result<Table, Box<dyn std::error::Error>> {
        let mut table = Table::new(Limits::for_entries(16, 48))?;
        for (path, value) in [
            ("runtime.native_ingress_x.a", 9),
            ("runtime.native_ingress.lane1.refusals", 2),
            ("runtime.native_ingress", 0),
            ("runtime.native_ingress.lane0.refusals", 1),
            ("recovery.arq.ch0.tx.retransmits", 5),
        ] {
            table.put_str(path, value)?;
        }
        table.seal()?;
        Ok(table)
    }

    #[test]
    fn pages_follow_prefix_and_cursor() -> Outcome {
        let table = table()?;
        let page = table.page("runtime.native_ingress", None, 2)?;
        assert_eq!(
            page.entries,
            vec![
                ("runtime.native_ingress", 0),
                ("runtime.native_ingress.lane0.refusals", 1)
            ]
        );
        assert!(page.more);
        let next = table.page(
            "runtime.native_ingress",
            Some("runtime.native_ingress.lane0.refusals"),
            2,
        )?;
        assert_eq!(
            next.entries,
            vec![("runtime.native_ingress.lane1.refusals", 2)]
        );
        assert!(!next.more);
        let all = table.page("", None, 100)?;
        assert_eq!(all.entries.len(), 5);
        assert_eq!(table.get("recovery.arq.ch0.tx.retransmits"), Some(5));
        assert_eq!(table.get("recovery.arq"), None);
        Ok(())
    }

    #[test]
    fn limits_and_errors_leave_table_unchanged() -> Outcome {
        let mut table = Table::new(Limits {
            entries: 2,
            path_bytes: 8,
        })?;
        assert_eq!(table.put_str("a.b", 1), Ok(()));
        assert_eq!(table.put_str("toolongpath", 1), Err(TableError::Full));
        assert_eq!(
            table.put_str("A", 1),
            Err(TableError::Path(PathError::InvalidByte))
        );
        assert_eq!(
            table.put_str("a..", 1),
            Err(TableError::Path(PathError::EmptySegment))
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.put_str("a.b", 2), Ok(()));
        assert_eq!(table.put_str("c", 2), Err(TableError::Full));
        assert_eq!(table.seal(), Err(TableError::Duplicate));
        assert_eq!(table.page("", None, 1), Err(TableError::Unsealed));
        table.clear();
        assert!(table.is_empty());
        Ok(())
    }

    #[test]
    fn copies_reuse_reservation() -> Outcome {
        let source = table()?;
        let mut target = Table::new(source.limits())?;
        assert_eq!(target.copy_from(&source), Ok(()));
        assert_eq!(target.get("runtime.native_ingress"), Some(0));
        let mut small = Table::new(Limits {
            entries: 1,
            path_bytes: 4,
        })?;
        assert_eq!(small.copy_from(&source), Err(TableError::Full));
        let clone = source.try_clone()?;
        assert_eq!(clone.len(), source.len());
        let compact = source.try_compact()?;
        assert_eq!(compact.get("runtime.native_ingress"), Some(0));
        assert!(compact.heap_bytes() < source.heap_bytes());
        Ok(())
    }
}
