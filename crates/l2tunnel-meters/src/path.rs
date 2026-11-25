//! Named register paths and whole-segment prefix matching.

/// Maximum path length in bytes (a 20-digit flow ID with the longest wait
/// reason needs 103).
pub const MAX_PATH_BYTES: usize = 128;
/// Maximum query prefix length in bytes.
pub const MAX_PREFIX_BYTES: usize = 96;
/// Maximum number of dot-separated segments.
pub const MAX_SEGMENTS: usize = 10;

/// Why a path or prefix was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// Empty path (an empty prefix is valid and matches everything).
    Empty,
    /// Longer than [`MAX_PATH_BYTES`].
    TooLong,
    /// More than [`MAX_SEGMENTS`] segments.
    TooManySegments,
    /// An empty segment (leading, trailing or doubled dot).
    EmptySegment,
    /// A byte outside `[a-z0-9_]` in a segment.
    InvalidByte,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty meter path",
            Self::TooLong => "meter path or prefix too long",
            Self::TooManySegments => "meter path with more than 10 segments",
            Self::EmptySegment => "meter path with an empty segment",
            Self::InvalidByte => "meter path byte outside [a-z0-9_.]",
        })
    }
}

impl std::error::Error for PathError {}

/// Validate one complete register path.
pub fn validate(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    let mut segments = 0_usize;
    for segment in path.split('.') {
        segments += 1;
        if segments > MAX_SEGMENTS {
            return Err(PathError::TooManySegments);
        }
        if segment.is_empty() {
            return Err(PathError::EmptySegment);
        }
        if !segment.bytes().all(segment_byte) {
            return Err(PathError::InvalidByte);
        }
    }
    Ok(())
}

/// Validate a query prefix: empty, or a valid path.
pub fn validate_prefix(prefix: &str) -> Result<(), PathError> {
    if prefix.is_empty() {
        Ok(())
    } else if prefix.len() > MAX_PREFIX_BYTES {
        Err(PathError::TooLong)
    } else {
        validate(prefix)
    }
}

/// Whether `path` lies under `prefix`, matching whole segments only.
///
/// `runtime.native_ingress` matches itself and `runtime.native_ingress.lane0`,
/// never `runtime.native_ingress_x`. The empty prefix matches every path.
pub fn under(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('.'),
        None => false,
    }
}

/// Byte allowed inside one segment.
pub const fn segment_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

/// One instance segment: `tag` followed by a decimal index without leading
/// zeros, for example `lane0`, `ch12`, `flow42`.
pub fn instance(segment: &str, tag: &str) -> Option<u64> {
    let digits = segment.strip_prefix(tag)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths_and_limits() {
        assert_eq!(
            validate("runtime.native_ingress.lane0.user.refusals"),
            Ok(())
        );
        assert_eq!(validate(""), Err(PathError::Empty));
        assert_eq!(validate("a..b"), Err(PathError::EmptySegment));
        assert_eq!(validate(".a"), Err(PathError::EmptySegment));
        assert_eq!(validate("a."), Err(PathError::EmptySegment));
        assert_eq!(validate("A.b"), Err(PathError::InvalidByte));
        assert_eq!(validate("a-b"), Err(PathError::InvalidByte));
        assert_eq!(validate("a.b.c.d.e.f.g.h.i.j"), Ok(()));
        assert_eq!(
            validate("a.b.c.d.e.f.g.h.i.j.k"),
            Err(PathError::TooManySegments)
        );
        let long = "a".repeat(MAX_PATH_BYTES);
        assert_eq!(validate(&long), Ok(()));
        assert_eq!(validate(&(long + "a")), Err(PathError::TooLong));
        assert_eq!(validate_prefix(""), Ok(()));
        assert_eq!(
            validate_prefix(&"a".repeat(MAX_PREFIX_BYTES + 1)),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn prefix_matches_whole_segments() {
        assert!(under("", "a.b"));
        assert!(under("runtime.native_ingress", "runtime.native_ingress"));
        assert!(under(
            "runtime.native_ingress",
            "runtime.native_ingress.lane0"
        ));
        assert!(!under("runtime.native_ingress", "runtime.native_ingress_x"));
        assert!(!under("runtime.native", "runtime.native_ingress.lane0"));
        assert!(!under(
            "runtime.native_ingress.lane0",
            "runtime.native_ingress"
        ));
    }

    #[test]
    fn instance_segments() {
        assert_eq!(instance("lane0", "lane"), Some(0));
        assert_eq!(instance("ch12", "ch"), Some(12));
        assert_eq!(instance("ch012", "ch"), None);
        assert_eq!(instance("ch", "ch"), None);
        assert_eq!(instance("chx", "ch"), None);
        assert_eq!(instance("flow18446744073709551615", "flow"), Some(u64::MAX));
        assert_eq!(instance("flow18446744073709551616", "flow"), None);
    }
}
