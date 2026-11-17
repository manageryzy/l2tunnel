//! Shared first-cause errors retain their source and exact owner-local identity.
use std::{fmt, io, sync::Arc};

#[derive(Clone, Debug)]
pub(crate) struct Failure {
    cause: Arc<io::Error>,
    peer_close: bool,
}
impl Failure {
    pub(crate) fn new(cause: io::Error, peer_close: bool) -> Self {
        Self {
            cause: Arc::new(cause),
            peer_close,
        }
    }
    pub(crate) fn error(&self) -> io::Error {
        io::Error::new(self.cause.kind(), self.clone())
    }
    pub(crate) fn is_peer_close(&self, error: &io::Error) -> bool {
        self.peer_close
            && error
                .get_ref()
                .and_then(|source| source.downcast_ref::<Self>())
                .is_some_and(|other| Arc::ptr_eq(&self.cause, &other.cause))
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(out)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_close_requires_the_same_retained_first_cause() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = Failure::new(io::ErrorKind::UnexpectedEof.into(), true);
        let error = first.error();
        assert!(first.is_peer_close(&error));
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            std::error::Error::source(error.get_ref().ok_or("missing retained source")?).is_some()
        );
        assert!(!first.is_peer_close(&io::ErrorKind::UnexpectedEof.into()));
        let other = Failure::new(io::ErrorKind::UnexpectedEof.into(), true);
        assert!(!first.is_peer_close(&other.error()));
        let timeout = Failure::new(io::ErrorKind::TimedOut.into(), false);
        assert!(!timeout.is_peer_close(&timeout.error()));
        Ok(())
    }
}
