//! One checked framing boundary for both existing Common security versions.
//!
//! This preserves their exact route, cover and protection bytes. Parsed routes
//! remain untrusted until the selected security owner accepts the complete record.

use super::{Capacity, Class, Error, Owners, ROUTE_BYTES, Records, Scope, Sealed};
use crate::{cover, security};

#[derive(Clone, Copy)]
pub(super) enum Format {
    Initial,
    Refreshable,
}
impl Format {
    pub(super) const fn prefix_bytes(self) -> usize {
        match self {
            Self::Initial => security::COMMON_PREFIX_BYTES,
            Self::Refreshable => security::refresh::PREFIX_BYTES,
        }
    }

    pub(super) fn capacity(
        self,
        cover: cover::Config,
        limits: security::Limits,
        protection: security::Protection,
        plaintext_bytes: usize,
    ) -> Result<Capacity, Error> {
        if plaintext_bytes > limits.max_body_bytes {
            return Err(Error::TooLarge);
        }
        let protected_bytes = plaintext_bytes
            .checked_add(self.prefix_bytes())
            .and_then(|bytes| bytes.checked_add(protection.tag_bytes()))
            .and_then(|bytes| bytes.checked_add(ROUTE_BYTES))
            .ok_or(Error::TooLarge)?;
        let packet_bytes = protected_bytes
            .checked_add(cover.overhead(cover::Phase::Established, protected_bytes)?)
            .ok_or(Error::TooLarge)?;
        if packet_bytes > cover.limits().max_packet_bytes {
            return Err(Error::TooLarge);
        }
        let open_workspace_bytes = plaintext_bytes
            .checked_add(protection.tag_bytes())
            .ok_or(Error::TooLarge)?;
        Ok(Capacity {
            plaintext_bytes,
            seal_workspace_bytes: protected_bytes,
            open_workspace_bytes,
            packet_bytes,
        })
    }
}

pub(super) struct Route {
    pub(super) class: Class,
    pub(super) scope: Scope,
    pub(super) bytes: [u8; ROUTE_BYTES],
}
impl Route {
    pub(super) fn new(class: Class, scope: Scope) -> Self {
        let mut bytes = [0; ROUTE_BYTES];
        bytes[0] = class as u8;
        bytes[1..].copy_from_slice(&scope.epoch.0.to_be_bytes());
        Self {
            class,
            scope,
            bytes,
        }
    }

    pub(super) fn metadata(&self) -> security::Metadata<'_> {
        security::Metadata {
            epoch: self.scope.epoch,
            configuration: self.scope.configuration,
            extra: &self.bytes,
        }
    }
}

pub(super) struct Incoming<'a> {
    pub(super) route: Route,
    pub(super) protected: &'a [u8],
}

impl Records {
    pub(super) fn format(&self) -> Format {
        match self.owners {
            Owners::Legacy { .. } => Format::Initial,
            Owners::Refreshable(_) => Format::Refreshable,
        }
    }

    pub(super) fn preflight(
        &self,
        outer: cover::PacketMeta,
        body: usize,
        workspace: &[u8],
        output: &[u8],
    ) -> Result<Capacity, Error> {
        if outer.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        let capacity = self.capacity(body)?;
        if workspace.len() < capacity.seal_workspace_bytes || output.len() < capacity.packet_bytes {
            return Err(Error::OutputTooSmall);
        }
        Ok(capacity)
    }

    pub(super) fn finish_cover(
        &self,
        outer: cover::PacketMeta,
        route: [u8; ROUTE_BYTES],
        sealed: security::Sealed,
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        let protected_bytes = ROUTE_BYTES
            .checked_add(sealed.bytes)
            .ok_or(Error::TooLarge)?;
        let protected = workspace
            .get_mut(..protected_bytes)
            .ok_or(Error::OutputTooSmall)?;
        protected[..ROUTE_BYTES].copy_from_slice(&route);
        let bytes = self.cover.encode(outer, protected, output)?;
        Ok(Sealed {
            number: sealed.number,
            generation: sealed.generation,
            bytes,
        })
    }

    pub(super) fn incoming<'a>(
        &self,
        packet: &'a [u8],
        workspace: &[u8],
        plaintext: &[u8],
    ) -> Result<Incoming<'a>, Error> {
        let decoded = self.cover.decode(packet)?;
        if decoded.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        let bytes: [u8; ROUTE_BYTES] = decoded
            .protected
            .get(..ROUTE_BYTES)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let class = match bytes[0] {
            1 => Class::User,
            2 => Class::Control,
            _ => return Err(Error::Malformed),
        };
        let epoch = security::Epoch(u64::from_be_bytes(
            bytes[1..].try_into().map_err(|_| Error::Malformed)?,
        ));
        let scope = self.registered_scope(class, epoch)?;
        let protected = &decoded.protected[ROUTE_BYTES..];
        let body_bytes = protected
            .len()
            .checked_sub(self.format().prefix_bytes() + self.protection.tag_bytes())
            .ok_or(Error::Malformed)?;
        let capacity = self.capacity(body_bytes)?;
        if workspace.len() < capacity.open_workspace_bytes || plaintext.len() < body_bytes {
            return Err(Error::OutputTooSmall);
        }
        Ok(Incoming {
            route: Route {
                class,
                scope,
                bytes,
            },
            protected,
        })
    }
}
