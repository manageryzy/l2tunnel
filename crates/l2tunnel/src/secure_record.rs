//! Pure authenticated User/Control records inside an explicitly selected cover.
//!
//! Routes are untrusted hints until the selected purpose owner authenticates the
//! exact route. Local staged readers do not negotiate or commit a peer switch.

use crate::{cover, security};
use std::fmt;

/// Explicit selected v2 consumption; legacy constructors and bytes are unchanged.
#[path = "secure_record_refresh.rs"]
pub mod refresh;

/// Public route bytes before the complete common packet-security record.
pub const ROUTE_BYTES: usize = 9;

/// Authenticated record authority, independent of user Ethernet/IP contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Class {
    /// User records and ordinary data-algorithm feedback.
    User = 1,
    /// Stable authenticated management records.
    Control = 2,
}

/// Registered authenticated epoch and complete configuration digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Epoch selected by the higher-level negotiated state machine.
    pub epoch: security::Epoch,
    /// Exact canonical configuration bound to that epoch.
    pub configuration: security::ConfigDigest,
}

/// Local ownership state of the single additional data reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderState {
    /// Receive is prepared, but outgoing data still uses the active scope.
    Staged,
    /// Default outgoing data changed; the prior scope remains registered.
    /// Explicit directional feedback can still use it through `seal_user_in`.
    Draining,
}

/// The one bounded additional data reader, sharing existing security state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataReader {
    /// Exact accepted additional epoch/digest.
    pub scope: Scope,
    /// Local staged or draining state; never proof of a remote commit.
    pub state: ReaderState,
}

/// Exact caller capacities for an opaque plaintext length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    /// Plaintext bytes returned after successful opening.
    pub plaintext_bytes: usize,
    /// Complete route plus protected record needed while sealing.
    pub seal_workspace_bytes: usize,
    /// Body plus selected tag required by the security receiver.
    pub open_workspace_bytes: usize,
    /// Complete established cover packet, excluding IP/UDP headers.
    pub packet_bytes: usize,
}

/// Successful complete covered packet emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sealed {
    /// Unique identity owned by this class's security sender.
    pub number: security::PacketNumber,
    /// Actual sender key generation used for this protected record.
    pub generation: security::KeyGeneration,
    /// Complete covered packet bytes in caller output.
    pub bytes: usize,
}

/// Authenticated dispatch result; no result exists on failed authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened {
    /// Authenticated User or Control authority.
    pub class: Class,
    /// Exact registered authenticated epoch/digest.
    pub scope: Scope,
    /// Full authenticated security packet identity, never the outer cover number.
    pub number: security::PacketNumber,
    /// Authenticated key generation selected by that security identity.
    pub generation: security::KeyGeneration,
    /// Plaintext bytes at the start of caller output.
    pub bytes: usize,
}

/// Structural, local-state, capacity or maintained-protection rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The route or protected record is shorter than its required fields.
    Malformed,
    /// The untrusted route does not identify a registered scope of that class.
    Scope,
    /// A local stage/activation/retirement does not match its bounded state.
    ScopeState,
    /// Only established-phase covered records are valid at this boundary.
    Phase,
    /// Plaintext or complete packet exceeds its checked fixed bound.
    TooLarge,
    /// Workspace or final output cannot hold the complete result.
    OutputTooSmall,
    /// The selected structural cover rejected the packet or capacity.
    Cover(cover::Error),
    /// The maintained common security owner rejected the operation.
    Security(security::Error),
    /// Selected refresh ownership/time/protection rejected the operation.
    Refresh(security::refresh::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "secure record error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<cover::Error> for Error {
    fn from(value: cover::Error) -> Self {
        Self::Cover(value)
    }
}
impl From<security::Error> for Error {
    fn from(value: security::Error) -> Self {
        Self::Security(value)
    }
}
impl From<security::refresh::Error> for Error {
    fn from(value: security::refresh::Error) -> Self {
        Self::Refresh(value)
    }
}

// Retain the existing inline legacy owner layout. Selected v2 is one fallibly
// reserved private singleton; no per-packet allocation or duplicate owner exists.
#[allow(clippy::large_enum_variant)]
enum Owners {
    Legacy {
        data_sender: security::Sender,
        data_receiver: security::Receiver,
        control_sender: security::Sender,
        control_receiver: security::Receiver,
    },
    Refreshable(Vec<security::refresh::Owners>),
}

/// Fixed-domain secure records, without clocks, I/O or per-packet allocations.
///
/// Control scope is immutable. Both registered data scopes share the same data
/// sender/receiver, so no scope operation resets counters, ratchets or replay.
/// The caller must authenticate and complete negotiated switch barriers before
/// changing outgoing scope or retiring an old reader.
pub struct Records {
    cover: cover::Config,
    limits: security::Limits,
    protection: security::Protection,
    control: Scope,
    data: Scope,
    additional: Option<DataReader>,
    owners: Owners,
}

impl Records {
    /// Consume an authenticated root and reserve exactly four distinct owners.
    /// Maximum configured plaintext must fit the selected complete cover packet.
    pub fn new(
        mut root: security::SessionRoot,
        lane: security::LaneId,
        limits: security::Limits,
        protection: security::Protection,
        cover: cover::Config,
        control: Scope,
        data: Scope,
    ) -> Result<Self, Error> {
        capacity_for(cover, limits, protection, limits.max_body_bytes)?;
        let data_sender = root.sender(security::Purpose::Data, lane, limits, protection)?;
        let data_receiver = root.receiver(security::Purpose::Data, lane, limits, protection)?;
        let control_sender =
            root.sender(security::Purpose::Management, lane, limits, protection)?;
        let control_receiver =
            root.receiver(security::Purpose::Management, lane, limits, protection)?;
        Ok(Self {
            cover,
            limits,
            protection,
            control,
            data,
            additional: None,
            owners: Owners::Legacy {
                data_sender,
                data_receiver,
                control_sender,
                control_receiver,
            },
        })
    }

    /// Exact checked capacities before reserving a sending packet number.
    pub fn capacity(&self, plaintext_bytes: usize) -> Result<Capacity, Error> {
        if matches!(self.owners, Owners::Refreshable(_)) {
            refresh::capacity(self.cover, self.limits, self.protection, plaintext_bytes)
        } else {
            capacity_for(self.cover, self.limits, self.protection, plaintext_bytes)
        }
    }

    /// Inspect the next unique class-specific number without reserving it.
    pub fn next_number(&self, class: Class) -> security::PacketNumber {
        match &self.owners {
            Owners::Legacy {
                data_sender,
                control_sender,
                ..
            } => match class {
                Class::User => data_sender.next_number(),
                Class::Control => control_sender.next_number(),
            },
            // The private constructor retains exactly one immutable cell.
            Owners::Refreshable(owners) => owners[0].next_number(refresh::class(class)),
        }
    }

    /// Immutable mode-independent control scope.
    pub const fn control_scope(&self) -> Scope {
        self.control
    }

    /// Scope used by outgoing user records.
    pub const fn active_data(&self) -> Scope {
        self.data
    }

    /// The one additional staged or draining reader, if present.
    pub const fn additional_data(&self) -> Option<DataReader> {
        self.additional
    }

    /// Register one strictly newer data reader without changing outgoing scope.
    /// Repeating the exact staged request succeeds without altering state.
    pub fn stage_data(&mut self, next: Scope) -> Result<(), Error> {
        let requested = DataReader {
            scope: next,
            state: ReaderState::Staged,
        };
        if self.additional == Some(requested) {
            return Ok(());
        }
        if self.additional.is_some() || next.epoch.0 <= self.data.epoch.0 {
            return Err(Error::ScopeState);
        }
        self.additional = Some(requested);
        Ok(())
    }

    /// Cancel only the exact staged reader, before its local activation.
    pub fn cancel_staged_data(&mut self, next: Scope) -> Result<(), Error> {
        if self.additional
            != Some(DataReader {
                scope: next,
                state: ReaderState::Staged,
            })
        {
            return Err(Error::ScopeState);
        }
        self.additional = None;
        Ok(())
    }

    /// Use the exact staged scope for sending and retain old receive scope.
    /// This is local ownership only, not a negotiated peer commit.
    pub fn activate_data(&mut self, next: Scope) -> Result<(), Error> {
        if next == self.data {
            return Ok(());
        }
        if self.additional
            != Some(DataReader {
                scope: next,
                state: ReaderState::Staged,
            })
        {
            return Err(Error::ScopeState);
        }
        self.additional = Some(DataReader {
            scope: self.data,
            state: ReaderState::Draining,
        });
        self.data = next;
        Ok(())
    }

    /// Retire only the exact old draining reader after caller-owned barriers.
    pub fn retire_data(&mut self, old: Scope) -> Result<(), Error> {
        if self.additional
            != Some(DataReader {
                scope: old,
                state: ReaderState::Draining,
            })
        {
            return Err(Error::ScopeState);
        }
        self.additional = None;
        Ok(())
    }

    /// Protect one User or Control record, then encode its established cover.
    /// All structural/capacity checks precede cryptographic nonce reservation.
    pub fn seal(
        &mut self,
        class: Class,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        let scope = match class {
            Class::User => self.data,
            Class::Control => self.control,
        };
        self.seal_scoped(class, scope, outer, plaintext, workspace, output)
    }

    /// Seal User bytes in their exact registered directional policy scope.
    /// The trusted negotiated owner selects source versus feedback provenance.
    /// This creates no scope or owner and shares the existing User counter.
    /// Refused scope, phase or capacity leaves nonces and output unchanged.
    pub fn seal_user_in(
        &mut self,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if self.registered_scope(Class::User, scope.epoch)? != scope {
            return Err(Error::Scope);
        }
        self.seal_scoped(Class::User, scope, outer, plaintext, workspace, output)
    }

    fn seal_scoped(
        &mut self,
        class: Class,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if matches!(self.owners, Owners::Refreshable(_)) {
            return Err(security::refresh::Error::Mode.into());
        }
        if outer.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        let capacity = self.capacity(plaintext.len())?;
        if workspace.len() < capacity.seal_workspace_bytes || output.len() < capacity.packet_bytes {
            return Err(Error::OutputTooSmall);
        }
        let route = route_for(class, scope);
        let metadata = security::Metadata {
            epoch: scope.epoch,
            configuration: scope.configuration,
            extra: &route,
        };
        let packet = &mut workspace[ROUTE_BYTES..capacity.seal_workspace_bytes];
        let Owners::Legacy {
            data_sender,
            control_sender,
            ..
        } = &mut self.owners
        else {
            return Err(security::refresh::Error::Mode.into());
        };
        let sealed = match class {
            Class::User => data_sender.seal(metadata, plaintext, packet)?,
            Class::Control => control_sender.seal(metadata, plaintext, packet)?,
        };
        workspace[..ROUTE_BYTES].copy_from_slice(&route);
        let bytes =
            self.cover
                .encode(outer, &workspace[..capacity.seal_workspace_bytes], output)?;
        Ok(Sealed {
            number: sealed.number,
            generation: sealed.generation,
            bytes,
        })
    }

    /// Authenticate one covered record before exposing its authority/plaintext.
    /// Capacity failures do not consume replay credit; plaintext output changes
    /// only after successful authentication in the separate caller workspace.
    pub fn open(
        &mut self,
        packet: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        if matches!(self.owners, Owners::Refreshable(_)) {
            return Err(security::refresh::Error::Mode.into());
        }
        let decoded = self.cover.decode(packet)?;
        if decoded.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        let (class, hinted_epoch, route) = parse_route(decoded.protected)?;
        let scope = self.registered_scope(class, hinted_epoch)?;
        let protected = decoded
            .protected
            .get(ROUTE_BYTES..)
            .ok_or(Error::Malformed)?;
        let body_bytes = protected
            .len()
            .checked_sub(self.protection.overhead_bytes())
            .ok_or(Error::Malformed)?;
        let capacity = self.capacity(body_bytes)?;
        if workspace.len() < capacity.open_workspace_bytes || plaintext.len() < body_bytes {
            return Err(Error::OutputTooSmall);
        }
        let metadata = security::Metadata {
            epoch: scope.epoch,
            configuration: scope.configuration,
            extra: &route,
        };
        let Owners::Legacy {
            data_receiver,
            control_receiver,
            ..
        } = &mut self.owners
        else {
            return Err(security::refresh::Error::Mode.into());
        };
        let opened = match class {
            Class::User => data_receiver.open(metadata, protected, workspace)?,
            Class::Control => control_receiver.open(metadata, protected, workspace)?,
        };
        plaintext[..opened.bytes].copy_from_slice(&workspace[..opened.bytes]);
        Ok(Opened {
            class,
            scope,
            number: opened.number,
            generation: opened.generation,
            bytes: opened.bytes,
        })
    }

    fn registered_scope(&self, class: Class, epoch: security::Epoch) -> Result<Scope, Error> {
        match class {
            Class::Control if epoch == self.control.epoch => Ok(self.control),
            Class::User if epoch == self.data.epoch => Ok(self.data),
            Class::User => self
                .additional
                .filter(|reader| reader.scope.epoch == epoch)
                .map(|reader| reader.scope)
                .ok_or(Error::Scope),
            Class::Control => Err(Error::Scope),
        }
    }
}

fn capacity_for(
    cover: cover::Config,
    limits: security::Limits,
    protection: security::Protection,
    plaintext_bytes: usize,
) -> Result<Capacity, Error> {
    if plaintext_bytes > limits.max_body_bytes {
        return Err(Error::TooLarge);
    }
    let protected_bytes = plaintext_bytes
        .checked_add(protection.overhead_bytes())
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

fn route_for(class: Class, scope: Scope) -> [u8; ROUTE_BYTES] {
    let mut route = [0; ROUTE_BYTES];
    route[0] = class as u8;
    route[1..9].copy_from_slice(&scope.epoch.0.to_be_bytes());
    route
}

fn parse_route(protected: &[u8]) -> Result<(Class, security::Epoch, [u8; ROUTE_BYTES]), Error> {
    let route: [u8; ROUTE_BYTES] = protected
        .get(..ROUTE_BYTES)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let class = match route[0] {
        1 => Class::User,
        2 => Class::Control,
        _ => return Err(Error::Malformed),
    };
    let epoch = security::Epoch(u64::from_be_bytes(
        route[1..9].try_into().map_err(|_| Error::Malformed)?,
    ));
    Ok((class, epoch, route))
}
