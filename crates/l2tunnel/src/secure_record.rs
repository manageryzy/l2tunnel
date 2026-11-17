//! Pure current User/Control records with one authenticated compact format.
//!
//! Routes are untrusted hints until the selected purpose owner authenticates the
//! exact route. Local staged readers do not negotiate or commit a peer switch.

use crate::{cover, security};
use std::fmt;

/// Explicit compact packet selection with short data checks and authenticated feedback.
#[path = "secure_record_compact.rs"]
pub mod compact;

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

/// Checked caller capacities for an opaque plaintext length and selected framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    /// Plaintext bytes returned after successful opening.
    pub plaintext_bytes: usize,
    /// Complete route plus protected record needed while sealing.
    pub seal_workspace_bytes: usize,
    /// Body plus selected tag required by the security receiver.
    pub open_workspace_bytes: usize,
    /// Complete current record, excluding carrier framing and transport headers.
    pub packet_bytes: usize,
}

/// Successful complete current record emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sealed {
    /// Unique identity owned by this class's security sender.
    pub number: security::PacketNumber,
    /// Actual sender key generation used for this protected record.
    pub generation: security::KeyGeneration,
    /// Complete current record bytes in caller output.
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
    /// True for a compact Feedback branch protected by the separate strong owner.
    pub feedback: bool,
    /// False only for explicitly selected compact ChaCha20/CRC32C data.
    pub authenticated: bool,
    /// At least a 128-bit authentication tag protects this complete record.
    pub strongly_authenticated: bool,
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
    /// The bounded selected owner backing could not be reserved.
    Allocation,
    /// The maintained common security owner rejected the operation.
    Security(security::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "secure record error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<security::Error> for Error {
    fn from(value: security::Error) -> Self {
        Self::Security(value)
    }
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
    control: Scope,
    data: Scope,
    additional: Option<DataReader>,
    // Exactly one fallibly reserved current owner; no per-packet allocation.
    owners: Vec<compact::Owners>,
}

impl Records {
    /// Checked maximum class capacity before reserving a sending packet number.
    /// Use `capacity_for` for exact wire charging; this method reserves the
    /// largest check selected across data, feedback and control.
    pub fn capacity(&self, plaintext_bytes: usize) -> Result<Capacity, Error> {
        compact::capacity(
            self.cover,
            self.limits,
            self.compact_selection().maximum_overhead() - compact::PREFIX_BYTES,
            plaintext_bytes,
        )
    }

    /// Inspect the next unique class-specific number without reserving it.
    pub fn next_number(&self, class: Class) -> security::PacketNumber {
        match class {
            Class::User => self.owners[0].data_sender.next_number(),
            Class::Control => self.owners[0].control_sender.next_number(),
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
        self.owners[0].additional_slot = Some((self.owners[0].data_slot + 1) & 0x3f);
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
        self.owners[0].additional_slot = None;
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
        let next_slot = self.owners[0].additional_slot.ok_or(Error::ScopeState)?;
        self.owners[0].additional_slot = Some(self.owners[0].data_slot);
        self.owners[0].data_slot = next_slot;
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
        self.owners[0].additional_slot = None;
        Ok(())
    }

    /// Protect one User or Control record with the selected current format.
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
        self.seal_compact(
            match class {
                Class::User => compact::Kind::Data,
                Class::Control => compact::Kind::Control,
            },
            scope,
            outer,
            plaintext,
            workspace,
            output,
        )
    }

    /// Verify one current record before exposing its authority/plaintext.
    /// Capacity failures do not consume replay credit; plaintext output changes
    /// only after successful authentication in the separate caller workspace.
    pub fn open(
        &mut self,
        packet: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        self.open_compact(packet, workspace, plaintext)
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
