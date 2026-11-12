//! Canonical credit tokens. Authenticate the enclosing packet before decoding
//! and validate the resulting token against its ledger before changing state.
use crate::{
    Credit, Direction, FinalOffset, FlowId, Grant, Record, RecordId, Release, RetirementMode, Scope,
};
use std::fmt;

/// Exact version-one credit token length; data payloads are framed separately.
pub const WIRE_LEN: usize = 72;

/// Bounded credit protocol messages; no variant by itself grants peer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    /// Request a fresh monotonic flow identity; receiver decides its actual grant.
    Open {
        /// Authenticated scope.
        scope: Scope,
        /// Requested flow identity.
        flow: FlowId,
    },
    /// Absolute irrevocable receiver reservation.
    Grant(Grant),
    /// Descriptor preceding exactly the specified logical payload bytes.
    Record(Record),
    /// Cumulative actual downstream release, not merely network receipt.
    Release(Release),
    /// Propose a final barrier after outstanding payload ownership is resolved.
    Final {
        /// Exact final sender offsets.
        offset: FinalOffset,
        /// Explicit drained or abandoned semantics.
        mode: RetirementMode,
    },
    /// Echo the exact agreed final offset and mode.
    FinalAck {
        /// Confirmed final sender offsets.
        offset: FinalOffset,
        /// Confirmed retirement semantics.
        mode: RetirementMode,
    },
}
impl Message {
    /// Return the scope to check against the authenticated carrier and ledger.
    pub const fn scope(self) -> Scope {
        match self {
            Self::Open { scope, .. } => scope,
            Self::Grant(token) => token.scope,
            Self::Record(token) => token.scope,
            Self::Release(token) => token.scope,
            Self::Final { offset, .. } | Self::FinalAck { offset, .. } => offset.scope,
        }
    }
    /// Return the flow to check against live monotonic identity admission.
    pub const fn flow(self) -> FlowId {
        match self {
            Self::Open { flow, .. } => flow,
            Self::Grant(token) => token.flow,
            Self::Record(token) => token.flow,
            Self::Release(token) => token.flow,
            Self::Final { offset, .. } | Self::FinalAck { offset, .. } => offset.flow,
        }
    }
}

/// Strict framing or arithmetic rejection, with no partial state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A frame is not exactly the supported size.
    Length,
    /// Magic, version, kind, direction or retirement tag is unsupported.
    Tag,
    /// A reserved field is nonzero.
    Reserved,
    /// A token's record range overflows or byte/count offsets contradict.
    Offset,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid credit token: {self:?}")
    }
}
impl std::error::Error for Error {}

fn valid_credit(credit: Credit) -> Result<(), Error> {
    if credit.records == 0 && credit.bytes != 0 {
        Err(Error::Offset)
    } else {
        Ok(())
    }
}

/// Serialize one validated token without allocating or touching a ledger.
pub fn encode(message: Message) -> Result<[u8; WIRE_LEN], Error> {
    let mut bytes = [0; WIRE_LEN];
    bytes[..3].copy_from_slice(b"LC\x01");
    let (kind, mode, words) = match message {
        Message::Open { .. } => (1, 0, [0; 4]),
        Message::Grant(token) => {
            valid_credit(token.flow_limit)?;
            valid_credit(token.session_limit)?;
            if !token.flow_limit.fits(token.session_limit) {
                return Err(Error::Offset);
            }
            (
                2,
                0,
                [
                    token.flow_limit.bytes,
                    token.flow_limit.records,
                    token.session_limit.bytes,
                    token.session_limit.records,
                ],
            )
        }
        Message::Record(token) => {
            token.end().map_err(|_| Error::Offset)?;
            (3, 0, [token.id.0, token.byte_start, token.byte_len, 0])
        }
        Message::Release(token) => {
            valid_credit(token.consumed)?;
            (4, 0, [token.consumed.bytes, token.consumed.records, 0, 0])
        }
        Message::Final { offset, mode } | Message::FinalAck { offset, mode } => {
            valid_credit(offset.admitted)?;
            (
                if matches!(message, Message::Final { .. }) {
                    5
                } else {
                    6
                },
                if mode == RetirementMode::Drained {
                    0
                } else {
                    1
                },
                [offset.admitted.bytes, offset.admitted.records, 0, 0],
            )
        }
    };
    bytes[3] = kind;
    bytes[4] = mode;
    bytes[5] = if message.scope().direction == Direction::Forward {
        0
    } else {
        1
    };
    bytes[8..24].copy_from_slice(&message.scope().session.to_be_bytes());
    bytes[24..32].copy_from_slice(&message.scope().epoch.to_be_bytes());
    bytes[32..40].copy_from_slice(&message.flow().0.to_be_bytes());
    for (index, word) in words.into_iter().enumerate() {
        bytes[40 + index * 8..48 + index * 8].copy_from_slice(&word.to_be_bytes());
    }
    Ok(bytes)
}

/// Decode a token only after authenticating its enclosing bounded frame.
/// Successful parsing is not flow admission, data receipt or barrier agreement.
pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    let bytes: &[u8; WIRE_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
    if &bytes[..3] != b"LC\x01" || !(1..=6).contains(&bytes[3]) || bytes[5] > 1 {
        return Err(Error::Tag);
    }
    if bytes[6..8] != [0, 0] {
        return Err(Error::Reserved);
    }
    if bytes[4] > 1 || (bytes[3] < 5 && bytes[4] != 0) {
        return Err(Error::Tag);
    }
    let mut session = [0; 16];
    session.copy_from_slice(&bytes[8..24]);
    let word = |offset| {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_be_bytes(value)
    };
    let scope = Scope {
        session: u128::from_be_bytes(session),
        epoch: word(24),
        direction: if bytes[5] == 0 {
            Direction::Forward
        } else {
            Direction::Reverse
        },
    };
    let flow = FlowId(word(32));
    let credit = Credit {
        bytes: word(40),
        records: word(48),
    };
    let message = match bytes[3] {
        1 => Message::Open { scope, flow },
        2 => Message::Grant(Grant {
            scope,
            flow,
            flow_limit: credit,
            session_limit: Credit {
                bytes: word(56),
                records: word(64),
            },
        }),
        3 => Message::Record(Record {
            scope,
            flow,
            id: RecordId(word(40)),
            byte_start: word(48),
            byte_len: word(56),
        }),
        4 => Message::Release(Release {
            scope,
            flow,
            consumed: credit,
        }),
        kind => {
            let offset = FinalOffset {
                scope,
                flow,
                admitted: credit,
            };
            let mode = if bytes[4] == 0 {
                RetirementMode::Drained
            } else {
                RetirementMode::Abandon
            };
            if kind == 5 {
                Message::Final { offset, mode }
            } else {
                Message::FinalAck { offset, mode }
            }
        }
    };
    // Exact re-encoding rejects every unused body byte without a second parser.
    if encode(message)? != *bytes {
        return Err(Error::Reserved);
    }
    Ok(message)
}

#[cfg(test)]
mod tests;
