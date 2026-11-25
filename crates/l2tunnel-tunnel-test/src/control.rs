//! Pre-test exchange on the authenticated control channel (owner decision 6,
//! 2026-11-24): the tester offers a fresh address pair, the responder accepts
//! it or refuses it (for example when its host uses one of the addresses),
//! and either side ends the test. The runtime carries these bytes in a
//! session-control ProfileControl body with the tunnel-test tag.
use crate::{Addresses, Error};

/// Encoded size of every message.
pub const MESSAGE_BYTES: usize = 24;
const MAGIC: [u8; 2] = *b"TT";
const VERSION: u8 = 1;

/// Why a responder refused an offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Refusal {
    /// The responder's host uses one of the addresses; offer another pair.
    AddressInUse = 1,
    /// The responder is already serving another test.
    Busy = 2,
    /// The responder cannot serve tests on this session.
    Unavailable = 3,
}

/// One pre-test control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    /// Tester: run test `id` on these addresses.
    Offer {
        /// Tester-chosen test identity.
        id: u64,
        /// Proposed pair.
        addresses: Addresses,
    },
    /// Responder: addresses taken; the responder captures its address now.
    Accept {
        /// Offered test.
        id: u64,
    },
    /// Responder: not on these addresses.
    Refuse {
        /// Offered test.
        id: u64,
        /// Reason.
        reason: Refusal,
    },
    /// Either side: test over; stop capturing its addresses.
    End {
        /// Ended test.
        id: u64,
    },
}
impl Message {
    /// Fixed-size wire form: `TT`, version, kind, four reserved zero bytes,
    /// id (u64 big-endian), then eight kind-specific bytes.
    pub fn encode(self) -> [u8; MESSAGE_BYTES] {
        let mut bytes = [0; MESSAGE_BYTES];
        bytes[..2].copy_from_slice(&MAGIC);
        bytes[2] = VERSION;
        let (kind, id, tail) = match self {
            Self::Offer { id, addresses } => (1, id, addresses.to_bytes()),
            Self::Accept { id } => (2, id, [0; 8]),
            Self::Refuse { id, reason } => (3, id, [reason as u8, 0, 0, 0, 0, 0, 0, 0]),
            Self::End { id } => (4, id, [0; 8]),
        };
        bytes[3] = kind;
        bytes[8..16].copy_from_slice(&id.to_be_bytes());
        bytes[16..].copy_from_slice(&tail);
        bytes
    }
    /// Strict parse; any other byte string is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let invalid = Error::Invalid("malformed tunnel-test control message");
        let bytes: &[u8; MESSAGE_BYTES] = bytes.try_into().map_err(|_| invalid)?;
        if bytes[..2] != MAGIC || bytes[2] != VERSION || bytes[4..8] != [0; 4] {
            return Err(invalid);
        }
        let mut id = [0; 8];
        id.copy_from_slice(&bytes[8..16]);
        let id = u64::from_be_bytes(id);
        let mut tail = [0; 8];
        tail.copy_from_slice(&bytes[16..]);
        let empty = tail == [0; 8];
        match bytes[3] {
            1 => Ok(Self::Offer {
                id,
                addresses: Addresses::from_bytes(tail)?,
            }),
            2 if empty => Ok(Self::Accept { id }),
            3 if tail[1..] == [0; 7] => Ok(Self::Refuse {
                id,
                reason: match tail[0] {
                    1 => Refusal::AddressInUse,
                    2 => Refusal::Busy,
                    3 => Refusal::Unavailable,
                    _ => return Err(invalid),
                },
            }),
            4 if empty => Ok(Self::End { id }),
            _ => Err(invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::Ipv4Address;

    #[test]
    fn messages_round_trip_and_garbage_is_refused() -> Result<(), Error> {
        let addresses = Addresses {
            tester: Ipv4Address::new(172, 20, 4, 9),
            responder: Ipv4Address::new(172, 20, 4, 10),
        };
        for message in [
            Message::Offer { id: 7, addresses },
            Message::Accept { id: 7 },
            Message::Refuse {
                id: 7,
                reason: Refusal::AddressInUse,
            },
            Message::Refuse {
                id: u64::MAX,
                reason: Refusal::Busy,
            },
            Message::End { id: 0 },
        ] {
            assert_eq!(Message::decode(&message.encode())?, message);
        }
        let good = Message::Accept { id: 1 }.encode();
        assert!(Message::decode(&good[..23]).is_err());
        for index in [0, 2, 3, 4, 20] {
            let mut bad = good;
            bad[index] ^= 0x40;
            assert!(Message::decode(&bad).is_err(), "byte {index}");
        }
        let mut public = Message::Offer { id: 1, addresses }.encode();
        public[16] = 8;
        assert!(Message::decode(&public).is_err(), "non-private offer");
        Ok(())
    }
}
