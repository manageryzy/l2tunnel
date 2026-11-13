//! Session control messages of the swift profile.
//!
//! They travel on the retained authenticated stream, never in a datagram and
//! never in user traffic, so their order and delivery are reliable. A frame is
//! `[length u16][kind u8][fields]`. Parsing is strict: unknown kinds, short or
//! trailing bytes are errors and nothing here panics on received bytes.
//!
//! A policy change is negotiated and then applied per direction behind a
//! drain barrier:
//!
//! 1. the coordinator sends [`Message::Propose`]; the peer answers
//!    [`Message::Accept`] with the digest of the complete new configuration,
//!    or [`Message::Reject`];
//! 2. each endpoint stops admitting native packets, waits until everything it
//!    sent is confirmed, and sends [`Message::Barrier`] naming its next
//!    datagram number;
//! 3. the peer delivers what it holds, replaces its receiving state and
//!    answers [`Message::BarrierAck`] naming its own next datagram number;
//!    only then does the sender replace its sending state and resume.
//!
//! Datagram numbers and keys are never reset.
use crate::Error;

/// Largest encoded frame including its length prefix.
pub const MAX_FRAME: usize = 2 + 1 + 8 + 32;

/// The negotiable protocol policy of a session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    /// IP path MTU available to tunnel datagrams.
    pub path_mtu: u16,
    /// Client-to-server budget in kilobits of IP bytes per second.
    pub forward_kbit: u32,
    /// Server-to-client budget in kilobits of IP bytes per second.
    pub reverse_kbit: u32,
    /// Independent ordering channels.
    pub channels: u8,
    /// Sources covered by one repair.
    pub window: u8,
    /// Proportional repairs per thousand sources.
    pub repair_permille: u16,
}

/// Why a proposal was refused; nothing changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The policy is outside what this endpoint supports.
    Invalid,
    /// Another change is in progress.
    Busy,
    /// The epoch is not the one after the current epoch.
    Epoch,
}

/// One control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    /// Request that `epoch` use `policy`.
    Propose {
        /// The epoch after the current one.
        epoch: u64,
        /// Complete replacement policy.
        policy: Policy,
    },
    /// Agreement, with the digest of the complete configuration the
    /// accepting endpoint derived from the proposal.
    Accept {
        /// Epoch being agreed.
        epoch: u64,
        /// Canonical configuration digest.
        digest: [u8; 32],
    },
    /// Refusal; the current epoch stays in force.
    Reject {
        /// Epoch that was proposed.
        epoch: u64,
        /// Reason.
        reason: Refusal,
    },
    /// Everything sent under the previous epoch is confirmed. Sources and
    /// repairs numbered `first_number` or later belong to `epoch`.
    Barrier {
        /// Epoch the sender is entering.
        epoch: u64,
        /// The sender's next datagram number.
        first_number: u64,
    },
    /// Receiving state was replaced. Feedback numbered `feedback_from` or
    /// later describes the new epoch.
    BarrierAck {
        /// Epoch being confirmed.
        epoch: u64,
        /// The acknowledging endpoint's next datagram number.
        feedback_from: u64,
    },
}

const PROPOSE: u8 = 1;
const ACCEPT: u8 = 2;
const REJECT: u8 = 3;
const BARRIER: u8 = 4;
const BARRIER_ACK: u8 = 5;

impl Message {
    /// Append the framed message to `output`.
    pub fn encode(&self, output: &mut Vec<u8>) {
        let start = output.len();
        output.extend_from_slice(&[0, 0]);
        match *self {
            Self::Propose { epoch, policy } => {
                output.push(PROPOSE);
                output.extend_from_slice(&epoch.to_be_bytes());
                output.extend_from_slice(&policy.path_mtu.to_be_bytes());
                output.extend_from_slice(&policy.forward_kbit.to_be_bytes());
                output.extend_from_slice(&policy.reverse_kbit.to_be_bytes());
                output.push(policy.channels);
                output.push(policy.window);
                output.extend_from_slice(&policy.repair_permille.to_be_bytes());
            }
            Self::Accept { epoch, digest } => {
                output.push(ACCEPT);
                output.extend_from_slice(&epoch.to_be_bytes());
                output.extend_from_slice(&digest);
            }
            Self::Reject { epoch, reason } => {
                output.push(REJECT);
                output.extend_from_slice(&epoch.to_be_bytes());
                output.push(match reason {
                    Refusal::Invalid => 1,
                    Refusal::Busy => 2,
                    Refusal::Epoch => 3,
                });
            }
            Self::Barrier {
                epoch,
                first_number,
            } => {
                output.push(BARRIER);
                output.extend_from_slice(&epoch.to_be_bytes());
                output.extend_from_slice(&first_number.to_be_bytes());
            }
            Self::BarrierAck {
                epoch,
                feedback_from,
            } => {
                output.push(BARRIER_ACK);
                output.extend_from_slice(&epoch.to_be_bytes());
                output.extend_from_slice(&feedback_from.to_be_bytes());
            }
        }
        let length = (output.len() - start - 2) as u16;
        output[start..start + 2].copy_from_slice(&length.to_be_bytes());
    }
    /// Decode one frame from the front of `input`. Returns the message and
    /// the bytes consumed, or `None` when the frame is not complete yet.
    pub fn decode(input: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let Some(prefix) = input.get(..2) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        if length == 0 || length + 2 > MAX_FRAME {
            return Err(Error::Malformed);
        }
        let Some(frame) = input.get(2..2 + length) else {
            return Ok(None);
        };
        let (kind, fields) = (frame[0], &frame[1..]);
        let word = |at: usize| -> Result<u64, Error> {
            let bytes = fields.get(at..at + 8).ok_or(Error::Malformed)?;
            Ok(u64::from_be_bytes(
                bytes.try_into().map_err(|_| Error::Malformed)?,
            ))
        };
        let exact = |expected: usize| {
            if fields.len() == expected {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
        };
        let message = match kind {
            PROPOSE => {
                exact(22)?;
                Self::Propose {
                    epoch: word(0)?,
                    policy: Policy {
                        path_mtu: u16::from_be_bytes([fields[8], fields[9]]),
                        forward_kbit: u32::from_be_bytes([
                            fields[10], fields[11], fields[12], fields[13],
                        ]),
                        reverse_kbit: u32::from_be_bytes([
                            fields[14], fields[15], fields[16], fields[17],
                        ]),
                        channels: fields[18],
                        window: fields[19],
                        repair_permille: u16::from_be_bytes([fields[20], fields[21]]),
                    },
                }
            }
            ACCEPT => {
                exact(40)?;
                let mut digest = [0; 32];
                digest.copy_from_slice(&fields[8..]);
                Self::Accept {
                    epoch: word(0)?,
                    digest,
                }
            }
            REJECT => {
                exact(9)?;
                Self::Reject {
                    epoch: word(0)?,
                    reason: match fields[8] {
                        1 => Refusal::Invalid,
                        2 => Refusal::Busy,
                        3 => Refusal::Epoch,
                        _ => return Err(Error::Malformed),
                    },
                }
            }
            BARRIER => {
                exact(16)?;
                Self::Barrier {
                    epoch: word(0)?,
                    first_number: word(8)?,
                }
            }
            BARRIER_ACK => {
                exact(16)?;
                Self::BarrierAck {
                    epoch: word(0)?,
                    feedback_from: word(8)?,
                }
            }
            _ => return Err(Error::Malformed),
        };
        Ok(Some((message, 2 + length)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Message> {
        let policy = Policy {
            path_mtu: 1500,
            forward_kbit: 99_000,
            reverse_kbit: 9_900,
            channels: 16,
            window: 64,
            repair_permille: 205,
        };
        vec![
            Message::Propose { epoch: 1, policy },
            Message::Accept {
                epoch: u64::MAX,
                digest: [7; 32],
            },
            Message::Reject {
                epoch: 3,
                reason: Refusal::Busy,
            },
            Message::Reject {
                epoch: 3,
                reason: Refusal::Invalid,
            },
            Message::Reject {
                epoch: 3,
                reason: Refusal::Epoch,
            },
            Message::Barrier {
                epoch: 9,
                first_number: 1 << 40,
            },
            Message::BarrierAck {
                epoch: 9,
                feedback_from: 12,
            },
        ]
    }

    #[test]
    fn every_message_round_trips_alone_and_in_a_stream() -> Result<(), Error> {
        let mut stream = Vec::new();
        for message in samples() {
            let mut frame = Vec::new();
            message.encode(&mut frame);
            assert!(frame.len() <= MAX_FRAME);
            assert_eq!(Message::decode(&frame)?, Some((message, frame.len())));
            // Every strict prefix is incomplete, never an error or a message.
            for cut in 0..frame.len() {
                assert_eq!(Message::decode(&frame[..cut])?, None, "{message:?} {cut}");
            }
            stream.extend_from_slice(&frame);
        }
        let mut decoded = Vec::new();
        let mut rest = &stream[..];
        while let Some((message, used)) = Message::decode(rest)? {
            decoded.push(message);
            rest = &rest[used..];
        }
        assert_eq!(decoded, samples());
        assert!(rest.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_frames_are_errors_not_messages() {
        for message in samples() {
            let mut frame = Vec::new();
            message.encode(&mut frame);
            // One byte longer or shorter than the kind requires.
            let mut long = frame.clone();
            long.push(0);
            long[1] += 1;
            assert_eq!(Message::decode(&long), Err(Error::Malformed));
            let mut short = frame.clone();
            short.pop();
            short[1] -= 1;
            assert_eq!(Message::decode(&short), Err(Error::Malformed));
            let mut unknown = frame.clone();
            unknown[2] = 0x7F;
            assert_eq!(Message::decode(&unknown), Err(Error::Malformed));
        }
        assert_eq!(Message::decode(&[0, 0]), Err(Error::Malformed));
        assert_eq!(Message::decode(&[0xFF, 0xFF, 1]), Err(Error::Malformed));
        let mut reason = Vec::new();
        Message::Reject {
            epoch: 1,
            reason: Refusal::Busy,
        }
        .encode(&mut reason);
        let last = reason.len() - 1;
        reason[last] = 9;
        assert_eq!(Message::decode(&reason), Err(Error::Malformed));
    }
}
