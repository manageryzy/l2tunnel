//! Emit canonical units from the Rust sender for the Python fixed-anchor golden test.
use l2tunnel_codec::{
    aligned_body,
    aligned_receiver::{ChannelId, Direction, RecordId, Scope},
    aligned_sender::{Config, Sender},
};
use l2tunnel_core::Epoch;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tape = Vec::new();
    std::io::stdin().read_to_end(&mut tape)?;
    let mut sender = Sender::new_ip(
        Scope {
            session: [1; 16],
            epoch: Epoch(1),
            direction: Direction::InitiatorToResponder,
        },
        Config {
            body: aligned_body::Config {
                max_frame_bytes: 4096,
                symbol_bytes: 1146,
                elide_payload_length: true,
                predictive: true,
                timestamp_pair_dictionary: true,
                independent_short_frame_bytes: 128,
            },
            channels: 2,
            first_record: RecordId(0),
        },
    )?;
    let mut input = tape.as_slice();
    let mut out = std::io::stdout().lock();
    while !input.is_empty() {
        let len = usize::from(u16::from_be_bytes(input[1..3].try_into()?));
        let ip = &input[3..3 + len];
        sender.stage_fixed_anchor_headers_observed(ChannelId(input[0]), ip)?;
        input = &input[3 + len..];
        while sender.is_pending() {
            let unit = sender.pending_unit()?;
            out.write_all(&u16::try_from(unit.bytes.len())?.to_be_bytes())?;
            out.write_all(unit.bytes)?;
            sender.commit_unit()?;
        }
    }
    Ok(())
}
