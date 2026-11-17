//! Exact establishment-bound fragmentation resource selection.
use super::*;

pub(super) fn validate(policy: engine::FragmentPolicy) -> io::Result<()> {
    for direction in [policy.forward, policy.reverse] {
        direction
            .framing
            .geometry(direction.framing.max_message_bytes)
            .map_err(invalid)?;
        if direction.labels[0] == direction.labels[1]
            || direction.labels[0] == direction.labels[2]
            || direction.labels[1] == direction.labels[2]
        {
            return Err(invalid(
                "fragment kinds require distinct directional labels",
            ));
        }
        for limits in [
            direction.reassembly.systematic,
            direction.reassembly.repair,
            direction.reassembly.feedback,
        ] {
            l2tunnel_codec::fragment_storage::Plan::for_reassembly(limits).map_err(invalid)?;
        }
    }
    Ok(())
}

pub(super) fn update_hash(
    policy: engine::FragmentPolicy,
    hash: &mut ring::digest::Context,
) -> io::Result<()> {
    hash.update(b"l2tunnel/common-resources/rolling-fragments/v1\0");
    for direction in [policy.forward, policy.reverse] {
        let framing = direction.framing;
        for value in [
            framing.path_mtu,
            framing.outer_overhead_bytes,
            framing.max_message_bytes,
        ] {
            hash.update(&u64::try_from(value).map_err(invalid)?.to_be_bytes());
        }
        hash.update(&u64::from(framing.max_fragments).to_be_bytes());
        for label in direction.labels {
            hash.update(&label.0.to_be_bytes());
        }
        hash.update(&direction.first_message.0.to_be_bytes());
        for limits in [
            direction.reassembly.systematic,
            direction.reassembly.repair,
            direction.reassembly.feedback,
        ] {
            for value in [
                u64::try_from(limits.max_message_bytes).map_err(invalid)?,
                u64::try_from(limits.max_messages).map_err(invalid)?,
                u64::from(limits.max_fragment_payload_bytes),
                u64::from(limits.max_fragments_per_message),
                u64::try_from(limits.max_total_fragments).map_err(invalid)?,
                u64::try_from(limits.max_reserved_bytes).map_err(invalid)?,
                limits.max_lifetime_ticks,
                u64::try_from(limits.replay_window).map_err(invalid)?,
            ] {
                hash.update(&value.to_be_bytes());
            }
        }
    }
    Ok(())
}
