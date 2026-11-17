//! Metadata-only saturation and injected-time boundaries.
use super::*;

#[test]
fn saturated_diagnostics_do_not_wrap_or_change_episode_identity() {
    let mut count = PacketCount {
        packets: u64::MAX,
        payload_bytes: u64::MAX - 2,
    };
    count.record(5);
    assert_eq!(
        count,
        PacketCount {
            packets: u64::MAX,
            payload_bytes: u64::MAX
        }
    );
    let mut send = SendIoSnapshot {
        would_block_observations: u64::MAX,
        would_block_episodes: u64::MAX,
        ..SendIoSnapshot::default()
    };
    send.would_block();
    send.would_block();
    assert_eq!(send.would_block_observations, u64::MAX);
    assert_eq!(send.would_block_episodes, u64::MAX);
    assert!(send.blocked);
    send.success();
    send.success();
    assert_eq!(send.resumed_episodes, 1);
    assert!(!send.blocked);
}
