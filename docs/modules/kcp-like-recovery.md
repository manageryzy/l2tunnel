# KCP-like recovery component

- [x] [KCP-01] Add an explicitly selected, bounded KCP-like Compact recovery policy, canonical parameters, paid-attempt timers, conservative fast ACK and timeout backoff. Evidence: [working-tree recovery checks](../../work/c48-parity-20261119/native/tun-ring-fix-20261119/inner-retrans-analysis/kcp-like-l2-gate-01/combined-check.log), including 76 passing recovery library tests.

`CompactRecovery::KcpLike(KcpLikeConfig)` reuses Compact's source custody,
authenticated feedback, cumulative prefix, selective bitmap and transmission
serials. The parameters are fast-resend threshold, estimator interval and
minimum/maximum RTO, encoded as four big-endian u16 values. Aligned configuration
tag 4 uses eight parameter bytes and eight required zero bytes in the existing
policy slot. Existing tags and descriptor length remain unchanged.

Only a fresh feedback serial can add one fast-ACK observation. Its acknowledged
higher source must have an actual payment later than the missing attempt. Timers
begin on complete physical acceptance. RTO uses `SRTT + max(interval, 4*RTTVAR)`
within negotiated bounds; initial RTO is 200 ms within those bounds. A timeout
retry grows its prior timeout by one half, while a fast retry retains it. Actual
feedback history, attempt limits and finite custody remain authoritative.

This component follows selected rules of the pinned upstream C KCP revision
`8004f7eba5d1bf33f0691eef5f887f2cd3140cb5`. It is not upstream KCP framing or a
complete behavioral port. It introduces no C FFI, real clock, I/O, encryption
primitive, congestion controller or fixed KCP data header.

The checkpoint isolates the recovery component and its Aligned configuration
encoding. Native Ethernet packing, independent delivery, service selection and
performance qualification are separate integration work. Tests were executed in
the current working tree, which contains other integration changes; a clean
checkout of this isolated checkpoint was not separately built. Passing this
component does not establish Linux TCP throughput or platform support.
