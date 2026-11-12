# Credit wire protocol

Status: implemented and locally tested; the design was recorded before code. This codec serializes the existing
cumulative credit tokens; it supplies neither authentication nor retry state.
It is a prerequisite for the scheduled runtime, not completed native flow control.

`Message::{Open { scope, flow }, Grant(Grant), Record(Record), Release(Release),
Final { offset, mode }, FinalAck { offset, mode }}` has one canonical 72-byte
encoding. `encode(Message) -> Result<[u8; WIRE_LEN], Error>` and
`decode(&[u8]) -> Result<Message, Error>` perform no heap allocation or mutation.
`Message::scope()` and `flow()` expose routing only after the caller has verified
the enclosing session authentication. Open never grants data authority by itself.

Bytes 0..2 are `LC`, byte 2 is version 1, byte 3 the message kind (1..6), byte 4
the retirement mode (zero except Final/FinalAck), byte 5 the direction (0/1), and
6..8 are zero. Bytes 8..24 hold the session, 24..32 the epoch, and 32..40 the flow.
All integers use network byte order. The remaining 32 bytes are four u64 fields:
Grant uses flow bytes/count and session bytes/count; Record uses ID, byte start,
byte length and zero; Release and final messages use bytes/count and two zeros.
Open uses four zeros. Unknown versions/kinds/directions, noncanonical reserved
bytes, invalid retirement modes, truncated/extended frames and overflowing record
ranges are rejected. Zero record counts cannot accompany nonzero byte offsets.

The authenticated enclosing data frame carries Record plus exactly its byte_len
bytes. The outer frame supplies replay/session integrity; the receiver ledger
supplies record-window validation. The codec does not infer trust from the LC
magic. FinalAck is an exact echoed offset/mode, never permission to retire a
different ledger. Distributed final barriers, retry/ack state and contradictory
duplicates remain runtime responsibilities. The runtime must not retire a flow
while recovery, packet queues or downstream native delivery remain outstanding.

- [x] [MOD-CWIRE-01] Implement strict fixed-size canonical encode/decode for all token variants. Evidence: [wire codec](../../crates/l2tunnel-flow-control/src/wire.rs).
- [x] [MOD-CWIRE-02] Verify an independent literal golden frame, every truncation and reserved-byte rejection. Evidence: [wire tests](../../crates/l2tunnel-flow-control/src/wire/tests.rs).
- [x] [MOD-CWIRE-03] Round-trip an actual two-ledger grant/data/release/final lifecycle without recreating credit. Evidence: [ledger integration test](../../crates/l2tunnel-flow-control/src/wire/tests.rs).
- [x] [MOD-CWIRE-04] Run focused tests, formatting and warning-denied Clippy. Evidence: [local validation](#local-validation).
- [ ] [MOD-CWIRE-05] Integrate authenticated retries, per-flow lifecycle and native scheduled-runtime acceptance.

## Local validation

`cargo fmt -p l2tunnel-flow-control`, `cargo test -p l2tunnel-flow-control
--offline` (29 unit tests and one doctest), and `cargo clippy -p
l2tunnel-flow-control --all-targets --offline -- -D warnings` passed. Four unit
tests cover the new wire/lifecycle contract; these tests do not authenticate or
transfer packets over a network.
