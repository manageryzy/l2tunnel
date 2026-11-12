# Pinned smoltcp quiescent snapshot proposal

Status: exact patch independently reviewed, imported and activated locally.
The pure [tracked owner](raw-owner-handoff.md) now implements logical consume;
external driver transfer and authenticated packet-phase integration remain planned.
This document specifies a small additive seam
for the [experimental raw packet phase](raw-packet-phase.md). The maintained
TCP/TLS path remains the default. No downloaded registry source or native
capability changed; root selected the reviewed local source. The additive tracked
owner leaves the original engine API unchanged.

## Provenance and proposed source boundary

The inspected package is `smoltcp` 0.14.0 from the crates.io registry, already
recorded in [Cargo.lock](../../Cargo.lock). Its cached `.crate` archive SHA-256
matches the original registry checksum recorded in the import provenance:
`b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`.
The archive's `.cargo_vcs_info.json` identifies upstream commit
`cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3`. Selected archived files were compared
byte-for-byte with the unpacked source. `src/socket/tcp.rs` SHA-256 is
`da2f1bec16505310b7f9a3ae83a4e804d98897665006f7d7c76da4109e96748d`;
`LICENSE-0BSD.txt` SHA-256 is
`beb2cad88fab8447f7975564e21f9506e733e14c344836f146fa02e811216694`.
The original notice names smoltcp contributors and its 0BSD terms. Preserve it
unchanged in any separately approved source package; this does not select a
license for this repository.

The approved production location is `third_party/smoltcp`, imported from the
verified archive with original source, license and provenance preserved. The
reviewable patch modifies only `src/socket/tcp.rs` and its in-file tests. Root
activated the Cargo/lockfile selection and extended source hashing to cover this
dependency. No downloaded-registry mutation occurred. The earlier review-only
patch and validation receipts remain under `work/`; local activation is not
upstream acceptance.

## Exact additive API

```rust
// Reviewed additive API in the activated local dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiescentSnapshot {
    pub local_endpoint: IpEndpoint,
    pub remote_endpoint: IpEndpoint,
    pub send_unacknowledged: TcpSeqNumber,
    pub send_next: TcpSeqNumber,
    pub receive_next: TcpSeqNumber,
    pub last_ack_sent: TcpSeqNumber,
    pub last_window_sent: u16,
    pub local_window_shift: u8,
    pub peer_window_shift: Option<u8>,
    pub peer_window_bytes: usize,
    pub peer_mss: usize,
    pub peer_sack_permitted: bool,
    pub timestamps_enabled: bool,
}
impl Socket<'_> {
    pub fn quiescent_snapshot(&self, now: Instant) -> Option<QuiescentSnapshot>;
}
```

Place the type beside `Socket` and the getter beside its existing public state
accessors in upstream `src/socket/tcp.rs`. The type reports maintained state; it
is not a transferable capability. Publicly constructing it cannot authorize a
packet engine. Only the unique raw engine/driver consume seam may produce the
private capability. No upstream consume method, timer mutation, new accepted
packet bookkeeping, controller export, allocator or platform dependency is needed.

| Snapshot field | Existing authoritative source in `Socket` |
| --- | --- |
| Endpoints | `tuple.local`, `tuple.remote` |
| `send_unacknowledged` | `local_seq_no`, acknowledged start of the transmit ring |
| `send_next` | `remote_last_seq`, required equal to `local_seq_no` at this boundary |
| `receive_next` | `remote_seq_no`, valid as next contiguous byte only with empty receive ring and assembler |
| Last ACK/window | `remote_last_ack`, `remote_last_win`; emitted to device, not confirmed physical send |
| Local/peer scaling | `remote_win_shift`, `remote_win_scale`; the upstream names reflect the remote's use of each scale |
| Peer accepted window | `remote_win_len`, relative to `local_seq_no` |
| Peer MSS/SACK | `remote_mss`, `remote_has_sack` |
| Timestamp capability | Existing `timestamp_enabled()`; the raw v1 wrapper rejects true |

Return `None` unless all these hold at injected `now`: `state == Established`,
present tuple, `!rx_fin_received`, empty transmit and receive rings,
`assembler.is_empty()`, `remote_last_seq == local_seq_no`,
`remote_last_ack == Some(remote_seq_no)`, `AckDelayTimer::Idle`,
`Timer::Idle { .. }`, no `pending_fast_retransmit`, no `ack_to_transmit()` or
`window_to_update()`, no due `timer.should_keep_alive(now)`, and no
`timed_out(now)`. Reuse these existing helpers instead of copying their rules.
A future idle keepalive deadline can be abandoned only by explicit transfer;
no outstanding retransmit, zero-window probe, close or delayed ACK is abandoned.
The caller must first poll with the same monotonic time and check its absolute
transition deadline. A read-only getter does not advance the stack clock.

A small window increase below `window_to_update()`'s threshold is not a pending
ACK obligation. Preserve the actual last advertised window, then bound the new
profile by that value and real configured capacity. Never replace the recorded
window with a larger ring capacity and describe it as advertised. Direct
`ack_reply()` also updates last ACK/window before physical I/O. Empty socket
fields alone never prove transmission: the wrapper additionally requires empty
engine ingress/egress queues, no retained driver packet, and successful exact
atomic sends for every removed output packet.

## ISNs, options and external ownership

The pinned socket does not retain original ISNs. They are unnecessary for the
phase's authoritative current frontiers. Given one established connection, no FIN
and exact checked totals from stream creation, `send_next - sent_ciphertext_bytes
- 1` and `receive_next - received_ciphertext_bytes - 1` modulo 2^32 reconstruct
candidate ISNs. Label them **derived**, not independently recorded SYN evidence.
Complementary peer snapshots and complete byte counts must match before Commit.
Current Driver diagnostic counters saturate and are insufficient for this proof:
the switchable path needs separate checked `u64` counters and terminal overflow.
If independent original ISN evidence becomes a requirement, first review narrow
one-time bootstrap provenance in our engine/driver; never invent upstream fields
or a second ACK/window acceptance implementation.

The pinned implementation also has no ECN negotiation state to export. Verify
its unsupported ECN behavior and actual bootstrap SYN flags in targeted tests and
captures, together with the authenticated no-ECN contract. An absent field does
not prove behavior for arbitrary peers or future stack versions. A true timestamp
flag is explicitly unsupported by raw v1: this seam intentionally does not export
PAWS, clock or timestamp echo state. The getter remains a truthful observation;
the wrapper decides which options its next profile supports.

The pure wrapper's consume operation returns its original live owner on failed
logical proof. The future I/O transfer must retain the same raw socket, reservation and
mark, stops the old stack completely, and emits no FIN/RST/close_notify through
Drop or explicit close. A queued ACK held across WouldBlock prevents transfer.
This dependency seam does not prove TLS freeze, bridge emptiness, paired-lane
agreement, native delivery, snapshot authenticity or safe old-prefix responses.
Those remain the separate raw phase gates.

## Narrow validation plan

Compare the unchanged archive baseline and patched source with the exact features
used here: `std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-tcp-reno`, with
default features disabled. Keep test results separate from workspace/native
qualification. Upstream tests may use their established local fixture conventions;
no workspace unsafe policy is weakened.

- [x] [MOD-RAWSEAM-01] Staged and independently reviewed the exact one-file patch, maintained helpers and five tests; preserved source/license provenance. Evidence: [approved patch and review scope](../../third_party/smoltcp-provenance.json), [source import receipt](../../work/smoltcp-source-import/receipt.json).
- [x] [MOD-RAWSEAM-02] Tested actual handshake, bidirectional bytes/ACK/drain and exact snapshot fields with unchanged repeated queries. Evidence: [handshake regression in staged patch](../../work/smoltcp-quiescent-proposal/smoltcp-0.14.0-quiescent-snapshot.patch), [focused log](../../work/smoltcp-quiescent-proposal/patched-focused.log).
- [x] [MOD-RAWSEAM-03] Rejected unsent/unacknowledged bytes, unread data, out-of-order assembly with an empty readable ring, missing tuple and every non-established/FIN state. Evidence: [negative regressions](../../work/smoltcp-quiescent-proposal/smoltcp-0.14.0-quiescent-snapshot.patch), [focused log](../../work/smoltcp-quiescent-proposal/patched-focused.log).
- [x] [MOD-RAWSEAM-04] Tested delayed/forced ACK, retransmit/zero-window/close timers, exact keepalive/timeout boundaries, fast retransmit and option/window reporting. Evidence: [timing and window regressions](../../work/smoltcp-quiescent-proposal/smoltcp-0.14.0-quiescent-snapshot.patch), [focused log](../../work/smoltcp-quiescent-proposal/patched-focused.log).
- [x] [MOD-RAWSEAM-05] Passed unchanged upstream baseline, patched focused/full relevant suites, strict production lint/docs, exact patch application and unchanged-other-file comparison. Evidence: [isolated receipt](../../work/smoltcp-quiescent-proposal/receipt.json).
- [x] [MOD-RAWSEAM-06] Activated reviewed local source with preserved 0BSD/provenance, root lockfile update and third-party source hashing; post-activation aggregate remains separate. Evidence: [source provenance](../../third_party/smoltcp-provenance.json), [Cargo selection](../../Cargo.toml), [lockfile](../../Cargo.lock), [source recorder](../../tools/record_check.py).
- [ ] [MOD-RAWSEAM-07] Implement wrapper consume/checked counters and test held native output, stale deadlines, failure ownership and no FIN/RST at successful transfer/drop.
- [ ] [MOD-RAWSEAM-08] Complete authenticated all-lane TLS freeze, packet-phase and native qualification before exposing any new client capability.

## Isolated patch receipt

The [exact patch](../../work/smoltcp-quiescent-proposal/smoltcp-0.14.0-quiescent-snapshot.patch)
contains 289 additions and no deletions in one archived file. It applies with
zero fuzz to a fresh verified archive and reproduces the tested source hash.
The [receipt](../../work/smoltcp-quiescent-proposal/receipt.json) records archive,
license, before/after source, patch and individual log hashes plus actual commands.

The original locked upstream suite passed 428 tests; the patched same-feature
suite passed 433, including five new tests. An independently compiled IPv6-only
configuration passed all five new tests. Production `cargo clippy --lib -- -D
warnings` and warning-denied rustdoc passed. Upstream tests use their own fixture
assertions and are not subject to the repository's application-test conventions.
These results are separate from wave8's 587 Rust / 46 Python workspace receipt,
which predates this staged patch and does not include it.

The first unchanged-baseline offline attempt failed because upstream's own
lockfile referenced uncached `proc-macro-error2` metadata through optional defmt.
An ordinary `--locked` dependency fetch/test then succeeded; subsequent checks
were offline. No manifest or lockfile was altered to bypass the missing dependency.
That isolated receipt predates local activation. There was no raw engine handoff,
privileged test, native packet phase, or middlebox qualification.

## Reviewed source import and activation

All 134 archived files were extracted from the verified original archive into
[third_party/smoltcp](../../third_party/smoltcp). The approved exact patch applied
with zero fuzz. All 133 other files remain byte-identical, with no missing or extra
source files. Original license and archive Cargo files were preserved. The
[sibling manifest](../../third_party/smoltcp-file-manifest.json) lists every original
and patched file hash; [provenance](../../third_party/smoltcp-provenance.json) retains
the exact patch hash and review scope. A new [import receipt](../../work/smoltcp-source-import/receipt.json)
records this step without overwriting the earlier isolated results.

Independent review covered the exact getter, five tests, mapped upstream fields
and maintained ACK/window/timeout helpers. A second read-only review found no
material blocker and highlighted the unscaled SYN-ACK window distinction: a
caller must prove a later non-SYN advertisement before applying negotiated scale
to the last raw window. The [wrapper design](raw-owner-handoff.md) requires a
positive, fully acknowledged ciphertext prefix and explicit regression for this
boundary. No upstream patch change was needed or made. Review is not upstream
acceptance or general connection-migration qualification.

Root separately selected the local package, updated the root lockfile offline,
excluded it from workspace membership, and extended source recording to include
third_party. Root reported successful local-source checks of raw-tcp and tcp-proxy.
The next source-stable aggregate must qualify this activated tree; wave8 predates
it. Pure checked counters and actual I/O ownership transfer remain unimplemented.


## Incremental current peer-window observation

A later [directional measured-pressure correction](proxy-directional-pressure.md)
adds a second, separately pinned [incremental patch](../../third_party/smoltcp-0.14.0-peer-window-observation.patch).
The original archive, license, quiescent patch, five tests and historical receipt
above remain unchanged. This increment exposes only current maintained scaled
peer receive-window bytes, including while stream bytes are retained. It returns
None in Closed/Listen/SynSent/SynReceived, and does not poll, mutate state, read a
clock or create transfer authority. Two new native socket tests exercise actual
scaled ACK updates, pending bytes, zero/reopen, repeated nonmutating observation
and every startup state. The full same-feature vendor suite passes 435 tests;
an IPv6-only build passes both new tests. Integrity checks pin the original
archive/patch and incremental patch/base/result hashes. This observation is not
cwnd, quiescence, migration or native qualification.
