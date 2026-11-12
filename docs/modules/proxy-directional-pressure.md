# Directional measured receiver pressure

Status: implemented with actual-stack regressions, independent exact source
review accepted and focused Linux tests/lint/docs. The stable root aggregate and
native pressure acceptance are separate gates. Evidence:
[scoped correction receipt](../../work/measured-directional-pressure17/validation.json)
and [immutable16b native failure audit](../../work/native-pressure16b-audit/validation.json).

A proxy leg has two distinct directions. Native receive-ring bytes are original
local application input waiting to produce outgoing relay records. Exhausting the
authenticated peer byte/record grant while those bytes remain is sender demand.
The existing measured Owner sends those exact facts in Demand.byte_blocked and
record_blocked. The opposite receiver checks them against its own actual grants
and derives grant_exhausted / sender_credit_exhausted as a growth input.

The same leg's native send ring holds incoming relay bytes for its local native
peer. Its original injected-byte count minus maintained send-queue bytes backs
the actual native acknowledged prefix. Local receiver pressure instead requires
this downstream send ring to retain bytes while the maintained peer's current
advertised receive window is zero. It does not follow from an upstream unread
ring, relay target, reservation size, or exhausted sender grant. Existing actual
native-arbiter/device WouldBlock and carrier/queue pressure remain unchanged.

The pinned maintained socket's read-only peer_receive_window accessor exposes
its existing scaled remote_win_len after establishment. Closed, Listen, SynSent
and SynReceived return None. The pure raw TCP Status carries that Option without
creating a parser, clock, queue, native window setting, cwnd estimate or ownership
transfer. The runtime additionally requires established evidence and nonempty
native sends; an idle zero window is not receiver pressure. Reads or real native
window/ACK progress clear the recomputed condition.

The original quiescent snapshot patch, archive, license and 133 unchanged vendor
files are preserved. A separately pinned incremental TCP-file patch adds only
this accessor and two tests. The strict source checker pins both patch identities,
the previous TCP-file hash and new result hash. Zero-fuzz reapplication reproduces
the exact tested TCP source. No manifest/lock, packet format, authenticated policy,
queue, transport algorithm, deadline or native acceptance gate changed.

The startup regression uses real TCP hosts, proxy tables, authenticated common-path
Demand/echo ownership and actual ACK-rate observation, with continuously reading
native peers and a finite small initial grant. It records source grant stalls,
requires both peer receive windows to remain positive and both targets to grow
beyond initial, and verifies all 524,288 original bytes in each direction. The old
runtime predicate deterministically fails on the source-stall/receiver-pressure
assertion; the correction passes. The test's smaller initial fixture grant is not
a native workload or production-default change.

The pause/release regression withholds the downstream B application's reads.
It proves A's source ring/grant stall remains demand, B has real zero-window
pending sends and receiver pressure, and B's authenticated grant-exhaustion
observation remains visible. Exact original bytes are delivered after release,
then B's actual peer window reopens and receiver pressure clears. A separate
actual-stack case fills the native peer receive ring but has no remaining send
bytes: its real zero window does not create pressure. Raw TCP IPv4/IPv6 tests
independently prove absent startup observation, actual zero/reopen, retained
sends, exact bytes and absent observation after local abort.

- [x] [MOD-DIRPRESSURE-01] Preserve immutable full/half16b failures and identify the precise directional source-demand classification defect. Evidence: [native audit](../../work/native-pressure16b-audit/validation.json), preserved online receipts and unchanged eight first-reopen proofs; WAN capture cap exhaustion remains a separate failure.
- [x] [MOD-DIRPRESSURE-02] Implement independently reviewed additive maintained peer-window observation with startup semantics, preserved original patch and strict incremental provenance. Evidence: [incremental patch](../../third_party/smoltcp-0.14.0-peer-window-observation.patch), [source checker](../../tools/check_smoltcp_source.py), full 435 vendor tests, both new IPv6-only tests and zero-fuzz exact reapplication.
- [x] [MOD-DIRPRESSURE-03] Correct receiver-control direction while retaining source demand, and verify real startup growth, downstream pause/release and idle-zero negatives. Evidence: [actual runtime regressions](../../crates/l2tunnel-runtime/src/proxy/measured_actor_tests.rs), [pure IPv4/IPv6 window regression](../../crates/l2tunnel-raw-tcp/src/tests.rs), 22 raw TCP + 160 runtime + 70 proxy tests and strict scoped lint/docs/format/integrity checks. Root stable aggregate and a future frozen native run remain pending in the scoped receipt.
