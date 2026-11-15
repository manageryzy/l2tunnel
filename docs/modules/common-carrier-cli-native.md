# Common original-carrier native CLI qualification

Status: implemented and integration-tested in four finite clean IPv4 Linux
production CLI/native cases. The [immutable build and tooling receipt](../../work/parallel-features-20261115/parallel-wave7-native-build-attempt-4/validation.json)
records a source-stable daemon build in 21.126 s and 12 focused tooling cases
passing in 0.276 s. The [native matrix](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-5/validation.json)
passed TAP/TUN × QUIC/media inner covers with cleanup in 26.643 s wall time.
This is an additive explicit backend of `tools/generic_cli_native.py`.
The existing Swift/APIv3 default remains unchanged.

The new invocation selects `--backend common-openvpn --common-plan ABSOLUTE_JSON`
with explicit `--cover quic-like|media-like --layer tap|tun`, immutable binary and
source-stable build receipt, fresh output and `--apply`. Without `--apply` it only
reads the bounded public plan and describes the run. The supplied Rust-canonical
plan is copied byte for byte, hashed, inspected by the actual CLI for both roles
and never pruned or re-encoded by Python. Complete APIv4 catalog pages are read
from the actual service. Python only checks canonical fixed headers and SHA256
digests; the maintained Rust parser remains authoritative.

The runner reuses actual owned topology, process bounds, credential generation,
native FD observation, ICMP/UDP byte probes, pcap primitives and journal cleanup
from the existing harness. A separate orchestration body is necessary because
the old worker hardcodes Swift304/APIv3. Real production connect/serve performs
outer TLS/member and inner Noise/member authentication on the original UDP pair,
then operates through the same service APIv4. No inherited packet-device fixture
substitutes for actual TAP/TUN attachment.

Owned tooling consists of `tools/common_carrier_cli_native.py`, its public
observation reader `tools/common_carrier_cli_validation.py`, focused
`tools/test_common_carrier_cli_native.py` and the early explicit-backend dispatch
in `tools/generic_cli_native.py`. Immutable build/helper receipts must include
both new loaded modules and all existing transitive helpers. Full CLI response
logs remain bounded and retained; receipt samples contain their public identity,
physical digest, counters and family rather than duplicating each complete C.

Each finite case requires all four record families in its complete supplied
catalog, switches through one representative of each noninitial family and back
to initial, checks keyed completion/replay and E0 refusal, exchanges exact bytes
and authenticated liveness at every phase, and preserves socket/device ownership
through switches. A controlled healthy local disconnect must release the client.
The peer must then expose its actual `Io(BrokenPipe)`/BrokenPipe service failure,
or authenticated `PeerTimeout`/TimedOut failure, through the retained API within
the original command deadline. An already failed peer's disconnect is the exact
`state` refusal retaining that failure, not a successful Aborted projection. Both
owners must be released before fresh reconnect. The final stop uses the same
controlled sequence. Reconnect establishes a fresh session; this does not qualify
retained-state recovery.

Raw socket and complete native FD observations are persisted before identity
comparison. The comparison requires the actual daemon PID, socket inode/FD and
native FD, target, mount ID, inode and exact interface. Position and flags remain
retained diagnostics rather than owner identity. These are finite point
observations, not proof that close/reopen was impossible between samples; the
production owner's type-level lifetime is complementary. In failed native
attempt 3, retained UDP logs showed unchanged socket identity, but the differing
device FD metadata was not retained. No specific changed metadata field is
claimed from that historical failure.

Native attempt 4 retained the exact metadata difference: the first native frame
advanced FD position from zero to 1500 (TUN) or 1514 (TAP), with descriptor,
target, mount ID, inode and interface unchanged. Its three receipt-publication
failures were `EFBIG` at the existing 1 MiB worker file limit; full daemon logs
were below that bound. Duplicate ready/lifecycle status projections now share
one public identity/digest/counter summary with hexadecimal public byte arrays.
Complete requested/effective catalogs, copied plan, raw CLI/probe logs, command
vectors and pcaps remain. The final phase table references the already retained
complete per-phase functional sections instead of duplicating probe rows.
`EFBIG` is a Common-runner bound exhaustion; historical receipt classifications
are preserved. The full64/six-phase serialization-budget regression passed in
the 12-case tooling batch. A completed six-phase probe set receives the same bounded
capture flush even after another error; that error remains nonpassing.

All mutation stays inside fresh user, mount and network namespaces. Credentials
and control sockets exist only in a verified fresh `/run` tmpfs. The runner
suppresses and verifies IPv6 in the four owned native namespaces and retains the
broad `ip or ip6 or arp` capture filter. Acceptance is explicitly finite IPv4;
IPv6 requirements remain open. Outer captures validate bounded OpenVPN grammar,
inner cover/public record shape, original tuple and complete IP MTU; they do not
authenticate captures or establish standard-dissector/interoperability/ISP claims.

Existing lab bounds remain case 240 s, startup 35 s, command 15 s, cleanup 30 s,
launcher 300 s, 256 commands/observations, 1 MiB logs and 8 MiB/4096 packet captures
with 2048-byte snapshots. Original phase caps are propagated through nested
operations. One retained cleanup deadline is shared by all cleanup. These are
finite lab budgets, not product recovery defaults. Missing capabilities,
tools, exhausted bounds and functional failures are explicit nonpassing results.

The input plan must explicitly configure a positive integer
`runtime.report_interval_micros` shorter than the existing five-second liveness
observation cap. Preflight refuses disabled or inadequate cadence before lab
mutation. This runner requires an actual observed pong; a null report cadence
retains the initial readiness snapshot and cannot provide that observation even
when native traffic succeeds. The plan is never assigned a reporting default,
and the cap and pong requirement are unchanged. The focused rejection case for
this prerequisite passed. The passing lab plans explicitly use a 500 ms local
report cadence; that is a finite lab input, not a product reporting default.

- [x] [CCN-01] Actual runner body and immutable public plan/helper/binary snapshot. Evidence: [build/tooling](../../work/parallel-features-20261115/parallel-wave7-native-build-attempt-4/validation.json), [owned native matrix](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-5/validation.json).
  Includes strict explicit selection and bounded owned isolation/cleanup.
- [x] [CCN-02] Four real production CLI cases: TAP/TUN × QUIC/media inner covers. Evidence: [all four cases and cleanup passed](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-5/validation.json).
  Includes complete catalog, actual four-family switching, native bytes/liveness, original
  socket/device custody, APIv4 completion/refusal/replay and fresh reconnect.
- [ ] [CCN-03] Full native/fault/resource/platform/CLI qualification, retained
  recovery, full SW-11 and all mode parity including RLNC/parity/rolling/packed/
  proxy, native P/early-short8192 and 80 Mbit/s performance. Finite clean cases do
  not close this gate or any unchanged parent definition.

The [canonical-plan receipt](../../work/parallel-features-20261115/parallel-wave7-final-build-cases-attempt-1/validation.json)
records Rust validation of four supplied TAP/TUN × QUIC/media plans, each retaining
all 64 catalog members across all four record families and both setup roles.
Their explicit lab flow capacity is 64, sufficient for the probe's 14 distinct
UDP source flows plus other native registrations; no catalog or probe rows were
removed. The runner does not generate or repair those protocol configurations.

Each passing native case inspected all 64 requested catalog members for both
roles and paged all 64 effective configurations from the actual generation-bound
APIv4 service. Four family representatives were active, with return to initial;
this is not a 64-active-configuration matrix. Six phases per case carried exact
bidirectional native ICMP/UDP bytes, including full 1500-byte IP packets, and
observed authenticated liveness. Socket/native descriptor identity remained
stable through switches. All 16 capture surfaces had zero kernel drops; each
native surface retained all 72 required ICMP fingerprints across the six phases.
Command counts were 204..221 below 256; receipts were 1,016,445..1,032,388 bytes
below the unchanged 1,048,576-byte file limit.

All eight controlled peer-failure observations, first and final stop in each
case, were actual `Io(BrokenPipe)` with the matching BrokenPipe service failure.
The API stayed available, refused the already-failed backend's disconnect with
`state`, and retained its real terminal outcome. Fresh reconnect completed new
outer TLS/member and inner Noise/member authentication with new session/E1
identities, followed by native traffic. The allowed `PeerTimeout` branch was not
exercised. Failed or cancelled replacement-setup handling is authored and source
reviewed only; these native cases do not validate those branches. Fresh
reauthentication is distinct from still-required retained-state recovery.

The failed runs remain historical evidence:

- [Attempt 1](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-1/validation.json)
  failed before worker startup because mapped root could not traverse private
  worktree ancestors. Fresh case outputs moved to private `/tmp`; no host
  permission or security-policy relaxation was applied.
- [Attempt 2](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-2/validation.json)
  passed initial native bytes but exhausted the original liveness observation
  cap with reporting disabled and the readiness-only snapshot unchanged.
- [Attempt 3](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-3/validation.json)
  stopped at the first switch because complete FD metadata was compared as
  identity. UDP identity was unchanged; the exact device field was not retained.
- [Attempt 4](../../work/parallel-features-20261115/parallel-wave7-native-cases-attempt-4/validation.json)
  completed six traffic phases but failed receipt publication in three cases
  and final peer-failure API handling in media/TUN. The latter also skipped
  capture draining, leaving buffered final fingerprints absent. Its original
  failures and classifications are preserved.

CCN-03 and all unchanged parent gates remain open: complete native/fault/resource
and platform coverage, all 64 active configurations, retained recovery, full
SW-11/mode parity and performance are not qualified by these four clean cases.
No performance workload or full `tools/check.py` result is claimed here.
