# Standalone native-drain qualification proposal

Status: four separately authorized clean native-drain cases passed once each: TUN
and TAP, full and genuine paired half. Each records actual native/carrier receipts,
original UDP socket release and owned-namespace cleanup. All four results passed
independent receipt/capture audit. Loss and
broader platform qualification remains open. The additive harness and focused
unprivileged tests are implemented.
The [client checkpoint](openvpn-drain-client.md#finite-implementation-evidence)
passed 68 local client tests, strict Clippy and rustdoc, with an earlier broad-suite
join timeout still [unattributed](../../work/openvpn-drain-client/original-broad-timeout.txt).
A later passing run does not explain that timing observation. The stable wave 10
aggregate also failed an existing paired carrier close with `IncompleteClose`;
[one isolated and one concurrent instrumented diagnostic](../../work/openvpn-paired-close-diagnostic/package-diagnostic.json)
passed without changing production semantics or deadlines. That aggregate failure
remains unattributed. Independent review approved the harness, residual-namespace
correction, immutable build and first case before execution. Independent review
of the first result then authorized the remaining three clean cases; no other
native case is authorized by this receipt.

## Scope and ownership

The separate `tools/openvpn_drain_native_smoke.py` and focused
`tools/test_openvpn_drain_native_smoke.py` implement this contract. Reuse existing
`netns_lab.py` owned
namespace plans, `native_smoke.py` strict native probe and bounded capture parsers,
and exclusive atomic case receipts. Do not alter the old harness's default
`original-2s`, `short-recovery` or `idle-loss` branches, or overwrite their receipts.
The new case names end in `-native-drain`; clean shutdown coverage includes no
outage probe and must never be reported as recovery-through-loss coverage.

Only Linux, ordinary frame records, one system FIFO, AEAD, compression off,
whole-IP MTU 1200, IPv4 underlay, TAP or TUN, and full or genuine paired half lanes
are proposed. Keep current three-second authenticated-TLS inactivity and one-hour
lease. TAP keeps system algorithms; native TCP control packets, ICMP, ARP/NDP and
other admitted user traffic share the same FIFO policy. No FEC, packed/aligned,
active/proxy, VXLAN, IPv6 underlay, native signal-to-drain, netem-loss or broader
mode-parity claim is included.

The first run, after separate approval, is exactly `tun-half-clean-native-drain`.
Preserve its result and obtain review before any additional run. A later reviewed
finite expansion consists of `tun-full`, `tap-half` and `tap-full`, each in its own
new output directory. The complete proposed four-case set is not authorization
to launch a matrix or retry a failed case.

Proposed dry-run/apply interface:

```text
python3 tools/openvpn_drain_native_smoke.py \
  --layer tun --duplex half --output NEW_DIRECTORY
# After source/test/checkpoint review only:
python3 tools/openvpn_drain_native_smoke.py --apply \
  --binary IMMUTABLE_DAEMON --build-receipt SOURCE_STABLE_BUILD_JSON \
  --layer tun --duplex half --output NEW_DIRECTORY
```

The plan enumerates exact namespaces/interfaces, daemon commands, fixed endpoint
tuples, file permissions, stage bounds and acceptance before any privileged
mutation. `--apply` requires a verified source-stable build receipt and refuses
an existing output path. Copy the reviewed daemon, helpers and build receipt,
check their hashes before launch, and record their hashes in the case receipt.
Only namespaces in this case's `netns_lab` ownership journal may be mutated.
Never change existing host routes, bridges, filters, socket policies or qdiscs.

## Setup and positive native evidence

Retain explicit private provisioning through existing keygen commands: verified
TLS certificate/member identity, independent admission and server-only cookie
bundles; no secret bytes in logs or receipts. Both daemon commands explicitly set
`--carrier openvpn-like --openvpn-close-profile native-drain`,
`--openvpn-drain-timeout-ms 5000` and separate private control sockets. Full mode
has one fixed UDP lane; half has distinct fixed forward/reverse tuples and the
actual joined capability. The new native status replaces legacy sampled queue
metrics; a harness must not wait for `openvpn_native_stats` in this profile.

Keep the existing setup limits: each fixed UDP bind observation has five seconds;
both authenticated endpoints share one 65-second observation deadline captured
before launching the server. Each actual client factory still has its own
unchanged 30-second original setup deadline. A poll or second lane never creates
a new observation allowance. Local readiness and socket-inspection commands use
at most two seconds, clipped to the remaining stage deadline. Ordinary setup
commands keep the existing 60-second ceiling; ownership cleanup is independently
bounded and recorded, not credited as successful protocol completion.

Start underlay captures before bootstrap and require actual capture readiness
within the setup deadline. Block outer TCP on both owned links; prove a real SYN
times out with an incremented owned drop counter. Observe expected UDP tuples
owned by each launched PID, and no underlay established TCP connection. Set actual
endpoint/router IP MTUs to 1200 and disable checksum/segmentation/receive
aggregation offloads on those owned links; record effective settings.

Reuse unchanged positive probes: three independent single IPv4 pings at each
existing size/direction with exact 1/1 counts and `-W 30`; existing exact IPv6
native probe counts; and the existing 65,536-byte native TCP SHA-256 check. Keep
the existing per-command transfer limits. Record each completed probe/stdout/hash
incrementally before proceeding. Stop and reap the probe producers before asking
for drain. Do not infer the total native accepted prefix from probe counts: system
ARP/NDP/neighbor traffic may also have been admitted. Kernel/device traffic not
read before the actual stop is outside the accepted prefix.

## Drain action and authoritative closure

Prearm one independent observer per endpoint before sending the first drain
action, then capture a single absolute observation deadline immediately before
that action: `t0 + 12 seconds`. This is a strict finite acceptance ceiling, not a
proof that both peers necessarily finish by adding 2 + 5 + 5 seconds. Each peer
starts its own five-second **local-only** grace after its actual runner returns;
one peer may finish earlier, and its API is not guaranteed to survive until the
global deadline. Each observer records the start of its most recent nonterminal
status query and completes its own socket proof and final status query before
`min(t0 + 12 seconds, last_nonterminal_query_start + 5 seconds)`. The latter is a
conservative bound: that query observed the runner before its grace started. It
is never computed as first-Closed-observation plus five seconds. Observers do not
wait for the sibling terminal before inspecting their own endpoint. Every query,
proof and process wait is clipped to the same global remaining allowance; retries
never reset it. A missed per-endpoint grace window fails the case. The harness cannot extend the runtime allowance. Its observed
terminal time is not substituted for the runtime's internally checked deadline.

Send `drain-openvpn` only to endpoint A. Endpoint B must stop from the authenticated
peer request; its status must keep `drain_accepted=false`. Require endpoint A's
first response to be `ok=true, code=accepted`, correct actual binding, and local
acceptance true. This response alone is never a clean result. Repeat the request
only while status remains nonterminal: require `already_accepted` without a new
request; if it became terminal concurrently, `closed` plus the immutable actual
terminal snapshot is the allowed race outcome. No new drain work may be accepted
after terminal.

Poll both private sockets for strictly decoded `openvpn_drain` snapshots. Reject
unknown/duplicate fields, over-8192-byte frames, unbounded diagnostics, missing
fields, incorrect cardinality or inconsistent bindings. Full endpoints must share
one actual session/config identity; paired endpoints must share the actual pair
digest and canonical two accepted lane configs. Do not reconstruct an exporter
or assert an authenticated capability from requested settings.

The exact wire action is `{"version":1,"action":{"command":"drain_open_vpn"}}`;
`drain-openvpn` is only the CLI spelling. Responses have exactly `version`, `ok`,
`code`, `state`; state has `epoch=1`, `phase`, `compression="off"`, `openvpn_drain`.
The latter has exactly `binding`, `drain_accepted`, `terminal`. An actually closed
terminal has lowercase `kind="closed"` and `report`; its carrier has `kind="full"`
with one object in `lanes`, or `kind="paired"` with exactly two lane objects.
Logs with `kind="openvpn_drain_status"` contain a direct snapshot, not the local
response envelope, and are not substituted for the required private RPC.

Both terminals must be Closed, copied from actual `NativeDrainReceipt` and its
original carrier receipts. Require exact cross-peer equality:

- A's local packets/native bytes/sources/source bytes equal B's peer prefix.
- B's local prefix equals A's peer prefix, with positive native payload traffic
  in both directions.
- Each carrier report has exactly one full or two paired lane receipts. Sum of
  their actual admitted sources equals the local source fence; sum of actual
  consumed sources equals the peer source fence. Control progress and physical
  write counters must be present and nonzero where that lane carried traffic.

Carrier application receive/ACK is not native delivery. Only the runtime's
successfully confirmed `PacketDevice::transmit` prefix and authenticated peer
native acknowledgment permit Closed. No queue emptiness, process signal, local
acceptance, observed silence or raw packet header may stand in for this proof.
The current receipt does not expose a wall-clock completion timestamp; use its
actual success semantics and the independently recorded harness timings.

While each endpoint still serves its local status grace, prove its original UDP
socket tuples are absent from PID-owned socket listings and can be bound by a
single bounded inspection helper **inside the same owned namespace**. It checks
exact address/port tuples and the original PID plus `/proc/PID/stat` start-time
identity, then binds all original lane tuples simultaneously using plain UDP
sockets without `SO_REUSEADDR` or `SO_REUSEPORT`. It sends no datagrams, verifies
the still-identical private Unix socket inode/owner/mode and queries the same
Closed terminal while those probe sockets are retained, then closes every probe
in a `finally` block. A PID substring or socket pathname existence alone is not
ownership or authenticated readiness. This single proof helper uses the endpoint
grace bound, not a new allowance per command. Require both daemon
processes to exit zero without signals within the original observation deadline.
A process kept alive beyond that deadline, an absent terminal, any Failed or
Cancelled state, a missing socket proof, or forced termination is a failed case.

The existing three-second carrier policy can end a delayed experiment sooner;
this is a real non-clean failure. Do not enlarge inactivity, runtime drain, setup,
RPC or observation bounds to obtain success. The earlier unprivileged broad-suite
timeout is relevant unresolved evidence and must remain linked from new receipts.

## Captures, failure retention and cleanup

Keep capture active through original network-owner closure. Audit complete PCAP,
fixed UDP tuples, expected standalone bootstrap/control/data discriminators and
whole-IP length at most 1200 without outer fragments. TLS control is encrypted:
recognizing an outer header cannot prove NativeAck or membership. Native receipts
and actual factory success provide those claims. Capture truncation, capture
limit exhaustion or missing required lane observations fails capture acceptance;
retain partial capture hashes separately without turning them into an overall
pass. Do not require a missing capture packet to prove unsent traffic.

The case receipt begins before probes and is atomically replaced after every
milestone, with the existing 4 MiB bound. Retain exact action responses, bounded
terminal snapshots, timing boundaries, process exit codes, actual socket output,
probe hashes, source/binary/helper hashes, packet captures and cleanup outcome.
Record failed/unrun stages explicitly. On failure, attempt all owned removals and
bounded process cleanup even if one step fails; preserve the first cause and all
cleanup failures. Only original journal-owned namespaces may be removed.
Before apply, read the existence and identity of every exact expected namespace
name. Repeat that read-only observation after cleanup, including failed apply
where the rollback journal has disappeared. An add command may create a namespace
then fail before its identity reaches the journal: new or changed residual names
therefore make cleanup fail even without a journal. Observation does not authorize
adopting or deleting those unaccounted names. Missing/incomplete observation also
cannot establish successful cleanup. Forced cleanup never becomes a clean-close
receipt. Historical failures are immutable and adjacent to any new finite passing
result.

## Proposed focused parser and orchestration tests

Before applying: strict dry-run/profile validation; one/two-lane binding and
cross-prefix matching; accepted-versus-Closed; retry/terminal race; peer-only local
acceptance false; negative terminal/exit/signal; response-byte and diagnostic
limits; exact original deadline clipping with an injected clock; sequential RPCs
and grace cannot renew the deadline; socket still bound during terminal; absent
or replaced local socket; pre-auth capture readiness/limit/MTU; incremental receipt
replacement failure; and all-removals-attempted cleanup after an injected error.
Tests use fake commands/clock or unprivileged parsers; none authorizes a namespace
mutation. Run focused tests and the coordinated workspace checks, then request
review of the concrete immutable build/first-case plan before execution.

- [x] [MOD-OVPNDNATIVE-01] Inspect existing native owners/harness bounds and freeze a separate clean-drain scope, acceptance and exact evidence contract before implementation. Evidence: [scope](#scope-and-ownership), [actual closure predicates](#drain-action-and-authoritative-closure).
- [x] [MOD-OVPNDNATIVE-02] Independently review the client checkpoint and exact harness implementation contract, including unresolved timing observations and independent grace observers; privileged execution remains a separate gate. Evidence: [reviewed timing and schema contract](#drain-action-and-authoritative-closure), [preserved aggregate failure](../../work/implementation-wave10/validation.json).
- [x] [MOD-OVPNDNATIVE-03] Implement the additive dry-run harness and strict bounded parser/orchestration tests without changing historical outage acceptance. Evidence: [harness](../../tools/openvpn_drain_native_smoke.py), [tests](../../tools/test_openvpn_drain_native_smoke.py), [focused receipt](../../work/openvpn-drain-native-harness/validation.json).
- [x] [MOD-OVPNDNATIVE-04] Run focused tests, strict source checks and a source-stable immutable daemon/helper build; review the concrete first owned case. Evidence: [22 focused tests](../../work/openvpn-drain-native-residual/validation.json), [stable wave 11](../../work/implementation-wave11/validation.json), [immutable build](../../work/openvpn-drain-native-build11/receipt.json), [reviewed exact preflight](../../work/openvpn-tun-half-native-drain11/preflight.json).
- [x] [MOD-OVPNDNATIVE-05] Execute one clean TUN/half case once with real native/carrier receipts, original socket closure, captures and cleanup; retain failures without retry or bound changes. Evidence: [single case receipt](../../work/openvpn-tun-half-native-drain11/receipt.json), [one invocation](../../work/openvpn-tun-half-native-drain11/launch.json), [finite result](#first-native-case).
- [x] [MOD-OVPNDNATIVE-06] Review that actual result before separately authorizing the remaining clean full/half TAP/TUN cases. Evidence: [independent first-case audit](../../work/openvpn-tun-half-native-drain11-audit.json), [exact expansion preflight](../../work/openvpn-drain11-expansion-preflight.json).
- [x] [MOD-OVPNDNATIVE-07] Complete independent audit of the remaining three recorded finite cases and link the coordinated aggregate; keep outage, impaired, VXLAN and broader platform/parity gates open. Evidence: [all four independent audits](../../work/openvpn-native-drain11-independent-audit.json), [reproducible read-only audit](../../work/openvpn-native-drain11-independent-audit.py), [four-case receipt](../../work/openvpn-native-drain11-matrix.json), [stable build aggregate](../../work/implementation-wave11/validation.json).


## Finite harness implementation evidence

The focused suite exercises strict full/paired identities and reports, unknown and
duplicate fields, byte bounds, independent early-peer proof while the other peer
remains nonterminal, unchanged global/per-endpoint deadlines, nonzero/signal
process exits, original PID/tuple ownership, simultaneous plain UDP probes,
private socket replacement, partial bind cleanup, atomic receipt replacement and
retained partial-setup rollback journals. Ordinary loopback UDP/Unix tests do not
configure namespaces or validate native protocol operation. Helper snapshots copy
and hash the reviewed harness, existing bounded capture/build utilities, unchanged
native probe parser and TCP helper. The shared checker includes the new suite.

The capture readiness and offload helpers come from the existing proxy harness;
its unrelated proxy runtime or native success is not credited to this carrier.
Original outage harness logic is unchanged. The initial harness checkpoint predates stable wave 11 and the separately reviewed
[first native case](#first-native-case). Wave 10 and the original client timing
observation remain failed/unattributed evidence; later success does not explain them.


The independent harness review identified an earlier cleanup-evidence gap when
`ip netns add` creates a name before returning failure and before journal update.
The narrow correction adds read-only before/after name identities and retains
unaccounted residuals. A no-journal residual regression verifies failure without
adoption/deletion; a replacement/symlink regression verifies observation only.
[Revised focused receipt](../../work/openvpn-drain-native-residual/validation.json)
keeps the earlier harness checkpoint and failed wave 10 immutable.


## First native case

On 2026-11-12, `tun-half-clean-native-drain` ran exactly once in fresh owned lab
`odrain-w11`, using the reviewed immutable daemon with SHA-256
`2107b577f9d2f1adb5c4b182870fb971626d5ceba9a70f7f46c28d8e34cdb1e9`.
The [preflight](../../work/openvpn-tun-half-native-drain11/preflight.json) verified
all six helper hashes against the stable build's source map before mutation.
[Wave 11](../../work/implementation-wave11/validation.json) recorded 702 Rust
cases including doctests and 85 Python cases; that aggregate is distinct from
this privileged finite native observation.

The [case receipt](../../work/openvpn-tun-half-native-drain11/receipt.json) records:

- All 18 native IPv4/IPv6 single probes met unchanged exact 1/1 acceptance.
  The 65,536-byte TCP payload matched SHA-256
  `a863d4360888ecceb6f59e575cd4eaa590b127c5a096a43e92d1274b5dccb5c9`.
- A's request returned `accepted`; its repeated request returned
  `already_accepted`. B stopped from the authenticated peer request and retained
  `drain_accepted=false`.
- Both actual Closed terminals were observed about 3.04 seconds after the first
  action. A's native/source fence was 70 packets, 83,608 native bytes, 127 sources
  and 89,808 source bytes; B's was 61 packets, 17,632 native bytes, 73 sources and
  21,528 source bytes. Each exactly matched the opposite peer receipt.
- Each independent proof observed no original PID-owned UDP tuple, held both
  original lane tuples simultaneously with plain UDP binds, and queried the same
  immutable terminal during local-only grace. Proofs completed at 3.159 and
  3.174 seconds. Both daemon processes exited zero by 8.151 seconds, within the
  unchanged 12-second global observation ceiling.
- Each complete underlay capture contains 383 packets, zero kernel drops, both
  lanes' required bootstrap/control/protected classes, maximum IP length 1200 and
  no outer fragmentation. Effective link MTUs/offloads and observed TCP-drop
  counters were recorded before authentication. This framing sample is not a
  cryptographic interpretation of encrypted TLS control.
- Every stage and cleanup passed. Post-cleanup expected-name observations matched
  the all-absent baseline; no unaccounted namespace remained.

This first result qualifies only the clean TUN/paired-half case. Its independent
[audit](../../work/openvpn-tun-half-native-drain11-audit.json) then authorized the
finite expansion below. No failed case was retried.


## Separately reviewed clean matrix expansion

On 2026-11-12 the remaining cases ran once each in order: TUN/full, TAP/half,
TAP/full. The [preflight](../../work/openvpn-drain11-expansion-preflight.json)
verified the same immutable binary, build source map and all six helper hashes,
fresh output paths, absent journals and absent expected namespace names before
any new mutation. Every case retained its original bounds and independent
per-endpoint terminal/socket observer. The aggregate source checkpoint remains
[wave 11](../../work/implementation-wave11/validation.json); no Rust or harness
source changed for this expansion.

| Case and receipt | Fresh lab | Latest Closed observation | Latest socket proof | Both process exits | Packets per capture |
| --- | --- | ---: | ---: | ---: | ---: |
| [TUN/full](../../work/openvpn-tun-full-native-drain11/receipt.json) | `odrain11-tun-full` | 3.052 s | 3.176 s | 8.150 s | 311 |
| [TAP/half](../../work/openvpn-tap-half-native-drain11/receipt.json) | `odrain11-tap-half` | 3.051 s | 3.180 s | 8.107 s | 391 |
| [TAP/full](../../work/openvpn-tap-full-native-drain11/receipt.json) | `odrain11-tap-full` | 3.042 s | 3.168 s | 8.117 s | 331 |

Times are rounded up to the next millisecond from the first drain action, not
from process launch. The protocol drain bound remains five seconds; the overall
observation cap remains twelve seconds, including the existing five-second
local-only grace. Each original tuple was absent from the original PID's socket
set and bound simultaneously with plain UDP while the same private local socket
still returned its immutable Closed result. Both processes exited zero without
a signal. A returned `accepted` then `already_accepted`; B closed from its peer's
authenticated request with local `drain_accepted=false`. Each local native/source
fence exactly matched the opposite endpoint's peer fence.

Every case passed all 18 exact native IPv4/IPv6 probes and the same 65,536-byte
TCP payload hash recorded above. Both captures had zero kernel drops, maximum
whole-IP length 1200, no outer fragments and all expected bootstrap, control and
protected framing classes. Each stage and cleanup passed; expected namespace
names returned to their all-absent baselines with no unaccounted residuals.
Non-secret launch logs and command receipts accompany each original case receipt.
The [matrix summary](../../work/openvpn-native-drain11-matrix.json) records exact
times, hashes and native/source counts without modifying the original receipts.
Independent [audit of all four saved results](../../work/openvpn-native-drain11-independent-audit.json)
passed. The [read-only audit script](../../work/openvpn-native-drain11-independent-audit.py)
checks hashes, actual bindings, complementary native/source fences, original
PID/start/socket identity, simultaneous tuple proofs, deadlines, whole-IP captures
and cleanup. The earlier matrix summary retains its then-pending audit status;
this later audit is a separate receipt rather than a historical rewrite.

This completes only four clean Linux TAP/TUN full/paired-half observations. There
is no outage, impairment, recovery-through-loss, VXLAN, throughput/fairness or
non-Linux qualification. The original two-second outage failures and both
unattributed unprivileged timing failures remain preserved and unexplained. No
retry or further native run followed this expansion.
