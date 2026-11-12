# Fixed-credit native TUN proxy qualification

Status: clean Linux TUN full and paired-half duplex passed the finite native
gates, an [independent final audit](../../work/native-proxy-clean-audit.json), and the
[stable wave9 aggregate](../../work/implementation-wave9/validation.json). The harness has focused validator
and ordinary kernel loopback tests. The privileged
gate below is deliberately a clean Linux TUN gate, separately from adaptive
windows, impairment, raw/UDP/QUIC carriers, TAP, or Python mode parity.

## Owned files and entry points

Owned files are `tools/proxy_native_smoke.py` and
`tools/test_proxy_native_smoke.py`, plus this document. Reuse `netns_lab.LabSpec`,
`apply`, `cleanup` and its identity-checked journal unchanged. Read shared
`netns_lab.py` and existing native harnesses as references; do not edit them or
import their changing profile-specific orchestration. Register the new pure
Python tests in `tools/check.py` only through a separately coordinated narrow edit.

The dedicated harness defaults to dry run. Its CLI is:

```text
python3 tools/proxy_native_smoke.py --lab-id NAME --output NEW_DIRECTORY
    [--binary PATH] [--build-receipt ORIGINAL_BUILD_RECEIPT] [--state-dir ROOT_PRIVATE_DIRECTORY]
    [--only-case tun-full-clean|tun-half-clean] [--apply]
```

Without `--apply`, validate arguments and print the exact namespaces, initial
topology commands, explicit clean override, client profile, policy, cases and
fixed acceptance/deadlines; create no directories, keys or
sockets. The apply path requires Linux, explicit root execution and a fresh
exclusive output directory. Apply also requires the successful original build
receipt, equal before/after source maps, and the exact copied binary hash.
Each case has a separate journal-owned topology,
using `NAME-f` or `NAME-h`; validate the suffixed LabSpec before any mutation.
No existing namespace, route, bridge, interface, socket path or qdisc is adopted.

Helpers stay inside this module: an explicit internal `probe` subcommand runs a
finite ordinary kernel TCP endpoint in an owned namespace. Copy the exact harness
and built CLI binary into the fresh output directory before execution and record
their SHA-256 digests. Capture workspace and every crate/application manifest,
source/compile asset, lockfile and vendored dependency source/license/provenance
hashes, plus the exact saved policy JSON hash. Verify those same source hashes
before and after the coordinated CLI build, retaining the build receipt;
keep ephemeral private keys in a separate mode-0700 temporary directory, never
in receipts. Receipt writes are atomic and bounded, retaining failure evidence.
When rerunning a harness-only fix with an immutable binary, keep its original
build source map separate from source observed at the later launch. A current
workspace hash is not evidence that a previous binary was built from it.

Pure interfaces to test before privileged execution include:

```text
case_plan(lab_id, duplex) -> immutable argv/policy/deadline description
validate_proxy_snapshot(response, expected_digest, expected_phase) -> counters
verify_probe(result, expected_tuple, directional_payloads) -> exact byte/EOF proof
verify_peer_closures(client, server, lanes, expected_owners) -> exact cross counters
audit_native_captures(paths, tuples, expected_owners) -> split/bypass/FIN proof
run_case(plan, immutable_binary, output) -> bounded case receipt
```

## Clean owned topology and immutable profile

Use the existing five-namespace lab ownership protocol. Its two endpoint
namespaces communicate through the owned router over `192.0.2.2` and
`192.0.2.6`. Configure the owned qdiscs to clean zero-loss/zero-delay service;
retain finite rate/queue limits and record actual qdisc output. Add `tun0` only
inside each owned endpoint, with MTU 1500 and addresses `198.19.0.1/24`,
`198.19.0.2/24`, `fd42:12:19::1/64`, and `fd42:12:19::2/64` (`nodad`). The
ordinary kernel TCP applications run in these endpoint namespaces. No host
forwarding/sysctl or host application route is changed.
Disable IPv6 only on endpoint `wan0` and router `a0`/`b0`, the four owned IPv4
underlay interfaces, recording original/effective values. This suppresses
unrelated MLD extension traffic from the observation path; native `tun0` IPv6
remains enabled and fully tested. Extension/fragment audit rules stay strict.

Use normal maintained TIME-WAIT behavior, 16 channels, fixed runtime defaults,
`--traffic proxy --carrier tcp --layer tun --record-profile frame
--compression off --max-packet 1600`, and private local sockets on both peers.
The exact strict policy grants only original endpoint A to endpoint B TCP port
24451, once for each address family. It grants no port 24452 rule. No policy
fallback, adaptive option, expiry extension or TIME-WAIT exception is permitted
in this gate. TLS client A is the only proxy originator; B is the authenticated
acceptor. Both policies must produce the same runtime digest.

Read and record namespace-local ECN settings; explicitly set ECN off only in
these new namespaces so the initial plain-SYN candidate is deterministic. Keep
normal Linux MSS/window-scale/SACK/timestamp options. If the real kernel SYN is
unsupported and the flow bypasses, report failed proxy admission with the saved
SYN; successful transparent transfer cannot satisfy the proxy gate. Disable
checksum/GSO/GRO/TSO offloads on the owned observation path where supported and
record the actual features. Failure to establish exact packet evidence is a
tool/qualification failure, never a relaxed acceptance rule.

## Required clean observations per duplex mode

1. Bind peer listeners and launch the same immutable CLI binary with freshly
   provisioned certificate/member keys. Poll both private APIs for Forwarding,
   identical immutable digest, zero flow owners and no terminal result. Capture
   every native `tun0` and physical `wan0` before generating test traffic.
2. Send three separate single IPv4 and IPv6 ICMP echo probes in each direction,
   with a fixed payload below the native MTU. Each must report exactly one sent
   and one received. No proxy owner is allocated; actual transparent counters
   advance on both peers. These user packets use the normal runtime arbiter.
3. Start concurrent IPv4 and IPv6 kernel TCP connections from A to B:24451,
   with distinct fixed source ports. Each endpoint concurrently sends its own
   deterministic opaque payload: A sends 65,537 bytes and B sends 32,771 bytes.
   Both call `shutdown(SHUT_WR)` only after their complete send, read until EOF,
   and verify exact opposite length/hash. Both peer status snapshots must show
   exactly two allocated proxy owners and no stopped flow. Captures must show
   complete handshakes and FIN in both native legs; the emitted remote SYN or
   SYN-ACK sequence space must differ from the originating kernel leg, alongside
   the two actual runtime owners. A transparent byte transfer alone is not split
   TCP evidence. Do not require equal packetization or advertised windows across
   the two independent native legs.
4. Repeat exact bidirectional kernel transfers to port 24452 in both families.
   These denied routes remain transparent for their whole lifetime: neither
   peer's owner count may increase, transparent counters must increase, and
   captures must preserve the original SYN/sequence identity through the tunnel.
   Denial of proxy ownership is not a firewall denial and must not be labelled
   blocked application traffic.
5. Start IPv4/IPv6 B-to-A connections on port 24451. They remain transparent
   because this profile has one originator; owner counts stay at two. Require
   exact payload/EOF and captured original handshake identity, documenting the
   role limitation rather than treating reverse ownership as implemented.
6. After applications have exact bytes and EOF, submit DrainProxy on both
   private sockets promptly, without waiting for the first terminal result
   before submitting the second. Accepted/already_accepted is submission only.
   Poll real terminal status during the finite local-only grace and retain both
   exact close reports. Require clean_flows=2, stopped_flows=0, one/two original
   physical TLS lanes closed for full/half, and cross-peer user-record and
   transparent/native packet equalities. Both processes must exit successfully.
   Any timeout/reset/stopped flow is a failed clean gate, even with exact prior
   application bytes. Do not replace a real runtime result with a killed process.

Each probe uses fixed per-case/family/purpose source ports, avoiding accidental
tuple reuse or lifetime tombstones; full and half use fresh namespaces. The
receipt separately records application EOF, native FIN, proxy retirement and
whole-session TLS closure. None implies application consumption beyond the
explicit probe readers.

## Deadlines, budgets and evidence

Freeze these bounds before implementation; retries cannot restart them:

| Stage | Absolute bound |
| --- | --- |
| Case including setup and all traffic, before emergency cleanup | 300 seconds |
| Each external setup command | remaining case bound, capped at 15 seconds |
| CLI authentication factory | existing 30-second original full/half bound |
| Both peers Forwarding after launch | 40 seconds, within case bound |
| Each concurrent transfer pair, including both FIN/EOF results | 30 seconds |
| Probe socket inactivity and sender join | 5 seconds, within original transfer bound |
| Each individual ICMP invocation | 5 seconds |
| Local RPC read/write/reply | 2 seconds and 8,192 response bytes |
| Both drain submissions plus terminal results and CLI exits | 127 seconds from first submission, within case bound |
| Runtime network drain | unchanged 120-second original deadline |
| CLI status-only grace after runtime result | unchanged 5 seconds |
| Emergency child cleanup | terminate 5 seconds, then kill 5 seconds; explicitly abnormal |
| Journal-owned namespace cleanup after child cleanup | separate 30-second absolute bound |

The 127-second harness observation bound includes runtime 120 seconds, local-only
grace 5 seconds and 2 seconds of polling/process scheduling; it grants no additional
runtime network time. Local RPCs use the smaller remaining stage/case bound.
The harness temporarily supplies the unchanged journal's command runner with
the original setup deadline, restores it even on failure, and uses a separate
finite cleanup deadline only after stopping retained children. This does not
extend authentication, transfer or network drain. Partial setup that cannot
prove cleanup remains failed evidence for inspection.
Status polling is bounded to one query per peer per 100 ms and retains at most
2,048 samples per case; diagnostics are never sent on a privileged user path.

Limit each capture to 8,192 packets and 32 MiB, each decoded IP packet to 65,535
bytes, each textual log to 4 MiB and each atomic JSON receipt to 4 MiB. Stop capture
on approaching its cap and fail the evidence gate; do not truncate and claim
complete coverage. Require complete capture records, supported link type,
zero tcpdump kernel drops and no capture-limit exhaustion. Audit full-IP
lengths against MTU 1500, checksums, TCP tuples/flags/sequence spaces, initial
SYN/SYN-ACK and both FIN boundaries. Unknown IP extension/fragment or capture
format is explicit unsupported evidence; do not infer a split from a truncated
or unparsable frame. The underlay capture/`ss` must show exactly the authenticated
one/two TCP carrier tuples between the owned endpoint addresses and no direct
native tuple on wan0. TLS payloads remain opaque; no keys are logged or exported.

Receipts distinguish `passed`, `failed`, `bound_exhausted`, `unsupported`, and
`tool_failure`, along with the last completed stage and original timestamps.
Preserve failed artifacts and exact binary/source digests. Stop only retained
child process objects, confirm owned namespaces have no remaining PIDs, and use
the existing device/inode manifest cleanup. Verify all owned namespaces and
private sockets are absent afterward. A cleanup failure prevents overall pass.
No arbitrary-loss tolerance, throughput improvement, adaptive-window behavior,
GUI, non-Linux device or full Python catalog claim follows from this clean gate.

## Acceptance checklist

- [x] [MOD-PROXYNATIVE-01] Review and freeze exact topology, profile, bounds and split/bypass/closure evidence before implementation. Evidence: [frozen contract](proxy-native.md), reviewed before implementation with unchanged clean/default-policy deadlines and distinct split versus bypass acceptance.
- [x] [MOD-PROXYNATIVE-02] Implement dry-run-first journal-owned harness, bounded internal kernel probe, immutable binary/source evidence and cleanup; unit-test strict validators and failure paths. Evidence: [harness](../../tools/proxy_native_smoke.py), [17 focused tests](../../tools/test_proxy_native_smoke.py), `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.test_proxy_native_smoke -v` passed, including real IPv4/IPv6 ordinary loopback helpers; native outcome remains separately gated.
- [x] [MOD-PROXYNATIVE-03] Qualify clean full duplex: actual IPv4/IPv6 split flows, transparent ICMP/route denial/reverse origination, exact bidirectional bytes/FIN and actual peer closure. Evidence: [full receipt](../../work/native-proxy-full-underlayipv4/receipt.json), [stage/capture/closure evidence](../../work/native-proxy-full-underlayipv4/tun-full-clean/receipt.json), [original stable binary build](../../work/native-proxy-full-build/receipt.json); exact original binary retained, fixed credit and maintained TIME-WAIT unchanged.
- [x] [MOD-PROXYNATIVE-04] Qualify the same clean paired-half gate with two original authenticated physical lanes and no scope/role substitution. Evidence: [half receipt](../../work/native-proxy-half-clean/receipt.json), [exact captures and two-lane closure](../../work/native-proxy-half-clean/tun-half-clean/receipt.json); same immutable original binary and strict clean/default policy.
- [x] [MOD-PROXYNATIVE-05] Independently audit native/underlay captures, all exact counters, source hashes, original deadlines and namespace/socket cleanup before promoting native status. Evidence: [integrator audit](../../work/native-proxy-clean-audit.json), which re-read both captures, exact transfers/fences, build and harness identities, and owned cleanup.
- [x] [MOD-PROXYNATIVE-06] Complete strict harness checks, independent review and coordinated source-stable workspace aggregate; retain clean-only limits. Evidence: [stable wave9 aggregate](../../work/implementation-wave9/validation.json), including all 17 proxy harness tests; the two native receipts remain separately scoped.
- [ ] [MOD-PROXYNATIVE-07] Design separate impaired, bounded-failure and measured adaptive target gates without weakening this frozen baseline.

## Recorded native observations

The [first full attempt](../../work/native-proxy-full-clean/tun-full-clean/receipt.json)
is preserved as `unsupported`, with successful cleanup. Its application transfers
and exact terminal reports completed, but the full capture parser rejected
IPv6 Hop-by-Hop MLDv2 traffic on the physical IPv4 underlay. It is not a passing
qualification receipt. The subsequent scoped interface setup adjustment above
did not change native IPv6, TCP options, runtime behavior or acceptance rules.

The [fresh full rerun](../../work/native-proxy-full-underlayipv4/tun-full-clean/receipt.json)
passed in 8.37 seconds including cleanup. The two proxied IPv4/IPv6 flows have
different native SYN and SYN-ACK sequence spaces on the two TUN surfaces; the
four denied/reverse flows preserve their original SYN bytes. All six flows have
both FIN directions, no RST, exact bidirectional 65,537/32,771-byte application
payloads and EOF. Both actual runtime reports contain two clean and zero stopped
owners, one closed original TLS lane, complementary 371/368 user-record counts
and 238/243 transparent/native-delivery counts. All four captures have maximum
whole-IP length 1500, no truncation and zero tcpdump kernel drops; WAN captures
contain exactly one matching carrier tuple and no direct native tuple.

Both attempts use binary SHA-256
`e9cf5bf6b3d535c8d0d58c6c9b4021b40b3c55ddd1afe685fc502ad9d0e044b9`
from the [source-stable build](../../work/native-proxy-full-build/receipt.json).
The successful rerun records that original build source map separately from
later workspace observations, plus the updated harness and saved policy hashes.
The [fresh paired-half case](../../work/native-proxy-half-clean/tun-half-clean/receipt.json)
also passed, in 8.51 seconds including cleanup, with that same binary and harness.
It satisfies the same six-flow/twelve-endpoint probes and exact SYN/FIN rules.
Both reports contain two clean and zero stopped owners, two closed original TLS
lanes, 369 user records per direction and complementary 235/241 native counts.
Both WAN captures contain the same two physical carrier tuples; all four IP
maxima are 1500 and capture kernel drops are zero. Only the clean full/half scope
is qualified; impairment, adaptive windows and throughput remain unqualified.
