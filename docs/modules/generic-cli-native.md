# Generic CLI native functional qualification

Status: **harness implemented and locally tooling-tested; native acceptance unqualified**.
This module adds finite production CLI/native acceptance to the complete-plan
frontend. It does not replace or narrow GCL-04/06/07, GCS-09, the complete native
matrix or the unchanged80Mbit/s performance gate. Existing simulator experiments,
performance harnesses and receipts remain intact. Engineering choices below are
not owner decisions. Root owns all execution, integration, evidence and Git.

## Exact scope and implementation ownership

New `tools/generic_cli_native.py` is dry-run by default and requires explicit
`--apply --binary PATH --build-receipt PATH --output FRESH_DIRECTORY` to launch.
It accepts one explicit `--cover quic-like|media-like --layer tap|tun --lab-id ID`
case per invocation. Root runs the four-case Cartesian product from one immutable
built binary and one combined tooling validation batch. The new runner launches
the production binary's actual connect/serve plan path and real Linux TunTap.
UnixDatagram devices, old policy flags, another carrier or legacy backend are
never fallback paths. No throughput/bulk/perf/runtime-model experiment is run.

Exclusive worker ownership: this module and new `tools/generic_cli_native.py`,
`tools/test_generic_cli_native.py`. Existing helpers are reused read-only.
`secure_udp_native.run_case` is not called: it unconditionally runs v2 policy and
bulk/performance acceptance. No existing performance harness or receipt changes.

Reuse the current namespace identity/proof, credential, cover-shape and owned
group termination helpers from secure_udp_native, bounded command/build/Receipt
and checksum helpers from proxy_native_smoke, actual UDP/ICMP probe children,
and journal/inode checked netns_lab apply/cleanup. Hash and snapshot every loaded
helper, including their transitive local imports. The new short launcher retains
the existing FD-anchored fresh user/net/mount and copied-worker protocol; no
mutable monkeypatch of old native policies is used.

## Frozen Python seams

The new module exports these internal harness/test seams, with no Rust API change:

```python
plan(lab_id: str, cover: str, layer: str) -> dict
transaction_plan(layer: str) -> dict
daemon_command(case: dict, side: str, binary: Path, secrets: Path,
               plan_file: Path, inspection: bool = False) -> list[str]
validate_inspection(value: dict, case: dict, side: str, public: dict) -> dict
validate_status(response: dict, case: dict, side: str, public: dict,
                inspected: dict, canonical: str, epoch: int,
                running: bool = True) -> dict
audit_capture(path: Path, case: dict, surface: str,
              epoch_mtus: dict[int, int]) -> dict
run_case(case: dict, output: Path, build: dict, proof: dict) -> dict
launch_isolated(case: dict, output: Path, binary: Path,
                build_receipt: Path) -> int
```

Input validation rejects unsupported/ambiguous covers, layers, roles, paths,
identity/digest/C values and malformed status. All commands are argv vectors.
Canonical C values and H0/E/K/D0 come from actual CLI inspection, not a Python
encoder or approximate SwiftPolicyV1 conversion. Independently check every
physical D(C), including the target, with standard SHA-256 over the exact
`b'l2tunnel/swift-transaction-config/v1\0'` domain followed by those304 bytes.
This mirrors `transaction::configuration_digest` and the Swift Configuration
domain; reuse its existing literal Rust wire/digest vector in the focused test.
The actual CLI remains the canonical decoder. Own-trust inputs remain manual
fresh lab files generated using the existing maintained-crypto helper.

## Test catalog and native topology

Two exact descriptors exercise1500→1400→1500 outer IP MTUs and asymmetric widths
2/3→4/1→2/3, odd byte rates1250001/625013→1375007/575011, exact1/3 and2/7 repair
fractions, directional windows7/11 and datagrams1200/1024→1280/1100. Preserve all
sixteen directional values. This finite catalog does not qualify full64 native
resource/fault acceptance. TAP uses ethernet/max_native1600/max_packet1601; TUN
uses ip/1500/1501, with the current1-byte Swift expansion. Every runtime field is
explicit in version1 JSON. The actual Profile validates both roles/all members.

Runtime test bounds are a64MiB retained budget,64 flow sources,8192-byte packing
queues,64 native pending packets,256-byte/32-record base control, explicit three
streams,1500ms transaction cap,300s session lease,100ms Ping,5s Pong timeout and
100ms local reports. These are lab inputs, not product defaults. Cadence is local
and excluded from peer identity; null-cadence behavior retains separate evidence.

Each case uses a fresh outer user/network/mount namespace, verifies anchored
namespace FDs and pristine loopback-only networking, makes mounts recursively
private and mounts a fresh /run before creating five journaled lab namespaces.
TAP uses the existing bridge/tap0 and host_a/host_b at198.18.0.1/.2. TUN follows
the existing proxy-native endpoint topology with tun0 and198.19.0.1/.2; unused
TAP/bridge/host links are down. Record this as endpoint-originated TUN evidence,
not independent forwarded hosts. Confirm actual selected device and daemon FD
ownership. No device fallback or modification of host routes, bridges, sysctls
or qdiscs.

This finite functional matrix carries IPv4 payloads only. After all owned native
links exist and before capture startup, enumerate actual links in endpoint_a,
endpoint_b, host_a and host_b. In each of those four owned namespaces, read the
IPv6 all/default/every observed interface disable keys in one bounded sysctl
command, write all.disable_ipv6=1 and default.disable_ipv6=1 in one command, then
read the identical complete key set and require every value to be1. Require the
selected tap0 or actual tun0 in each endpoint inventory and retain link names,
before values, write results and verified after values in the case receipt.
No router-namespace or launcher-host sysctl is part of this helper. The broad
ip/ip6/arp capture filter and strict rejection of unexpected IPv6 stay unchanged; these controls
prevent DAD/MLD from invalidating an explicitly IPv4-only observation. They do not
waive any IPv6 native, carrier or platform gate. Four link observations and twelve
sysctl commands consume the existing256-command budget without increasing it.
The source-count one-read polling path records127 Owner commands for TAP and143
for TUN, including the new16; further bind/commit/liveness polls consume the
remaining129/113 slots and fail at the unchanged ceiling. Reused fixed-topology,
offload, underlay and credential helpers retain their own bounded command loops;
the256 ceiling applies to this Owner's recorded command observations.

Keep WAN192.0.2.2:24440↔192.0.2.6:24440, owned100/10Mbit/s shaping and explicit
clean0ms/0% path. Only after journal/inode checks recreate owned WAN qdiscs before
daemons. Clean functional acceptance does not qualify impairment or performance.

## Required native sequence

1. Verify source-stable build and helper hashes; copy immutable binary/helpers
   into a fresh0700 output. Start both WAN and native captures before daemons.
2. Inspect the exact plan in both actual CLI roles using existing credentials;
   require matching H0/E/K/D0, full two-member catalog and unauthenticated labels.
3. Launch separate production serve/connect processes with the explicit selected
   cover, Swift/full/off, native device and complete plan; no old mutable flags.
   Require actual generic ready events and external v3 status with expected public
   pins/member/session, exact C0/current/physical scope and complementary roles.
   Require the actual service phase to be the string forwarding while running
   and disconnected for the retained Aborted terminal overlay; an idle transaction
   phase alone does not establish the service lifecycle.
4. Run simultaneous finite bidirectional application UDP probes using14 distinct
   source sockets, lengths0/1/18/64/512/1200/1472, zero/nonzero/trailing-zero data,
   exact hashes and full-MTU DF ICMP fingerprints. Each phase retains actual byte
   results. This is not every native hash-channel or performance qualification.
5. Switch once to the inspected target C, then once back to C0 through actual
   external APIv3. Require coordinator completion and follower idle/current/
   physical scope at consecutive epochs, exact directions and unchanged session/
   H0/original socket pair. Repeat exact bidirectional probes under each C.
6. Require actual observed fresh fixed-control Pong and one connected UDP pair,
   with no TCP bootstrap/second data flow. Wrong v1/v2 requests must leave actual
   generation/session/configuration/device ownership unchanged.
7. Disconnect both via external v3; require actual Aborted terminal/running=false,
   released UDP and TunTap FDs, retained final status and bounded terminal output.
   Reconnect concurrently from the retained plan, require fresh generation/Noise
   session/transcript, original endpoint pair and initial C/epoch, then repeat
   bytes/liveness. Finish with actual disconnect before process cleanup.

## Capture, deadline, failure and cleanup contract

Four full captures use2048-byte snapshots,4096 packets and8MiB per file. A new
small bounded pcap/link/IP/UDP iterator follows the existing checked extent rules;
the proxy reader cannot be reused wholesale because it rejects UDP. Native
link types are Ethernet1, RAW101, SLL113 or SLL2-276, with checked extents and no
truncation. WAN validates source/destination/ports, IP checksum/extent, no outer
fragmentation/TCP, selected cover/record shape and observed User epochs under the
accepted1500/1400/1500 map. Native captures retain exact probe fingerprints; TAP
requires ARP, TUN does not. Capture counters must be final/nonempty/lossless and
below ceilings. These are header/shape and finite endpoint-byte claims, not full
standard-protocol validity, interoperability, identification resistance or ISP QoS.
An ICMP port-unreachable packet racing an actual close is retained separately
only after validating its checksum and quoted original UDP endpoints/ports;
another underlay transport or an unvalidated error is rejected. Complete known
native fingerprints must be present before capture writers are interrupted.

Use original240s case,35s startup/reconnect,15s command,30s cleanup and300s launcher
caps;1MiB child logs,256 command/status observations, bounded receipt and four
capture ceilings. Retries consume original caps. Outcomes distinguish failed,
bound_exhausted, tool_failure and unsupported; no missing tool/capability becomes
a skip/pass. Partial/final errors retain structured terminal receipts.

Propagate each original startup, configuration, liveness and functional-phase
deadline through nested command/RPC/status waits and recheck it before publishing
phase success. A command cannot replace an earlier phase cap with the full case
cap. Each finite functional phase retains one35s cap covering readiness, its
original5s/12s/17s substage caps and residual child stop. Normal residual functional
children stop within their original phase cap;
they do not start overall cleanup merely because a successful phase has ended.
On failure or actual case teardown, retain one cleanup deadline of at most30s
and reuse it for every recorded child, capture and topology release. Wait errors
cannot append an independent helper stop timeout or restart cleanup in finally.

Fresh private credentials and control sockets live in a0700 temporary directory
under the verified private /run tmpfs, created only after the copied worker has
proved its mount namespace and mounted /run. No credential path is created in
the launcher's host /tmp. The short /run directory prefix keeps Unix socket paths
bounded. Ordinary cleanup removes the directory; forced worker/group termination
also releases the private mount namespace instead of leaving host credential
files behind. Public credential observations remain non-secret receipt fields.

Before topology mutation, require ip/tc/ss/tcpdump/mount/sysctl/ethtool and import
the maintained cryptography X25519/Raw serialization APIs used by the existing
credential helper. A missing executable, cryptography module or import is a
tool_failure; missing native or isolation capabilities remain unsupported.

Finally stop only recorded process groups, drain/stop captures, await children,
preserve stopped capture counters and invoke journal/inode-checked cleanup.
Check no owned namespace handles/PIDs/control sockets remain and recheck original
launcher namespace identities. Incomplete cleanup fails explicitly. Never adopt
existing directories/namespaces or discover host processes by name for cleanup.

## Stable acceptance leaves

- [x] [GCN-01] Freeze this complete scope/API/ownership/bounds before source edits. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [x] [GCN-02] Implement deterministic dry-run/plan/command/schema/status handling with full exact C/identity/native/error validation and side-effect-free tests. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [ ] [GCN-03] Implement verified copied-worker fresh namespace launch and journaled
  topology, source/helper/binary provenance and all partial-failure cleanup paths.
- [ ] [GCN-04] Implement actual production generic connect/serve, external v3
  status/two-switch/byte/liveness/disconnect/reconnect sequence for both layers.
- [ ] [GCN-05] Implement complete bounded WAN/native capture/audit and truthful
  failure/unsupported/ceiling/cleanup evidence; preserve every failed attempt.
- [x] [GCN-06] Pass focused tooling/failure checks and the required source-stable aggregate on the combined batch; no native claim from mocks or dry runs. Evidence: [source-stable combined checks](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json); finite local scope and remaining gates are described below.
- [ ] [GCN-07] Pass immutable Linux quic-like and media-like TAP functional cases
  with every stated actual CLI/socket/device/byte/control/capture/cleanup criterion.
- [ ] [GCN-08] Pass the corresponding two actual TUN functional cases, explicitly
  recording endpoint-originated topology and real TUN device evidence.

Leaf success closes only its literal deliverable. GCL-04/06/07/GCS-09 retain their
complete selection/failure/external compatibility definitions. Full GCS-06,
native impairment/resource/fault matrices,80Mbit/s, retained recovery/fresh DH,
SW-11, all47 modes, other carriers, GUI/platform and ISP requirements remain.

## Executed finite attempts and remaining acceptance

The [combined tooling/workspace baseline](../../work/generic-functionality-20261114-batch2/aggregate-attempt-3/validation.json)
passes, including30 focused generic harness tests. The actual four-case native
matrix was run with2 concurrent isolated cases from the same retained debug
binary. No additional Cargo build or performance workload was launched.

[Attempt1](../../work/generic-functionality-20261114-batch2/native-matrix-attempt-1/matrix-receipt.json)
failed UID-map setup before topology. [Attempt2](../../work/generic-functionality-20261114-batch2/native-matrix-attempt-2/matrix-receipt.json)
used existing sudo authority but the root-only child mapping could not traverse
the owner's home directory. [Attempt3](../../work/generic-functionality-20261114-batch2/native-matrix-attempt-3/matrix-receipt.json)
ran verified immutable copies in a private root-owned temporary directory,
then archived them after every launcher returned. All four actual case cleanup
checks passed; all four functional acceptance gates remain unqualified.

QUIC-like/TUN completed the initial bidirectional14-source UDP byte probes and
full-MTU ICMP probes. Its first switch exposed the production completion reply
phase defect documented in [shared service](generic-client-service.md); the
switch itself reached actual epoch2, but the strict reply contract failed.
The focused service repair is tested, not native requalified. The other cases
exhausted topology/capture/stage bounds, including an ip link lo-up command's
original15s bound before daemon startup. These observations do not establish a
kernel/scheduling cause or a tunnel throughput result. Caps remain unchanged.
Do not repeat the full suite or widen caps to obtain a green native receipt.
Stage native setup separately from independent payload checks after diagnosing
its actual shared-resource/launch latency; retain all failed captures and logs.
