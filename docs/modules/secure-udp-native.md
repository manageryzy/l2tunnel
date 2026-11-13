# Source-pinned secure UDP native lab

Status: **tooling implemented and focused-tested; native execution pending**,
2026-11-13.
The design below was recorded and reviewed before implementation. This finite Linux
TAP laboratory refines FIX-04/FIX-13, SW-14/SW-15 and the shared service/runtime
ledgers. It preserves every simulator experiment and historical native receipt.
It does not qualify full SW-11, automatic retained-state recovery, OpenVPN wire
handshakes, the original raw HTTPS path, Windows/Android or ISP classification.
No existing SNL-* namespace was present when this contract was recorded.

## Frozen harness interface

```text
python3 tools/secure_udp_native.py
    --cover quic-like|media-like
    --path clean|delay|loss1|impaired
    --workload forward16|reverse-stress
    --output FRESH_DIRECTORY
    --binary IMMUTABLE_BINARY
    [--build-receipt SOURCE_STABLE_JSON]
    [--lab-id LABEL]
    [--apply]
```

Default execution prints a deterministic JSON plan without reading the binary,
creating output, generating credentials, opening sockets or mutating namespaces.
`--apply` is required for a case. The parent integrator owns the build, source
snapshot and native execution; writing this harness does not execute a lab.
One invocation performs one cover/path/workload. The matched matrix is both
covers across clean, delay, actual 1% loss and actual 15% loss. Reverse bulk is a
separate stress invocation and never substitutes for forward TCP with ACK return.

Apply requires the existing successful build-receipt contract: exit status zero,
stable equal before/after source hash maps, an empty changed-input list and an
exact binary SHA-256. Required helper hashes cover this new harness/probe and
the unchanged reused netns_lab, proxy_native_smoke, native_throughput,
proxy_measured_native_smoke and throughput_probe modules. The launcher copies
and verifies them and the binary/receipt into a fresh exclusive directory, then
executes only those verified copies. Receipt provenance never comes from a later
mutable working tree.

## Namespace and subprocess safety

Every apply, including root execution, launches through a new user, network and
mount namespace. Retained original namespace descriptors anchor identity checks;
all three current namespace identities must differ before topology work. The new
network namespace must initially contain only loopback and no route. Mount
propagation becomes private before mounting a fresh tmpfs over /run. Existing
host routes, bridges, interfaces, qdiscs and /run/netns are never adopted.

The harness reuses netns_lab's five owned namespaces, deterministic veth/TAP/bridge
topology, ownership journal and inode-checked cleanup. It reuses bounded command,
process and immutable-receipt helpers rather than changing their historical
behavior. All shaping and offload operations name only those freshly journaled
namespaces. Partial setup is cleaned only through its validated ownership record.
Children, captures, probes, logs, samples, packets and complete cases have explicit
bounds. Startup ICMP observations remain in the capture rather than becoming a
false tool-format error. Policy-status polling tolerates bounded asynchronous
peer epoch observations while still requiring immutable bindings and eventual
exact aligned commits. Parent timeout cleanup targets its own child process group; remaining
owned-process/namespace cleanup errors are recorded as failures. A launcher
timeout finalizes a running worker receipt without discarding its evidence and
marks cleanup unverified; leader exit alone never proves descendant exit.

## Explicit credentials and selected CLI

Each case generates independent fresh X25519 keys through Python cryptography's
public X25519/Raw serialization APIs, records its version/API preflight, and uses
the immutable binary's existing keygen command for ring-generated Ed25519 PKCS#8.
Fresh admission/cookie and optional IKpsk2 material come from the OS CSPRNG.
There is no hand-written DER or crypto implementation. Private inputs are
exclusive owner-only 0600 regular files in a temporary 0700 directory. Receipts
contain public identities, tool versions and credential roles, never private
bytes. No certificate, TLS exporter or second TCP control connection is created.

The frozen implementation-draft CLI explicitly selects connect/serve, carrier
quic-like/media-like, record-profile swift, full duplex, compression off, TAP,
the fixed UDP bind/peer pair, Noise profile and raw32 private/pin/admission/cookie
files. Connect uses the existing member PKCS#8 and serve its raw32 public key.
Local status, set-swift, disconnect and reconnect explicitly use API version 2.
The harness checks real running state, public pins/member/session/configuration,
requested/effective policy, generation, original endpoints and capability limits.
Authentication alone cannot satisfy native readiness.

## Functional, policy and lifecycle phases

The same selected carrier must deliver ARP, complete MTU-sized IPv4 DF pings,
arbitrary UDP payloads including all zeros and real trailing zeros, and exact
TCP counts/SHA-256/EOF in both directions. TCP payload integrity and post-window
drain are separate from goodput. The application probe retains one original
connection/transfer deadline and bounded socket count; byte-ceiling exhaustion
cannot become successful performance evidence.

A separate loaded policy phase changes and restores the supported Swift policy
through actual API-v2 set-swift. It requires committed matching effective values,
increased policy epochs, continuing counters and exact concurrent traffic. It is
not included in the stable reference throughput window. Policy transactions are
within Swift; no cross-profile SW-11 claim follows.

Manual lifecycle checks disconnect both owners, verify local stopped state, then
reconnect both concurrently. They require new matching cryptographic sessions
and increased generations while retaining the configured UDP five-tuple. The
new session is explicitly fresh; no retained-state continuation, automatic
restart, graceful peer drain or uncertain-commit rollback is inferred.

## Matched measurement and capture definitions

The matched workload has sixteen forward kernel TCP CUBIC flows and ACK return,
100/10 Mbit/s IP-byte HTB, 35 ms one-way delay on the delayed paths, and independent
per-direction netem loss of 0%, 1% or 15%. Clean uses 1 ms one-way delay. TAP keeps
kernel TCP ownership. The selected inner route minimum RTO is explicitly recorded.
Each stable run has 5 s warm-up and a 20 s shared monotonic measurement window,
with bounded post-window drain. Reverse stress enables simultaneous reverse bulk
and is labeled separately.

The new probe reuses throughput_probe's payload/TCP_INFO observation definitions;
it adds the sixteen-flow and one-way-send behavior absent from the older 1/2/4-flow
always-duplex helper. Unique application bytes returned by recv during the same
window define goodput. Complete per-flow sent/received counts, hashes, EOF, actual
kernel TCP observations and process usage are retained. Probe getrusage is
reported separately from the tunnel daemons. Each periodic status sample reads
only the exact launched daemon PID, checks it has not exited and brackets its
bounded /proc/stat and /proc/status observations with unchanged start time.
Raw user/system CPU ticks, their SC_CLK_TCK units, stat resident-page units,
VmRSS and VmHWM KiB are retained. A reused PID, exit, malformed field or oversized
read prevents resource qualification. Host logical/allowed CPU counts, machine,
kernel and load averages describe shared CPU conditions; namespaces do not
reserve CPUs. CPU deltas describe the actual sampled interval and are not
silently relabeled as an exact throughput-window measurement. The 80 Mbit/s forward
target comes from the existing FIX-04/native qualification requirement; it is a
lab target, not a new owner decision or an ISP promise. Measurements below it
remain visible failures. Historical simulator ratios are not reused because the
new cover/protection overhead differs.

WAN capture starts before either daemon and includes all IP traffic rather than
filtering only the expected UDP port. Header snapshots deliberately retain enough
bytes for Ethernet/IP/UDP, cover and routing headers; payload integrity comes from
the endpoint probes. Packet counts, original IP lengths, timestamp precision,
capture limits and capture-kernel drops are checked. Parsed complete packet
records must exactly match tcpdump's final captured counter. The audit requires the
configured original UDP pair and both handshake/data phases, with no TCP
bootstrap or outer fragmentation. Genuine ICMP destination-unreachable path
errors are counted separately only when they quote that exact original UDP
tuple; unknown transports or quotes fail. Canonical one/two-byte QUIC-like
length fields are checked against the actual protected extent. Visible User
epochs must satisfy the pinned workload mapping (1:1500, 2:1400, 3:1500), and
all three must appear in each WAN capture across the loaded policy phase. This visible route is
authenticated by endpoint record processing; the capture itself cannot verify
the AEAD tag. User/Control require the exact common AEAD prefix and minimum
extent; Control stays at epoch1; Joining has direction-correct proof/acceptance
extents. Admission and bootstrap ARQ public headers/lengths/roles are checked
without claiming MAC or Noise verification from truncated capture.
Appearance/header checks are not full QUIC/WebRTC protocol validity or resistance
to identification. Source-pinned native socket observations and captures supply
complementary continuity evidence.

IP wire cost uses original captured IP lengths over the same monotonic window,
with a real/monotonic clock anchor and explicit timestamp uncertainty. Interface,
HTB and netem counters are recorded separately; sender socket acceptance, qdisc
drops, captured link packets and delivered application bytes are not conflated.
Capture loss, truncation outside the declared snapshot, unsupported tool output
or finite-bound exhaustion prevents qualification.

## Results and acceptance

Each fresh output preserves its source/binary/helper identity, exact command
vectors, namespace identities/journal, selected policies, status samples, clock,
captures, tool versions, native payload results, rates and cleanup. Outcomes
separate passed, failed, bound_exhausted and tool_failure. Negative native or
tooling results never overwrite historical receipts or become skipped success.

- [x] [SNL-01] Record/review the explicit CLI/status/build interface, fresh namespace proof, workloads, measurement/capture semantics and finite bounds before implementation. Evidence: this pre-implementation design, integrator review and the [implemented public interface](../../tools/secure_udp_native.py).
- [ ] [SNL-02] Implement dry-run-by-default planning and source-pinned copied-helper/binary execution with fresh user/network/mount verification and owned cleanup. Partial evidence: [launcher/worker](../../tools/secure_udp_native.py) and [passing ownership, hash, dry-run and interrupted-receipt tooling tests](../../tools/test_secure_udp_native.py); actual isolated apply/cleanup remains unexecuted by this harness.
- [ ] [SNL-03] Implement maintained fresh credential generation, exact selected CLI/API-v2 observations and no TLS/TCP bootstrap substitution. Partial evidence: [maintained X25519/Raw and existing binary keygen composition](../../tools/secure_udp_native.py), strict CLI/status fixtures; actual credential/bootstrap/native observations remain part of the apply gate.
- [x] [SNL-04] Verify sixteen-flow forward-only and distinct duplex stress probes with exact bytes/hash/EOF, common-window accounting and meaningful bound/error tests. Evidence: [probe](../../tools/secure_udp_native_probe.py), [ordinary sixteen-flow TCP and exact UDP loopback, accounting and original-deadline regressions](../../tools/test_secure_udp_native.py), and the [26-test focused passing receipt](../../work/secure-udp-native-tooling-focused-20261113/attempt-3/validation.json). This is tooling/ordinary-loopback evidence, not a TAP throughput result.
- [ ] [SNL-05] Implement and test complete-MTU/ARP/zero-payload checks, real under-load policy changes and fresh manual reconnect observations without claiming SW-11 or automatic recovery.
- [x] [SNL-06] Verify bounded all-IP capture parsing, original tuple/phase/MTU/fragment checks, same-window IP cost and nonzero capture-loss rejection. Evidence: [streaming capture/parser and final counters](../../tools/secure_udp_native.py), [both-cover, policy-epoch, role/extent, ICMP, truncation, exact-counter, checksum, fragment, resource and common-window fixtures](../../tools/test_secure_udp_native.py), and the [source-stable focused result](../../work/secure-udp-native-tooling-focused-20261113/attempt-3/validation.json). Capture of actual native traffic remains SNL-08.
- [x] [SNL-07] Pass focused tooling checks and the source-stable required aggregate, retaining failed attempts and exact provenance. Evidence: the [required source-stable aggregate](../../work/secure-udp-runtime-service-20261113/attempt-1/validation.json) passed all local workspace checks with 1487 Rust cases including doctests, 271 Python tooling cases and 1658 simulator cases; formatting, strict workspace Clippy and rustdoc passed, and before/after input hashes match. The 26-test tooling receipt is retained separately from actual native execution and performance gates SNL-08..SNL-10.
- [ ] [SNL-08] Execute both appearances on clean/delay/1%/15% matched sixteen-flow ACK-return paths with immutable binary/helpers; retain exact integrity, policy/lifecycle and capture outcomes.
- [ ] [SNL-09] Meet the existing 80 Mbit/s forward lab target on the matched impaired composition; retain honest timing, overhead, CPU/resource and negative results.
- [ ] [SNL-10] Execute separate reverse-bulk stress and document its limits independently from matched reference, native-device scope and all remaining platform/ISP gates.

The parent-owned [final focused receipt](../../work/secure-udp-native-tooling-focused-20261113/attempt-3/validation.json)
records 26 passing tests, exact commands, unchanged before/after hashes for the
executed tooling/helper inputs and a saved log digest. Its explicit scope is
fake namespace/capture acceptance, daemon resource parser/identity/exit/size
regressions and ordinary TCP/UDP loopback; no TAP or privileged native case ran.
Actual daemon CPU/RSS and distinct probe usage are instrumented, not yet native
measurements. The earlier [20-test](../../work/secure-udp-native-tooling-focused-20261113/attempt-1/validation.json)
and [23-test](../../work/secure-udp-native-tooling-focused-20261113/attempt-2/validation.json)
snapshots remain preserved. This evidence-only documentation reconciliation
follows those checks. The required aggregate subsequently passed as recorded
under SNL-07; final evidence-only edits are reconciled against its unchanged
non-document inputs.

Source, dry-run and synthetic tooling tests alone do
not qualify native performance. Only the parent integrator executes --apply after
its immutable build and source checks.
