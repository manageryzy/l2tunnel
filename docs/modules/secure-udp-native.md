# Source-pinned secure UDP native lab

Status: **tooling implemented and focused-tested; native qualification pending**,
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

## Owned shaping recreation after the first native attempt

The [first native launcher attempt](../../work/secure-udp-native-20261113/quic-clean-attempt-1/receipt.json)
could not read its workspace-private path from inside the new user namespace. The parent preserved that failure and retried
from an explicit accessible /tmp snapshot. The [second attempt](../../work/secure-udp-native-20261113/quic-clean-attempt-2/receipt.json) proved fresh
user/network/mount isolation and created the journaled topology, then failed
before either daemon: changing the existing HTB root to install a new size table
returned `Change operation not supported by specified qdisc`. Owned cleanup
passed. Neither attempt is a payload or throughput result.

The reviewed correction preserves the exact requested IP-byte accounting. Before
code changes, its recorded contract is: retain the original netns_lab topology and acquire
its existing private journal lock; load/validate the manifest; require all five
created namespace identities and no existing endpoint processes; accept only the
known wan0 root HTB handle1: and child netem handle10: at parent1:10. Recheck the
namespace identity immediately before deleting only that owned wan0 root. Add a
fresh root with the original STAB overhead-14, class100/10Mbit and selected netem
delay/loss, then verify and preserve its structural observation. An unexpected
qdisc, replaced/missing namespace or active process is a refusal, never permission
to adopt or modify it. No host qdisc or old helper is changed, and no fallback
silently changes the accounting definition. A partial recreation failure follows
the same journaled namespace cleanup path and remains a failed receipt.

## Worker file-size limit correction after the third native attempt

The [third parent-run native attempt](../../work/secure-udp-native-20261113/quic-clean-attempt-3/receipt.json) reached capture launch, then failed with
`SubprocessError: Exception occurred in preexec_fn`; owned cleanup passed. The
worker had inherited a4MiB soft and hard RLIMIT_FSIZE from the launcher, while its
capture child requested the explicit256MiB cap. A child in the nested user
namespace cannot raise that initial-owner hard limit; an unrestricted initial
root reproduction does not establish its feasibility. The parent preserved the [failed third attempt](../../work/secure-udp-native-20261113/quic-clean-attempt-3/receipt.json)
with passed cleanup independently from this correction.

Before implementation, the reviewed correction is: require the launcher's
inherited RLIMIT_FSIZE hard ceiling to permit256MiB; otherwise refuse explicitly
before spawning the isolated worker. Give that owned worker a4MiB soft limit and
256MiB hard ceiling. Its own log remains capped at4MiB, while capture children
may select their existing explicit256MiB soft/hard ceiling without raising the
inherited hard limit. Other children retain their explicit smaller caps. Do not
change any host limit, reused helper, capture allocation or original time bound.
Validate actual limits across real nested subprocesses and reject an insufficient
inherited ceiling; native namespace validation remains parent-owned. The parent's actual
[fresh-namespace limit/capture preflight](../../work/secure-udp-native-preflight-20261113/file-limit-and-capture.json)
reproduces the insufficient inherited ceiling and default tcpdump ownership
failure, and observes successful listening with `-Z root`, while preserving the
launcher identities. It is separate from an end-to-end native case.

## Measurement and capture corrections in the same checkpoint

Before implementation, the reviewed follow-ups retain the exact workloads,
limits, rates and accounting. Save timestamp-bounded raw class/qdisc observations
inside the manifest-verified endpoint namespaces after reference completion and
again before cleanup, including failed cases where the topology still exists.
These are cumulative/setup-to-postreference and later-phase observations; they
are never substituted for the exact20s capture window.

Qualifying reference wire cost requires positive conservative same-window
captured IP-byte lower/upper bounds on both sender WANs, including the reverse
ACK-return path even when its reverse application payload is zero. Valid packets
outside the window, or only uncertain boundary packets, cannot provide a usable
denominator for positive measured payload. Do not invent packet costs.

The parent's bounded fresh-namespace tcpdump preflight confirmed that its default
privilege-drop target could not own a savefile in a namespace mapping onlyuid0.
Capture commands therefore explicitly select `-Z root`, the root identity inside
the already verified fresh user namespace. No user/network/mount isolation is
removed or host privilege expanded. Retain all capture ceilings and arguments.

The byte-ceiling exhaustion event is recorded when a successful TCP send first
reaches its configured maximum, not later when shutdown observes the next clock
sample. A send just before the window boundary cannot become qualified merely
because the next iteration runs after that boundary. The existing maximum and
original transfer deadline stay unchanged.

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

The next evidence-retention correction is designed before code: publish initial
ready events, validated status, daemon resources and sole-socket observations
before running functional probes. Publish the completed reconnect lifecycle and
final socket observations before its new functional probes. Preserve each
bounded raw ping result before checking exact zero loss, including a failed
direction and any preceding successful direction. If a functional phase fails,
attempt one status observation per peer while its private control socket still
exists, with a2s per-command cap under the unchanged original case deadline.
Failure responses and ping stdout each have a64KiB bound. Save diagnostic
failures separately and re-raise the original functional error; no extra retry,
time, packet count or acceptance relaxation follows. The [harness](../../tools/secure_udp_native.py)
now implements this ordering and the [four focused regression cases](../../tools/test_secure_udp_native.py)
cover ready-event retention, both functional phases' partial ping evidence,
independent diagnostic errors, original-bound refusal and failure-publication
isolation. The [40-test parent-run focused check](../../work/secure-udp-native-tooling-focused-20261113/attempt-7/validation.json)
passed for that earlier revision. The later exact ICMP implementation and new
native evidence below supersede the external ping command, preserving exactly
three requests,1472-byte payload, full1500B/DF packets, all replies and the
original12s phase bound including subprocess startup.

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

Captured emitted IP cost uses original IP lengths over the same monotonic window,
with a real/monotonic clock anchor and explicit timestamp uncertainty. Interface,
HTB and netem counters are recorded separately; sender socket acceptance, qdisc
drops, captured link packets and delivered application bytes are not conflated.
In these owned labs the WAN captures observe emission after the egress qdisc:
matching packet sets appear on both endpoints, including identical gaps under
loss, and their inter-capture transit is much shorter than the configured netem
delay. Thus this same-window cost excludes packets dropped by netem. Runtime
socket-acceptance and full-wire charge counters include separate earlier stages;
their sampled deltas are not relabeled as exact20s attempt costs. Cumulative tc
counters corroborate loss but do not provide exact-window drop counts. The
payload/emitted-IP ratio must not be advertised as loss-inclusive efficiency.
Capture loss, truncation outside the declared snapshot, unsupported tool output
or finite-bound exhaustion prevents qualification.

## Initial immutable native baseline

The [source-stable optimized build](../../work/secure-udp-native-build-20261113/attempt-3/build-receipt.json)
has binary SHA-256 `b579b17660d2441a6d1f2fba1e46d1e7995aac1d067cf53425b6a102d27175cb`.
Its copied helpers and binary ran in fresh owned user/network/mount namespaces.
The [receipt-derived summary](../../work/secure-udp-native-20261113/baseline-summary.json)
retains exact measurements, sampled daemon CPU/RSS and source-verified flow mapping.

| Appearance/path | Forward Mbit/s | Case result |
| --- | ---: | --- |
| [QUIC-like, clean](../../work/secure-udp-native-20261113/quic-clean-attempt-4/receipt.json) | 83.0069 | Passed |
| [QUIC-like, 70 ms RTT, no loss](../../work/secure-udp-native-20261113/quic-delay-attempt-1/receipt.json) | 83.4842 | Passed |
| [QUIC-like, 70 ms RTT, 15% loss each way](../../work/secure-udp-native-20261113/quic-impaired-attempt-1/receipt.json) | 38.9124 | Failed the unchanged 80 Mbit/s target |
| [Media-like, 70 ms RTT, 15% loss each way](../../work/secure-udp-native-20261113/media-impaired-attempt-1/receipt.json) | 39.7644 | Failed the unchanged 80 Mbit/s target |

All four completed exact TCP hash/EOF, native full-MTU/zero-payload probes,
two live policy commits, fresh manual reconnect, complete capture checks with
zero kernel capture drops and owned cleanup. The failed cases retain their
overall failure; functional success does not qualify performance. These runs
do not cover the full appearance/path matrix or reverse-bulk stress, and cannot
qualify later runtime source corrections without a new immutable build/run.

The impaired QUIC case used nine forward and five reverse ordering channels for
its sixteen connections. The source-pinned classifier hashes each direction;
the reference connection-round-robin/reverse-affinity composition remains open.
Its sampled endpoint CPU was about 20% of one core rather than saturation;
sampled inner TCP RTT increased and brief native-pressure drops occurred.
These observations motivate source-backed scheduling/fairness work, not a claim
that one mechanism has already explained the slowdown. Ready retransmission
wakeup and native event expiry require dedicated regressions and new measurements.

The later [corrected-runtime build](../../work/secure-udp-native-build-20261113/attempt-4/build-receipt.json)
has binary SHA-256 `a7c85df1fae560e3bd8c73084dff99f3e0ac7d725472490c644af3c2f87c5410`.
Its first [impaired attempt](../../work/secure-udp-native-20261113/quic-impaired-attempt-3/receipt.json)
failed a full-MTU ping phase before a reference measurement. A
[repeat](../../work/secure-udp-native-20261113/quic-impaired-attempt-4/receipt.json)
entered bulk traffic, then both daemon logs reported `TimedOut`; final status
samples retain unanswered Pong challenges and fresh User traffic. Neither is a
qualified throughput result. Both owned cleanups passed. The intervening
[incorrect build-receipt path](../../work/secure-udp-native-20261113/quic-impaired-attempt-2/receipt.json)
is separately preserved as a launcher-only tool failure, with no worker started.

Captured missing Control numbers and retained ordered-source observations are
consistent with repeated lost copies blocking a later Pong. The default ARQ
backoff can place its next retry after the original five-second challenge bound.
Packet identities remain an inference from protected captures; a deterministic
control-loss fixture is required before changing retry policy. Fresh User traffic
must not renew a challenge and no deadline is extended to hide these failures.

The installed ping manual and a [fresh-namespace delayed-third-request preflight](../../work/secure-udp-native-preflight-20261113/ping-deadline-semantics.json)
also show that `-W3` can exit early after partial replies; it is not an exact
three-second wait for every request. A trial deadline flag did not preserve the
fixed request count and was not adopted. A future finite ICMP probe must preserve
exactly three requests, all replies, full MTU/DF and the original twelve-second
phase bound. That is now implemented by the bounded raw ICMP probe below; the
historical ping observations and failures remain unchanged.

## Counter-guided performance correction

The [50-test tooling focus](../../work/secure-udp-native-tooling-focused-20261113/attempt-9/validation.json)
passed with stable inputs. The exact ICMP owner validates source/destination,
checksums, fresh ID/payload, sequence, extent, duplicates and unique replies,
sends exactly three requests without retries, and keeps one original12s bound.
A [fresh-namespace preflight](../../work/secure-udp-native-preflight-20261113/exact-three-icmp-attempt-2.json)
passed all three replies when only the third request was delayed1.5s. This
corrects the external ping wait semantics; it does not relax loss acceptance.

The owner requested production counters rather than inferring performance from
wire overhead. [Runtime metrics](secure-udp-runtime.md#performance-counter-correction)
and the [shared report](secure-udp-service.md#local-api-and-cli-compatibility)
now retain actual service/session/epoch/time, finite batch/work limits, packet
classes/charged IP bytes, credit/refill discard, native pressure and current
Swift channel recovery. Reports contain neither keys nor packet bodies.

| Immutable candidate | Path | Forward Mbit/s | Outcome |
| --- | --- | ---: | --- |
| [Build5, counters and original9500B burst](../../work/secure-udp-native-20261113/quic-impaired-perf-attempt-1/receipt.json) | QUIC-like impaired | 40.0928032 | Failed80 |
| [Build5](../../work/secure-udp-native-20261113/quic-clean-perf-attempt-1/receipt.json) | QUIC-like clean | 59.6234272 | Failed80 |
| [Build6, fixed initial-rate4ms burst](../../work/secure-udp-native-20261113/quic-impaired-perf-attempt-2/receipt.json) | QUIC-like impaired | 64.5726912 | Failed80 |
| [Build7, bounded native output before next UDP batch](../../work/secure-udp-native-20261113/quic-impaired-perf-attempt-3/receipt.json) | QUIC-like impaired | 70.6235936 | Failed80 |
| [Build7](../../work/secure-udp-native-20261113/quic-clean-perf-attempt-2/receipt.json) | QUIC-like clean | 72.0171488 | Failed80 |
| [Build7](../../work/secure-udp-native-20261113/media-impaired-perf-attempt-1/receipt.json) | Media-like impaired | 78.2192224 | Failed80 |
| [Build8, one-shot IPC helper runtime correction](../../work/secure-udp-native-20261113/quic-ipcfix-impaired-attempt-1/receipt.json) | QUIC-like impaired | 77.346368 | Failed80 |

These runs pass exact TCP bytes/hash/EOF, exact full-MTU ICMP and arbitrary UDP,
under-load policy commits/restoration, fresh manual reconnect on the configured
tuple, complete captures and owned cleanup. Their overall target failures remain
failures. Build7's [sampled comparison](../../work/secure-udp-performance-analysis-20261113/build7-clean-impaired-sampled-focus.json)
records zero native-pressure drops, output-full polls and native write WouldBlock
on both endpoints. Build6's original impaired session had11,877 pressure-rejected
non-feedback User records despite zero write WouldBlock; this is distinct from
an exact count of lost native frames. The scheduler correction addresses that
specific admission boundary without increasing queues or per-turn write work.

Busy sampled build7 forward intervals still show packing backlog at every
sampled endpoint. Refill discard is11.64% impaired and26.31% clean, with late
credit checks. These are selected approximately8s driver intervals, not the
exact20s goodput window or continuous queue occupancy. Separately, process CPU
inside the reference window is about0.68/0.57 of one core impaired and0.82/0.68
clean, for the respective endpoints; system time is substantial. No exclusive
scheduler/CPU/syscall bottleneck follows from those averages. Processed native
readiness now includes pre-drain observations, so its denominator differs from
the earlier selected-branch count.

The [nine fresh simulator sensitivity runs](../../work/secure-udp-simulator-sensitivity-20261113/attempt-1/validation.json)
retain three seeds for each overhead/timing case. Mean forward goodput is
80.5717Mbit/s for legacy authentication budget21/flush0.5ms,78.7502 for
QUIC-like budget45/flush1ms, and78.6011 for media-like budget46/flush1ms.
All reach delivery/confirmation. This is a counterfactual overhead/timing study,
not exact Swift wire/flow-mapping parity or kernel/runtime performance; it lacks
the real pacer, native syscall/CPU and authenticated liveness composition. It
does not explain the large native gap by overhead alone.

An [authentic historical-binary replay](../../work/secure-udp-native-20261113/quic-old-baseline-clean-attempt-1/receipt.json)
uses the preserved build3 and its exact original archived helpers, with bytecode
writes disabled and a fresh output/namespaces. It measures71.4825472Mbit/s clean
and fails80 while passing its original functional checks and cleanup. The
historical83.0069 result remains valid for its recorded run, not a current
environment baseline. This replay supports a changed run environment, without
isolating host load or attributing the entire new-code gap to it.

Two additional [diagnostic clean cases](../../work/secure-udp-native-20261113/quic-clean-profile-attempt-2/receipt.json)
measure77.4106592 and78.1329216Mbit/s, both below80. The CPU sampler's
[first setup failed](../../work/secure-udp-performance-analysis-20261113/owned-perf-clean-attempt-1/failure.json)
before samples; its [second attempt](../../work/secure-udp-performance-analysis-20261113/owned-perf-clean-attempt-2/failure.json)
exceeded its original25s bound and produced an unparseable file. Neither
provides CPU instruction attribution or replaces the uninstrumented cases.
Remaining native-read fairness is separately tracked as SUR-11. Full appearance/
path/reverse-stress coverage,80Mbit/s and SNL-11 remain open.

### Requested kernel profiling

The owner requested kernel perf rather than attributing the gap to other host
I/O work. A separate [owned-process kernel diagnostic](../../work/secure-udp-native-20261113/quic-kernel-perf-attempt-1/receipt.json)
uses the same build7, selected clean workload and fresh namespaces. It passes
functional/capture/cleanup checks and measures92.5081Mbit/s, but is explicitly a
profiled diagnostic, not the impaired acceptance result. The recorder targets
only the two verified tunnel PIDs, uses99Hz `cycles:k`, bounded per-thread
buffers and address callchains without raw stack bytes, then stops with SIGINT.
The initial wrapper treats that expected signal exit as failed; its raw outcome
is preserved. A [separate data validation](../../work/secure-udp-performance-analysis-20261113/kernel-perf-owned-attempt-1-analysis-validation.json)
verifies successful parsing,472512B of event data, approximately1K samples and
zero lost samples. The monotonic recording bracket lies inside the shared
measurement window; individual sample timestamps were not recorded.

The [inclusive caller report](../../work/secure-udp-performance-analysis-20261113/kernel-perf-owned-attempt-1-callers.txt)
places about29.18% under `tun_chr_write_iter`,17.07% under
`__x64_sys_epoll_wait`,13.01% under `__x64_sys_futex`, and22.89% under
`schedule`. These nested chains overlap and must not be added. They estimate
sampled execution cost, not off-CPU waiting or exact wall-time percentages.
The hardware event is configured to exclude userspace, but some userspace IPs
appear in this nonprecise sample; do not treat it as precise instruction timing.
TAP's VFS write path feeds the network stack, so `vfs_write` alone is not disk I/O.

The [simultaneous process/host observations](../../work/secure-udp-performance-analysis-20261113/kernel-perf-owned-attempt-1-counter-analysis-1.json)
span16.6188s inside that window. Both tunnel processes read zero physical storage
bytes and each writes172032B; their system CPU is8.63/9.96s and user CPU2.08/3.19s.
Each has255 threads, but only two accrue nonzero CPU ticks in the observed
interval. Host iowait is14.97% and I/O PSI some/full is63.11%/60.44%, demonstrating
concurrent host I/O pressure without assigning it to the tunnel. Delay accounting
and scheduler statistics are disabled; zero block-delay counters cannot prove
an absence of I/O waiting. This evidence favors investigating network/scheduler
execution rather than asserting disk I/O as the primary cause.

A separate [process-local worker override trial](../../work/secure-udp-native-20261113/quic-worker1-impaired-attempt-1/receipt.json)
sets `TOKIO_WORKER_THREADS=1` and measures64.6538Mbit/s impaired, failing80 with
functional/cleanup checks passed. That inherited environment changes both daemon
and local API helper pools; it does not isolate daemon scheduling. Actual live
thread counts were not retained before process exit. It supports no default
change or performance improvement claim. Source review separately finds that
each one-shot status/control command creates the same CPU-count-sized pool;
the narrow IPC-only correction is tracked by SUS-11 and keeps daemon scheduling
unchanged.

The [IPC-only source correction](../../crates/l2tunnel-client-core/src/cli.rs)
then keeps the persistent daemon scheduler while running private status/control
helpers on one I/O/timer-enabled thread. A [real old/new CLI comparison](../../work/secure-udp-ipc-runtime-proof-20261113/comparison.json)
holds each socket reply, checks live255-to-1 helper thread counts and identical
requests/replies for eight commands/nine cases. The original private transport
and65s timeout bytes are unchanged. [Immutable build8](../../work/secure-udp-native-build-20261113/attempt-8/build-receipt.json)
measures77.346368Mbit/s impaired with functional/capture/cleanup passed and80
still failed. This removes unnecessary helper pools, without proving that they
explain all prior throughput differences. The kernel diagnostic and all earlier
failures retain their original source identities and outcomes.

### Saturated ingress fairness

SUR-11 now has a deterministic failing old-loop regression and a
[passing runtime/client focus](../../work/secure-udp-performance-focused-20261113/attempt-8/validation.json).
The production loop alternates ready UDP/native priority while shutdown and local
control requests stay first. Existing quotas, authentication, wire rates and
original deadlines are preserved. This proves a scheduling defect and its finite
correction; it does not establish that the defect caused the prior throughput gap.

[Immutable build9](../../work/secure-udp-native-build-20261113/attempt-9/build-receipt.json)
has four fresh owned Linux namespace observations, all with70ms RTT and15% loss
each way. The forward16 workload retains sixteen forward TCP flows and only
reverse ACKs; reverse stress separately adds sixteen reverse bulk flows.

| Case | Forward Mbit/s | Reverse Mbit/s | Result |
| --- | ---: | ---: | --- |
| [QUIC-like forward16](../../work/secure-udp-native-20261113/quic-fairness-impaired-attempt-1/receipt.json) | 78.620608 | 0 | Failed80; functional/cleanup passed |
| [Media-like forward16](../../work/secure-udp-native-20261113/media-fairness-impaired-attempt-1/receipt.json) | 78.2435488 | 0 | Failed80; functional/cleanup passed |
| [QUIC-like reverse stress](../../work/secure-udp-native-20261113/quic-fairness-reverse-impaired-attempt-1/receipt.json) | 52.054832 | 7.62484 | Functional/cleanup passed; forward80 target not applicable |
| [Media-like reverse stress](../../work/secure-udp-native-20261113/media-fairness-reverse-impaired-attempt-1/receipt.json) | 51.2209824 | 7.5413232 | Functional/cleanup passed; forward80 target not applicable |

The [matrix](../../work/secure-udp-performance-analysis-20261113/fairness-native-matrix-attempt-2/validation.json)
therefore retains an overall failed result. All four cases pass exact TCP
counts/hashes/EOF, the original three full-MTU ICMP probes, UDP/ARP, loaded policy
changes/restoration, fresh manual reconnect and capture/owned-cleanup checks.
[Counter reconciliation](../../work/secure-udp-performance-analysis-20261113/fairness-native-matrix-attempt-2/counter-binding.json)
matches every class packet/IP-byte total to charged output. Reported native
backpressure drops, full-output polls and write WouldBlock maxima are zero in
both endpoints of every case. Sampled counters do not prove continuous occupancy
or causality. The first orchestration attempt's post-run permission failure is
preserved separately; its completed QUIC case was hash-verified and reused rather
than overwritten or rerun as though the first result had not occurred.

The [source-bound workload audit](../../work/secure-udp-performance-analysis-20261113/hash-geometry-attempt-1/diagnostic.json)
also prevents treating78.7502Mbit/s simulator sensitivity as exact Rust parity.
That study owns an independent recovery transport per TCP connection and sends
reverse inner ACKs without compact recovery. Rust uses directional flow hashing
and per-channel ordering. In the archived build8 tuple set, sixteen connections
occupy nine forward and ten reverse ACK channels; only one uses the same index
both ways. These are calculated mappings corroborated by channel activity, not
decryption of the capture or a measurement of collision cost. P-unified-duplex-mux,
full SW-11, the80Mbit/s target and every existing mode/platform gate stay open.

### Conditional framing capacity estimate

The [source-bound calculation](../../work/secure-udp-performance-analysis-20261113/hash-geometry-attempt-1/conditional-ceiling.json)
uses the actual99Mbit/s full-IP allowance,1500B IPv4 path,76/77B fixed
QUIC-like/media-like overhead and1416/1415B maximum packed source payload.
Maximum SOURCE packets cost1497IP bytes; REPAIR packets cost1500, because repairs
also code the source-length word. The per-native two-byte record length is a
separate cost. Assuming independent15% packet loss, full useful symbols, steady
allowance and no other costs, optimistic packed-stream rates are79.5968/79.5406Mbit/s.
For1448B TCP payloads with an optimistic two-byte compressed header and two-byte
record length, those estimates become79.3775/79.3215Mbit/s.

This is a conditional asymptotic estimate, not a strict finite20s bound or a
measurement of an actual codec's average compression. Burst/warmup boundaries,
variable packets, realized loss and record geometry require separate treatment.
It explains why CPU/scheduler improvements alone cannot guarantee expected80
under these fixed assumptions. Changing rate accounting or wire efficiency needs
its own explicit configuration/negotiation and controlled comparison; no rate,
security, MTU, mode default, target or owner decision changes here. The simulator
variants also change flush timing, so they do not isolate overhead alone.

The scheduler checkpoint's [required aggregate](../../work/secure-udp-fairness-progress-20261113/attempt-2/validation.json) passes
1528 Rust cases including doctests, 295 Python tooling cases and 1658 simulator cases. Its
first aggregate failure and unchanged isolated deadline recheck remain preserved
as documented in SUR-11; the complete successful rerun retains all cases and
original assertions/deadlines. Local checks remain distinct from the failed
forward performance target and outstanding carrier/mode/platform qualification.

### Impaired build9 kernel diagnostic

The owner requested kernel perf on the impaired path. A fresh
[owned-namespace diagnostic](../../work/secure-udp-native-20261113/quic-build9-kernel-impaired-attempt-1/receipt.json)
uses the same preserved build9 binary and archived helpers: QUIC-like, forward16,
100/10Mbit/s, 70ms RTT and independent15% loss each way. Measured20s goodput is
77.4992768Mbit/s with perf attached; exact bytes/EOF, functional/control checks,
captures and cleanup pass, while the unchanged80Mbit/s gate fails. It is a
separate instrumented observation, not a replacement uninstrumented baseline or
qualification of the later streamed-control source.

The [raw recorder](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-attempt-1/profile.json)
remains failed because perf reached its requested16MiB event-stream threshold
before the planned stop. Metadata makes the actual file19,444,472bytes; its
separate enforced whole-file ceiling was32MiB. Independent
[partial-data validation](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-analysis-attempt-2/validation.json)
checks raw record boundaries against `perf script`, hashes and timestamps. The
retained13.704321962s span lies wholly inside the20s measurement, with1,047 cycles
samples,515,065 switch records and zero recorded loss markers. One byte-identical
SWITCH-IN duplicate remains in raw counts and is excluded only from interval
pairing. Neither this validation nor the recorder exit code changes the failed
raw-wrapper or native target status.

The PERIOD-weighted kernel share is63.7058% of sampled on-CPU cycles, not wall
time. Independently timestamped process observations contained in that span
cover12.4845s: sideA uses1.18s user plus3.41s system CPU (0.3677core average),
sideB1.71s plus4.31s (0.4822core). These averages do not prove absence of per-thread
delays. All switch records belong to four active main/worker TIDs. Closed switch
pairs measure off-CPU intervals, with censored recording boundaries; nonpreempted
switch-outs do not uniquely identify disk sleep or separate blocked from runnable
delay. Sparse wait-channel observations include futex and epoll.

The cap path did not retain the final host-PSI/disk/process-I/O snapshot, so this
run cannot establish those interval deltas or rule out other host I/O activity.
Hardware PMU bookkeeping also appears in the flat sample report and must not be
attributed wholly to tunnel work. Inclusive kernel chains overlap, finite CPU
samples are estimates, and profiling can perturb scheduling. No single causal
throughput bottleneck or target waiver follows from these observations. The
earlier clean build7 kernel percentages remain a different experiment.

The same-data [self/inclusive reports](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-reports-attempt-1/validation-3.json)
separate leaf costs from caller contexts. Inclusive kernel frames include
schedule16.42%, epoll syscall13.01%, futex syscall12.17%, TAP write11.29% and
UDP send8.63% of all sampled PERIOD weight. These overlap and cannot be added or
interpreted as off-CPU durations. Flat userspace `Vec::extend` accounts for9.90%
of that denominator. [Exact sample-IP/disassembly attribution](../../work/secure-udp-performance-analysis-20261113/build9-quic-impaired-kernel-reports-attempt-1/vec-attribution.json)
places all86 matching samples in the byte-at-a-time deque-to-vector append loop,
with none in its reserve-call branch. The two compiled direct callers match
Swift sender packing and receiver packet extraction; both source hashes equal
build9. Optimized frame-pointer chains cannot divide the cost between callers,
and zero allocation-branch samples do not measure allocation frequency. Compare
bounded two-slice bulk copying under unchanged byte/order/recovery semantics as
a controlled hypothesis; this does not establish a unique bottleneck or a change
that meets80Mbit/s.

## Results and acceptance

Each fresh output preserves its source/binary/helper identity, exact command
vectors, namespace identities/journal, selected policies, status samples, clock,
captures, tool versions, native payload results, rates and cleanup. Outcomes
separate passed, failed, bound_exhausted and tool_failure. Negative native or
tooling results never overwrite historical receipts or become skipped success.

- [x] [SNL-01] Record/review the explicit CLI/status/build interface, fresh namespace proof, workloads, measurement/capture semantics and finite bounds before implementation. Evidence: this pre-implementation design, integrator review and the [implemented public interface](../../tools/secure_udp_native.py).
- [x] [SNL-02] Implement dry-run-by-default planning and source-pinned copied-helper/binary execution with fresh user/network/mount verification and owned cleanup. Evidence: [launcher/worker](../../tools/secure_udp_native.py), [ownership, hash, dry-run and interrupted-receipt tooling tests](../../tools/test_secure_udp_native.py), and the four terminal native receipts above. Fresh namespace identity proofs, executed helper hashes and cleanup passed; the first three failed attempts remain preserved. This scoped execution gate does not complete the performance matrix.
- [x] [SNL-03] Implement maintained fresh credential generation, exact selected CLI/API-v2 observations and no TLS/TCP bootstrap substitution. Evidence: [maintained X25519/Raw and existing binary keygen composition](../../tools/secure_udp_native.py), strict CLI/status fixtures and actual CLI/TAP receipts above for both appearances. Public member/Noise/transcript/configuration bindings, sole UDP socket pair and explicit version2 local commands were checked; fresh private credentials were temporary and excluded from receipts.
- [x] [SNL-04] Verify sixteen-flow forward-only and distinct duplex stress probes with exact bytes/hash/EOF, common-window accounting and meaningful bound/error tests. Evidence: [probe](../../tools/secure_udp_native_probe.py), [ordinary sixteen-flow TCP and exact UDP loopback, accounting, original-deadline and byte-ceiling boundary regressions](../../tools/test_secure_udp_native.py), and the [40-test focused passing receipt](../../work/secure-udp-native-tooling-focused-20261113/attempt-7/validation.json). This is tooling/ordinary-loopback evidence, not a TAP throughput result.
- [x] [SNL-05] Implement and test complete-MTU/ARP/zero-payload checks, real under-load policy changes and fresh manual reconnect observations without claiming SW-11 or automatic recovery. Evidence: current immutable build7 [QUIC-like](../../work/secure-udp-native-20261113/quic-impaired-perf-attempt-3/receipt.json) and [media-like](../../work/secure-udp-native-20261113/media-impaired-perf-attempt-1/receipt.json) TAP receipts pass exact three-request1500B/DF ICMP with the original12s bound, arbitrary/zero/trailing-zero UDP, captured ARP, TCP hashes/EOF, changed/restored policy epochs and new authenticated sessions on the configured UDP tuple. [Fifty focused tooling cases](../../work/secure-udp-native-tooling-focused-20261113/attempt-9/validation.json), the [delayed-third ICMP preflight](../../work/secure-udp-native-preflight-20261113/exact-three-icmp-attempt-2.json), and five production-owner control-loss tests in the [runtime focus](../../work/secure-udp-performance-focused-20261113/attempt-4/validation.json) retain original timeout/retry semantics. Deterministic control loss is fixture evidence, distinct from stochastic native impairment. Overall throughput targets still fail; full SW-11 and automatic recovery remain open.
- [x] [SNL-06] Verify bounded all-IP capture parsing, original tuple/phase/MTU/fragment checks, same-window IP cost and nonzero capture-loss rejection. Evidence: [streaming capture/parser and final counters](../../tools/secure_udp_native.py), [both-cover, policy-epoch, role/extent, ICMP, truncation, exact-counter, checksum, fragment, resource and common-window fixtures](../../tools/test_secure_udp_native.py), and the [source-stable 40-test focused result](../../work/secure-udp-native-tooling-focused-20261113/attempt-7/validation.json). The new coverage gate rejects positive measured payload with no conservative same-window WAN denominator, including missing ACK-return observations. Capture of actual native traffic remains SNL-08.
- [x] [SNL-07] Pass focused tooling checks and the source-stable required aggregate, retaining failed attempts and exact provenance. Evidence: [50 focused tooling tests](../../work/secure-udp-native-tooling-focused-20261113/attempt-9/validation.json), the [expanded runtime/client focus](../../work/secure-udp-performance-focused-20261113/attempt-5/validation.json), and the [preceding source-stable required aggregate](../../work/secure-udp-performance-progress-20261113/attempt-3/validation.json) passed. The aggregate records1526 Rust cases including doctests,295 Python tooling cases and1658 simulator cases; formatting, strict workspace Clippy, rustdoc, CLI checks and input stability passed. Rust tests were serialized without skipping cases or changing assertions/deadlines. Earlier40-test/1498-Rust checkpoints and both failed performance-correction aggregates retain their original results. Native qualification remains separate under SNL-05 and SNL-08..SNL-11.
- [ ] [SNL-08] Execute both appearances on clean/delay/1%/15% matched sixteen-flow ACK-return paths with immutable binary/helpers; retain exact integrity, policy/lifecycle and capture outcomes.
- [ ] [SNL-09] Meet the existing 80 Mbit/s forward lab target on the matched impaired composition; retain honest timing, overhead, CPU/resource and negative results.
- [x] [SNL-10] Execute separate reverse-bulk stress and document its limits independently from matched reference, native-device scope and all remaining platform/ISP gates. Evidence: the build9 [QUIC-like](../../work/secure-udp-native-20261113/quic-fairness-reverse-impaired-attempt-1/receipt.json) and [media-like](../../work/secure-udp-native-20261113/media-fairness-reverse-impaired-attempt-1/receipt.json) impaired Linux TAP cases pass integrity/control/capture/cleanup, with separately recorded directional goodput above. These finite bidirectional cases do not substitute for the forward16 target, other native devices, full path matrix or platform/ISP evidence.

The parent-owned [29-test focused receipt](../../work/secure-udp-native-tooling-focused-20261113/attempt-4/validation.json)
records the owned-qdisc correction with stable tooling inputs. The earlier
[26-test](../../work/secure-udp-native-tooling-focused-20261113/attempt-3/validation.json),
[23-test](../../work/secure-udp-native-tooling-focused-20261113/attempt-2/validation.json)
and [20-test](../../work/secure-udp-native-tooling-focused-20261113/attempt-1/validation.json)
snapshots remain preserved. Their scope is fake namespace/capture acceptance,
daemon resource parsing and ordinary loopback, not TAP throughput.

The [40-test focused checkpoint](../../work/secure-udp-native-tooling-focused-20261113/attempt-7/validation.json) passed with stable inputs. It covers actual nested subprocess worker/capture limit checks,
insufficient-hard-limit refusal, exact mapped-root capture arguments, owned tc
phase/failure observations, rejection of zero or boundary-only same-window wire
cost and the TCP byte-ceiling boundary regression. Four additional failure tests
verify retained readiness/predecessor observations, raw failed ping/partial UDP,
live diagnostic status bounds and preservation of the original error/deadline.
That earlier diagnostic-helper revision passed its [recorded aggregate](../../work/secure-udp-native-progress-20261113/attempt-1/validation.json); exact-ICMP and current immutable native follow-ups are recorded above. The earlier36/29-test scopes and all failed native attempts remain distinct.
Actual daemon CPU/RSS and distinct probe usage now have finite native observations
in the explicitly bounded intervals above. The failed native attempts and namespace preflights remain
failures or scoped observations; they do not qualify the performance matrix.

Source, dry-run and synthetic tooling tests alone do
not qualify native performance. Only the parent integrator executes --apply after
its immutable build and source checks.

- [ ] [SNL-11] Diagnose the secure-UDP native performance regression using source-pinned runtime/channel performance reports, matched clean and impaired workloads and explicitly limited simulator overhead/timing sensitivity. Use measured counters to justify each correction, retain before/after failures, and rerun integrity, original-deadline/liveness and the unchanged80Mbit/s impaired target. Instrumentation alone cannot complete this gate.
