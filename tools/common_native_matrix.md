# Current Common native matrix runner

`common_native_matrix.py` consumes the version1 manifest emitted by the maintained
`common_benchmark_plan` example. A ready exporter row means the selected protocol
planners accepted it. A generated constructor refusal is `plan_refused`, not a
claim that the algorithm is unsupported. The runner still performs actual daemon CLI inspection,
mutual authentication, native TCP transfer, observation and cleanup. It never
substitutes another algorithm for a refused plan row.

The default invocation is a dry run:

```sh
python3 tools/common_native_matrix.py --manifest /absolute/plans/manifest.json \
  --binary /absolute/l2tunnel --output /absolute/new-results
```

An explicitly authorized Linux namespace experiment adds `--apply`. Optional
repeated `--case ROW_ID` arguments select exact rows. `--phase forward`,
`--phase reverse` or `--phase simultaneous` selects an independent direction run;
omitting this option retains all three phases on one tunnel. A new direction run
is separate evidence, not a retry of a failed earlier direction. The output directory must
not already exist. The default root-owned exclusive lock serializes default runs.
An explicit `--parallel-lane udp|raw|tls|quic` permits independent carrier lanes;
each lane requires only its carrier rows and the distinct `--lab-id cm-CARRIER`.
Lane locks serialize that lane. Its processes inherit a fixed eight-CPU set
(UDP0..7, raw8..15, TLS16..23, QUIC24..31); unavailable CPU sets fail closed.
Receipts record the selected lane and affinity. These runs still share host
memory, storage and kernel resources, and are concurrent-host observations, not
isolated capacity maxima. Do not launch a default run concurrently with a lane
using the same lab prefix; namespace journal identity checks remain mandatory.
All route, interface, offload, firewall and qdisc changes stay inside the
new journal-owned namespaces. Cleanup verifies namespace inode identity and that
no processes remain before deletion. No host route or qdisc is changed.

Each Full-duplex TUN case uses the actual current Common daemon entry, its complete
catalog, member credentials, Noise credentials, and any required raw/maintained
carrier policy. TLS server identity is pinned to a fresh owned certificate. The
manifest's fixed endpoint pair is `192.0.2.2:24440` and `192.0.2.6:24441`; native
addresses are `198.18.0.1` and `198.18.0.2`. Raw TCP suppresses only unmarked RSTs
for that exact tuple in each owned namespace, using the same mark passed to the
actual CLI. This experiment does not qualify broader firewall/NAT behavior.

The path has100Mbit/s forward and10Mbit/s reverse HTB ceilings, one35ms netem delay
and independent15% random loss in each direction. Effective qdisc/class state,
rate/delay/loss readback and counters are retained. Offloads are disabled on the
owned WAN/router/native interfaces and read back; inability to do so is an
unsupported observation, never silently accepted packet accounting.

Each TCP connection exchanges a bounded four-byte flow ID and acknowledgment
before `Connected`; the receiver orders sockets by that identity. These setup
bytes are excluded from payload hashes, byte totals and the timed window. This
avoids attributing one flow to another when accept order differs under loss.

Three phases run serially on the same authenticated tunnel: forward, reverse and
simultaneous. Each phase opens16 ordinary kernel TCP connections, uses a shared
monotonic2-second warmup and10-second sample window, and has an original60-second
cap including connection and tail drain. Each direction/flow has a32MiB byte cap.
The data pattern is deterministic pseudorandom64KiB; payload compression is off
in the supplied baseline. Failed phases do not trigger reconnect, retries,
algorithm replacement or timeout changes. Remaining phases are explicitly
`not_run`; later independent cases may continue after successful cleanup.
The current exporter also sets an original120-second session lease. Three slow
phases can cumulatively exhaust it even when each phase fits its60-second cap.
Report `LeaseExpired` as observed; use explicitly labeled independent phase
sessions to isolate a direction without extending that lease or implying one
continuous three-phase pass. The stable `swift-arq` ID disables proportional
repairs only; Swift's existing tail-probe repair equations remain enabled and
are counted as repair traffic.

Live phase cleanup stops all capture processes, checks their terminal counters,
and takes the original post-phase qdisc/kernel snapshots. Full pcap parsing and
hashing for every phase run only after requested local disconnects and owned
process/namespace cleanup. Each stopped capture retains its own address pair
and sample wall-clock window. This removes offline file analysis from the
absolute session lease; it does not shorten TCP tail/EOF validation or extend
any session, phase, case, capture, or cleanup bound. Live startup, capture stops,
status/kernel snapshots and cumulative TCP tails can still exhaust the lease.

Known capture drops immediately stop later live phases. A malformed pcap or a
packet-count mismatch discovered during deferred analysis invalidates its
phase and the case; later phases that already ran retain their own evidence.
There is no automatic replay or reconnect. Observed throughput remains
`pending_capture_validation` until that phase's full capture checks pass.
`data_status` and `shutdown` report separate results. A case cannot pass if either
endpoint's API4 requested local disconnect fails, even when all three data
phases pass. A successful local disconnect response is not a bilateral protocol
drain proof. Both existing local disconnect commands are submitted concurrently
before waiting for either completion, using at most two workers and the unchanged
three-second command cap within the original shared cleanup deadline. This avoids
waiting for the first endpoint to close before even asking the second endpoint.
It does not guarantee simultaneous service acceptance: an actual peer-close or
already-failed state can still win and remains a failed shutdown. No retry or
terminal-error rewriting is performed. Primary workload/setup failures are
preserved through cleanup.

## Metric definitions

- **Application goodput** is unique bytes returned by the receiving application
  during the common10-second sample, converted to Mbit/s. All sent/received stream
  totals, hashes and EOFs must match after bounded tail drain. Warmup and tail bytes
  are retained separately. TCP samples expose endpoint kernel cwnd, retransmits,
  RTT and socket windows; these are not tunnel or proxy credit.
- **Captured IP bytes** sum IPv4 `total_length` at one observation surface. Each
  endpoint captures both directions on WAN and native TUN. Local WAN egress is
  observed before its qdisc loss; remote ingress is after path loss. Keep surfaces
  separate: summing both endpoint captures double-counts delivered packets.
- **Packet-size mean/p50/p99** describe captured IP packet lengths, not per-native
  packet encapsulation overhead. They include the observed mix of data, ACKs,
  feedback and control; the capture does not decrypt TLS or QUIC or infer payload
  identity. Packet-size summaries include the whole phase and the sample window,
  mapped by a saved wall/monotonic clock anchor. Clock-anchor uncertainty remains
  visible.
- **Runtime record metrics** are opt-in actual accepted-record histograms emitted
  at Runtime Drop using `L2TUNNEL_WIRE_METRICS`. They are cumulative across this
  case's phases and distinct from physical captured transport bytes. Inner record
  overhead is actual final-record length minus actual algorithm-body length;
  neither a fixed21-byte tag cost nor a configured carrier allowance is total
  packet overhead. Unavailable padding/retry/native correlation remains null in
  the runtime report. Its observer heap is reported separately.
- **CPU** stores host `/proc/stat`, load and per-owned-process user/kernel ticks
  and RSS. Host-wide kernel time includes unrelated jobs. Probe CPU, daemon CPU
  and capture CPU remain separate observations; this harness cannot attribute all
  host utilization to the tunnel.

Captures have finite512MiB and2million-packet ceilings per surface. Snaplen2048
must preserve complete packets. Captures use preopened output descriptors and
tcpdump immediate mode with the original 8192 KiB capture ring. Output uses
ordinary buffered file writes; it does not request a file flush per packet.
Clean bounded SIGINT shutdown must flush the output before parsing and exact
tcpdump/pcap packet-count validation. This reduces capture write calls without
changing packet timestamps, tunnel socket buffers, impairment or protocol bounds.
Missing/truncated captures, kernel capture drops,
exhausted bounds and missing/invalid metrics reports prevent a passing row.
Histogram counts, totals, quantiles, carrier boundaries and invalid/overflow
counters are checked; failed probes retain partial sample-window byte counts
with an explicit completion flag. If byte/hash/identity qualification fails,
observed receiver counts and completed-window rates remain available but are
labeled invalid or incomplete, never promoted to a passing throughput result. The original overall cleanup cap is shared
by disconnect, child termination and namespace removal. IPC disconnect
precedes bounded metrics publication and supervisor termination. Receipts include
binary/input/helper hashes; the separate build receipt binds the executable to
its source revision. Credentials remain in an owned private temporary directory
and are removed after the run.

No result from this Linux lab establishes all47 Python parity gates, Windows or
Android operation, public ISP QoS classification, or production performance. This
runner's unprivileged parser/socketpair tests are separate from real namespace
execution, which requires its own preserved receipts.

## Packed C48 native comparison

Generate both descriptors using `common_benchmark_plan --output-dir NEW --packed-c48-pair`.
Run `--case packed-c48-control-udp --case packed-c48-queue-aware-udp --phase forward
--packed-c48-workload` on one release binary. The optional probe schedules 512-byte
application records round-robin on 16 ordinary CUBIC TCP streams at an aggregate
76 Mbit/s. Each record carries its sequence and monotonic first-write timestamp
in its 512 bytes. The receiver timestamps a record when the application has read
all its bytes. Each flow requests 128 KiB per socket send/receive buffer and
reports the kernel's effective values. The kernel owns segmentation, congestion
and retransmission. The original native 2-second warmup, 10-second sample and
60-second phase cap still apply.

The receipt gives one P99 from the first attempted write and a second from its
scheduled release. Both distributions cover complete records received during
the offer and drain. The scheduled, started, fully written and fully read counts
expose backpressure and incomplete transfers. The ordinary payload hash, EOF,
capture and teardown checks also apply. After passing application EOF, the runner
queries each live endpoint for its outstanding recovery state before disconnect.
The kernel netem draws and actual TCP hosts are independent of the simulated C48
seed. Compare the two Rust cells under this workload and retain the scope when
comparing them to the 90-second Python experiment.

## Saved-result reporting

`common_matrix_report.py --manifest MANIFEST --results RESULTS --output NEW_DIR`
reads receipts without starting a workload. Repeat `--results` to include earlier
attempts and explicitly independent direction sessions. Every manifest row and
attempt remains visible. The selected result for each explicitly requested phase
is its latest started attempt, never the fastest or most successful result.
Independent sessions retain their own binary/input/receipt provenance. Cumulative
runtime histograms remain per session and direction; they are not merged or
attributed to a phase. Unmeasured total encapsulation overhead remains null.
