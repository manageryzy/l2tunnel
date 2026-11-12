# Owned native throughput and TCP window observations

Status: implemented with unprivileged kernel-loopback and ownership-contract
checks. Privileged TAP/TUN execution is not yet claimed by this module. Each
native result needs its own immutable build, exact helper provenance, owned
namespace cleanup and measurement receipt. Run performance cases serially.

## One explicit case

`tools/native_throughput.py` is dry-run by default. A run selects exactly one
profile, duplex mode, path, IP family and flow count. Profiles are `tap-system`,
`tun-system`, `tun-active` (transparent active credit with `--adaptive on`) and
`tun-measured-proxy`. All use genuine authenticated TCP/TLS, the original full or
paired-half CLI path, frame records and compression off. No profile falls back.
The transparent active profile does not control endpoint TCP congestion windows.
The measured proxy's relay credit is separate from its native TCP legs.

The existing journal-owned five-namespace topology supplies shared 100 Mbit/s
A-to-B and 10 Mbit/s B-to-A HTB classes. All flows in a direction share that class;
rates are not multiplied by flow count. Only owned namespace WAN child netem
settings change:

| Path | Delay per direction | Base configured RTT | Random loss per direction |
| --- | ---: | ---: | ---: |
| `clean` | 1 ms | 2 ms | 0% |
| `delay` | 35 ms | 70 ms | 0% |
| `loss1` | 35 ms | 70 ms | 1% |
| `impaired` | 35 ms | 70 ms | 15% |

A 15% loss stage in each direction is not labelled 15% total path loss. Actual
qdisc/class counters and TCP retransmissions accompany the configured profile.
TAP applications run in the two host namespaces through the existing bridges;
TUN applications run on endpoint TUN addresses. Both IPv4 and IPv6 are explicit
single-family cases. Native and underlay offload completion is recorded using the
unchanged helper. Measured proxy disables ECN only in its owned endpoint
namespaces, matching its supported maintained TCP profile.

Example dry run:

```sh
python3 tools/native_throughput.py --profile tap-system --duplex full \
  --path loss1 --flows 1 --family 4 --lab-id speed23 \
  --output work/speed23 --binary work/native-build23/l2tunnel-linux
```

Execution additionally requires `--apply --build-receipt PATH` and privileges.
The output directory must be new. The binary, original successful source-stable
build receipt and all five executing helpers are copied into it. Every helper's
hash must match that exact build's source map. The launcher re-execs its copied
worker before namespace mutation, validates directory identity/layout and loaded
module paths, and verifies helpers/binary again after cleanup. No historical run
is adopted or overwritten. All network mutation uses the identity journal;
existing host routes, bridges, namespaces and qdiscs are not changed.

## Explicit measured WAN benchmark policy

The throughput harness uses its own `wan_measured_policy()` for every clean,
delay-only, 1%-loss and 15%-loss measured-proxy case. The historical clean-pressure
helper policy and product defaults remain unchanged. The new complete strict
policy is validated before namespace mutation, saved with its hash, and bound by
both peers' original authenticated configuration digest.

| Setting | WAN benchmark value | Reason |
| --- | ---: | --- |
| Bootstrap RTT | 70 ms | Largest configured base RTT, used identically across paths until actual observations replace it |
| Demand report interval | 100 ms | Bounded report load and repeated demand updates |
| Probe creation interval | 250 ms | Four creation opportunities per second, retaining the one-live-probe rule |
| Probe lifetime | 2 s | Original creation-to-completion bound, including queueing and return path |
| Unadmitted pending TTL | 1 s | Ten report intervals for replaceable unadmitted demand/replies |
| Admitted full-write deadline | 2 s | Original admission deadline; retries never renew it |
| Sample TTL | 4 s | Twice the probe lifetime, covering the complete retained history |
| Empty-demand idle interval | 1 s | Ten report intervals before removing fresh empty demand |
| Rate interval/history | 250 ms / 8 bins | Two seconds of history; twice that history remains below the 120-second ceiling |
| Emission allowance | 32 records / 100 ms | Bounded 320/s ceiling, sufficient for the 16-owner report geometry and echo service |

The explicit recovery allowance is 70 ms base RTT plus a 1-second RTO allowance
and 200/400 ms recovery allowances, rounded up to the next 500 ms: 2 seconds.
This finite budget is not a guarantee against arbitrary loss, congestion or
transport head-of-line blocking. It does not increase connection setup, liveness,
shutdown, whole-probe, command or case deadlines. Routes, rings, allocation caps,
service work limits and planning/status cadences are unchanged. Full validation
checks 1 ms..120 s duration ceilings, sample/probe/report/rate relationships,
bin/emission limits and actual 16-owner/33-token service scans at the 1 ms poll.

An independent [actual Rust Controller/Owner proof](../../work/wan-policy23c/RECEIPT.md)
uses the unchanged source23b production implementation and the exact new policy.
The old 30 ms probe returns a 70 ms Echo as stale with no sample; the WAN policy
accepts the same exchange as a fresh 70,000 us service observation. Replies at and
beyond the original 2-second boundary remain stale. Repeated handoff callbacks at
0.9 and 1.9 seconds cannot renew the original terminal 2-second full-write
expiry. The two focused regressions, all 72 proxy tests and strict Clippy pass.
These injected-time results establish policy behavior, not native WAN freshness:
actual measured-proxy WAN execution must still show fresh service and admitted
Echo request/reply evidence before a native qualification claim.

## Observed tc format compatibility

The first eight system half-duplex attempts failed before clock publication or
measurement, with all owned cleanup passing. They are tool/format observations,
not zero-throughput results. The preserved
[owned diagnostic](../../work/throughput23-tc-diagnostic/receipt.json) proves
iproute2-6.1.0 prints plain HTB class statistics despite `tc -j -s class`, while
qdisc output is valid JSON. Historical failed receipts remain unchanged.

Class observations now permit strict JSON or the complete observed HTB text
grammar. Exactly one class `htb 1:10` must be attached directly to the root, with
leaf `10:`, actual directional 100/10 Mbit rate and equal ceiling, and explicit
byte, packet, drop, overlimit and requeue counters. Missing, duplicate, ambiguous,
wrong-parent/rate or malformed observations fail closed. Qdisc observations
remain strict JSON requiring the owned root HTB and child netem identities and
all counters. Raw bounded stdout/stderr, argv and exit code are published before
parsing, retained with normalized observations and labelled by observed format.
Parser/tool incompatibility is explicitly `tool_failure`; it is not a protocol
failure or silently accepted empty/zero measurement. Deadline exhaustion remains
`bound_exhausted`.

## Measurement contract

One selector-based Python process per application side owns 1, 2 or 4 real kernel
TCP connections. Each connection sends and receives concurrently. Nonblocking
partial writes, queued data, half-close and EOF are independent; the probe never
assumes bidirectional completion occurs together.

After both sides establish all sockets, the harness atomically publishes a
complete common monotonic clock file. A one-second scheduling lead precedes two
seconds of warmup and ten seconds of measurement. Both processes share the host
monotonic clock. The original 30-second probe deadline starts before socket setup
and includes setup, warmup, measurement and remaining drain. It is never renewed.
The original daemon protocol deadlines, 40-second startup observer, 15-second
command limit, 300-second case limit and owned cleanup limits are unchanged.

Directional receiver goodput is unique application bytes returned by `recv`
whose read-completion timestamp lies inside the shared ten-second window,
multiplied by eight and divided by that window's duration. Kernel TCP stream
reassembly removes retransmission duplicates. Read batches crossing a boundary
are assigned wholly by their completion timestamp; this is an application
observation, not a packet arrival timestamp. Warmup and post-window drain bytes
are separate. Successful EOF requires each full sent stream's byte count and
SHA-256 to match its peer's full received stream, including warmup/drain. Drain
bytes never contribute to the measurement numerator.

The default ceiling is 256 MiB per direction per flow; validated values range
from 64 KiB through 1 GiB. Payload generation retains one 64 KiB repeating block,
not the full stream. Reaching the ceiling before the window ends produces
`bound_exhausted`, even when exact byte/hash/EOF checks pass. The default ceiling
exceeds the configured 100 Mbit/s path's twelve-second offered-byte capacity.

## Bandwidth, windows and host observations

Application probe samples every 0.5 seconds retain all flows' sent, received,
warmup, measured and post-window counters, along with length-checked Linux
`TCP_INFO` and raw struct bytes:

- Actual sender congestion window in bytes is `tcpi_snd_cwnd * tcpi_snd_mss`.
- RTT, RTT variance, total retransmitted segments and 64-bit acknowledged, sent
  and retransmitted byte counters are separately labelled.
- `tcpi_snd_wnd` is the kernel-maintained scaled peer advertised receive window
  in bytes. `tcpi_rcv_wnd` is the scaled local advertised receive window. These
  nullable suffix fields are sampled TCB observations, not every wire packet.
  Older kernels lacking the fields report `null`.
- `tcpi_rcv_space` remains a distinct local receive-space estimate. Neither it
  nor internal tunnel credit is called native cwnd or advertised rwnd.

The harness records bounded `ss -tinm` for application namespaces and endpoint
outer/proxy sockets, native TCP defaults, congestion-control names, socket buffer
sizes, process CPU ticks/RSS, probe CPU/RSS samples and common-host load averages.
For measured proxy, bounded actual shared API status records requested/effective
capabilities and aggregate controller state. Other frontends retain their actual
post-authentication CLI readiness markers; unavailable shared API status is
explicit rather than inferred from a profile enum.

Per-interval owned WAN TX/RX byte counters have monotonic read-time brackets.
Actual byte deltas and elapsed observation time yield measured virtual-interface
Mbit/s, including outer TCP/TLS, ACKs and retransmissions. This is not physical
Ethernet line rate. Measurement-only summaries use intervals fully inside the
shared window, report covered seconds and boundary clock uncertainty, and do not
interpolate missing time. Missing coverage is `unobserved` and prevents an
otherwise successful case being classified as measured. `tc` class/qdisc
cumulative normalized observations (strict class JSON or observed HTB text;
strict qdisc JSON) and byte/packet/drop deltas are also saved. Whole-transfer tc
deltas include warmup and post-window drain and are explicitly not ten-second
application-window counters; drops and interface accounting have distinct scopes.

## Finite ownership and evidence

There are at most two daemon and two probe children, 96 harness samples and 256
probe samples. Each child log is limited to 4 MiB by `RLIMIT_FSIZE`; the atomic
receipt is limited to 4 MiB, each command has bounded captured output, and no
packet capture runs in this first version. Probe work ends at its original
30-second deadline. All owned processes stop before identity-checked namespace
cleanup. Daemon termination after exact application EOF is labelled test cleanup,
not proof of graceful tunnel drain. Failed/time-limited/unsupported observations
remain separate receipts; no threshold is tuned into a throughput superiority
claim.

The [current focused receipt](../../work/native-throughput23c/validation.json) records exact
source hashes and actual commands. Loopback tests exercise IPv4 1/2/4-flow and
IPv6 bidirectional transfers, exact hashes/EOF, byte-ceiling exhaustion, nullable
TCP_INFO suffixes, cwnd units, atomic clock publication, drain exclusion,
WAN/tc accounting, immutable helper checks and a mutation-free dry run. Reused
namespace and proxy helper suites run without production edits. Full frozen
workspace checking and privileged native performance cases belong to the
integrator's separate receipts.

- [x] [MOD-NATIVE-SPEED-01] Specify explicit profiles, shared bottleneck/path parameters, monotonic receive-goodput windows and separate native window/credit domains. Evidence: [harness](../../tools/native_throughput.py), [probe](../../tools/throughput_probe.py).
- [x] [MOD-NATIVE-SPEED-02] Implement finite real TCP probes, copied-build/helper verification, journal-owned setup/cleanup and bounded bandwidth/window/resource observations. Evidence: [source](../../tools/native_throughput.py), [tests](../../tools/test_native_throughput.py), [receipt](../../work/native-throughput23/validation.json).
- [ ] [MOD-NATIVE-SPEED-03] Execute immutable serial TAP/TUN native cases and independently audit exact payload/EOF, actual measurement windows, bandwidth/windows and owned cleanup.

- [x] [MOD-NATIVE-SPEED-04] Select one validated WAN measurement policy across all benchmark paths and prove old/new 70ms Echo and absolute overdue behavior through actual unchanged Rust Controller/Owner APIs. Evidence: [policy function](../../tools/native_throughput.py), [actual-controller proof](../../work/wan-policy23c/RECEIPT.md), [scoped receipt](../../work/native-throughput23c/validation.json). Native fresh-service qualification remains part of MOD-NATIVE-SPEED-03.
- [x] [MOD-NATIVE-SPEED-05] Parse the observed iproute2 HTB text format strictly, preserve raw diagnostics and distinguish tool incompatibility from product failure. Evidence: [real diagnostic](../../work/throughput23-tc-diagnostic/receipt.json), [tests](../../tools/test_native_throughput.py), [scoped receipt](../../work/native-throughput23c/validation.json). Corrected native execution remains separate.
