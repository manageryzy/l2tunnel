# Finite pressure WAN capture allocation

Status: implemented and contract-tested locally. Root accepted an explicit
pressure-WAN-only 32,768-packet allocation. Fixed/native/clean defaults remain
8,192. New immutable source/build and privileged pressure qualification remain
root-owned pending work; no native run used these changed helpers yet.

The immutable16b full and paired-half pressure captures reached 8,192 packets
about 5.2 seconds into each case, more than six seconds before the owned TCP
stage completed. Each file used only about 1.9 MB of its existing 32-MiB file
allowance. Traffic was approximately 1,975 packets/s with complete one-second
bins up to 3,402 packets/s. About 30–32% were empty ACKs, and more than 83% of
payload segments carried fewer than 256 opaque bytes; 26-byte payloads dominated.
Unique payload overlap was zero in full and only 26 bytes in half. Retransmission
therefore does not explain the packet volume. Runtime status before the cutoff
records approximately 800 admitted measurement records per peer. Encryption
prevents assigning each observed segment to a particular Demand/echo record.

These executed prefixes provably need additional capture beyond 8,192: at most
1.25 MB/full or 1.20 MB/half of the 3,145,732 pressure application bytes could
already have crossed the captured outer TCP streams. With no compression, at
least 1,299/full or 1,332/half additional 1,460-byte payload packets would still
be needed, even ignoring remaining framing, ACKs and later probe stages. This is
an execution-specific lower bound. The semantic payload minimum alone does not
prove every corrected-runtime execution intrinsically exceeds the old packet cap.
Original16b remains failed; its complete WAN audit stays bound exhausted.

The allocation is local evidence storage, separate from runtime behavior and
acceptance. The approved pressure profile uses 32,768 packets for each WAN
surface, retaining 8,192 for each native surface. Clean and fixed profiles retain
8,192 everywhere. Every surface keeps the existing 32-MiB file limit and capture
child RLIMIT_FSIZE; four surfaces therefore retain at most 128 MiB of capture
files. The parser bounds retained Packet rows by 81,920 across the pressure case,
with total retained IP byte arrays bounded by the same 128 MiB; a currently parsed
file adds at most 32 MiB of input bytes plus bounded per-record decoding
scratch (input record at most 65,555 bytes, accepted whole IP at most 1,500
bytes). This is a value storage bound, not a Python allocator/RSS claim. Logs/receipts, status samples,
all command/case/original drain deadlines and owned cleanup remain unchanged.

The shared fixed helper accepts an explicit validated per-call packet limit,
2..32,768, through parsing, capture counters, finishing and aggregate audit.
Default arguments stay 8,192. The measured harness derives a finite four-surface
map from its explicit profile and records it in the plan/receipt. It passes the
same selected limit to tcpdump and every read/count/audit path; it never mutates
a module global. Reaching the exact packet cap or exceeding the byte cap remains bound
exhausted. A dropped packet, truncated record or incomplete capture still
rejects the evidence. No
filtered-only capture, packet omission, automatic retry or cap growth is allowed.

One-below/exact-cap at both 8,192 and 32,768, invalid scalar/map, default
compatibility and selected-map propagation tests pass. A mocked real case body
checks tcpdump command and failure cleanup limits agree with the recorded map,
classification stays `bound_exhausted`, and a substituted profile map is rejected
before namespace setup. The full unprivileged Linux harness group passes 147
tests, including existing actual kernel loopback probes; no namespaces or host
network changes are involved. The first-reopen validator, payload/FIN/EOF proof,
actual growth/demand/pressure checks and final native/TLS fences are unchanged.
Changed helpers require a new root-frozen source/build receipt before native use;
they cannot claim immutable build18 identity.

- [x] [MOD-PRESSCAP-01] Preserve original16b packet/byte/time/class evidence and freeze reviewed independent capture-allocation contract. Evidence: [forensic proposal](../../work/native-pressure16b-audit/wan-budget-proposal.json) and [original failed audit](../../work/native-pressure16b-audit/validation.json).
- [x] [MOD-PRESSCAP-02] Implement explicit per-call limits through parser/counter/finish/audit and pressure surface map without changing historical defaults or semantic acceptance. Evidence: [unchanged acceptance/resource/deadline AST audit](../../work/proxy-pressure-capture19/unchanged-acceptance.json) and [focused receipt](../../work/proxy-pressure-capture19/validation.json).
- [x] [MOD-PRESSCAP-03] Pass focused boundary/default/propagation/safe-ownership tests and freeze exact helper hashes; root owns new aggregate/build/native qualification. Evidence: [147-test Linux group](../../work/proxy-pressure-capture19/focused-python.log) and [five-file frozen overlay](../../work/proxy-pressure-capture19/validation.json).

The [source19 aggregate](../../work/implementation-wave19/validation.json) and
[exact build](../../work/native-build19/receipt.json) passed. In subsequent
pressure executions, full WAN captures contained 24158 packets per side and
half contained 25022, below the fixed 32768 allocation, with zero kernel drops.
Native captures also stayed below 8192. These solve the observed collection
bound for these runs, not the separate growth gate: both executions still failed
because no candidate exceeded the initial 32768-byte target. See the independent
[full](../../work/native-pressure19-audit/full-audit.json) and
[half](../../work/native-pressure19-audit/half-audit.json) audits. Their failures
are preserved, and no further allocation increase or deadline change is proposed.
