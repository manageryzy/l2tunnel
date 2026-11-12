# Packed native qualification checkpoint

Status: additive harness and offline audit implementation passed focused tests,
independent source review and stable wave12. The first native attempt failed at
startup readiness; its evidence and successful cleanup are retained below.
The [packed client](packed-client.md) and shared runtime passed stable wave11;
this does not yet qualify a physical TAP/TUN/VXLAN path or multi-unit captures.

## First finite case and later expansion

The first case is one clean Linux TUN, paired-half, TLS-bootstrapped custom UDP
session with QUIC-like cover, HMAC integrity, Cauchy 4+2 with 5 ms flush, maximum
native packet 1600 and whole-underlay IP MTU 1200. Packed settings are four
channels, 1000 microseconds hold, four maximum units and work limit16. Both peers
explicitly select compression off and system traffic. Integrity is deliberate:
it makes the envelope inspectable while the actual runtime still authenticates
every datagram. An offline capture cannot by itself verify the HMAC or identity.

Keep the existing native smoke's positive IPv4/IPv6 probes, checksum-verified
65,536-byte TCP transfer, UDP interruption/negative probe/restoration, finite
timeouts and journal-owned cleanup. Record each result and both underlay captures.
Only owned namespace routes/bridges/qdiscs/offloads may change. No new clean-close,
native window-control, throughput, fairness, hard realtime or parity claim follows.

Use a new immutable daemon build and source-stable receipt, fresh output and lab
ID. Do not overwrite aligned/frame evidence. Review the first result before any
additional case; a failed case is preserved and investigated without extending
deadlines. The later finite matrix would cover TAP/TUN/VXLAN full/half on protected
UDP and genuine QUIC, then separately reviewed impairments. AEAD/QUIC captures
prove packet shape/size/path evidence only, never unencrypted packed content.

## Additive CLI and harness interface

Extend `tools/native_smoke.py` only at explicit selection points:

```text
--record-profile frame|aligned|packed
--packed-channels 1..255
--packed-hold-micros 1..1000
--packed-max-units 1..255
--packed-work-limit 1..255
--packed-auditor PATH
--build-receipt PATH
```

All four packed defaults match the client (4,1000,4,16). Reject packed flags under
other profiles, aligned flags under packed, and packed with TCP/standalone UDP,
compression, active/proxy policies or reload. Validate configured MTU geometry
through the client before network work. Preserve frame/aligned arguments, case
names and existing call signatures by adding optional trailing parameters.
For packed `--apply`, the auditor and build receipt are mandatory. Verify the
successful source-stable receipt, immutable daemon hash, additional
`packed_auditor_sha256` and copied helper hashes before namespace mutation. Copy
both executables and every used helper into the fresh output, verify copies, and
use only those snapshots. Legacy profiles retain their current build defaults.
For packed apply, the entry point itself must be the verified
`BUILD/tools/native_smoke.py`, with the receipt, daemon and auditor directly in
BUILD and all six helpers in its real `tools` directory. All inputs are regular
non-symlink files. The fresh output must be outside BUILD. This avoids loading
live workspace helper code after copying a nominal snapshot. Workspace dry runs
remain available. Snapshot/hash failures retain a bounded preflight receipt and
explicitly report that namespace mutation never started.
Dry-run validates flag compatibility and prints the required preflight; actual
packed apply invokes the auditor's validation-only mode before any namespace work.
Add the same read-only before/after expected-namespace identity observation used
by the reviewed native-drain harness: an unjournaled new/replaced/residual name
or failed observation fails cleanup evidence, even after setup rollback removed
its journal. Never adopt/delete such a name. Preserve old saved receipts.
Record the exact requested profile/settings and verify both daemon startup
messages report them. The harness does not infer selection from successful ping.
For packed UDP, set and verify MTU1200 and disabled checksum/segmentation/receive
offloads on both owned endpoint links and both owned router links. Start both
underlay captures before client authentication, require actual tcpdump readiness,
retain stderr statistics, and reject kernel drops, truncation, fragmentation or
capture packet/byte cap exhaustion. A sleep alone is not capture readiness.

The first case uses an explicit `--only-case tun-half-clean` and fresh top-level
output marked packed; the common existing scenario names need not change. Strict
unprivileged tests cover selection/rejection, exact generated peer commands,
receipt metadata and unchanged frame/aligned defaults before any privileged run.

## Small-packet evidence through the common native path

Add a bounded native UDP burst helper selected only by the packed harness. Each
side receives 64 distinct 64-byte deterministic datagrams from the other side's
original native device. Start both receivers and observe actual bind readiness
before launching the two one-shot producers. Use fresh explicit native ports and
the existing native IP addresses; no management, direct carrier or special probe
channel. Verify the exact multiset of all64 payloads per direction, including
duplicates/missing/excess, with saved SHA256 and one shared10-second absolute
observation deadline for both directions and all four helpers, begun before producer launch.
Readiness has its own prior fixed5-second bound. Both receivers continue observing
through the shared deadline after reaching64 records, so a 65th queued/late record
is rejected rather than hidden by early exit. Producers stop at that same
observation deadline. Use a separate shared result-only reap deadline one second
later (t0+11 seconds): this permits receivers to serialize the completed result
and all four children to exit, without accepting another packet, sending another
payload, retrying or extending the ten-second transfer observation. Each join
uses the remaining portion of that one reap deadline, not a new per-child timeout.
Cleanup after either deadline is recorded separately and cannot create a
successful transfer. Stop and join all helpers on every path.
This additional finite burst makes multi-unit wire observation an acceptance
condition rather than assuming that serial pings necessarily pack together.

## Exact offline capture verification

Do not scan arbitrary packet bytes for `L2PK` magic. Parse the actual pcap and
Ethernet/IP/UDP path, reject truncation/fragmentation, and enforce the recorded
whole-IP MTU and expected endpoint/lane tuples. For the first visible-integrity
profile, validate the fixed cover/header/version/suite/length and strip exactly
the declared payload and trailing32-byte HMAC. No key extraction or crypto
bypass is involved: this is a structural audit, explicitly not tag verification.
Custom UDP half uses port24440 only from A to B and port24441 only from B to A;
its bootstrap/control stays on TLS. Genuine QUIC half has handshake/control in
both directions on both ports. Capture parsing must select the actual carrier's
tuple set and retain it in evidence, rather than requiring reverse UDP traffic
on a direction-disabled custom lane.

A small offline Rust example under `l2tunnel-client-core/examples/` accepts
bounded length-prefixed complete UDP payloads plus fixed negotiated geometry
and reported direction. It derives geometry through `packed::udp_config` from
the exact client settings, including default runtime queues; a validation-only
mode performs this before namespace/socket work. Local dev-dependencies on the
already present reliable/recovery/FEC crates are sufficient; add no production
dependency or cryptographic provider. It uses the existing reliable/FEC/ARQ inspectors and
`l2tunnel_codec::packed_envelope::decode` for the exact nested source, with no
receiver, replay admission, recovery reconstruction or live socket. Direct ARQ
copies and actual FEC systematic vectors may expose complete sources; repair
equations are counted separately and never searched for apparent inner magic.
Cross-check original recovery source ID, packed source ID, scope, unit range,
record IDs, channel count, lengths, padding and each complete inner unit. Scope
fields are untrusted observations for structural consistency, never manufactured
authentication authority. The audit tool must say so in its result.

Cap each input record at the configured physical payload ceiling, record count
at4096 and total input at8 MiB. Reject trailing, oversized or malformed input
before unbounded allocation. Summarize sources and multi-unit sources by original
direction, maximum units, unit kinds and observed context/fragment records.
Require at least one valid multi-unit source in each direction containing two
complete kind-2 raw-IP units with distinct `(channel, absolute record ID)` pairs,
and no malformed captured source. Merely packing multiple context/fragment units
of one record does not prove native packet aggregation. Report other multi-unit
framing separately. Deduplicate repeated source identities before statistics and
reject conflicting bytes under one identity; retransmissions are not new packing
events. Bind results to capture, verifier, daemon and helper hashes.

Use exact fixtures emitted by production maintained encoders to test direct,
systematic, repair, wrong-scope, malformed nested length, literal magic in user
payload and repeated/conflicting-source cases. A passing decoder is structural
evidence; actual authenticated runtime delivery and exact native payload receipts
remain separate acceptance conditions.

## Verifier interface

The executable is `packed_capture_audit`, with exactly `validate --config PATH`
and `audit --config PATH --input PATH`. Both emit one bounded JSON result.
Configuration files are at most 8192 bytes and contain only these required fields:
`version` (1), `layer` (`tap` or `tun`, with VXLAN mapped to `tap`), `duplex`
(`half` or `full`), `carrier` (`udp` or `quic`), `path_mtu`, `max_packet` (1600),
`channels`, `hold_micros`, `max_units`, `work_limit`, `fec_sources`,
`fec_repairs`, `fec_flush_ms`, `cover`, and `protection`. UDP requires
`quic-like`/`openvpn-like` cover and `integrity`/`aead` protection; genuine QUIC
requires both fields to be null. Validation uses the actual public client
geometry and reports `scope: configuration-only`. It establishes no authenticated
binding or native support. Audit currently rejects AEAD and genuine QUIC.

The validation `geometry` object contains `underlay_ip_version` (4),
`outer_overhead_bytes`, `udp_payload_ceiling`, `recovery_packet_ceiling`,
`recovery_source_bytes`, `fec_source_bytes`, `fec_packet_ceiling`,
`packed_header_bytes`, `record_id_bytes`, `symbol_bytes`, `channels`, `max_units`,
`max_fragments_per_record`, `native_queue_packets`, and `native_queue_bytes`.
These values come from the public client configuration. The offline construction
uses fixed IPv4 endpoint placeholders, and a nonzero placeholder ALPN for QUIC,
solely to obtain geometry without opening sockets. This does not validate actual
endpoint identity, ALPN negotiation or an authenticated configuration digest.
An IPv6 underlay needs a separately explicit configuration/interface extension.

Audit input contains at most 4096 records and 8 MiB total. Each record starts with
a four-byte prefix: complete UDP payload length as a big-endian u16, original
direction (0 for A to B, 1 for B to A), and one zero reserved byte. The exact UDP
payload follows, including cover, LD header and integrity tag. The Python capture
reader supplies direction from the validated endpoint IP, not a searched marker.
For this fixed UDP runtime, each recovery owner and its outer LD owner use the
same actual TLS lane session ID. Freeze the logical scope independently in each
direction and require its session to equal that packet's physical lane session.
Full duplex shares one session across directions; paired half duplex requires two
distinct sessions. Epoch remains one. These are observed structural bindings,
not tag verification or a proof of the authenticated pairing exchange. The prior
single logical-session assumption was contradicted by the second native attempt
and is corrected below.

Successful audit JSON contains `version: 1`, `status: passed`,
`scope: structural-only`, and `directions` ordered 0 then 1. Each direction has
an explicit `direction` (0 or 1) and exactly `sources`, `multi_unit_sources`, `complete_packet_aggregation_sources`,
`max_units`, `direct_copies`, `systematic_copies`, `repair_packets`, and
`duplicate_sources`. The harness requires positive complete-packet aggregation
in both directions for the visible-integrity first case. The auditor can report
zero when the bounded capture simply contains no qualifying source.
This initial metric counts only configured TUN kind-2 complete raw IP units,
using their declared aligned raw length and the maintained native IP classifier.
For TAP, kind 2 contains the original whole Ethernet frame. The additive
[complete Ethernet witness](packed-ethernet-audit.md) uses the maintained
VLAN-inclusive header and declared IP/ARP extent, with only the reviewed exact
or minimum-padding rule. It does not guess an IP offset or reinterpret codec
fragments as packets. Native TAP/VXLAN acceptance remains separately pending.

## Checklist

- [x] [MOD-PACKNATIVE-01] Independently review first-case scope, additive arguments, finite burst deadlines and exact structural audit path before implementation. Evidence: independent harness review accepted the fixed ten-second observation plus shared one-second result-only reap, pre-authentication capture readiness, actual four-link MTU/offloads, immutable build/helper identity, and complete distinct packet aggregation; [frozen verifier interface](#verifier-interface) separates structural observations from authentication.
- [x] [MOD-PACKNATIVE-02] Implement strict opt-in harness selection and exact startup/receipt settings while retaining frame/aligned defaults. Evidence: [additive harness](../../tools/native_smoke.py), [30 Python harness tests](../../work/packed-native-python-review-fixes/validation.json); independent source review accepted corrected carrier-specific lane expectations, immutable helper-tree execution, preflight failure receipts and namespace residual observations.
- [x] [MOD-PACKNATIVE-03] Implement bounded native burst helper with exact bidirectional multisets and owned-process cleanup. Evidence: [bounded helper](../../tools/udp_burst_probe.py), [eight tests including the real four-process loopback](../../tools/test_udp_burst_probe.py), [focused receipt](../../work/packed-native-python-checkpoint/validation.json); independent source review accepted the original shared observation/reap deadlines, fixed bitmap, late/excess rejection and cleanup.
- [x] [MOD-PACKNATIVE-04] Implement bounded offline maintained-parser audit with direct/systematic nesting, deduplication, malformed/conflict rejection and explicit nonauthentication scope. Evidence: [offline auditor](../../crates/l2tunnel-client-core/examples/packed_capture_audit.rs), [128 affected-package tests and CLI checks](../../work/packed-capture-audit/validation.json); independent source review accepted maintained structural inspectors, exact nested geometry, source deduplication, cross-symbol FEC generation consistency and explicit structural-only results.
- [x] [MOD-PACKNATIVE-05] Pass unprivileged parser/harness tests, strict Rust lint/docs and independent source review before a privileged case. Evidence: [source-stable wave12](../../work/implementation-wave12/validation.json) passed 787 Rust and 105 Python cases, strict workspace lint/docs and CLI/golden checks; [immutable build12](../../work/packed-native-build12/receipt.json) uses exactly the aggregate's checked source map and retained helper hashes.
- [ ] [MOD-PACKNATIVE-06] Build immutable reviewed binaries and run the one clean TUN/half visible-integrity case under unchanged bounds; retain exact captures, payloads, both-direction multi-unit evidence and cleanup.
- [ ] [MOD-PACKNATIVE-07] Independently audit the first receipt and review a finite later TAP/TUN/VXLAN/carrier/impairment matrix before expansion.
- [x] [MOD-PACKNATIVE-08] Correct actual full/half UDP lane scope bindings in the offline auditor and fixtures, add substitution regressions, and independently inspect the unchanged failed capture without rewriting its native verdict. Evidence: [independent source/capture review](../../work/packed-scope-review13/REPORT.md), [focused strict checks and offline reinspection](../../work/packed-scope-fix13/validation.json), twelve passing auditor tests including three new session-substitution regressions. Both unchanged captures show eighteen/twenty complete-packet aggregation sources in the two directions. Native run13 remains failed; a fresh stable build/native acceptance is separate.

## First native attempt

The [first TUN/half attempt](../../work/packed-native-first-tun-half12/receipt.json)
used the exact source-stable [build12](../../work/packed-native-build12/receipt.json).
Geometry validation, fresh namespace checks, four-link MTU/offload setup,
pre-authentication capture readiness and actual two-peer authentication completed.
Both daemon logs reported the requested packed settings. The harness then waited
for its existing `recovery Cauchy` startup marker, which the packed CLI branch
did not print. Its original readiness deadline expired before payload probes or
the small-packet burst ran. This is a failed acceptance, not a forwarding result.

The original logs, two partial captures and failed receipt remain unchanged.
Owned cleanup passed and all five independently observed namespace names were
absent afterward. An [independent audit](../../work/packed-native-readiness-fix12/failure-audit.json)
verified the build, six helpers, 502-entry source map, captures and all 20
unchanged historical files. Both packed CLI branches now print their actual
`profile.recovery`; [ten existing CLI tests and formatting](../../work/packed-native-readiness-fix12/validation.json)
passed. The readiness check and deadlines are unchanged. The correction is now
included in [source-stable wave13](../../work/implementation-wave13/validation.json)
(805 Rust and 105 Python cases) and its [exact immutable build13](../../work/packed-native-build13/receipt.json).
A fresh native output is still required for the retry. No later
TAP/TUN/VXLAN/carrier/impairment expansion is authorized by the failed first case.

## Second native attempt and scope correction

The [second TUN/half attempt](../../work/packed-native-tun-half13/receipt.json)
used [build13](../../work/packed-native-build13/receipt.json). Startup, twelve
IPv4 and six IPv6 probes, the 65,536-byte TCP checksum, both 64-by-64-byte UDP
bursts, and the existing negative/restoration path probe completed under their
original bounds. Offline capture inspection then failed with `logical recovery
scope changed`; the native acceptance therefore remains failed. Owned cleanup
passed, with all five namespace names observed absent and no unaccounted changes.

Two independent source reviews traced each packed recovery context and outer LD
context to the same actual lane's TLS session. Half pairing explicitly rejects
equal lane sessions. The auditor instead retained one logical session across
both directions, and its synthetic fixtures incorrectly used unrelated physical
and logical IDs. The [maintained-parser capture diagnosis](../../work/packed-scope-review13/a-contexts.json)
observed 369 packets per endpoint capture, with stable but distinct half-lane
sessions: 223 packets in direction zero and 146 in direction one. All observed
recovery session IDs equal their own outer LD session; 237 direct/systematic
source copies also pass maintained packed-envelope scope decoding. This is
structural evidence only, without HMAC verification.

The correction requires layer equality within each lane, freezes scopes per
direction, and checks full shared versus half distinct sessions. Original failed
receipts and captures remain unchanged. [Focused correction checks](../../work/packed-scope-fix13/validation.json)
passed all client/example tests, formatting, strict all-target Clippy and rustdoc,
with stable affected inputs. Corrected offline inspection of both saved captures
found eighteen complete-packet aggregation sources in direction zero and twenty
in direction one, with at most four units per source and whole-IP packets no
larger than 1176 bytes. This reinspection is separate from a fresh source-stable
build and native acceptance, and does not change the original failed verdict.
