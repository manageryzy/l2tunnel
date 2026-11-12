# Original raw packet native acceptance

Status: four clean Linux integrity-mode TAP/TUN full/half packet-phase cases are
integration-tested and independently audited. The [original native opener](raw-native-packet.md),
[explicit runtime](raw-runtime.md) and [shared client selection](raw-packet-client.md)
are separate implementation evidence. Retained raw TCP/TLS defaults remain intact.
The [checkpoint 18 plan](../../work/raw-packet-native18/PLAN.md) defines four clean
TAP/TUN full/half cases and a later integrator-owned immutable native execution.

The initial matrix explicitly selects HMAC/integrity and selective repeat. This
allows bounded offline structural inspection of protected phase headers and Data
without exporting keys. Capture inspection does not verify HMAC; real runtime
native delivery and peer confirmations plus exact end-to-end bytes establish the
observed authenticated session outcome. AEAD, impairment, congestion, PMTU/NAT,
platform qualification and broad interoperability are separate gates.

The harness defaults to dry run with no process, filesystem or network mutation.
Apply requires an exact immutable binary/build receipt and copied helpers, then
creates only journal-owned namespaces. It prearms underlay/native captures,
requires original SYN/TLS and phase sequence continuity on the same lane tuples,
matching Active session status and no kernel stream ownership, exact IPv4/IPv6
native packets and TCP bytes/EOF, and all-lane protected Data. It then deliberately
loses the carrier in owned namespaces and requires both peers' natural bounded
TimedOut failures. Forced process cleanup cannot satisfy this requirement.
Outer FIN/RST absence and descriptor/port/namespace release remain capture and
ownership checks, not a successful graceful-close claim. This runtime has no
protected clean-drain protocol.

- [x] [MOD-RAWPKTNATIVE-01] Implement dry-run-default four-case plans, strict native profile/status/terminal/capture parsers and bounded journal-owned lifecycle with immutable build/helper provenance. Evidence: [checkpoint 18](../../work/raw-packet-native18/final/REPORT.md); executable native acceptance remains separately gated below.
- [x] [MOD-RAWPKTNATIVE-02] Pass focused unprivileged parser, ownership, denial, dry-run and finite fake lifecycle tests; preserve failed/unsupported/bound-exhausted/tool-failure distinctions. Evidence: [checkpoint 18](../../work/raw-packet-native18/final/REPORT.md), 16 new and 45 reused helper tests passed; all four supervisor cases use explicit fake clocks/processes and are not native execution.
- [x] [MOD-RAWPKTNATIVE-03] Pass integrator-reviewed source-stable build and required `python3 tools/check.py` with this harness included before any native qualification claim. Evidence: [immutable source 18 aggregate](../../work/implementation-wave18/validation.json), 620 stable inputs, 987 Rust and 142 Python cases; [exact native build 18](../../work/native-build18/receipt.json), daemon SHA-256 `99c03eee25eda37a6e4940cc9622144dcd0623046e93f5b1e1e1fe138f83a6cb`. This certifies the frozen checkpoint 18 harness; later auditor corrections require their own reviewed source provenance.
- [x] [MOD-RAWPKTNATIVE-04] Execute and independently audit four clean native TAP/TUN full/half cases: original tuple/sequence/TLS ownership, actual phase Data, exact IPv4/IPv6 packets/TCP bytes, natural bounded carrier-loss failure and complete owned cleanup. Evidence: [independent four-case audit](../../work/raw-native-matrix19-audit.json), three source18 executions with corrected source19 structural readback and [new TAP half execution](../../work/native-raw-packet19-tap-half/receipt.json); [source19 required aggregate](../../work/implementation-wave19/validation.json) and [exact build](../../work/native-build19/receipt.json). Original failed receipts are preserved; this gate does not claim graceful close or broader path behavior.
- [ ] [MOD-RAWPKTNATIVE-05] Separately qualify AEAD, impairment, congestion, PMTU/NAT/middleboxes, protected clean close, hot switching and broader platforms; the clean integrity matrix cannot satisfy these gates.
- [x] [MOD-RAWPKTNATIVE-05A] Add explicit `--suite aead` plans and a separate bounded opaque-capture auditor; pass downgrade, length, sequence/counter reuse, window, peer identity and copied-launcher regressions. Preserve the integrity default and its stronger visible-Hello checks. Evidence: [scoped source20 receipt](../../work/raw-aead-native20/validation.json), 29 raw and 68 combined unprivileged cases passed; no native execution is implied.
- [ ] [MOD-RAWPKTNATIVE-05B] Pass the required aggregate and exact build, then execute and independently audit AEAD TAP/TUN full/half cases with exact native bytes, original lane ownership, authenticated delivery fences, bounded natural carrier-loss failure and owned cleanup.

## Additive AEAD native profile

The explicit suite selects `packet.protection` on both peers and is included in
their existing authenticated configuration digest. Integrity remains the default;
AEAD uses distinct owned namespace names and a separate fresh output directory.
The immutable copied launcher must retain the requested suite. Payload sizes,
capture limits, deadlines, original descriptor checks and delivery/cleanup gates
are identical across suites.

The AEAD capture auditor reads only the clear datagram header: version, suite,
direction, session, lane, epoch, packet number and bounded encrypted length. It
reconstructs the original SYN and complete TLS stream, checks the no-SNI hello,
and requires packet-phase sequence allocation to continue at the original TLS
boundary without counter/range reuse or wrap. The unchanged advertised horizon
must follow from original TCP window witnesses and negotiated SYN scaling.
Visible ACKs must name the original peer boundary or an observed peer packet end.
Both captures must agree on bootstrap/session identity and contain identical
opaque packets on every lane and direction. Intentional final carrier loss may
produce different counter tails.

The complete observed counter prefix and contiguous allocation requirement is a
conservative clean-lab gate. Production may expire an allocated but unsent control
packet; a resulting gap fails this gate without proving nonce or range reuse.
ACK endpoint membership is a geometry check, not a packet-timestamp causality or
encrypted retirement proof.

Encrypted Hello/Commit/Data kinds, internal retirement offsets and authentication
tags cannot be inspected without keys. This auditor does not decrypt, infer
confidentiality from entropy, verify tags, or label opaque bytes as Data. Actual
authenticated session status, per-lane native delivery fences and exact native
packet/TCP bytes remain independent acceptance requirements. AEAD runtime
cryptographic negative tests are separate from this structural capture check.

The first four native checkpoint 18 runs remain failed observations. TAP/TUN full
and TUN half reached exact native delivery and natural bounded terminal failure,
but the original capture auditor incorrectly required the requested 32,768-byte
horizon instead of the original TCP window's effective 18,560-byte horizon. TAP
half stopped at startup because descriptor observation preceded the RPC's Active
transition. All four owned namespace/process cleanups passed; see the preserved
[independent initial audit](../../work/raw-native18-initial-audit.json). The later
source19 TAP half rerun and independent four-case audit now complete gate 04;
they do not rewrite these original failed observations. No graceful-close claim
is made.

The [checkpoint 19 correction receipt](../../work/raw-native-audit19/final/validation.json)
preserves both deterministic before-fix failures and 21 focused passing tests.
The revised structural auditor recomputes each effective horizon from the fixed
policy, captured original SYN scale/MSS/SACK, complete all-lane Hello fences and
an actual original TCP sequence/ACK/window witness. Complementary peer proofs,
all-lane equality and every phase advertised window remain required. It does not
trust the first phase horizon or authenticate capture bytes independently. The
startup supervisor samples the same original descriptor owners again after the
actual Active status RPC; absent or replaced original descriptors still fail.
Three complete checkpoint 18 captures pass the new offline auditor with separately
recorded source/input hashes. Their original failed receipts remain intact.

The new TAP half execution uses source19's exact 629-input build. All four cases
passed an independent check of source/build/binary/helper identity, complete
capture counters, original descriptors and lane tuples, exact native payloads,
peer-delivery fences, natural timeout under deliberate 100% carrier loss, resource
release and absence of every owned namespace. Source18 and source19 executions
remain individually identified; the offline auditor supplies no independent
cryptographic verification of captured HMAC records.
