# Original raw packet native acceptance

Status: harness implemented with finite unprivileged contract tests; no native packet-phase qualification
is claimed. The [original native opener](raw-native-packet.md),
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
- [ ] [MOD-RAWPKTNATIVE-03] Pass integrator-reviewed source-stable build and required `python3 tools/check.py` with this harness included before any native qualification claim.
- [ ] [MOD-RAWPKTNATIVE-04] Execute and independently audit four clean native TAP/TUN full/half cases: original tuple/sequence/TLS ownership, actual phase Data, exact IPv4/IPv6 packets/TCP bytes, natural bounded carrier-loss failure and complete owned cleanup.
- [ ] [MOD-RAWPKTNATIVE-05] Separately qualify AEAD, impairment, congestion, PMTU/NAT/middleboxes, protected clean close, hot switching and broader platforms; the clean integrity matrix cannot satisfy these gates.
