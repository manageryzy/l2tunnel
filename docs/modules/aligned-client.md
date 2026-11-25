# Explicit aligned record client selection

Status: implemented and locally tested; the first clean TAP/full/genuine-QUIC
native case and all 18 fixed native matrix cases passed. Existing frame/fragment
clients remain the default. This slice selects the already implemented
[aligned runtime](aligned-runtime.md); it does not introduce another runtime or
change its recovery, codec, ordering, native credit or control behavior.

## Reviewed interface and compatibility

Add `--record-profile frame|aligned`, default `frame`, and
`--aligned-channels 1..256`, default four when aligned is selected. The channel
option is rejected for frame records. Aligned requires explicit `--carrier udp`
or `--carrier quic`, explicit `--fec cauchy`, `--compression off`, and system
traffic. Local control sockets, active TUN/active catalogs and compression reload
are rejected before credential/device I/O. Existing explicit lane endpoints,
UDP cover/protection, genuine QUIC application ID, native TAP/TUN/VXLAN selection,
path MTU and full/paired-half contracts remain authoritative. No profile falls
back to another carrier, recovery mode or record format.

TAP/VXLAN use the aligned runtime's Ethernet body selection, including exact raw
fallback. TUN uses its explicit raw-IP body and ordinary bounded DRR. This option
does not rewrite endpoint TCP headers/windows or compose adaptive credit control.
All packet types retain the same common MUX/channel pool. Global recovery source
ordering and fixed CRC32 mapping remain explicit limitations.

New `client_core::aligned` is UI independent:

```text
Settings { channels: u16 }
udp_config(ConnectionConfig, udp::Settings, Settings)
    -> Result<(runtime::udp::Config, runtime::aligned::Config)>
quic_config(ConnectionConfig, quic::Settings, Settings)
    -> Result<(runtime::quic::Config, runtime::aligned::Config)>
connect_udp/accept_udp(existing credentials and endpoints, ConnectionConfig,
    udp::Settings, Settings) -> Result<(aligned::UdpLink, udp::Config, aligned::Config)>
connect_quic(existing roots/name/member, ConnectionConfig, quic::Settings, Settings)
    -> Result<(aligned::QuicLink, quic::Config, aligned::Config)>
QuicListener::bind(certs, key, ConnectionConfig, quic::Settings, Settings)
QuicListener::accept(allowlist)
    -> Result<(aligned::QuicLink, quic::Config, aligned::Config)>
```

Narrow private UDP/QUIC lane-establishment helpers accept the authoritative
validated aligned carrier/base bindings and return actual authenticated carrier
ownership. Existing public client APIs continue selecting the original frame
binding and constructors. Both lane sockets bind before authentication, second
lane deadlines stay finite, fixed peer checks and random authenticated pair proof
remain unchanged. No native device opens before authentication/pair construction.

## Validation and native qualification

The 25 client tests pass, including six new focused tests. Real client entry
points authenticate and forward exact 1600-byte packets in both directions across
eight UDP/QUIC × TAP/TUN × full/half combinations. Both carriers reject mismatched
channel counts during authentication. Original frame clients still authenticate
full/half pairs through the refactored helpers, and a spent QUIC pair deadline
cannot restart. Configuration tests cover explicit Cauchy, compression/channel/
MTU limits, digest separation and incompatible CLI mixtures. These are loopback
carriers with memory devices, separate from the native receipt below.

Executed: `cargo test --offline -p l2tunnel-client-core` (25 passed),
`cargo clippy --offline -p l2tunnel-client-core --all-targets --no-deps -- -D warnings`,
warning-denied `cargo doc --offline -p l2tunnel-client-core --no-deps`, and
`python3 -m unittest tools.test_native_smoke -v` (11 passed). The client-only lint
deliberately excludes concurrent unfinished runtime proxy work; it is not a whole
workspace lint receipt. The coordinated aggregate remains a separate gate.

The initial native case used one clean TAP/full/genuine-QUIC aligned session with
explicit Cauchy 4+2, 5 ms partial flush, four channels and compression off. Its
[receipt](../../work/native-aligned-first-quic/receipt.json) passed: 12 IPv4 and six
IPv6 single-probe checks, exact 65,536-byte TCP SHA-256, observed TCP-block rules,
UDP-drop failure plus recovery after rule removal, and owned cleanup. The
[capture audit](../../work/native-aligned-first-quic-audit.json) verifies every
saved UDP/IP length, no captured truncation/fragmentation and a maximum of 1500
whole-IP bytes. This does not claim throughput or a graceful tunnel shutdown.
The fixed matrix passed all nine [protected UDP QuicLike AEAD cases](../../work/native-aligned-udp-matrix/receipt.json)
and all nine [genuine QUIC cases](../../work/native-aligned-quic-matrix/receipt.json):
TAP/TUN/VXLAN × clean full/half and 70 ms/15% half duplex. Every case retained
four channels, Cauchy 4+2 with 5 ms partial flush, compression off, 1500-byte outer
IP MTU, existing 30-second single-ping bounds, 45-second TCP I/O inactivity and
50-second sender-process bound. Every receipt reports owned cleanup passed;
there are no failed or unrun cases in this declared matrix. No automatic retry
or deadline increase occurred.

Both matrices use immutable binary SHA-256
`e23bccaeeebf20e56f50b917ee9de19de284f1e0a37046b0fdfe0a8307ff3e81`;
the separate first integration gate used the earlier behavior-equivalent build
recorded in its own receipt, before the private configuration-borrow lint fix.
The [independent audit](../../work/native-aligned-matrix-audit.json) checks all 19
saved cases (the first gate plus the matrix): exact payload/probe counts, actual
netem drops for every impaired case, real UDP interruption/restoration, retained
TLS for protected UDP versus blocked TCP for genuine QUIC, exact physical lane
ports, complete captured packet lengths and immutable hashes. Across the two
matrices it checks 25,212 captured packets, all at most 1500 whole-IP bytes and
without captured truncation or IP fragmentation. Captures have a finite packet
cap and do not establish complete all-wire accounting. VXLAN cases explicitly
disable checksum/segmentation offloads on the owned kernel VTEP boundary.

These are finite Linux forwarding/path tests. They do not qualify throughput,
Windows/Android devices, graceful drain, early-short gap bypass, packed/sliding
FEC modes, adaptive TUN composition or hot reload. The [coordinated wave7 aggregate](../../work/implementation-wave7/validation.json)
also passed after this slice with source stability confirmed.

## Checklist

- [x] [MOD-ALCLIENT-01] Review additive options, strict compatibility, UI-independent API and bounded qualification before code. Evidence: [reviewed design](#reviewed-interface-and-compatibility).
- [x] [MOD-ALCLIENT-02] Implement canonical aligned configuration and actual authenticated UDP/QUIC client lane assembly without changing default-frame wire behavior. Evidence: [client (retired in Common cutover)](compact-wire-cleanup.md), [authenticated regression tests (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-ALCLIENT-03] Expose strict CLI selection and actual aligned runtime dispatch before native device use. Evidence: [CLI and rejection tests](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-ALCLIENT-04] Pass focused bounds/configuration/authentication regression tests and strict client lint/docs checks. Evidence: [executed checks](#validation-and-native-qualification), [tests (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-ALCLIENT-05] Extend the owned native harness and pass the first clean integration case with immutable artifacts. Evidence: [harness](../../tools/native_smoke.py), [first receipt](../../work/native-aligned-first-quic/receipt.json), [audit](../../work/native-aligned-first-quic-audit.json).
- [x] [MOD-ALCLIENT-06] Qualify the fixed native carrier/layer/duplex/impaired matrix, preserving every failed or unrun case. Evidence: [UDP nine cases](../../work/native-aligned-udp-matrix/receipt.json), [QUIC nine cases](../../work/native-aligned-quic-matrix/receipt.json), [independent audit](../../work/native-aligned-matrix-audit.json).
- [x] [MOD-ALCLIENT-07] Record a coordinated stable aggregate after client/native source handoff. Evidence: [wave7 source-stable validation](../../work/implementation-wave7/validation.json), 549 Rust cases including doctests and 39 Python tool tests.
