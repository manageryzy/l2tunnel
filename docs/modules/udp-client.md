# Explicit UDP client selection

Status: implemented, unit-tested and qualified on native Linux for both custom
covers and both protection suites. This extends the shared headless client and CLI and consumes
the authenticated UDP carrier and device runtime. It does not add a second
protocol implementation to the CLI. Each cover/suite has its own native receipt.

## User configuration and early validation

`--carrier tcp|udp` defaults to `tcp`. UDP additionally requires explicit
`--udp-bind IP:PORT`, `--udp-peer IP:PORT` and
`--udp-cover openvpn-like|quic-like`. `--udp-protection aead|integrity` defaults
to authenticated encryption. Integrity mode still authenticates/replay-protects
every data packet; the retained TLS control channel remains encrypted.
`--path-mtu` defaults to 1500 and applies to the complete outer IP packet.

Default half duplex uses two independently authenticated UDP lanes. It requires
`--udp-reverse-bind IP:PORT` and `--udp-reverse-peer IP:PORT`; ports are never
silently incremented. Forward means initiator to listener on both hosts, so the
second pair always carries listener to initiator. Full duplex uses the first
pair and rejects redundant reverse endpoints. Each side's bind pair must be
distinct; unspecified/zero/multicast addresses and mismatched families fail.
Unsupported carrier strings and UDP-only options on TCP fail before connecting.

TCP listener/remote, certificate trust, no-SNI server-name verification and member
identity remain required for the UDP bootstrap. UDP endpoints are trusted local
configuration and are never learned from unverified datagrams. Initial runtime,
recovery, packetization, direction and protection settings are bound into member
authentication before any device packet is accepted. There is no unauthenticated
fallback or downgrade. Raw TCP remains an explicit unsupported selection until
its implementation and path qualification exist.

The first UDP runtime profile fixes compression for the session. A local hot
switch API must report unsupported for this profile until its real epoch/barrier
implementation is integrated. The CLI must not expose TCP's managed handle as
if it controlled the UDP data path. Status and diagnostics should name actual
`udp-over-tcp-tls-bootstrap`, cover resemblance, suite and lane count.

## Optional block FEC extension

Design before integration: add `--fec none|cauchy`, default none, for UDP only.
Cauchy uses explicit `--fec-sources` and `--fec-repairs` (defaults 4 and 2) plus
`--fec-flush-ms` (default 5). These knobs are forbidden with none or TCP. Shared
`udp::Settings` carries `runtime::udp::RecoveryMode`; its `with_recovery` builder
recalculates exact MTU/ARQ source bounds and binds all derived limits before auth.
Runtime validation caps source/repair counts and requires flush before initial RTO.
The frontend does not duplicate that budget algorithm. This is bounded systematic
Cauchy repair with selective-repeat fallback, not completion of every Python FEC
mode. Native tests must run the selected profile; enum/configuration alone is not
evidence of FEC data-path use.

- [x] [MOD-UCLIENT-07] Bind explicit optional Cauchy settings through the shared client runtime builder and reject incompatible CLI combinations. Evidence: [settings builder](../../crates/l2tunnel-client-core/src/udp.rs), [binding/CLI rejection tests](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-UCLIENT-08] Qualify actual selected native Cauchy TAP/TUN/VXLAN forwarding and retain exact configuration/binary receipts. Evidence: [36-case Cauchy audit](../../work/native-fec-matrix-audit.json).

## Lifecycle and ownership

The client core owns endpoint validation, bounded socket setup/auth deadlines,
the full or paired carrier assembly and error conversion. The runtime owns
continuous TLS liveness/feedback and UDP forwarding. Device creation/attachment
remains the existing platform boundary. Failure to authenticate or bind either
half closes all partially established connections and does not start forwarding.
No silent TCP fallback is performed for an explicitly selected UDP profile.

The native lab will use explicit endpoint UDP ports inside its existing owned
namespaces. It will test TAP/TUN, full/paired-half, both covers and both suites,
actual payload checksums, MTU fragmentation and loss/reorder. TCP control being
reachable is not proof that UDP data traversed the configured path; UDP qdisc/
capture counters and a failed-path case must establish the data transport.

- [x] [MOD-UCLIENT-01] Implement strict explicit carrier/profile/address validation before network/device work. Evidence: [shared settings and validation](../../crates/l2tunnel-client-core/src/udp.rs).
- [x] [MOD-UCLIENT-02] Compose retained authenticated full/paired-half UDP sessions with shared client APIs. Evidence: [client assembly](../../crates/l2tunnel-client-core/src/udp.rs), [native receipt](../../work/native-udp-buffer/receipt.json).
- [x] [MOD-UCLIENT-03] Route the Linux CLI to the actual UDP runtime and expose precise supported behavior. Evidence: [CLI](../../crates/l2tunnel-client-core/src/cli.rs), [native receipt](../../work/native-udp-buffer/receipt.json).
- [x] [MOD-UCLIENT-04] Test wrong profile, incomplete half pairing, bad endpoints and forbidden TCP/UDP option mixtures. Evidence: [settings tests](../../crates/l2tunnel-client-core/src/udp.rs), [CLI option tests](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-UCLIENT-05] Run owned TAP/TUN/VXLAN UDP integrity/MTU/loss qualification with transport evidence. Evidence: [36-case capture and receipt audit](../../work/native-udp-matrix-audit.json), [native matrix](#initial-native-receipt).
- [ ] [MOD-UCLIENT-06] Add UDP data-mode hot switches, controlled fallback, standalone UDP bootstrap and native Windows/Android qualification.

## Initial native receipt

[QuicLike/AEAD](../../work/native-udp-buffer/receipt.json) passed all nine
TAP/TUN/VXLAN clean-half, clean-full and impaired-half cases. Path MTU was 1200;
1200-byte inner ICMP payloads exercised tunnel fragmentation. Each case verified
IPv4/IPv6 replies and a 65,536-byte TCP transfer by SHA-256. Underlay captures
recorded actual UDP. Dropping only UDP inside the owned endpoint namespace stopped
the data probe while both endpoint processes and the expected TLS control sockets
remained alive; removing that filter restored the probe. Cleanup passed.

The [first failed run](../../work/native-udp-quic-aead/receipt.json) is retained:
the native adapter required its 65,536-byte receive sentinel even when negotiated
packet size was smaller. The runtime now uses the shared device buffer constant
and tests this contract. This is finite transport/data-integrity evidence; it does
not qualify sustained throughput, fairness, native FEC or standalone UDP handshake.

The other three nine-case matrices also passed with cleanup:
[QuicLike/integrity](../../work/native-udp-quic-integrity/receipt.json),
[OpenVpnLike/AEAD](../../work/native-udp-openvpn-aead/receipt.json), and
[OpenVpnLike/integrity](../../work/native-udp-openvpn-integrity/receipt.json).
An independent [saved-evidence audit](../../work/native-udp-matrix-audit.json)
rechecked all 36 cases, binary/harness/pcap hashes, exact probe counts, expected
TCP digest, UDP failure/restoration and retained TLS socket counts. It parsed both
underlay captures in every case: all observed outer IPv4 packets fit the 1200-byte
path MTU without IP fragmentation, and the expected one or two UDP lanes appeared.
Each run uses its own immutable tested binary; hashes are recorded separately.

[Fixed LZ4 qualification](../../work/native-udp-lz4/receipt.json) passed another
nine OpenVpnLike/AEAD cases with cleanup. The [Cauchy matrix audit](../../work/native-fec-matrix-audit.json)
passed all 36 cover/suite/native-layer/duplex/network cases with four sources,
two repairs and a 5 ms partial flush. Integrity-mode captures contain actual
systematic and repair symbols in both directions, validated against the canonical
session/direction/epoch/length layout. AEAD captures preserve confidentiality.
Capture inspection does not verify secret MAC keys or establish that a particular
repair caused a native delivery; deterministic real-socket runtime tests separately
prove recovery before initial RTO and ARQ fallback when repair rank is insufficient.
