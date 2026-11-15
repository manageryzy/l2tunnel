# OpenVPN outer-wire carrier

Status: **implemented; six pure wire/control tests, four protected-factory tests
and three explicit raw-substrate tests passed in their recorded finite scopes**.
The latest affected batch revalidated all seven carrier cases; its aggregate
result is **failed: 23 of 26 cases passed**, not a passing stage acceptance.
The raw substrate retains real TLS/member control without exporter data resealing;
it is not yet the selected common Noise/member/runtime handoff.
The original custom-gate implementation and its native, outage and drain receipts
remain unchanged. This additive module is a prerequisite for the original
OpenVPN wire-handshake requirement, not completion of CONN-10,
FIX-10, FIX-13, SEC-*, full SW-11, the 47 parity modes or platform/native gates.

## Exact implementation boundary

`l2tunnel-openvpn-wire` is a pure library. It owns no Tokio, sockets, OS handles,
privileges, TLS configuration, cryptographic primitive or real clock. The caller
injects `Duration`. It implements the OpenVPN UDP opcode/key-ID layout, eight-byte
control-session IDs, explicit network-order packet-ID ACK arrays, the conditional
remote-session ID and control packet ID. ACK-only packets have no own packet ID;
remote-session ID exists exactly when the ACK count is nonzero. DataV1 adds only
the opcode/key byte; DataV2 additionally carries the standard three-byte peer ID.
The runtime explicitly selects DataV1/key ID zero.

The selected outer profile omits `tls-auth` and `tls-crypt`; their headers are not
guessed or negotiated by the parser. Reset uses client/server hard-reset-v2
opcodes and packet ID zero. Reliable control starts at packet ID one, never wraps,
and retransmits the same packet ID and original TLS bytes. These fields follow
the [OpenVPN packet format](https://build.openvpn.net/doxygen/network_protocol.html).
This is a particular standard outer profile, not a claim that arbitrary OpenVPN
configurations can be parsed or negotiated.

`control::Transport` reuses the actual reserved `SelectiveRepeat` owner for
fragment retention, ordering, duplicate checks, retransmission and validation
against the actual sent ledger. It converts that owner's private source/ACK
records into the standard control fields; no `L2AR` header, private source length
or bitmap is emitted. Explicit ACK IDs are translated back into its bounded
prefix/bitmap interface locally. Reset retries, pending ACK IDs, translation
scratch, partial stream reads, source count/bytes and original lifetime are finite.
This translation is intentionally coupled to the existing recovery wire version
and authoritative parser; the byte-level tests must detect incompatible changes.

`l2tunnel_openvpn::wire_carrier` is the additive Tokio runtime. Both explicit
factory families take an already connected UDP socket, so reset, TLS, ACK and data
use the original socket and endpoint pair. The sole actor bridges ordered control
bytes into the existing maintained TLS 1.3/member factories and retains the TLS
stream afterward. No carrier user-data ARQ or profile codec is inserted; loss and
reordering remain visible to the caller's recovery algorithm.

The existing protected factories, `wire_carrier::{client_connect, server_accept}`,
retain exporter-derived `ProtectedDatagrams` for DataV1 bodies. Their AEAD and
authenticated-cleartext paths use the existing replay/key-use checks; optional
payload confidentiality does not remove authentication. This compatibility path
remains available and does not silently fall back to raw data.

The additive `wire_carrier::common::{Config, Class, Carrier, client_connect,
server_accept}` API explicitly selects raw DataV1 transport in a separate
TLS/member authentication digest domain. It constructs no exporter packet keys,
sealer or opener and reserves no unused crypto-output buffer. `send(Class,
record)` adds only the standard DataV1 opcode to the exact caller-provided opaque
bytes; its completion means one whole original-socket write, not queue admission
or peer delivery. `recv()` returns untrusted arrival bytes, including duplicates.
The caller must supply the actual common security owner and enforce authentication,
replay, authenticated User/Control dispatch and full/half-direction policy. Local
`Class::{User, Control}` selects pacing only; it grants no incoming authority.
`outer_info()` reports the real outer TLS/member proof, not common Noise membership;
`control()` retains that actual TLS stream. Addresses, exact effective config and
wire-admission status remain observable.

The real certificate-root/name check and existing member allowlist remain the
authority. Outer session/key IDs and reset completion grant no membership. This
factory preserves the existing no-SNI TLS policy; configurable HTTPS SNI/trust
separation remains its own gate. Complete profile, resource, timing and shared
wire-budget settings enter a new domain-separated session digest. There is one
original deadline for reset plus TLS/member authentication and a separate original
total control lifetime; retries and reset duplicates renew neither. Both additive
factory families explicitly check the same handshake deadline before and after
TLS/member completion and activation, and before publishing the final carrier.
An immediately ready future cannot bypass this check through `timeout_at` polling
order. An expired constructed carrier drops and aborts its owned actor. These
guards are implemented; the listed success cases do not constitute a dedicated
near-deadline activation-failure test.

The existing shared wire ledger reserves control packets/bytes, limits control
emissions, and charges exact full-IP costs once. The configured IPv4/IPv6 outer
overhead is respectively 29/49 bytes, including the additional DataV1 opcode.
Socket-family checks reject mismatches. An admitted packet is retained unchanged
across `WouldBlock`; data submission completes only after a whole UDP socket write.
Wire admissions are observable separately from delivery. The protected factories
enforce full duplex and either half-duplex bulk direction without disabling reverse
TLS control. The raw substrate leaves that policy to its authenticated caller.
Its bounded User and Control submission channels have separate held submissions
and two independent retained output slots/buffers, alongside the existing TLS
control output. A quota-blocked User therefore does not occupy the Control slot;
all three emission paths share the same wire ledger and control ceiling. These
are local ownership/service properties, not a completed management FSM. Full
receive queues drop datagrams without manufacturing an upper-layer ACK.

## Guarantees, limitations and required integration

The runtime passes actual TLS ciphertext through a reliable byte stream, but the
encrypted application exchange is our existing member/session protocol. OpenVPN
key-method option strings, PUSH, virtual address allocation, endpoint control
semantics and endpoint interoperability are not implemented. Data bodies remain
our own protected tunnel records. Standard outer grammar, full OpenVPN connection
validity, interoperability, resistance to identification and ISP prioritization
are separate claims.

The no-`tls-auth` outer ACK/reset channel is unauthenticated. Forged ACKs cannot
create a TLS/member proof or valid exporter-protected data, but spoofed packets at
a known connected tuple can disrupt control availability or exhaust its bounded work.
Raw records are never treated as authenticated at this boundary; the caller must
authenticate them before granting data or management authority.
This slice does not add a listener-wide cookie, NAT rebinding, peer migration or
automatic reconnect. Wrong-session, malformed, out-of-window, conflicting and
unsent-ACK input is refused without replacing the established owner. Original
deadline/retry exhaustion closes it. Dropping a carrier aborts its owned actor;
that is bounded cancellation, not authenticated distributed drain.

The public carrier APIs are additive and are not yet selected by the shared
CLI/service or native loop. The protected factories retain the historical
TLS/member and exporter-bound packet owners; the raw factories provide the
explicit no-resealing substrate but do not install the selected common Noise
session. The common runtime integration must use the same wire owner while
choosing the actual common security owner exactly once, and preserve authenticated
management, liveness, rekey, negotiated profile switching and physical native
proofs. Carrying bytes named Swift or management in a focused test does not
establish that integration. There is no new default connection mode.

The source-bound missing common-Noise seam is concrete. The protected
`wire_carrier::Carrier` still derives exporter keys in its activation and opens
data through that owner; wrapping already sealed common records through this
particular API would retain the extra protection layer. The distinct
`wire_carrier::common::Carrier` instead activates the actor's raw variant after
actual TLS/member authentication and carries unchanged caller records. It avoids
that data double protection, but neither API creates the existing common
bootstrap/Joining handoff, admission proof, `member::Parts` or selected
common-security runtime owner. The raw test's actual Noise and Data/Management
primitives use test-injected bindings; they do not establish that integration.

Conversely, the existing common Noise/member `member::Parts` and
`transport::run_common` handoff owns a concrete connected `UdpSocket`, appearance
configuration/counter, session root and retained bootstrap/Joining tails. It does
not accept this OpenVPN actor/TLS-control owner. Integration therefore needs an
explicit bounded carrier handoff that retains the original socket and genuine
TLS control, preserves original setup/final-flight deadlines and exact full-wire
pacing, and gives the actual common security/management loop one authoritative
owner. The new outer contract, authenticated binding, handshake placement and
credential migration must be specified before claiming that composition. These
are engineering gaps, not recorded owner decisions or permission to duplicate
crypto, recovery, native custody or transaction state machines. OWC-04 retains
all common session, profile, service/CLI and native requirements.

The pure control recovery backing and additional scratch are fallible and bounded.
The runtime retains bounded channels, TLS stream buffers, selected protected-path
crypto buffers, raw priority buffers and owned payload copies. It does not claim
complete aggregate retained-capacity accounting,
fallible TLS/channel allocation, all nested allocator failure coverage or packet
time allocation freedom. Existing complete resource parents remain unchanged.

The executed checks provide no standard-dissector, packet-capture, Linux native
device, Windows, Android, impaired-network, performance or ISP-QoS qualification.
The new pure crate is platform independent by construction; runtime portability
and real-device support require their own execution evidence.

## Stable work and validation gates

- [x] [OWC-01] actual selected no-tls-auth reset/control/ACK/DataV1/DataV2 grammar, (Evidence: [three packet-grammar passes](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json).)
  full-width IDs, conditional fields, bounded parse/output failure and exact byte
  vectors. Three packet-codec tests passed in
  `l2tunnel-openvpn-wire/src/tests.rs`; see the source-bound receipt below.
- [x] [OWC-02] actual reserved control owner bridges contiguous TLS bytes through (Evidence: [three control-owner passes](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json).)
  lost reset/ACK/source, reorder, duplicate, partial reads, original retry/copy and
  lifetime caps, wrong session and unsent ACK refusals. Three actual control-owner
  tests passed in `l2tunnel-openvpn-wire/src/control/tests.rs`. Their TLS-shaped
  literal byte stream is a recovery fixture; real TLS is exercised by OWC-03.
- [x] [OWC-03] actual connected UDP factories complete real verified TLS/member (Evidence: [four focused runtime-crate passes](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json).)
  authentication, retain the original endpoint pair, exchange opaque AEAD and
  authenticated-cleartext data, preserve later TLS control and half-direction
  policy, and reject an unauthorized member before data activation. Four focused
  cases passed in `l2tunnel-openvpn/src/wire_carrier/tests.rs`: three socket/TLS
  integration cases and one complete-policy digest/refusal case. This finite
  evidence covers IPv4, full duplex and client-to-server half bulk; the original
  broader half-direction/native/platform matrix remains OWC-06 scope.
  All four protected cases also passed after the shared-actor/raw-substrate change
  in the [latest affected receipt](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json).
  The three additional raw-substrate passes below are finite prerequisite
  evidence and do not close OWC-04.
- [ ] [OWC-04] compose this actual wire owner with the selected common secure
  session and shared service/CLI/native runtime, selected Swift and other record
  profiles, authenticated control/liveness/rekey/switching, bounded recovery and
  requested/effective capability observations. No empty adapter or codec vector
  closes this gate; all original FIX-10/FIX-13/SEC/SW-11 requirements survive.
- [ ] [OWC-05] save a finite same-socket PCAP from the actual new runtime; parse
  reset/session IDs, ACK arrays, retransmitted packet IDs and reassembled real
  TLS with a standard OpenVPN dissector. Report parser failures and any decode-as
  configuration. Keep full protocol validity and endpoint interoperability as
  distinct, unclaimed properties.
- [ ] [OWC-06] qualify original resource, native full/half TAP/TUN, impairment,
  recovery, cancellation/drain, platform and active-probe behavior, and controlled
  ISP classification/QoS comparisons with retained original settings and receipts.
  Initial-packet classification remains a measured hypothesis, not a guarantee.

## Recorded verification and evidence limits

The
[2026-11-15 affected receipt](../../work/parallel-features-20261115/carrier-pure-attempt-1/validation.json)
passed with stable source inputs. It records all six `l2tunnel-openvpn-wire`
library cases and these four exact runtime-crate filters, each selecting and
passing one test:

- `wire_carrier::tests::actual_reset_tls_member_and_protected_data_retain_original_udp_pair_and_tls_control`: actual certificate-root/name and member verification, unchanged connected UDP endpoints, exact arbitrary opaque body exchange for AEAD and authenticated cleartext, and later reverse TLS control.
- `wire_carrier::tests::half_direction_rejects_reverse_user_data_and_preserves_reverse_authenticated_control`: client-to-server half bulk with reverse user-data refusal and retained reverse authenticated TLS control.
- `wire_carrier::tests::actual_member_refusal_never_returns_an_activated_data_owner`: a member outside the allowlist cannot obtain either activated data endpoint.
- `wire_carrier::tests::complete_bound_policy_changes_auth_digest_and_old_udp_overhead_is_refused`: selected complete-policy mutations change the authenticated digest and the historical opcode-free overhead is refused.

The same receipt records affected library compilation, strict Clippy and format
checks passing. It is a focused library-test batch: the three Tokio tests run
real user-space actors over kernel loopback UDP sockets, not a shared-service
startup, a TAP/TUN packet loop, a privileged namespace lab or an impaired link.
The receipt's generic scope label says no runtime qualification; the exact
commands/test logs establish only the finite runtime cases listed here. Data
labels such as `swift-or-packed` are arbitrary bytes, not actual selected record
engines or negotiated management transactions.

The
[separate OpenVPN rustdoc receipt](../../work/parallel-features-20261115/openvpn-rustdoc/validation.json)
records `cargo doc --no-deps --all-features --locked --jobs=4` for
`l2tunnel-openvpn` and `l2tunnel-openvpn-wire` passing with unchanged inputs.
Those receipts retain the then-current 22 OpenVPN source hashes; they predate the
raw API/shared-actor extension and do not qualify its new public rustdoc surface.
Exact commands, logs and immutable executable/source hashes are retained there.
The earlier
[pure-batch receipt](../../work/parallel-features-20261115/pure-attempt-1/validation.json)
remains failed for its Bank Clippy fixture and two zero-selected Aligned filters;
it contains no executed new OpenVPN cases and is not OpenVPN pass evidence.

The later
[2026-11-15 affected-case receipt](../../work/parallel-features-20261115/integrated-cases-attempt-1/validation.json)
records stable source and executable hashes and **23 passes among 26 exact cases**.
Its aggregate status remains **failed**, with failures in a Swift feedback case,
the Common retained-reader feedback case and the Common service case. All four
protected carrier cases above and these three exact raw-substrate cases passed:

- `wire_carrier::common::tests::actual_common_noise_records_cross_raw_original_udp_without_exporter_resealing`: real TLS/member authentication and unchanged IPv4 loopback UDP endpoints; actual existing Noise IK flights carried as raw records; exact Data-purpose ciphertext preserved, opened by the caller's real security receiver and rejected on replay there; separate Management-purpose protection; later real TLS stream service. Its Noise session/configuration/carrier/outer/member bindings and entropy are test-injected, not derived through the production common admission/member factory. The Management-purpose body is a primitive fixture, not the complete management FSM, liveness, rekey or mode switch.
- `wire_carrier::common::tests::actual_raw_emission_retains_wouldblock_bytes_and_exact_wire_charge_without_crypto_storage`: the actor's actual shared raw encoder uses an empty crypto buffer and emits one standard opcode plus byte-exact opaque content; two injected `WouldBlock` attempts retain identical bytes, pending completion and one full-IP debit; a subsequent actual connected UDP whole write completes the pending output. This exercises the physical-output helper, not simultaneous whole-actor TLS/Control service under a blocked User output.
- `wire_carrier::common::tests::raw_policy_has_distinct_binding_and_retains_control_reservation_after_user_saturation`: exact raw MTU boundary/refusal and a distinct authenticated configuration domain; the actual shared budget blocks further User admission after saturation while still admitting Control. Paused time makes this quota test deterministic; it is separate from the retained-output test.

The raw source provides separate bounded User/Control ownership, but combined
whole-actor retained User-`WouldBlock` with continuing TLS and common Control
service remains an explicit unverified case. These passes do not demonstrate a
production `Parts` handoff, selected common admission/member binding, shared
service/native loop, complete authenticated management FSM, liveness, rekey or
negotiated switching through OpenVPN. They also provide no standard-dissector,
captured-packet, native-device, impairment, Windows/Android or ISP-QoS evidence.

OWC-01..03 qualify only their complete stated finite codec/control/factory scope.
OWC-04..06 and the original CONN-10/FIX-10/FIX-13/SEC/SW-11/P-* parents remain
open. A standard dissector must still inspect captured actual outer reset/ACK/TLS
and data packets; a passing internal parser cannot prove that external result.
Neither successful TLS nor standard-looking headers proves endpoint
interoperability, resistance to identification or improved ISP prioritization.
Those claims require their separate controlled evidence and retained settings.
No simulator, performance or native workload was rerun for this documentation
reconciliation. Root retains the required full `python3 tools/check.py` stage;
none of the focused receipts above substitutes for it.

The independent [scoped checkpoint](../../work/parallel-features-20261115/openvpn-scoped-checkpoint-validation.json)
reuses these13 distinct positive cases and passes strict affected formatting,
Clippy and rustdoc after the raw addition. The single later recv rustdoc
clarification changes no behavior. No failed full aggregate is relabeled and
no unaffected test suite is repeated. OWC-04..06 remain open.
