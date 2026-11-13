# Common-session client composition tests

Status: **implemented and executed local client-library fixture**, 2026-11-13. These finite local
tests exercise the actual [shared client factory](client-secure-udp.md),
[UDP establishment](secure-udp-establishment.md), existing-member proof,
[numbered Swift records](swift-record-engine.md), common packet protection and
fixed reliable control. They are subordinate evidence for CSU-04/FIX-13, not a
new default, native forwarding implementation or complete shared-session gate.

## Authentication and custody

The fixture binds two real connected Tokio UDP sockets and records both original
local/peer address pairs. It provides explicit pinned X25519 identities, an
existing Ed25519 member key, independent admission/cookie secrets and one
absolute deadline. It calls the real `secure_udp::connect` and `Server::accept`
factories. No fixture constructs a packet-security root from byte arrays, injects
an authenticated enum in place of member proof, opens a TCP side flow or moves
authentication through a relay tuple.

Both selected appearances run this full authentication path. Returned session
observations must agree on the actual fresh Noise session/transcript,
configuration and admitted member; roles and fixed peer endpoints must be
complementary. The actual returned root supplies the session ID for management
binding. Settings and effective role-specific configuration remain observable.

As one factory completes before the other is polled to completion, the sole test
socket owner retains and services its returned bootstrap and membership tails
on that original socket. A short bounded pause of the incomplete future allows
real final-flight retry service before peer completion. Tail output is
preflighted and charged before handoff; the same outer counter continues through
tail and established traffic. This proves custody and asymmetric completion at
the factory boundary. It does not claim deterministic loss of an internal
factory datagram: runtime-owned fault tests cover final-flight loss with their
own precisely scoped hooks.

Negative cases require an explicit wrong member or pinned identity to produce
no authenticated `Session`. Where the factory rejects a mismatched local member
before network work, the peer socket must observe no datagram. Canonical-setting
field/digest substitution tests remain with the factory's unit tests; these
composition tests cannot replace signature/Noise parser failure cases.

## Established data and control

After both factories return actual authenticated roots and tails, each endpoint
constructs common `secure_record::Records` with mandatory Swift AEAD, the actual
selected cover and explicit fixed control/data scopes. A short authenticated
packet-key interval is a finite test parameter, not a client default. Each
endpoint uses the complete extracted multi-channel `swift::records::Engine`,
including native header records and connection-affinity channels, rather than a
single raw stream standing in for the runtime algorithm.

One reader dispatches covered bootstrap and Joining tails before common User or
Control records. Only a successfully opened Control record supplies verified
management ingress to `management::delivery::Service`. Opened User bodies carry
their unchanged full security number into Swift, including feedback. Both
directions deliver exact native bytes and opaque control commands, with arbitrary
bytes and trailing zeros, bounded queues, retransmission and adjacent key changes.

Scripted established loss skips selected logical attempts before actual UDP
send, while still charging their complete handoff cost and consuming their
security number. This is explicit application-handoff loss, not a kernel/netem
or ISP measurement. Additional delayed/reordered or duplicate ciphertext retains
the original number and bytes; replay rejection must not create a second native
or control delivery. The same two sockets and endpoint pairs remain in use.

A finite local data-scope stage/activation keeps control's scope unchanged and
preserves security counters/replay/key generations. It demonstrates coexistence
of old/new registered data scopes and fixed control service. It neither sends a
negotiated mode transaction nor proves barrier completion, atomic policy change,
SW-13 qualification or full SW-11 cross-profile switching.

Each service turn has one shared complete-wire allowance. Management attempts,
Swift sources/repairs/feedback, bootstrap tails and Joining tails all consume
their actual selected-cover UDP payload plus the modeled IPv4/UDP 28 bytes.
The test preflights worst-case record/tail capacity before consuming an attempt,
checks management's reported charge against the actual wrapped packet and
asserts that the turn's total never exceeds its allowance. Bytes deliberately
lost at application handoff remain charged. This is accounting evidence, not
throughput, latency, CPU, fairness under native saturation or link-rate evidence.

## Acceptance and evidence

- [x] [CSUT-01] Freeze the real-factory/root, original-socket, sole-reader/tail and shared-wire-accounting test contract before source implementation. Evidence: this design preceded the fixture implementation and retained the explicit root/socket/tail/budget boundary. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSUT-02] Complete actual paired Noise and Ed25519 member authentication through the shared factory for both appearances, with observable complementary roles/bindings and unchanged sockets. Evidence: both covers and both Noise profiles complete actual member authentication with complementary observed roles, bindings and original endpoints. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSUT-03] Exercise asymmetric factory completion and bounded bootstrap/Joining tail service without another reader or renewed deadline; test wrong-member/pin failure before user release. Evidence: the fixture services retained tails during asymmetric factory completion and rejects wrong member/pins; deterministic final-loss injection stays in runtime regressions. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSUT-04] Deliver exact bidirectional arbitrary native/control bytes using common AEAD, complete Swift records, loss/retransmission, replay rejection and packet-key generations on the original pair. Evidence: bidirectional native/control bytes, complete Swift records, charged handoff loss/reordering/duplicates, replay refusal and adjacent key generations pass. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSUT-05] Keep fixed management available across a local registered data-scope change and enforce one complete-wire budget for all emitted classes without claiming negotiated switching or native-rate qualification. Evidence: fixed control progresses through a local data-scope change under one complete-wire budget; the fixture does not force old-scope replay/in-flight traffic across activation or qualify negotiated switching. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).
- [x] [CSUT-06] Record exact focused commands, stable inputs, logs and required aggregate outcome; preserve failures and distinguish these local client-library fixtures from native devices, service/CLI selection, Windows/Android, standard protocol validity and ISP/QoS behavior. Evidence: actual focused/aggregate commands, stable input hashes and failures are retained; native, platform, standard-protocol and ISP/QoS claims remain unqualified. See the [executed factory fixture](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json).

All parent SEC-*, CSU-06, full SW-11, retained-state automatic recovery, genuine
OpenVPN and original HTTPS packet-path requirements remain open at their stated
scope. Test design or source presence cannot check these acceptance items.
