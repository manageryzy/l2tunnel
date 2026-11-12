# Explicit genuine QUIC client composition

Status: the explicit base-frame delivery migration passed 144 local client tests, strict
Clippy, rustdoc and formatting. Aggregate and new-profile native qualification are pending. The historical 36-case finite Linux native matrix
below qualifies its recorded earlier identity. Genuine QUIC remains UDP-only;
custom `--carrier udp --udp-cover quic-like` is a separate selection.

## Base-frame delivery boundary

The [shared base-frame contract](udp-client.md#mandatory-base-frame-delivery-policy)
defines mandatory policy, CLI validation, original deadlines and observations.
Public `Listener::bind` validates and retains that delivery policy before parsing
credentials or binding endpoints. Public `accept` uses only this immutable bound
policy. A private derived `bind_base` listener rejects public base `accept` with
InvalidInput before endpoint I/O; derived record owners continue using their own
private authenticated lane path. No accept-time override or capability flag can
replace a bound base policy.

- [ ] [MOD-QCLIENT-06] Qualify mandatory QUIC base policy binding, private-derived/public-base rejection before I/O, original full/half setup deadline with actual first-auth/second-Initial witnesses, and exact existing derived identities. Record scoped and aggregate evidence separately from historical native receipts.

Local evidence is recorded in the [client receipt](../../work/base-delivery28/client-validation.json)
and the [shared scoped evidence](udp-client.md#mandatory-base-frame-delivery-policy).
The actual first-lane-authentication/second-Initial test rejects a deliberately
removed outer deadline while retaining the original 200 ms setup allowance.

## Interface and ownership

`Settings { forward: udp::Endpoints, reverse: Option<udp::Endpoints>,
application_id: [u8;16], path_mtu, recovery: udp::RecoveryMode }` validates exact
unicast/nonzero endpoint pairs before binding or credential/device work. Half
requires distinct forward/reverse endpoint pairs in one IP family; Full forbids
reverse settings. Both peers explicitly provision the same nonzero application ID.
It is observable ALPN, not a promise of HTTP/3 or resistance to identification.
QUIC always uses maintained transport AEAD; integrity-only is not available.

`connect(roots, server_name, member, ConnectionConfig, Settings, DeliveryConfig)` binds both required
UDP lanes, authenticates their exact profiles, and performs the existing runtime
pair proof. `Listener::bind(certs, key, ConnectionConfig, Settings, DeliveryConfig)` binds both
server endpoints before readiness; `accept(allowlist)` authenticates/pairs them.
Only then may the shared CLI open a TAP/TUN/VXLAN adapter. The resulting runtime
link retains endpoint handles; all intermediate handles are dropped on failure.
One admitted connection per physical endpoint and finite pending/handshake limits
apply. Public accept includes the idle first-listener wait in its one original setup
bound; persistent idle waiting and retries are caller policy.
After cryptographic authentication, the configured exact peer address is also
checked before link creation. Address matching never replaces member identity.

## CLI contract

`--carrier quic` explicitly selects this path. It reuses `--udp-bind/--udp-peer`
and optional paired reverse addresses, plus `--path-mtu` and existing finite
`--fec` settings. Required `--quic-application-id HEX32` has no fixed default.
The normal `--remote` (connect) or `--listen` (serve) must match the configured
forward peer/local endpoint, preventing an apparently accepted ignored endpoint.
Existing CA/name/member and server certificate/key/allowlist inputs are required.
`--udp-cover`, `--udp-protection`, active TUN and local hot switching are rejected
for this profile. Minimum complete IP MTU is 1228 for IPv4 and 1280 for this IPv6
client policy. UDP-only reachability is a native acceptance gate, not inferred from
selecting an enum or using a local QUIC library.

## Acceptance checklist

- [x] [MOD-QCLIENT-01] Freeze explicit genuine-carrier config/API and reject ambiguous endpoints or incompatible profile knobs. Evidence: [client API](../../crates/l2tunnel-client-core/src/quic.rs), [strict selection](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-QCLIENT-02] Implement shared full/paired-half lifecycle without opening a TCP socket; preserve cryptographic peer/lane/config validation. Evidence: [client lifecycle](../../crates/l2tunnel-client-core/src/quic.rs), [TCP-blocked native receipt](../../work/native-quic-arq-qualified/receipt.json); independent read-only review found no material blocker.
- [x] [MOD-QCLIENT-03] Test missing/zero/malformed ALPN, endpoint family/duplex/MTU and authenticated policy differences; run client strict checks. Evidence: [CLI tests](../../crates/l2tunnel-client-core/src/cli.rs), [endpoint tests](../../crates/l2tunnel-client-core/src/quic.rs); 13 client tests and strict Clippy passed.
- [x] [MOD-QCLIENT-04] Qualify native TAP/TUN/VXLAN, both duplex modes, None/LZ4 and ARQ/Cauchy with UDP-only routing, packet captures and cleanup receipts. Evidence: [36-case independent audit](../../work/native-quic-matrix-audit.json), real interface MTU 1228 and offloads disabled; all exact payload/path interruption checks and cleanup passed.
- [x] [MOD-QCLIENT-05] Run required aggregate checker at a stable workspace snapshot and record unsupported platform/hot-switch limits. Evidence: [wave4](../../work/implementation-wave4/validation.json), 352 Rust/18 Python cases with unchanged source hashes; Windows/Android native and QUIC hot switches remain unsupported.
