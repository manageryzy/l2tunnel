# Shared client for negotiated active policies

Status: strict catalog, shared authenticated lifecycle, local action and CLI
implemented and focused tested; native acceptance is partial (11 of 12 explicit
slow-profile cases). This frontend selects the reviewed
active-management runtime; it cannot turn an unmanaged active session into a
managed one after authentication. Runtime/native switch acceptance remains in
[the active management ledger](active-management.md).

## Shared API and configuration

`client_core::active_managed::{connect, accept}` reuse the existing bounded
TCP/TLS authentication and full/paired-half lifecycle. They derive the actual
managed session digest from the runtime's complete Config, verify matching duplex,
and return the retained Link. No native device is opened before authentication.

`catalog_from_json(input, ConnectionConfig, active::Settings)` accepts at most
32768 bytes with exact schema `{"version":1,"policies":[{"channels":4,
"dscp_weights":[...64 integers...]}]}`. Unknown/duplicate fields, wrong versions,
invalid array lengths, empty/excessive/duplicate policy catalogs and an absent
initial policy fail before credential loading or socket/device operations. All
runtime configuration limits remain authoritative. There are no secrets or local
paths in this catalog; it is explicitly authenticated by both peers.

An optional complete `transaction` object selects the existing finite
`retry_ms`, `phase_timeout_ms` and `reconcile_timeout_ms`. Omitting it preserves
100/5000/15000 ms. A present object must contain all three unsigned values;
null, unknown or duplicate fields fail. Runtime ordering and maximum bounds
remain authoritative, and every value participates in the authenticated digest.
These are immutable session choices, not live policy knobs. An explicit slow
qualification profile uses 250/30000/60000 ms; it does not change the defaults.

The CLI requires `--traffic active --active-policies PATH` for
the managed profile. `--control-socket` is then permitted; without a catalog,
unmanaged active behavior stays unchanged. `set-active-policy --mux-channels N
--qos-dscp D:W,...` constructs the complete target policy, with unspecified DSCP
weights one, and requests an already negotiated catalog entry. It does not edit
a file or expand the negotiated catalog. Immutable options still require a new
authenticated session.

The bounded local API gains a typed `switch_active_policy` action and an optional
active-policy snapshot containing complete weights/channel count, admission state
and actual epoch. Existing compression-only responses retain their bytes by
omitting this optional field. A compression request to active management, or an
active request to compression management, returns unsupported. The initiator alone
can request a switch. Success means runtime-confirmed peer transaction completion;
request timeout still means unknown outcome, requiring a subsequent status query.

## Acceptance checklist

- [x] [MOD-AMCLIENT-01] Implement bounded exact catalog JSON and shared authenticated lifecycle with the complete managed runtime digest. Evidence: [shared client](../../crates/l2tunnel-client-core/src/active_managed.rs), delegates existing retained-lane lifecycle with the actual managed authentication digest.
- [x] [MOD-AMCLIENT-02] Test schema/version/size/weight/count/duplicate/initial-policy failures and preserve unmanaged/compression profiles. Evidence: [two focused catalog tests](../../crates/l2tunnel-client-core/src/active_managed.rs), unchanged unmanaged and compression entry points; strict client Clippy passed.
- [x] [MOD-AMCLIENT-03] Add typed bounded local action/snapshot and explicit CLI selection with requested/effective status and unsupported-action errors. Evidence: [CLI](../../crates/l2tunnel-client-core/src/cli.rs), [private API](../../crates/l2tunnel-client-core/src/local.rs), exact 64-weight policies and committed status; no early switch success.
- [x] [MOD-AMCLIENT-04] Test real local socket policy requests, coordinator-only selection, failure/status behavior and no early success. Evidence: [local socket and client tests](../../crates/l2tunnel-client-core/src/local/tests.rs), [actual CLI coordinator rejection and peer state audit](../../work/native-active-switch-audit.json), [runtime failure coverage](../../crates/l2tunnel-runtime/src/active_management/runtime/tests/failure.rs).
- [ ] [MOD-AMCLIENT-05] Qualify native channel/weight switches during exact TCP payload transfer in full/half, static/adaptive and impaired profiles; preserve packet/epoch receipts.
- [ ] [MOD-AMCLIENT-06] Run focused strict checks and stable aggregate verification; keep unrelated carrier/recovery/GUI/platform switches open.
- [x] [MOD-AMCLIENT-07] Accept optional complete transaction timing with unchanged absence defaults, strict field/count/order bounds and canonical authentication binding. Evidence: [catalog parser and timing adversarial test](../../crates/l2tunnel-client-core/src/active_managed.rs), 19 focused client tests and warning-denied Clippy passed.

Focused frontend tests exercise real private Unix-socket serialization and cleanup,
unknown/duplicate nested fields, unchanged compression response bytes, unsupported
profile actions, invalid policies, bounded busy responses, and a queued operation
that stays pending until runtime completion (or returns closed on runtime loss).
Coordinator-only rejection and actual epoch completion also passed through the
complete native CLI path in the [finite switch audit](../../work/native-active-switch-audit.json).
The static LZ4 impaired case exhausted its progress deadline, so the full requested
native matrix remains unchecked. All failure receipts and the distinct default
versus slow-profile timing boundaries are documented in the
[runtime acceptance record](active-management.md#native-acceptance-profiles-and-retained-failures).
