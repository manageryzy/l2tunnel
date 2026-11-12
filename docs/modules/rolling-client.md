# Explicit rolling-frame client, CLI and local status

Status: the previous client profile has finite unprivileged Linux loopback
evidence. Version2 now requires a separate authenticated delivery policy; its
combined validation is tracked below. Native activation, W8192 deployment,
compact-record composition and complete Python-family qualification remain open.

## Selection and strict policy

New `client_core::rolling::Settings::from_json` accepts at most 65536 total
untrusted bytes before parsing. Every object uses deny_unknown_fields; all fields
are required, duplicate/missing fields and unsupported versions/profiles fail.
The document is `{version:2, profile:"rolling-frame-v2", channels, stream, epoch,
recovery:{window,local_window,global_every,max_payload,max_rows,repair_history,
handoff_sources,job_millis,debt_millis,handoff_millis,memory_bytes},
scheduling:{repair_numerator,repair_denominator,tail_millis,feedback_millis,
feedback_packets,memory_bytes},service:{field_work,copy_work,metadata_work,
passes_per_turn},delivery:{forward_bandwidth_bps,reverse_bandwidth_bps,
bootstrap_rtt_micros,min_rtt_micros,max_rtt_micros,headroom_percent,minimum_bytes,
max_inflight_bytes,max_records,metadata_limit_bytes,sample_ttl_micros,
flush_timeout_micros}}`. Scalars use checked typed integers and existing pure/runtime
limits. Scheduler times use milliseconds; delivery times use explicit microseconds.
Runtime-dependent MTU,
layer/duplex, memory and geometry validation finishes before credentials or I/O.

CLI selection is `--record-profile rolling --rolling-policy JSON_FILE` with
explicit `--carrier udp|quic`, TAP/TUN and system traffic. Rolling owns recovery;
`--fec` and ARQ/Cauchy tuning, aligned/packed options, active/proxy/raw/standalone
selection and VXLAN are incompatible in this initial slice. Existing UDP cover,
protection, path MTU, explicit full/half lane endpoints and genuine QUIC ALPN
remain authoritative. Genuine QUIC never falls back to custom cover or TCP.
No default/profile is inferred from JSON fields alone. No new cover claims
standard OpenVPN or QUIC interoperability.

Common Pipeline channels come from the document; TAP FIFO/MUX versus transparent
TUN DRR and all remaining bounded Pipeline fields derive from the shared runtime
profile. The resulting complete immutable policy, not only user-editable fields,
is bound before authentication by runtime rolling factories. All native user
traffic/probes retain that same common MUX. This profile does not own endpoint
TCP windows, measured adaptation or weight editing.

Delivery bandwidth is canonical initiator-to-responder and reverse, independent
of which peer reads the file. Both peers must authenticate the same values.
The native byte budget is bandwidth times causal delivery RTT with configured
headroom and hard byte/record bounds. The bootstrap RTT applies before a valid
sample. Local Pipeline/device queue limits remain separate. A writer completion
means the final original fragment was accepted by the datagram carrier; it is
not a physical-wire timestamp. Version1 is rejected instead of silently retaining
the old local-queue-sized flight window. Recovery support is still capped at128;
raising the native record cap does not qualify retained-source8192 service.

## Shared API and lifecycle

New `rolling::{udp_config,quic_config,connect_udp,accept_udp,connect_quic,
QuicListener}` reuse existing credential types, explicit lane/socket helpers and
retained runtime rolling full/pair constructors. New Settings are passed by
reference; no sender/receiver implementation, TLS/crypto or device adapter is
copied. Factories return a single `Session` capability with an `Observer`, actual
carrier/runtime configs and immutable authenticated digest. Session owns the only
runtime/device run future. No device opens until authenticated full/pair setup
succeeds. A single original setup deadline covers endpoint establishment, both
half lanes, authentication and final pair proof, with explicit pre/post checks
for ready futures. Cancellation drops only owned in-progress sockets/connections;
borrowed TCP/QUIC listener owners remain reusable.

Observer snapshots report requested/effective carrier, custom UDP cover versus
QUIC not-applicable, rolling recovery/profile, TAP/TUN, full/half, channels/window,
digest and actual Authenticated/Forwarding/Failed/Cancelled lifecycle. No
Forwarding is reported merely from JSON validation. No runtime counters or
native delivery proof are fabricated when the current runtime supplies none.
Hot reload, clean drain, native qualification and large-window qualification are
explicitly unavailable. Dropping an owned Session/run future records cancellation,
which is never clean closure. Terminal diagnostics are bounded and non-secret.

An optional private local control socket serves only Status through the same
service/session owner. Other actions return unsupported and preserve observed
state. Existing response cap stays 8192 bytes; the additive optional rolling
snapshot is omitted from legacy replies. The CLI uses shared settings/factories /
Session rather than a separate pump. No profile chooses a default carrier or
opens another socket just to furnish status.

## Checklist

- [x] [MOD-ROLLINGCL-01] Implement strict bounded versioned policy and complete pre-auth runtime binding; test unknown/duplicate/nested/missing/limit/geometry cases. Evidence: [strict policy and all-field digest tests](../../crates/l2tunnel-client-core/src/rolling/tests.rs).
- [x] [MOD-ROLLINGCL-02] Reuse actual UDP/QUIC full/half lifecycle under one original deadline and cancellation ownership; test both layers, mismatch, timeout and listener reuse. Evidence: [actual eight-scenario byte matrix](../../crates/l2tunnel-client-core/src/rolling/tests.rs), [authenticated first-lane/deadline and original socket ownership regressions](../../crates/l2tunnel-client-core/src/rolling/failure_tests.rs).
- [x] [MOD-ROLLINGCL-03] Wire explicit CLI selection/dispatch and bounded requested/effective local status through the shared API; test unsupported action and unchanged defaults. Evidence: [frontend selection/status tests and actual shared Session dispatch](../../crates/l2tunnel-client-core/src/rolling/cli.rs), [optional legacy-compatible local snapshot](../../crates/l2tunnel-client-core/src/local.rs).
- [x] [MOD-ROLLINGCL-04] Join and pass root's next stable `tools/check.py` aggregate; scoped checks do not close this gate. Evidence: [immutable source19 aggregate](../../work/implementation-wave19/validation.json), 629 unchanged inputs, 999 Rust and 154 Python cases, formatting, strict Clippy/rustdoc and golden/CLI checks.
- [x] [MOD-ROLLINGCL-04A] Pass scoped tests, strict lint/docs/formatting and exact-file review receipt. Evidence: [113 library and 19 example tests, strict checks and exact files](../../work/rolling-client19/validation.json).
- [ ] [MOD-ROLLINGCL-05] Qualify separately selected native owned-lab/capture, large-window service and full Python-family behavior before closing parent gates.
- [ ] [MOD-ROLLINGCL-06] Require and bind the version2 canonical bandwidth/RTT/byte/record delivery policy through the shared API, CLI and native harness. Reject old/missing/unknown policies and prove each field changes authentication; pass the actual carrier/layer/duplex matrix and root aggregate before accepting the replacement.

## Finite evidence and operating boundary

The checked client tests run eight actual API sessions: custom protected UDP and
maintained genuine QUIC, TAP/TUN, full/paired half. Each transfers independent
nonuniform native bytes in both directions, including a 1600-byte fragmented
packet and exact zero tails, then explicitly cancels the original runtime owners.
Both carriers also reject mismatched policy, certificate name and member identity
in full and half modes. Tests delay first-lane authentication and leave the second
lane incomplete, preserving the original setup deadline and releasing original
attempt sockets. Cancelled accepts preserve borrowed listener owners. A wrong
native device layer fails before forwarding. No test interprets task cancellation
as clean drain or application consumption.

The [complete strict example policy](../../crates/l2tunnel-client-core/src/rolling/test-policy.json)
uses W8 for finite tests; it is not a deployment recommendation. The current
runtime validation caps support at 128. The client matrix itself uses clean local
loopback; loss/feedback-loss/backpressure evidence belongs to the independently
recorded [rolling runtime](rolling-runtime.md) and pure scheduler tests. No new
privileged native test, platform qualification or Python-family claim follows.

Historical scoped results remain in the linked receipts. Version2 corrections
require their own current aggregate and do not inherit throughput qualification.
