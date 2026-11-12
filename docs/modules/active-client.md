# Explicit transparent-TUN active client

Status: implemented and native Linux TUN tested with fixed bootstrap targets.
The design preceded implementation. The shared client selects the independent
authenticated [active runtime](active-runtime.md). It retains the ordinary
connection/authentication lifecycle while binding the active profile before the
first TLS member exchange. It does not treat transparent TUN credit as ownership
of endpoint TCP windows.

## Public interface and CLI

`active::connect` and `active::accept` mirror existing client-core functions and
take a validated `runtime::active::Settings`. They derive the canonical session
digest through that runtime and use shared private connection functions; they
never instantiate a second protocol engine. Devices open after authentication.

`--traffic system|active` defaults to system. Active requires `--layer tun` and
`--carrier tcp`; TAP, VXLAN and current UDP composition reject it before network
work. `--control-socket` is rejected because active epoch switching has not been
integrated. Fixed None/Lz4 compression remains negotiated. `--mux-channels N`,
`--max-flows N` and `--qos-dscp D:W[,D:W...]` are active-only trusted policy inputs.
DSCP entries are unique, D is 0..63, W is a positive integer, and runtime validation
sets finite bounds. Unspecified DSCP weights are one. DSCP is a scheduling input,
never a privilege or bypass of the common user-packet admission policy.

`--flow-idle-ms` sets the authenticated idle-retirement age (default 60000,
range 1..86400000). The runtime freezes the flow, drains actual queued/flushed
data and control, then waits for the exact Final acknowledgment before reusing
a slot. A short age never discards buffered traffic. The native churn gate uses
two slots and twelve unique source ports, verifying a checksummed payload on each
connection. This is finite retirement evidence, not a fairness benchmark.

The first native active profile implements bounded per-flow credits, weighted DRR,
CRC MUX affinity and actual downstream release/regrant. `--adaptive off|on` defaults
to off; on selects authenticated measured RTT, native delivery rate/sojourn and
actual sender demand. `--active-stats-ms 0|100..60000` controls optional coalesced
JSON diagnostics (default off). Diagnostics retain at most one measured-growth
peak snapshot; output cadence is bounded and reporting never controls the engine.
Both active peers must select the same authenticated algorithm policy.

The native lab adds an explicit TUN/TCP active selection, checks both duplex modes
and impaired links, and preserves hashes/cleanup. Native fairness/target-growth
claims require additional multi-flow measurements beyond connectivity checks.

- [x] [MOD-ACLIENT-01] Compose the active canonical authentication profile through shared bounded connection APIs. Evidence: [active client](../../crates/l2tunnel-client-core/src/active.rs), [shared lifecycle](../../crates/l2tunnel-client-core/src/lib.rs).
- [x] [MOD-ACLIENT-02] Add strict active-only traffic/MUX/flow/DSCP CLI policy validation and honest status. Evidence: [shared CLI](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-ACLIENT-03] Test forbidden profiles, duplicate/out-of-range DSCP and canonical policy binding. Evidence: [active policy tests](../../crates/l2tunnel-client-core/src/cli.rs).
- [x] [MOD-ACLIENT-04] Run native TUN full/paired-half and loss cases through the active runtime with checksummed payloads. Evidence: [uncompressed native receipt](../../work/native-active-plain/receipt.json), [LZ4 native receipt](../../work/native-active-lz4/receipt.json).
- [ ] [MOD-ACLIENT-05] Integrate measured adaptive feedback, distributed lifecycle and managed active hot switches with native multi-flow receipts.
- [x] [MOD-ACLIENT-06] Expose authenticated idle age and prove more distinct native TCP flows than available slots complete under both duplex modes and loss. Evidence: [native receipt](../../work/native-active-churn-qualified/receipt.json), two slots and twelve distinct source-port connections with per-flow 4096-byte SHA-256 verification in half/full clean and half-duplex 70ms RTT/15% loss; cleanup passed. Earlier [fixture failure](../../work/native-active-churn/receipt.json) is preserved (TIME_WAIT source-port reuse after the first successful case).
- [x] [MOD-ACLIENT-07] Expose optional measured adaptation and bounded diagnostics; qualify native TUN payload/retirement under None/LZ4. Evidence: [None receipt](../../work/native-active-measured/receipt.json), [LZ4 receipt](../../work/native-active-measured-lz4/receipt.json), [None audit](../../work/native-active-measured-audit.json), [LZ4 audit](../../work/native-active-measured-lz4-audit.json); six cases passed, measured growth recorded in 11 of 12 endpoint/case traces, with no growth recorded on LZ4 full-clean initiator; no fairness/performance claim.

Both native receipts passed TUN half/full clean and half-duplex 70 ms RTT / 15%
loss cases. Each checked 12 exact IPv4 and six IPv6 probes, plus a SHA-256-verified
65,536-byte TCP transfer; ownership-scoped cleanup passed. The runtime carried
real Open/Grant/Record/Release messages and native delivery confirmations. These
six cases establish connectivity/data integrity through that path; they do not
measure weighted fairness or adaptive target growth. Flow weights are fixed by
the first packet's configured DSCP policy and later DSCP changes preserve bytes
and the original flow weight.
