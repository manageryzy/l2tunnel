# Explicit measured proxy client

The client slice connects the implemented measured runtime to shared client-core
and the Linux CLI. It does not change fixed proxy defaults or claim a native
advertised-window qualification. The accepted runtime contract is
[proxy-measured-runtime.md](proxy-measured-runtime.md).

Status: implemented with finite local Linux integration evidence. The focused
[receipt](../../work/proxy-measured-client/validation.json) records 95 client
library tests and 19 example tests. The measured cases use retained authenticated
TCP/TLS, bounded synthetic packet devices and actual full/paired runtime drain;
they are not a kernel TUN, advertised-window, fairness or performance test.

`proxy_measured::Settings` contains `fixed: proxy::Settings`, the exact pure
`measurement::MeasuredConfig`, and measured runtime `ServicePolicy`.
`from_json` accepts at most 65536 bytes with every version-one field required;
all nested records reject duplicate and unknown fields. The fixed route decoder
remains authoritative and bounded to 256 rules. `runtime_config(connection,
settings)` validates the complete policy and native geometry before socket or
device I/O. No target or timer is filled from an omitted JSON field.

The public factories mirror fixed proxy `connect`/`accept`, return an immutable
`Session {link,config}`, and run the actual measured actor. One original setup
deadline covers TCP, TLS/member authentication, both half-duplex lanes and pairing.
TLS verification/no-SNI/member identity behavior remains in the existing auth
crate. Typed configuration is inseparable from retained authenticated links.

CLI selection is explicit: `--traffic proxy-measured --proxy-policy PATH`, with
TUN, ordinary TCP/TLS, frame records and compression off. Reject active/adaptive,
UDP/QUIC/raw, FEC, aligned/packed, TAP/VXLAN and reload options before credential
files or device setup. Both peers authenticate the exact measured profile digest.

The private local API reuses one bounded drain command and the existing five-second
post-result local grace. `drain-proxy` acknowledges submission promptly and never
uses a dropped waiter as completion. Only the actual run result sets terminal
Closed/Failed. Status reports requested/effective profile capabilities and a
bounded aggregate of actual Controller observations. Exact advertised-window
control, native RTT/cwnd, hot reload, and per-flow pagination are explicitly
unavailable; no synthetic measurements or full unbounded flow dump are exposed.
All DTOs reject unknown/duplicate fields, and maximum aggregate responses must
fit the unchanged 8192-byte local limit. Fixed-profile replies omit the additive
measured object and keep their existing wire representation.

- [x] [MOD-PROXY-MEASURED-CLIENT-01] Implement strict bounded policy parsing and exact combined runtime validation; test required/duplicate/unknown/numeric/route limits and each bound configuration field. Evidence: recursive nested parser and numeric-leaf binding tests in [tests.rs](../../crates/l2tunnel-client-core/src/proxy_measured/tests.rs), strict fixed-route regressions and the focused receipt.
- [x] [MOD-PROXY-MEASURED-CLIENT-02] Implement real full/paired factories and typed Session ownership; test original deadlines, mismatches before device input and actual measured run/clean drain. Evidence: [focused checks](../../work/proxy-measured-client/validation.json) cover actual retained TLS factory, forwarding, controller-loss, identity/member/profile rejection, first/second-lane original deadline and local drain tests in the focused receipt. These client forwarding fixtures exercise transparent opaque IPv6 packets; maintained native TCP streams have separate runtime evidence.
- [x] [MOD-PROXY-MEASURED-CLIENT-03] Connect explicit shared CLI dispatch, reject incompatible options before external I/O, and expose accurate requested/effective capabilities without changing fixed defaults. Evidence: [actual measured CLI execution](../../crates/l2tunnel-client-core/src/proxy_measured/cli.rs), pre-I/O selection tests, explicit profile/carrier/UDP-cover/capability DTOs and unchanged legacy-schema tests.
- [x] [MOD-PROXY-MEASURED-CLIENT-04] Integrate bounded strict aggregate status, prompt drain submission and actual terminal-only reporting; test maximum response size, unsupported actions, dropped/repeated waiters and original deadline preservation. Evidence: [focused checks](../../work/proxy-measured-client/validation.json) cover one shared fixed/measured local service, actual private-socket full/half tests, repeated requests during a blocked native write, and the maximum aggregate roundtrip (including u128 ACK bytes and worst escaped diagnostics) below the unchanged 8192-byte cap. All nested response objects reject unknown/duplicate fields.
- [x] [MOD-PROXY-MEASURED-CLIENT-05] Pass focused client/parser/CLI/API integration checks, strict lint/docs and independent review; record separate target-directory source evidence. Evidence: the [focused receipt](../../work/proxy-measured-client/validation.json) records 95 library/19 example passes, client-only all-target warning-denied Clippy, warning-denied rustdoc, owned source hashes, and independent read-only review with no material blockers. Root aggregate/build and privileged native qualification remain separate.

The required `python3 tools/check.py` was run with `CARGO_TARGET_DIR=work/target-client`;
its [preserved log](../../work/proxy-measured-client/check.log) stops at workspace
rustfmt differences in concurrently edited raw-carrier sources. It does not
establish an aggregate pass. Client formatting, scoped strict Clippy and warning-
denied rustdoc have separate focused logs; root coordinates a stable whole-
workspace check. Earlier test-only fixture failures were corrected by giving
measured local sockets their own temporary directory prefix and constructing
u128 maximum counters directly instead of through `serde_json::Value`. No runtime
deadline, buffer, maintained TIME-WAIT behavior or close predicate was relaxed.
