# Current implementation review follow-ups

The independent review in Codex thread `01a1cde0-0a4e-74d1-81f4-f3891cc7911b`
reported three correctness failures from an isolated historical source copy.
All three affected paths were still present in the source19 integration
checkpoint. Passing aggregate checks did not cover these scenarios.

The review's live-tree compile failure occurred during concurrent edits; its
probe copy also excluded an incomplete unrelated module to compile. Keep those
observations distinct from immutable passing checkpoints. Each fix below needs
a new reproduction on its declared baseline and focused before/after evidence.

- [x] [REVIEW-01] Pace and coalesce outgoing proxy control messages so a healthy authenticated transfer cannot exceed the peer's configured control allowance. Preserve liveness service, exact credits, common MUX admission, shutdown bounds and bounded receiver work service. Evidence: [proxy control pacing](modules/proxy-control-pacing.md), [source23b aggregate](../work/implementation-wave23b/validation.json), [unchanged-deadline client fixtures](../work/client-pacing-fixture23/validation.json).
- [x] [REVIEW-02] Retire safe idle aligned/packed flow registrations and treat temporary table capacity as bounded backpressure. Cover more than 1024 sequential flows, pending selected/recovery/native byte ownership, and both ingress and learned reverse flows. Retirement must not discard data or silently change channel ordering. Evidence: [focused before/after](../work/aligned-flow-retirement20/validation.json), [source22 aggregate](../work/implementation-wave22/validation.json).
- [x] [REVIEW-03] Preserve one absolute base-client setup deadline through initial connect/accept, both TLS/member handshakes and pairing. Reject late-ready completion, release partial lanes and preserve the caller-owned listener. The source19 reproduction completed after 1.5167 seconds despite a 1-second limit. Evidence: [before-fix log](../work/base-handshake-deadline20/before.log), [focused after](../work/base-handshake-deadline20/validation.json), [source22 aggregate](../work/implementation-wave22/validation.json).

Workers own disjoint implementation files. The integrator reviews each frozen
bundle, runs the required aggregate on a copied source tree, and commits accepted
changes locally. The source20 raw/rolling native harness and editor-tooling
checkpoint excludes these in-progress repairs and must not claim to fix them.

The base deadline bundle now passes 124 client tests and 19 example tests. The
aligned/packed retirement bundle passes 52 scoped tests and two doctests. Both
passed the source22 combined check (1034 Rust and 183 Python cases, stable649
inputs). Rolling and raw actors have analogous independent registration lifecycle
repairs with scoped evidence awaiting combined validation. Proxy pacing review additionally
reproduces compliant sender output rejected after buffered delivery, and accepted
rate/timer combinations that cannot fit local control service. Receiver work
backpressure and pre-I/O feasibility validation pass scoped tests without renewing
original deadlines. Source23b passes the combined check with the client fixtures'
original 100 ms deadlines and explicitly compatible test control rate preserved.
This closes the three finite review defects, not native throughput or broad mode
qualification.

## Test-entry and fixture review

The subsequent review found five test reliability defects. Its first aggregate
failed with `AddrInUse`; later retries do not erase that original failure.
A silent child also reproduced an unbounded readiness `readline()`. The clean
simulator copy needed ignored historical data and a complete optional dependency
environment. Repairs preserve the original behavioral assertions and historical
receipts, rather than treating a successful retry as proof of stability.

- [x] [REVIEW-04] Bound pre-start UDP/QUIC fixture retries specifically to actual AddrInUse errors under one original deadline; never retry forwarding or count a bind collision as expected authentication failure. Evidence: [scoped tests](../work/review-tests24/RECEIPT.md), [test helper](../crates/l2tunnel-client-core/src/test_udp_bind.rs).
- [x] [REVIEW-05] Bound child readiness by an absolute deadline and reap it on failure; retain real IPv4/IPv6 pressure checks and add a silent-child regression. Evidence: [scoped tests](../work/review-tests24/RECEIPT.md), [harness tests](../tools/test_proxy_measured_native_smoke.py).
- [x] [REVIEW-06] Replace implicit ignored historical-result dependencies with a minimal version-controlled fixture and provenance without weakening original assertions. Evidence: [simulator receipt](../work/review-simulator24/validation.json), [test](../simulator/tests/test_predictive_wire_budget.py).
- [ ] [REVIEW-07] Execute simulator tests, raw-native example tests and the codec no-default-features branch in the maintained check/CI entry; hash all new test inputs and run the combined check.
- [x] [REVIEW-08] Defer optional QUIC imports to selected adapters and prove absent aioquic does not block non-QUIC execution. Evidence: [1654-case simulator receipt](../work/review-simulator24/validation.json), [isolated absence regression](../simulator/tests/test_optional_quic_collection.py).
