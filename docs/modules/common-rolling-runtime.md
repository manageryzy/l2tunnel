# Rolling service in the selected Common runtime

Status: **implemented and finite original-UDP/Unix packet-device integration-tested**.
The [scoped final validation](../../work/parallel-features-20261115/parallel-wave3-scoped-validation.json)
records exact cases and strict checks, preserving failed attempts. This is the
runtime portion of RCE-04, not completion of its service/CLI, full resource or
original rolling/mode acceptance definitions.

Read [the fourth pure record family](rolling-common-records.md),
[the Common transaction State](common-transaction-state.md) and the unchanged
architecture, implementation plan/checklist and mode parity before extending it.
The implementation uses the existing Bank, leased transaction State, security
record owner, shared admission, native pool and sole original-UDP I/O loop.

`transport::Config::rolling_work` is an explicit optional GF/copy/metadata budget.
Every selected component must be in 1..=65536. Absence preserves the previous
resource digest bytes and refuses a catalog containing rolling. Presence adds a
domain-separated authenticated resource extension containing every cap and the
fixed scheduling geometry. The legacy Swift runtime rejects this Common-only
selection. No cap is inferred from packing work, packet batches or a rate.

The sole loop calls actual rolling service once per turn, independently of its
repeated per-packet progress calls. At most two actual retained generations each
service their real send and receive scheduler: at most four directional caps
per turn. This is not a wall-clock CPU guarantee. Compact-codec work retains its
own configured limit. Common observations expose the actual selected work cap,
directional scheduler-step count and cumulative GF/copy/metadata consumption.
Resumable computation wakes immediately; immutable output waiting for wire
credit stays a separate I/O condition. Native completion wakes an actually
blocked recovery-to-record handoff without an unbounded busy retry.

Rolling data and feedback are classified using their maintained strict parsers.
Reverse feedback is checked against the actual local sending recovery policy.
Authenticated Busy/Capacity ingress is counted as pressure loss; it does not
silently acknowledge a logical source. Record/native counters remain exact
generation-specific events and preserve the existing physical drain barriers.

One sealed Common User output retains its exact bytes, security number, charge,
scope, original cap and move-only Bank carrier token through WouldBlock. Its cap
also includes the rolling owner's original hard deadline. Encoding, sealing and
polling do not confirm that token or earn repair credit. Only a whole actual UDP
write consumes it through its exact issuing generation. Physical acceptance and
token retirement remain recorded if the following injected clock sample crosses
the original cap; the connection then fails rather than resuming with that fact
rolled back. Partial writes fail without confirmation. Other record families
retain their existing output semantics.

- [x] [CRU-01] Validate explicit work selection, component bounds and authenticated resource extension, with absent-policy legacy bytes unchanged. Evidence: `actual_rolling_requires_explicit_authenticated_work_and_preserves_absent_digest` in the [initial exact-case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json); old None policy has no digest extension.
- [x] [CRU-02] Validate actual nonempty original-UDP Swift/Rolling/Aligned/Packed switching, both appearances and both rolling source formats, exact bidirectional Unix packet-device delivery, bounded work and original tuple. Evidence: `actual_original_udp_switches_all_four_record_families_with_bounded_rolling_work` in the [initial exact-case receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
- [x] [CRU-03] Validate retained rolling WouldBlock bytes/number/debit/token, post-whole-write confirmation, real socket loss and actual repair recovery, plus original-cap late-write physical facts. Evidence: the two rolling custody cases in the [narrow repair receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-2/validation.json).
- [ ] [CRU-04] Complete actual shared service/IPC/CLI selection and the full RCE-04 definition, including nonempty native/drain/held-output failures and complete control/lifecycle resource integration. **Open; parent scope unchanged.**
- [ ] [CRU-05] Complete original RCE-02..05, CRL-02..06, all relevant P-* matrices, reference8192, native/platform and performance acceptance. **Open; unchanged full definitions.**

The four new `secure_udp::transport::tests::common_selected::rolling` cases cover
the stated local fixture boundaries only. The original batch remains failed51/55.
Two custody fixtures initially polled before the real queue populated the compact
owner. Their repair uses bounded actual packing/work turns, with no production
or assertion weakening. Only failures and directly affected setup cases ran
again. Exact names/source hashes and the final syntax-only Clippy guard change
are recorded in the scoped receipt. They do not
qualify real TAP/TUN, netem, remote deployment, Windows/Android, standard
dissectors, identification resistance, throughput or ISP/QoS treatment.
