# Retired old-record CPU benchmark

Status: **removed with the old Records format**.
The old `secure_record_bench` executable, recorder and format-specific tests
assumed a nine-byte route, the older security prefix and repeated appearance
bytes. They cannot measure the current five-byte record prefix and are no longer
built or called by `tools/check.py`.

Saved observations under `work/shared-session-cpu-20261113/` remain unchanged.
They describe the old source and executable, not current-format performance.
Current CPU, wire-cost and network performance qualification remains open under
[CWC-18](compact-wire-cleanup.md#full-implementation-and-acceptance-ledger).

## Stable retired checkpoint IDs

These historical deliverables remain identifiable without preserving obsolete
code or interpreting their receipts as current validation.

- [x] [PERFREC-01] Record the finite CPU-only CLI, strict 12-case schema, exact current framing, bounded output/timeout, failure preservation, fresh-output and source/executable identity contract before implementation. Evidence: retained [historical checkpoint](../../work/shared-session-cpu-20261113/results/performance.json); implementation retired by the current cutover.
- [x] [PERFREC-02] Implement a standard-library-only recorder that executes every requested bounded attempt, retains raw output/outcomes and complete/incomplete summaries, and fails on invocation/result/capture/identity errors without building or rerun substitution. Evidence: retained [historical checkpoint](../../work/shared-session-cpu-20261113/results/performance.json); implementation retired by the current cutover.
- [x] [PERFREC-03] Test malformed/nonfinite metrics, boolean integer fields, missing/duplicate cases, wrong layout/counts, failed invocation, timeout, bounded capture, source/binary drift and preservation of failed attempts using safe fake executables; CI tests must not measure real performance. Evidence: retained [historical checkpoint](../../work/shared-session-cpu-20261113/results/performance.json); implementation retired by the current cutover.
- [x] [PERFREC-04] Run focused Python tests and the required parent aggregate checker, record actual commands/evidence and preserve source freeze before parent benchmark execution. Evidence: retained [historical checkpoint](../../work/shared-session-cpu-20261113/results/performance.json); implementation retired by the current cutover.
- [x] [PERFREC-05] Execute the prebuilt real example under a frozen source/executable snapshot and retain its finite raw/summary receipt separately from network/native/ISP/QoS validation. A passing fake-fixture test does not complete this measurement gate. Evidence: retained [historical checkpoint](../../work/shared-session-cpu-20261113/results/performance.json); implementation retired by the current cutover.
