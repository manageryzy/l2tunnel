# Finite secure-record CPU measurements

Status: **implemented; 17 focused Python tests, the required local aggregate and
three real finite CPU repetitions passed**. The design below preceded
implementation. Source and executable identities were stable during measurement;
the aggregate also reports stable inputs. Subsequent evidence-only ledger prose
is qualified separately from the master ledger.
This tool measures only the prebuilt `secure_record_bench` example's finite CPU
seal-cover-parse-open round trips. It does not measure network throughput,
native forwarding, endpoint congestion control, carrier identification, ISP/QoS
classification or production capacity. All existing network-performance and
mode-parity requirements remain in scope.

## Recorder contract

```text
python3 tools/secure_record_perf.py \
  --binary /absolute/path/to/prebuilt/secure_record_bench \
  --output /fresh/output/directory --iterations 100000 \
  --repetitions 3 --timeout-seconds 120
```

The caller supplies an already compiled executable, preferably an immutable copy
under `work/`. The recorder never runs Cargo or builds a binary. `--iterations`
is required and bounded to 1..1,000,000; `--repetitions` defaults to three and is
bounded to 1..20. The per-repetition timeout defaults to 120 seconds and is
explicitly configurable within 0.01..3600 seconds. The output directory must not
already exist; its parent must exist. Recorder writes stay inside that fresh
directory, including child working directories and retained process output.
The supplied executable itself is trusted project code, not a sandboxed program.

Exactly the requested number of attempts run, each invoking the executable with
the requested iteration count as its sole positional argument. An invocation
error, nonzero exit, timeout, malformed result or capture overflow remains a
failed attempt; later successes never replace it. The recorder never retries
until green. The deadline also bounds output draining after a direct child exits.
On POSIX, each child has a newly owned session/process group, which is terminated
on timeout to close inherited output pipes. Capture cleanup has a bounded grace
period and explicitly fails if pipes still cannot drain. This does not sandbox
arbitrary executables or qualify native Windows process-tree behavior.

Each repetition retains `repetition-NN.stdout`, `.stderr` and `.json`. Each raw
stream is drained, counted and hashed; at most one MiB per stream is retained.
Overflow is explicit and fails that attempt instead of exhausting memory/disk or
silently accepting truncated output. The outcome records invocation/validation
errors, exit status, timeout/capture status and its exact command. Successful
output is retained verbatim and also as validated raw cases.

`performance.json` includes all attempts, requested parameters, platform/process
context, per-case sample counts and minimum/median/maximum across valid attempts.
A partial summary is explicitly incomplete and cannot make a failed overall run
pass. There are no fabricated confidence intervals or throughput guarantees.
The receipt stores executable SHA-256 before/after and source maps from the
existing `record_check.hashes()` before/after. Missing/unreadable inputs or drift
fail the receipt. These observed hashes bind the recorded input snapshot; they
do not prove that an unrelated executable was built from that source. The caller
must preserve its separate build receipt. No source edits are allowed while a
measurement is running.

## Strict result validation

The example emits one JSON object with its exact CPU-only scope and 12 unique
cases: two appearances (`quic_like`, `media_like`), two protections
(`chacha20_poly1305`, `hmac_sha256`) and bodies of 64, 512 and 1340 bytes.
Every case must report the requested positive iteration count, exact payload
count (`iterations * body_bytes`), positive integer elapsed nanoseconds and
finite nonnegative rounded metrics. A very low positive operation rate can
round to zero at the example's fixed precision. Booleans are not accepted as integers. Unknown,
missing, duplicate or malformed cases/fields fail validation; duplicate JSON
object keys and nonfinite JSON constants are rejected.

The current layout uses nine route bytes, ten common-prefix bytes, a 16-byte
AEAD tag or 32-byte HMAC tag, and a 13-byte QUIC-like or 14-byte media cover.
`packet_bytes` must equal body plus those exact costs. The modeled IPv4/UDP byte
count must equal `iterations * (packet_bytes + 28)`. These are format accounting
assumptions, not observed packets or link goodput. Reported nanoseconds per round
trip must match `elapsed_ns / iterations` to the example's three decimal places;
reported payload round-trip Gbit/s must match `payload_bytes * 8 / elapsed_ns`
to its six decimal places. The latter is an operation-rate conversion for one
CPU round trip, not simultaneous independent network directions.

## Acceptance ledger

- [x] [PERFREC-01] Record the finite CPU-only CLI, strict 12-case schema, exact current framing, bounded output/timeout, failure preservation, fresh-output and source/executable identity contract before implementation. Evidence: this [recorder design](secure-record-performance.md#recorder-contract) preceded implementation; no owner decision about protocol defaults or production performance is inferred.
- [x] [PERFREC-02] Implement a standard-library-only recorder that executes every requested bounded attempt, retains raw output/outcomes and complete/incomplete summaries, and fails on invocation/result/capture/identity errors without building or rerun substitution. Evidence: [recorder source](../../tools/secure_record_perf.py) and the passing local fixture suite below; source/binary hashes use the existing helper, with no change to its scope.
- [x] [PERFREC-03] Test malformed/nonfinite metrics, boolean integer fields, missing/duplicate cases, wrong layout/counts, failed invocation, timeout, bounded capture, source/binary drift and preservation of failed attempts using safe fake executables; CI tests must not measure real performance. Evidence: all 17 [focused tests](../../tools/test_secure_record_perf.py) passed locally, including deeply nested JSON, inherited-pipe timeout and nonregular binary rejection. Safe executable fixtures require POSIX and are explicitly skipped elsewhere; schema tests are portable.
- [x] [PERFREC-04] Run focused Python tests and the required parent aggregate checker, record actual commands/evidence and preserve source freeze before parent benchmark execution. Evidence: the focused command below passed 17 tests before the real run, frozen inputs were observed by the [CPU recorder](../../work/shared-session-cpu-20261113/results/performance.json), and the later [required aggregate](../../work/shared-session-primitives-20261113/validation.json) passed with stable source hashes and 17 recorder tests. This records the actual execution order, not an aggregate run before measurement.
- [x] [PERFREC-05] Execute the prebuilt real example under a frozen source/executable snapshot and retain its finite raw/summary receipt separately from network/native/ISP/QoS validation. A passing fake-fixture test does not complete this measurement gate. Evidence: the [separate build identity](../../work/shared-session-cpu-20261113/build-receipt.json) and [all three real repetitions](../../work/shared-session-cpu-20261113/results/performance.json) passed with 100,000 iterations for each of 12 cases, stable source/binary hashes and all raw stdout/stderr retained.

The parent owns the Rust example, its build identity, required-check integration
and actual measurement runs. Historical experiments and receipts are preserved.

Executed local check:
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.test_secure_record_perf -v`
reported `Ran 17 tests in 2.004s`, `OK`. This used only safe fake executables and
did not execute the real benchmark, Cargo, network traffic or native devices.

The parent then executed the recorder with `--iterations 100000 --repetitions 3
--timeout-seconds 120`, using the immutable prebuilt copy at
`work/shared-session-cpu-20261113/secure_record_bench` and fresh output
`work/shared-session-cpu-20261113/results`. All 3,600,000 seal-cover-parse-open
round trips passed exact-byte verification. For 1340-byte bodies, median elapsed
time per round trip was 2047.885 ns (QUIC-like AEAD), 2055.728 ns (media-like AEAD),
2482.257 ns (QUIC-like HMAC) and 2477.000 ns (media-like HMAC). These are finite
local CPU observations; the raw receipt includes all sizes and repetitions.

After measurement, `PATH=/tmp/l2tunnel-quic-venv/bin:$PATH
PYTHONDONTWRITEBYTECODE=1 python3 tools/record_check.py --output
work/shared-session-primitives-20261113` ran the required `tools/check.py` and
passed: 1392 Rust cases including doctests, 245 Python tooling cases and 1658
simulator cases. It ran no privileged lab, Windows/Android device or ISP test.
