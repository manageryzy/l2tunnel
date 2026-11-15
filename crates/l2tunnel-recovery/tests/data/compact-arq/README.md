# Actual Python CompactARQ event oracle

Regenerate from the repository root:

```sh
python3 tools/generate_compact_arq_events.py
python3 tools/generate_compact_arq_events.py --check
```

The generator refuses any change to the six actual simulator source hashes in
`source-pins.json`. It writes `python-events.json` here and the Rust literal table
at `src/arq/compact/python_events.rs`. The `--check` command reconstructs all events
and compares both files exactly without overwriting them. The generated literal
table has a scoped `#[rustfmt::skip]` attribute; the importing line is already in
normal rustfmt order. There is no dependency on an ignored work directory.

The generator imports the maintained `CompactARQTransport`,
`FirstFlightARQTransport`, `BoundedGapARQTransport`, and `CompactSimulation`.
It invokes their actual source admission/flush, receipt, feedback, timeout, and
generation-checked feedback timer methods. Actual `Simulation.send` is retained;
only each instance's `Link.finish` is supplied an explicit serialization finish.
Actual send callbacks are delivered at explicit arrival times. Network departure
callbacks, unrelated TCP production/timers, and `Simulation.run` are not executed.
No estimator, RTO, feedback qualification, or fast-retry formula is copied into
the oracle.

The five traces comprise99 explicit events and68 actual protocol outputs:

1. Receiver-delay subtraction, naturally reordered stale feedback with a newer
   echo, and an actual timeout retry supplying an unambiguous new RTT sample.
2. Ordinary guarded recovery before and after its actual guard.
3. First-flight acceleration and the original guard on a later attempt.
4. Duplicate receipt resetting three ordinary reports and a rotating bitmap.
5. Bounded-gap spacing measured from any ordinary feedback, advancing missing
   prefixes, and cancelled original timers.

Python's valid modeled MTU is128 and its explicit modeled authentication cost is75
bytes, leaving one bitmap byte after its modeled52-byte feedback header. This is
a small deterministic oracle geometry;75 is not a Rust crypto/tag selection.
Modeled requested IP sizes are recorded as such. They are not the new Rust v2
encoded sizes. Python models source lengths; the Rust consumer carries actual
opaque four-byte payloads of the same length, verifies their identity, and
separately encodes/parses the selected52/76-byte Rust v2 format. No Python byte
encoder or cross-format byte parity is invented.

The consuming Rust test uses actual `CompactRepeat` sender/receiver owners and
source output tokens, confirmed at the recorded physical acceptance times. It
checks actual flights, cumulative base, unsampled history, RTT state, output
counts, feedback fields, repeat count, cursor, deadlines, and retained capacities.
Binary64 event times are exported once to nearest nanoseconds. Comparisons allow
only one nanosecond for sum-then-quantize versus summed `Duration` values; no cap
or policy is extended. This finite oracle does not qualify runtime selection,
authenticated installation, native delivery, performance, all pressure/failure
dimensions, or complete mode parity.
