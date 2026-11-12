# Proxy control pacing and cumulative credit

Status: implemented and locally integration-tested for fixed and explicitly
selected measured proxies. The shared actor, retained TLS writer and reader use
the same immutable per-physical-direction control budget. Native pressure and
broader performance qualification remain separate.

## Failure and correction

The source19 actor sent a cumulative transparent Credit after each previous
credit flush. Two actual mutually authenticated peers transferring 2,000 packets
failed after 255 received packets in 0.31 seconds with `proxy control rate`.
The [before log](../../work/proxy-control-pacing/regression-before.log) preserves
that failure. The same fixed-profile case subsequently forwarded all 2,000 exact
packets in each direction and completed the original TLS drain in 2.33 seconds;
see the [initial after log](../../work/proxy-control-pacing/regression-fixed.log).

Credit now retains one cumulative delivered prefix, admitting at most one new
update per four control slots and waiting for the prior queued prefix's actual
full flush. Intermediate unsent prefixes coalesce into the latest actual native
delivery count. Pong and Ping admission precede Credit. The original writer
spaces every Start/Ready, Credit, Ping/Pong and Quiesce/Barrier/Ack full flush by
`ceil(1 second / control_rate)`. Missed slots never accumulate a catch-up burst.
One held control occupies the existing delayed slot; admitted user and measured
records continue through the same bounded writer and common MUX while it waits.
Failed full flushes cannot advance credit, liveness or final-fence progress.

TCP/TLS can buffer legally spaced records and deliver them together. Counting
local decode arrivals in one wall-clock second therefore falsely rejected a
healthy peer. The reader now services one control per the same configured slot,
holding only the existing bounded record and backpressuring the retained stream.
This limits parsing/actor work rather than increasing the receiver allowance or
adding a queue. Outer scope/sequence, inner phase, replay and heartbeat ownership
checks remain active. User-data decoding and MUX admission are unchanged.

## Supported timer policy

Let `slot = ceil(1 second / control_rate)` and `poll` be the configured native
poll interval. Before I/O or runtime allocation, configuration must reserve:

- Startup: at least `2 * slot`, for Start and Ready service.
- Liveness: at least `12 * slot + 2 * poll`. Each normal writer can own one Credit,
  one Ping and one Pong; four send/receive service edges reserve three slots each,
  with two actor polls for the request/response handoff.
- Shutdown: at least `32 * slot + 4 * poll`. This adds the four-slot credit
  coalescing wait to four service edges containing the three normal controls and
  Quiesce, Barrier, the latest Credit and Ack (`4 + 4 * 7` slots), with four actor
  polls. The wait is additive; the policy assumes no overlap to reduce it.

These are conservative supported-minimum local service reservations. They are
not a worst-case time bound on arbitrarily buffered transport, network RTT,
remaining native TCP work or user-data drain. All such work still consumes the
original startup, heartbeat and shutdown deadlines. No deadline is renewed, no
default duration increases, and late failure remains terminal. Integral
millisecond boundary tests accept the supported minimum and reject one
millisecond below it at rates 16, 256 and 1024.

The old public 30ms shutdown configuration is now rejected before device I/O.
A direct paused-clock Actor regression retains the exact original 30ms deadline
and proves a later drain request cannot renew it. The existing actual-peer short
startup-expiry and measured startup-before-long-native-poll tests remain intact.

## Evidence and limits

The final isolated source19 overlay passes all 179 runtime tests, including
2,000 exact transparent packets per direction through both fixed/measured and
full/paired-half actual TLS peers; rate-16 heartbeats, latest credit and clean
drain; all physical control kinds; bounded buffered receive service; user
progress during a held control slot; and failed flushes at every progress-bearing
control. The new test observers use the existing configured startup allowance
and one shared original shutdown allowance. Earlier artificial three-second
observer failures and compile/lint failures remain preserved; they are not
classified as corrected protocol failures.

The independent review's legally paced 17-record buffered-input and infeasible
short-timer regressions failed on the before implementation and pass after it:
[before](../../work/proxy-control-review20/before.log),
[after](../../work/proxy-control-review20/after.log).
The exact owned source, commands, strict-check results and retained failures are
recorded in the [scoped receipt](../../work/proxy-control-pacing/validation.json).
The integrator's complete frozen workspace check is a separate receipt. This
module does not claim privileged native pressure acceptance, native congestion
control, fairness, throughput, cross-platform execution or remote CI.

- [x] [MOD-PROXY-CPACE-01] Reproduce the existing high-rate failure through two real authenticated peers and preserve exact source/log evidence. Evidence: [before log](../../work/proxy-control-pacing/regression-before.log), [receipt](../../work/proxy-control-pacing/validation.json).
- [x] [MOD-PROXY-CPACE-02] Implement bounded cumulative credit coalescing and total physical control send/receive service with retained liveness/shutdown headroom. Evidence: [actor](../../crates/l2tunnel-runtime/src/proxy/actor.rs), [physical I/O](../../crates/l2tunnel-runtime/src/proxy/io.rs), [validated policy](../../crates/l2tunnel-runtime/src/proxy/config.rs).
- [x] [MOD-PROXY-CPACE-03] Cover fixed/measured full/half high-rate traffic, the lowest legal rate, latest-credit progress, timer/write failure and drain ordering; run focused strict checks and freeze exact source evidence. Evidence: [179 runtime tests](../../work/proxy-control-pacing/runtime-tests-reviewed.log), [strict Clippy](../../work/proxy-control-pacing/clippy-reviewed.log), [scoped receipt](../../work/proxy-control-pacing/validation.json).
