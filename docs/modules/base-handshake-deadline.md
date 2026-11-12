# Base TCP whole-handshake deadline

Status: implemented with local loopback integration tests; independent integrator
review and the required source-stable workspace aggregate remain separate gates.
This corrects the existing shared base TCP/TLS lifecycle, including its active
callers. It adds no carrier, wire protocol, timeout extension or reconnect policy.

The deadline starts immediately after configuration/profile validation in each
one-attempt `connect_session` or `accept_session` helper. One absolute Tokio
`Instant` bounds the first TCP connect/accept, first TLS/member authentication,
second TCP connect/accept and independent TLS/member authentication in Half, and
final pairing. Auth receives only the remaining duration. The runtime's existing
smaller pairing guard stays unchanged and cannot extend this original deadline.
The field describes an upper bound for one whole handshake, not a fresh budget
for every phase.

The first server accept is included. An idle attempt therefore returns TimedOut
at the configured bound. The listener is borrowed from the caller and remains
open and reusable after timeout/cancellation. A service that wants to listen
indefinitely must explicitly decide to start another attempt; idle retry and
multi-peer arbitration are outer service policy. This helper never resets its
clock silently after a peer arrives or after a first lane authenticates.

An explicit pre-check prevents polling an already expired attempt. Post-checks
reject a successful ready I/O result that crosses the original deadline inside
one poll; Tokio's timeout wrapper alone does not guarantee that condition. No
successful Link escapes after expiry. Timeout, TLS failure and cancellation drop
all sockets accepted/connected during the attempt. The existing Duration-based
socket helper used by the separate UDP bootstrap stays unchanged.

- [x] [MOD-BASEDEADLINE-01] Preserve a causal before failure for the documented whole-attempt bound. Evidence: [before log](../../work/base-handshake-deadline20/before.log), real loopback Half with a 1000 ms setting incorrectly admitted at 1.516720784 seconds; exact original lib/test inputs are retained in the [receipt](../../work/base-handshake-deadline20/validation.json).
- [x] [MOD-BASEDEADLINE-02] Carry one absolute deadline through all base TCP/TLS/member/pair phases with explicit pre/post late-ready rejection. Evidence: [base helpers](../../crates/l2tunnel-client-core/src/lib.rs), [focused tests](../../crates/l2tunnel-client-core/src/base_deadline_tests.rs), [scoped receipt](../../work/base-handshake-deadline20/validation.json).
- [x] [MOD-BASEDEADLINE-03] Exercise real loopback Full/Half with TAP/TUN and None/LZ4, delayed first/second auth and pairing, first-accept timeout and listener reuse, cancellation, invalid configuration before I/O, late-ready output drop and original socket EOF on failure. Evidence: [11 focused tests](../../crates/l2tunnel-client-core/src/base_deadline_tests.rs), [scoped receipt](../../work/base-handshake-deadline20/validation.json).
- [x] [MOD-BASEDEADLINE-04] Pass scoped formatting, strict Clippy, full client tests and freeze exact source/evidence for independent review. Evidence: [scoped receipt](../../work/base-handshake-deadline20/validation.json), 124 client unit tests (including 11 new deadline tests), 19 example tests, strict all-target Clippy, rustfmt, rustdoc and checklist checks; this is local Linux evidence.
- [ ] [MOD-BASEDEADLINE-05] Integrate the reviewed bundle and pass required `python3 tools/check.py` on the stable composed source; local loopback tests do not replace workspace, remote CI or platform evidence.

Timing assertions include a finite scheduling-observation tolerance while always
requiring TimedOut and rejecting every late successful admission. That tolerance
never changes the protocol timeout. Socket-release checks read each original peer
until bounded EOF/terminal close, rather than treating a dropped local variable
or a successful compile as cleanup evidence. The malformed second-lane and
cancellation tests also prove the already authenticated first socket closes.

The first default full-client attempt exposed an unbounded manual-peer second
accept in the test fixture when the tested client had already expired. That run
was terminated and preserved. Manual peer accepts now have finite guards, and
only this new module serializes its real-time network fixtures to avoid consuming
each other's short deadlines during concurrent crypto work. The default full
client runner remains concurrent; its final 124 plus 19 cases passed. Production
deadlines and the original 1000 ms regression setting were not increased.
