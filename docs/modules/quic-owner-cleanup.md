# QUIC endpoint abandonment ownership

Status: implemented with focused Linux carrier/client validation and independent
final source review accepted. Root owns the derived stable workspace aggregate; this checkpoint is not
native-network or remote-CI qualification. Frozen wave15/wave15b failures and the
deterministic pre-fix regressions remain preserved.

Maintained Quinn endpoint/connection drivers retain UDP sockets while a closed
connection drains for three PTOs. Dropping the application's last endpoint or
preauth attempt previously left those detached tasks alive. Initial RTT is not a
general cleanup bound. The existing five-second cleanup observation and all
production QUIC/TLS/member/pair deadlines remain unchanged.

The private endpoint-scoped Quinn `Runtime` adapter delegates socket I/O, clock
and timers to `quinn::TokioRuntime`. It retains a bounded `JoinSet` of only that
endpoint's drivers: validated admitted plus pending capacities and one endpoint
task. Completed entries are reaped before registration; overflow and registration
after abandonment fail closed by dropping the new driver. A mutex serializes
registration with the closed latch. No extra cleanup task or queue is created.

A separate application lifetime token belongs to each endpoint and every actual
authenticated session. Driver/runtime references cannot retain that token. Its
last drop closes registration and wakes the existing drivers. Each inner driver
gets exactly one final nonblocking poll, then is dropped. The endpoint wrapper
retains its inner endpoint until all connection wrappers have dropped their
actual inner drivers/socket references; it does not repoll the endpoint. There
is no cleanup timer, PTO wait or retry budget. A pending, blocked or failed final
poll is dropped as well: abandonment cannot promise delivery or successful drain.
Tokio must continue scheduling these existing tasks for asynchronous release.

Pinned Quinn 0.11.11 `ConnectionDriver::poll` calls `drive_transmit` directly on the
connection's retained socket. A queued CONNECTION_CLOSE therefore does not need
a second endpoint poll. The existing preauth-cancellation regression forces the
endpoint final poll before the connection final poll and requires an actual
remote ApplicationClosed result. A synthetic driver regression separately counts
exactly one inner poll per driver under that order. Writable loopback proves the
queued close path; socket backpressure does not create another retry allowance.

A reusable server listener remains an application owner when one accept is
canceled. Live authenticated Control/data sessions retain ownership after their
factory endpoints are dropped. Tests send actual authenticated datagrams in both
retention/isolation cases and then rebind the exact original tuples after the
last owner is dropped. Unrelated endpoint abandonment does not close them.

Packed factories also check the original deadline after a ready inner result
before propagating either success or failure. A late inner error is TimedOut,
just like a late capability. The deterministic regression preserves the former
failure and does not renew any setup allowance. No QUIC transport defaults, TLS
verifier, packet format, normal close predicate or native workload changed.

- [x] [MOD-QUIC-OWNER-01] Preserve deterministic pre-fix exact-tuple failure with delayed test-only PTO and original five-second observation, plus the late-error original-deadline failure. Evidence: [receipt](../../work/quic-owner-cleanup/validation.json), preserved before logs therein and frozen wave15b aggregate log.
- [x] [MOD-QUIC-OWNER-02] Implement bounded endpoint-scoped ownership transferred to authenticated sessions; verify abandonment, listener/session retention, endpoint isolation, closed registration and exact final-poll budget. Evidence: [owner adapter](../../crates/l2tunnel-quic/src/owned_endpoint.rs), [real carrier tests](../../crates/l2tunnel-quic/src/tests.rs).
- [ ] [MOD-QUIC-OWNER-03] Pass scoped carrier/client regressions and strict lint/docs, independent final source review and root's derived stable aggregate. Focused evidence: 95 client + 19 example + 14 carrier tests passed with four threads from the private verified source15 copy plus only owned overlays; Clippy/rustdoc/format checks passed. Final independent root review accepted the owner/Driver and Session drop ordering with no material issue; root aggregate remains pending in the [receipt](../../work/quic-owner-cleanup/validation.json).
