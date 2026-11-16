# Fixed and measured TCP proxy through the shared service

The additive [explicit Common proxy slices](common-tcp-proxy.md) now reuse
this service and actor through a bounded record adapter. The TLS evidence below
retains its original scope. The explicitly selected
[measured retained composition](common-tcp-proxy-measured.md) uses the same
controller and service; the complete PCOM follow-up remains open.

Status: actual fixed/measured shared service is implemented and finite full-mode
TLS/Unix-device integration cases pass, with affected strict checks. The existing
actor is reused. No native, Python parity or complete service qualification is claimed.

## Explicit public construction

Add four constructors on the existing `service::Prepared`:

```text
proxy_client(connection, credentials: service::Client,
             settings: proxy::Settings, attachment) -> io::Result<Prepared>
proxy_server(connection, credentials: service::Server,
             settings: proxy::Settings, attachment) -> io::Result<Prepared>
proxy_measured_client(connection, credentials: service::Client,
                      settings: proxy_measured::Settings, attachment)
                      -> io::Result<Prepared>
proxy_measured_server(connection, credentials: service::Server,
                      settings: proxy_measured::Settings, attachment)
                      -> io::Result<Prepared>
```

They validate the existing complete fixed/measured runtime policies and binding
before any socket, credential exchange or attachment work. Client endpoint/name
checks and exact attachment layer checks remain the existing service checks.
The plan retains immutable Settings and genuine existing TLS/member credentials.
No Common record profile or carrier capability is inferred from this selection.

The selected setup dispatcher calls the existing fixed or measured connect/accept
factory and retains its actual Session. The original accepted setup deadline
covers listener publication, full/paired authentication, deferred native device
opening and real actor readiness, with explicit pre/post checks. Readiness means
the existing actor published Forwarding after its real Start/Ready exchange;
successful TLS authentication or constructing a future is insufficient.

## Runtime ownership and observation

The same existing actor, selected through Session::run_service_owned, owns the maintained TCP Table, legs, exact tuple
authorization, transparent bypass, wire/native arbiters and fixed or measured
controller. No second TCP, TLS, security, proxy or service FSM is introduced.
One private control owner is retained by the backend; public copied observations
must not clone it or accidentally keep cancellation authority alive.

Add bounded fixed/measured proxy observations to the existing service Snapshot,
including exact requested/effective profile, authenticated digest, last actual
runtime facts and service terminal result. Reuse the existing local proxy and
measured aggregate DTOs, preserving the 8192-byte local response cap. Runtime
target changes remain relay grants; exact native advertised-rwnd control, native
RTT/cwnd, full qualification, hot reload and Common proxy support stay unavailable.

Disconnect remains an abnormal local abort, not successful drain. Fresh reconnect
must release the actual previous TLS/device/task owners before constructing the
replacement under its already accepted original cap. An expired queued reconnect
cannot destroy the old generation. Retained request keys/results keep the shared
service's existing replay/conflict semantics.

### Actual release implementation

The actor still owns the same actual I/O JoinSet. Existing run retains its old
error cleanup behavior. Additive run_service_owned retains that JoinSet through
every error and returns only after all aborted children have actually joined.
Fallible Table, measured state, arbiter and Start-channel preflight occur before
the first spawn. A bounded constructor-only writer-future vector holds at most
the actual one or two original lanes; it is not a user-data queue or recovery
owner. Full allocation/resource qualification remains open.

Fixed and measured Handle::request_abort(deadline) share the existing one-slot
local command channel. It carries an immutable original absolute deadline and
returns AbortWaiter::wait. The actor acknowledges only after actual joins; a late
acknowledgement is TimedOut. An already expired deadline may request cleanup,
but can never become success or acquire a replacement cap. No peer wire changes.

The service accepts a disconnect deadline from the selected owner's existing
shutdown policy. Reconnect retains its already accepted setup deadline. Factory
setup returns an unpolled actual runtime owner, and the service retains it before
driving real Start/Ready. Cancellation or expiry during readiness aborts and
joins that same owner. If cleanup exceeds the original operation deadline, the
operation fails while Active remains retained as failed/releasing. Subsequent
fresh mutations are refused until the same runtime observes actual join release.
No replacement factory, attachment or socket can start during that state.

Observation::Proxy exposes exact requested/effective profile and authenticated
digest, actual runtime facts, original release deadline, drain acceptance and
released/releasing. Existing local ProxySnapshot/ProxyTerminal remain the status
projection. Only an actual successful runtime drain supplies Terminal::Closed.
An uncontrolled Run drop publishes local Phase::Closed and Failed(Interrupted)
when proxy release is unobserved, retaining released=false. It cannot await joins
or prove child release; that limitation is observable and remains outside an
explicit completed disconnect. Other backend drop semantics remain unchanged.

### Focused executed regressions

- fixed_and_measured_share_actual_ready_bytes_clean_drain_and_fresh_reconnect:
  genuine full TLS/member pairs for each installed proxy family; Forwarding-only
  readiness, exact binding/status, bidirectional native bytes, actual clean-close
  reports, retained drain replay and fresh setup after original device release.
- cancelled_actor_readiness_joins_real_tls_children_before_completion: hold a
  genuine peer Session after TLS but before its actor Start/Ready, cancel the
  actual client service and require observed owned-runtime release.
- expired_disconnect_retains_joining_owner_and_refuses_replacement_until_release:
  expire the accepted original cap before one controlled service poll; preserve
  Failed(TimedOut), reject replacement while actual children still join, retain
  the original cap and only then permit a real fresh setup/refusal.
- dropping_live_proxy_service_never_claims_joined_release_or_clean_close: drop a
  real ready owner and require released=false/Failed(Interrupted), not a closure
  or join proof.

The finite cases do not qualify every half-duplex/failure/resource/platform
combination, Common composition, native performance or exact advertised rwnd.

## Finite acceptance

- [x] [TPS-01] Add explicit fixed/measured Prepared construction and validate exact complete policies before I/O, retaining all unselected constructors/defaults. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
- [x] [TPS-02] Drive genuine existing TLS full/paired factories and the same actor to actual readiness through the shared Run owner with original caps and deferred attachment. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
- [x] [TPS-03] Publish bounded truthful shared status and real fixed/measured control results, with retained-key replay and unsupported Common/apply rejection. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
- [x] [TPS-04] Prove actual child/socket/device release before disconnect/reconnect completion, original setup/cancel/drop/expiry behavior and failed replacement handling. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
- [x] [TPS-05] Pass focused actual fixed/measured service byte/readiness/lifecycle cases and affected checks with source-bound evidence. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).

Complete TCP advertised-window, Common record-family composition, all modes,
full SW-11, platform/native/resource/performance and retained-session recovery
requirements remain unchanged. This additive service backend does not close them.

- [x] [TPS-06] Move actual fixed/measured production CLI dispatch and external local commands onto this same shared Prepared/Run/Handle, removing the private production lifecycle after its meaningful coverage is migrated. Current typed shared-service tests do not close this CLI integration gate. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).

The scoped batch preserves its initial failures. Expired proxy stop now requests
cleanup and checks the original cap before polling release; actual late joins
remain with the same retained Active. One existing secure-UDP cancellation case
initially timed out; its exact diagnostic retry passed twice, without a proven
root cause or increased timeout. No new full-suite or native pass is inferred.

### Finite production CLI migration evidence

TPS-06 implementation now routes fixed and measured production connect/serve
through the same Prepared/Run/Handle, with deferred original device attachment
and the maintained SNI-aware TLS reader. Thirteen focused CLI cases pass,
including the actual presentation adapter and Unix local lifecycle. Local v1 status, drain, abnormal disconnect and explicit fresh
reconnect use the shared owner; exact runtime phase remains the v1 projection,
while the typed Snapshot retains its separate service phase.

The original native readiness sentence is emitted only after actual Connected
and matching Forwarding/profile/digest facts. A terminal grace can exit only
after actual released/not-releasing observation, with no queued/pending operation
or live replacement setup. Read-only close-report lookup uses the existing
bounded 32-generation terminal ledger with inline report data; it retains no
backend, control sender or cancellation owner. Uncontrolled owner drop supplies
no successful close report. The superseded private lifecycle adapter is retained
only for historical transport tests.

Executed focused cases use the actual production presentation adapter, genuine
TLS/member factories, packet devices and Unix local sockets for both profiles,
including bytes, exact v1 phase, drain/terminal, fresh reconnect, and pending
setup surviving expired local observation grace. A separate actual pair checks
that the first close-body read after replacement still returns the original
report. These are actual adapter/TLS/packet-device/Unix-local cases, not external
production TUN startup. No platform, complete resource, Python-parity or
performance qualification follows. See [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
