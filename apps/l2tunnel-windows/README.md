# Windows foreground lifecycle control

This application implements an explicit Wintun L3 foreground client over the
existing managed TCP/TLS frame service. Source implementation, portable service
integration and Windows cross-compilation are separate from native Windows
qualification. No native Windows device execution is claimed here.

Add `--control stdin` to the existing explicit `connect --carrier tcp-tls --layer
tun ...` invocation to enable local commands. Without that option the original
one-shot foreground behavior remains: Ctrl+C cancels setup/forwarding, and an
actual setup/runtime failure ends the invocation. `--help`, `--version`, and
`plan` create no tunnel.

With stdin control enabled, submit one exact ASCII command per LF or CRLF line:

| Command | Behavior |
| --- | --- |
| `status` | Copy the current shared `Handle::snapshot()`, including pending operation, actual generation, effective managed counters and retained terminal. Available during platform setup, authentication, forwarding, idle and failure. |
| `disconnect` | Cancel an unfinished connection attempt, or submit the shared abort for a live generation, and remain idle after actual release. Repeated disconnect is harmless. |
| `reconnect` | Explicitly release the old generation, create a fresh device, then submit the retained shared plan again. Conflicting reconnect input reports `Busy`; it is not saved for an automatic retry. |

The input queue holds four typed commands. The reader uses fixed 256-byte read
and 32-byte line buffers. Empty, malformed, non-ASCII, oversized or unterminated
lines fail closed with bounded errors. Input EOF/read failure and Ctrl+C end
foreground ownership, including during initialization. A command followed by EOF
is **not** a request-and-wait protocol: EOF cancels unfinished work after the
already queued input has been processed. Keep stdin open to observe completion.

Stdin is claimed at most once per process. Safe standard-library input may remain
blocked in its input-only thread until another byte or process exit. That thread
owns no credentials, `Prepared`, `Handle`, `Run`, device or socket. Dropping the
receiver releases channel backpressure; shutdown never waits for stdin. Output
uses the existing eight-record, 2048-byte-per-record best-effort diagnostics
writer. A blocked/broken stderr consumer can lose text events, but cannot block
owner release. This is not a reliable request/response IPC protocol or Windows
Event Log implementation; status can be requested again while control is open.

## Execution and ownership

The actual startup path is:

```text
main -> cli::parse -> native::execute
     -> Plan::prepare(Staging::attachment) -> shared Prepared::client
     -> foreground::controlled -> service::channel (one Handle + one Run)
     -> Staging::prepare -> joined Setup worker -> Windows Device::open
     -> Handle::connect -> existing TLS/member authentication
     -> Attachment::open (take exclusive device) -> shared managed runtime
```

The same `Prepared` identity and the same service owner remain across commands.
The application retains at most one inline request continuation and an accepted
operation receipt; neither supplies lifecycle phases. `Phase`, `Completed`,
`OperationId`, generation and `Terminal` come from the shared service. Status does
not allocate a service request key or refresh authentication deadlines. The
one-second observation timer only samples counters; it performs no reconnect,
rekey, negotiation or device I/O.

A live explicit reconnect runs this sequence:

1. `Handle::disconnect` -> `Handle::wait` -> `Handle::wait_stopped(old_generation)`.
2. Clear any unused staged owner. The original shared runtime has already dropped
   its native device and transport socket before publishing the terminal.
3. Start the joined platform worker, create a fresh Wintun adapter, and place its
   sole owner in the refillable attachment slot.
4. `Handle::reconnect(prepared.clone(), next_key)` -> existing authentication ->
   take the new device -> actual shared runtime readiness.

This reports the **two real shared operations**, not a fabricated atomic frontend
reconnect. Platform creation has a separate diagnostic and no invented operation
or generation. If the initial platform constructor fails before the first shared
acceptance, an explicit retry uses `Handle::connect` for that first acceptance.
No service plan, authentication, protocol or carrier implementation is duplicated.

Only explicit reconnect attempts another generation after platform, authentication
or runtime failure in control mode. Cleanup cancels any accepted setup and waits
for its retained result, then aborts any remaining live backend. An operation ID
is retained outside a disposable request future, so cancellation/readiness races
still report its authoritative completion even after `snapshot.operation` clears.
An accepted disconnect is awaited rather than treated as cancellable setup.

Wintun creation may block in the OS. The staging guard retains that exact worker
across request-continuation cancellation. Local disconnect awaits it asynchronously,
so status and the shared owner remain pollable, then drops any late result before
acknowledging completion. Dropping the entire foreground future synchronously joins
the worker. This provides ownership safety, not a hard cancellation deadline. An unused preopened
device is cleared after authentication failure/cancellation and before frontend
completion; a consumed device belongs exclusively to `Run`. Dropping the
foreground future also drops the inline service owner and joins pending setup.
Final `Closed` observation follows dropping `Run` and clearing the staging slot.

Credentials are parsed once by `Plan::prepare` and retained by the existing shared
plan. They never enter local input or diagnostics. DLL pinning/loading, adapter
creation, permissions, address/MTU setup and native handle destruction remain in
`l2tunnel-platform-windows`. No unsafe code or dependency changes are introduced.

## Scoped progress ledger

This ledger extends [WFG-01..05](../../docs/modules/windows-wintun.md) within this
application's ownership boundary. Existing receipts and broad CL definitions are
unchanged; the integration owner may link this evidence from the shared ledger.

| ID | Deliverable | Status / evidence |
| --- | --- | --- |
| WFG-06 | Explicit bounded local foreground status/disconnect/reconnect through the retained shared service | Implemented; portable real-TLS/fake-device integration in `lifecycle_tests.rs` and `termination_tests.rs`; bounded input in `input_tests.rs`. |
| WFG-07 | Old-generation release before replacement device and observed operation completion across cancellation races | Implemented; Half/Full exact packet exchange across generations, staged-owner counters, authenticated failure retry, real socket EOF on cancelled authentication, joined late setup, and retained accepted-result checks. |
| WFG-08 | Native Windows console/device lifecycle qualification | Open; no Windows runner/device execution available. Cross-linked `.exe` is not this evidence. |

The original requirements remain open at their full scope:

- CL-25: Windows service ownership, nonprivileged UI/CLI operation, authorized
  named-pipe control and ACLs.
- CL-26: Wintun **and TAP L2**, complete setup/teardown/routing ownership, privilege
  failure and real native device qualification.
- CL-27: credential vault integration, Windows event logging, recovery, sleep/wake
  and the complete required platform lifecycle behavior.
- Common/raw carriers and every originally required mode remain on the existing
  implementation/parity plan. This foreground TCP/TLS slice neither implements
  nor removes those requirements. It adds no automatic reconnect or periodic key
  rotation.

## Validation boundary

The scoped receipt is `work/windows-lifecycle-20261116/validation.json` (local,
ignored output), based on `4612014105fad0c6899b2ea58882783ad1952bc1`. Logs and a patch
are beside that receipt. Necessary checks use the independent target directory
`/tmp/l2tunnel-windows-20261116-target`; no integration-tree target is touched.
Per the task's explicit concurrent-work restriction, the repository-wide
`python3 tools/check.py`, workspace tests and scans are reserved for the integration
owner. This change edits only `apps/l2tunnel-windows`; shared Cargo, Linux,
secure-UDP/Common cfg fixes and dependency snapshots remain outside it.

Native Windows verification still needs: real stdin/console Ctrl+C and EOF while
creating/opening Wintun; permission and pinned-DLL failures; two-way real IP traffic
across repeated explicit disconnect/reconnect; failed auth and driver I/O cleanup;
old adapter/session/event/library/socket release before replacement; local route
removal and absence of orphan adapters after late setup completion; broken/blocked
stdio. Those checks must record Windows version, Wintun DLL identity, privileges,
exact command and observed handles/traffic. Portable fake devices and Linux
cross-builds do not substitute for them.
