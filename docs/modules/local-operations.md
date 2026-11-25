# Local operation API (v5) and grouped CLI

Status: implemented and tested on Linux (`l2tunneld daemon`, `l2tunnel-linux-gui`,
`l2tunnelctl`, fake-service and real-daemon integration tests) and cross-compiled
for Windows (`l2tunnel-windows` named-pipe service, `l2tunnel-windows-gui`, and
`l2tunnelctl`; native Windows execution remains open under
[WLS-02..WLS-08](windows-local-service.md)). This module adds the asynchronous
operation surface required by [CL-04](../client-design.md),
[CL-12](../client-design.md) and [CL-14](../client-design.md) on top of the
existing [shared local API](local-api.md). It does not complete those parent
items by itself: CL-04 also requires broader configuration-apply operations and
revisions (CL-05), and CL-15 full cross-platform GUI parity remains open.

## Selected design

These choices were selected in discussion with the owner on 2026-11-23:

1. A new local API version 5 keeps one bounded request/reply per connection.
   Mutating actions return an accepted operation immediately; separate
   long-poll actions read, wait for and cancel operations and read a bounded
   event log. Versions 1 and 4 keep their exact action and reply bytes.
2. The event log is exact and owned by the service actor: every atomically
   published service state that changes the lifecycle tuple, every accepted
   operation, every setup-stage change and every completion is one event.
3. `l2tunnelctl` gains noun-verb command groups. Every existing flat command
   keeps its options, stdout JSON and exit codes unchanged.
4. Grouped commands use this exit-code contract, chosen to agree with the
   existing flat commands (`1` generic failure, `2` unknown command):

| Code | Meaning |
| --- | --- |
| 0 | Completed successfully; with `--detach`, accepted |
| 1 | Operation rejected by the service or completed with a failure/cancellation |
| 2 | Usage or argument error, including an unknown command |
| 3 | Service unreachable, refused the connection, or replied incompatibly |
| 4 | Watch deadline reached while the operation is still running |
| 5 | Outcome unknown (lost custody, uncertain commit, service restarted, reply lost after submit) |
| 6 | Unsupported by this service, backend or platform |

## Service event log

`service.rs` owns a fixed-capacity ring of 256 events with a monotonic `u64`
sequence starting at 1, plus a random 64-bit service instance identifier drawn
once from `ring::rand::SystemRandom` (time-derived fallback if the system
generator fails; it is an identity, not a secret).

Recording is attached to the state lock guard: `Shared::lock()` returns a guard
whose `Drop` compares the published state with the last recorded state before
the mutex is released. One locked section is one atomic transition, so no
published state is skipped, including from mutation sites added later. Per
release, for each retained entry in acceptance order:

1. `operation_accepted {operation, kind}` when the entry is new;
2. `operation_progress {operation, stage}` when its setup stage changed;
3. `operation_completed {operation, outcome}` when its result was newly set
   (`outcome` is the short result name; details via `operation_get`);

then `lifecycle {phase, operation, generation, terminal}` when that tuple
changed. The guard publishes the existing change signal when it appends.
The service records its initial lifecycle as sequence 1.

Work is O(retained entries) = O(32) per lock release and allocates nothing after
the ring is constructed. `Handle::events(after, limit)` returns at most `limit`
events with `seq > after`, the next cursor and `gap = true` when `after` is older
than the oldest retained event minus one. A gap requires the caller to read a
full status snapshot; events are never synthesized.

New `Handle` accessors: `instance()`, `operation(id)` (non-blocking view of a
retained entry: acceptance, deadline, cancel flag, setup observation and
result), `connect_retained(key)`/`reconnect_retained(key)` (lifecycle submission
with a caller key using the retained plan, same semantics as the v4 lifecycle
commands) and `wait_event(after)` (wake when the sequence passes `after`).

## Wire format (version 5)

Framing, peer UID checks, socket ownership and the 4096-byte request bound are
unchanged. Version-5 replies use the 32768-byte bound. The transport decodes the
request version first and then the strict typed request for that version.

`{"version":5,"action":{"command":NAME,...}}` with `deny_unknown_fields`:

| Command | Fields | Reply |
| --- | --- | --- |
| `status` | — | `status` |
| `connect`, `reconnect`, `disconnect`, `drain_proxy` | `request_key` (nonzero) | `operation` (accepted view) |
| `switch_common_configuration` | `configuration`, `request_key` | `operation` |
| `reuse_connection` | `request`, `request_key` | `operation` |
| `operation_get` | `operation`, optional `service` | `operation` |
| `operation_wait` | `operation`, `timeout_ms` 1..=30000, optional `service` | `operation`; code `running` on timeout |
| `operation_cancel` | `operation`, optional `service` | `operation` |
| `events` | `after`, `limit` 1..=32, `timeout_ms` 0..=30000, optional `service` | `events`; on a gap also `status`, code `gap` |
| `catalog` | `generation`, `catalog`, `offset`, `limit` 1..=4 | `observation` (Common catalog page) |
| `tuning_get` | — | `tuning` ([live tuning](live-tuning.md) decision 10): `live`, `current` setting, the choices of each control (`repair` with `off` first then ascending rates, `device_mtu`, `path_mtu` ascending), every reachable `entries` setting (at most 64, across Swift, Aligned, and Packed catalog members) and the service's `device` MTU state; code `closed` without a Common session |
| `tuning_switch` | `request_key`, `setting` (`repair` `off` or `N/D`, `device_mtu`, `path_mtu`) | `operation` (kind `common_switch`): the service resolves the setting to the exact catalog member across Swift, Aligned, and Packed (preferring the active protocol family with only the tuned fields changed when the catalog holds it, else the single entry with that setting) and runs the normal hot switch; codes `invalid_setting`, `not_in_catalog`, `ambiguous_setting`, `status_unavailable` before any key is consumed |
| `rate_budget_set` | `upload_bps`, `download_bps` (1 Mbit/s..=10 Gbit/s, unkeyed live control) | applies authenticated live speed-budget update (`ProfileTag::RateBudgetV1 = 6`) on both peers, scaling pacing bursts, credit ceilings, and runtime work batches; codes `not_running`, `invalid_budget`, `unsupported` |
| `test_start`, `test_get`, `test_cancel` | `test` / `id?, timeout_ms` / `id` (unkeyed) | `test` ([tunnel tests](tunnel-tests.md)); capability `tests` |
| `service_info` | — | `info` (version, role, API, uptime, per-feature capabilities with reasons) |
| `metrics` | — | `metrics` (cumulative counters computed from the [meter CSR](meter-csr.md); `unreported` names the missing paths); code `not_running` while idle |
| `meters_read` | `side` (`local`/`remote`), `prefix`, optional `cursor`, `limit` 1..=256 | `meters` page (`side`, `generation`, `sampled_ms`, `age_ms`, `entries`, `next`); codes `not_running`, `invalid_limit`, `invalid_prefix`, `invalid_cursor`, `busy`, `peer_timeout`, `peer_malformed`, `remote_unavailable` (non-Common backends) |
| `meters_catalog` | `prefix`, optional `cursor` (pattern index), `limit` 1..=256 | `meter_catalog` page (`version`, `entries`, `next`) |
| `device_list`, `route_list` | — | `devices` / `routes` with ownership; code `unsupported` without `--state-dir` |
| `device`, `route` | `request_key`, `change` (`op`: `create`/`configure`/`delete`; `add`/`remove`/`default`) | `operation`; result `host_applied` or `host_refused` |
| `session_list` | — | `sessions`: at most the live server session (generation, peer?, connected_ms?, profile?, member?, sent/received bytes?); `unsupported` unless the retained plan is a server |
| `session_kick` | `request_key` | `operation` (kind `session_kick`): end the live server session and listen again with the same plan; `state` when no session is live. Member revoke is composed by frontends from `profile` (save `--allow-key`) and `profile_connect` with `replace` |
| `service_stop` | `request_key` | `operation`; daemon only (capability `stop`, else `unsupported`): disconnect, release session routes, then the process exits |
| `profile_list` | — | `profiles` (name, revision, version, role, summary, default, editable) |
| `profile_keys` | `name` | `keys` (option, path, role, usable, reason?, public key or certificate SHA-256; never private material) |
| `profile_get`, `profile_validate` | `name` | `profile` (`{name, revision, document}`) / `check` (`{valid, summary, reason?}`) |
| `profile` | `request_key`, `change` (`op`: `save` with `document` and optional `expected_revision`, `delete` with `expected_revision`, `default` with optional `name`) | `operation`; result `profile_applied` or `profile_refused` |
| `profile_connect` | `request_key`, `name`, `replace` | `operation` (kind `connect`, or `reconnect` when replacing); code `invalid_profile` with `check` when the plan cannot be built (key not consumed) |

Device, route and profile changes are keyed operations sequenced by the
service actor like lifecycle operations; they never change the session phase.
Route changes need a connected session (`state` otherwise) and the service
removes its routes when the session ends. A profile connect prepares the plan
only for a new key, so an exact retry never rereads credentials; the plan
becomes the retained plan for later `reconnect`.

Reply: `{version:5, ok, code, service, status?, operation?, events?, observation?,
info?, metrics?, meters?, meter_catalog?, devices?, routes?, profiles?, profile?,
check?, keys?, sessions?, tuning?, test?}`
with `service` as 16 lowercase hex characters. `status` holds the service
`phase` (`disconnected`, `preparing`, `authenticating`, `connected`, `applying`,
`stopping`, `failed`, `closed`), current `operation`, `generation`, `terminal`,
`next_request_key`, `event_cursor`, `listening`, the existing backend
`observation` (the version-1/4 `Snapshot` projection, unchanged) and, when
known, the stored `profile` the plan came from and `connected_ms` since the
live session connected (connected phase only; both optional). Profile summaries
carry an optional `device` (the profile's `--device`). An operation
view holds `id`, `kind`, `state` (`pending` or `completed`), remaining
`deadline_ms`, `cancel_requested`, optional `setup` evidence and optional
`result` (`connected`, `aborted`, `applied`, `rejected`, `common_committed`,
`common_refused`, `reuse_confirmed`, `reuse_refused`, `host_applied`,
`host_refused`, `profile_applied`, `profile_refused`, `cancelled`,
`outcome_unknown`, `failed`).

A supplied `service` that differs from the instance identifier returns
`service_restarted` without touching state. Request keys keep the existing
sequential/idempotent service rule: an identical retry returns the original
acceptance; a different action under a retained key returns `conflict`.
Cancelling an applied peer transaction returns `cancel_unsupported`; it is
never reported as rolled back. Submission codes map existing `SubmitError`
values (`busy`, `conflict`, `expired_key`, `future_key`, `state`, `closed`,
`unsupported`, `invalid_configuration`).

## Server concurrency

`Server::serve(handler)` keeps its signature but now polls at most 8
connections concurrently inside its own task (no spawned tasks); further
connections are closed without a reply. It answers a version-5 request with
an explicit `unsupported_version` reply. `Server::serve_service(handle)`, used
by the Common and proxy CLI frontends, also dispatches version 5. A
`--control-socket` endpoint of any profile therefore answers status while an
operation runs. Each connection keeps the 5-second
read and write bounds; long-polls (`operation_wait`, `events`, `test_get`) hold
their slot for at most 30 seconds and release the slot immediately via
`cancel_on_eof` if the client disconnects while waiting; remote `meters_read`
waits up to its bounded `DEADLINE_MS` (2 s). A status request is answered while
a reconnect or switch is running. Version 1/4
requests are dispatched exactly as before (`lifecycle_request`). Local-API
timing instrumentation records each request's original timestamps and replays
them atomically under one lock, preserving its single-request accounting.

## CLI groups

`l2tunnelctl GROUP VERB [ARGS] --control-socket PATH [--json]`:

- `service status`
- `service connect|reconnect|disconnect|drain-proxy [--request-key K] [--watch SECONDS | --detach]`
- `operation show|watch|cancel ID [--service HEX] [--timeout SECONDS]`
- `events [--after N] [--limit N] [--timeout SECONDS] [--follow]`
- `config switch --configuration HEX [--request-key K] [--watch SECONDS | --detach]`
- `config catalog --generation G --catalog HEX --offset O --limit L`
- `profile inspect ...` and `key generate ...` run the existing offline
  `inspect-common-transaction-plan` and `keygen` commands with the same options.

Without `--request-key`, the CLI reads `next_request_key` from status, uses it
and prints it so a retry can reuse it. Submissions wait by default for at most
120 seconds (`--watch` changes the bound). A watch deadline exits 4 and prints
`operation watch ID` for reattachment; it never cancels or resubmits. A lost
reply after a submission exits 5 and prints the key to retry. Human-readable text
is the default; `--json` prints each version-5 reply as one JSON line.
`connect`/`serve` (foreground daemon entry points) stay flat.

Additional groups (see [desktop GUI](desktop-gui.md) for the full parity table):
`service info|start|stop`, `service connect|reconnect --profile NAME`,
`tune show|set`, `test speed|ping|status|cancel`, `stats show|watch`,
`meters read|catalog|watch`, `device list|create|configure|delete`,
`route list|add|remove|default`, `profile list|show|validate|export|import|delete|default|keys`,
`key generate|generate-noise|generate-secret`, `session list|kick`, `member revoke`,
`diagnostics export`. `daemon --control-socket PATH --state-dir DIR` is the
long-running Linux service that hosts stored profiles.

## File ownership

`crates/l2tunnel-client-core/src/local/operations.rs`, `local/transport.rs`,
`service/events.rs` plus the lock-guard and accessor hooks in `service.rs` and
`service/owner.rs`, `cli_groups*.rs` and the dispatch hook in `cli.rs`.

## Tasks

- [x] [LOP-01] Record an exact bounded event log in the service actor through the state lock guard, with instance identity, gap reporting and long-poll wake-up. Evidence: [event log and tests](../../crates/l2tunnel-client-core/src/service/events.rs).
- [x] [LOP-02] Add strict version-5 request/reply types with version-first decoding, bounds and legacy-byte preservation tests. Evidence: [DTOs and strictness tests](../../crates/l2tunnel-client-core/src/local/operations.rs), [decoder](../../crates/l2tunnel-client-core/src/local/framing.rs).
- [x] [LOP-03] Dispatch version-5 actions onto the existing `Handle` without blocking on completion; map every `SubmitError` and `Completed` variant. Evidence: [dispatcher and tests](../../crates/l2tunnel-client-core/src/service/operations_local.rs), [retained-plan replay test](../../crates/l2tunnel-client-core/src/service/prepared_transaction_tests.rs).
- [x] [LOP-04] Serve concurrent bounded connections so status is answered during a running operation; preserve version 1/4 behavior and timing accounting. Evidence: [transport](../../crates/l2tunnel-client-core/src/local/transport.rs), [real-socket tests](../../crates/l2tunnel-client-core/src/local/transport_operations_tests.rs).
- [x] [LOP-05] Add the grouped CLI with request-key defaulting, watch/detach, reattachment, `--json` and the exit-code contract. Evidence: [grouped CLI](../../crates/l2tunnel-client-core/src/cli_groups.rs), [parser/exit/real-service tests](../../crates/l2tunnel-client-core/src/cli_groups_tests.rs).
- [ ] [LOP-06] Test the acceptance matrix below with fake service backends and real Unix sockets. Every row has a local test except the first row's actual runtime completion: acceptance with a real retained plan and the event/wait sequence through the actor's own `finish`/`stage` paths are tested separately, but no test drives a real connect to readiness through version 5.

## Acceptance matrix

| Case | Expected |
| --- | --- |
| Submit reconnect on idle service with retained plan | `accepted`, then events accepted → progress → completed → lifecycle; `operation_wait` returns the actual result |
| Identical retry of a submitted key | Same operation ID; no second event |
| Different action under a retained key | `conflict`; no state change |
| `operation_wait` before completion | `running` after the timeout; operation still pending |
| Cancel pending connect / applied switch | `cancel_requested` then `cancelled` / `cancel_unsupported` |
| Service dropped during apply | `outcome_unknown` completion event; CLI exit 5 |
| Events cursor older than the ring | `gap = true`; caller reads status |
| Status during a running reconnect | Answered within the read bound |
| Ninth concurrent connection | Closed without reply; existing connections unaffected |
| Wrong `service` identifier | `service_restarted` |
| Oversized, unknown-field or wrong-version request | Closed without reply (unchanged rule) |
| Version-1/4 requests | Byte-identical replies to the previous implementation |
| CLI watch deadline | Exit 4 with reattachment hint; no cancel or resubmission |
| CLI usage error / unreachable socket / unsupported | Exit 2 / 3 / 6 |

## Executed checks (2026-11-23, local Linux)

- `cargo test -p l2tunnel-client-core --locked`: 227 library tests and 7
  integration tests passed.
- `cargo clippy -p l2tunnel-client-core --no-deps --all-targets --all-features --locked -- -D warnings`
  and `RUSTDOCFLAGS='-D warnings' cargo doc -p l2tunnel-client-core --no-deps --locked` passed.
  `--no-deps` was needed because concurrent uncommitted runtime work failed Clippy.
- `cargo check -p l2tunnel-client-core -p l2tunnel-windows --target x86_64-pc-windows-gnu`
  compiled (cross-compilation only; `l2tunnelctl` grouped v5 commands now build
  for Windows as well, see [Windows local service](windows-local-service.md)).
- Binary smoke: `l2tunnelctl` usage errors exit 2, a missing socket exits 3,
  and the legacy flat `status` keeps exit 1.
