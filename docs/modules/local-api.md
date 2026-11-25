# Shared local service API

Status: implemented and locally tested on Unix. This is the local-service transport
for CLI and GUI clients; it is not the authenticated peer management protocol.
The same serve loop, framing, bounds, concurrency and dispatch also back a
Windows named-pipe endpoint (`transport/windows.rs`). That endpoint is
cross-compiled and unit-tested only. Its design, proposed DACL and status are in
[Windows local service](windows-local-service.md).

The version-1 API uses a 4-byte big-endian byte length and one bounded JSON object.
Requests are limited to 4096 bytes and replies to 8192. Unknown fields, versions,
commands and compression names are rejected. Actions are status, the profile
drains, compression and active-policy switches, and the lifecycle commands
`disconnect` and `reconnect`; no arbitrary code, path, shell or raw
control-frame submission is exposed. The lifecycle commands were added without
a version change: an endpoint that predates them rejects the unknown command,
and only a frontend that keeps its daemon alive across generations (today the
swift profile) serves them; every other frontend answers `unsupported`.
`Request`, `Action`, `Response` and `Snapshot` are shared typed interfaces.

`Server::bind(path)` requires an existing private directory owned by the effective
user, refuses an existing path, creates a mode-0600 Unix socket and authenticates
every accepted peer by kernel UID. `Server::serve(handler)` serves at most eight
bounded connections concurrently within its task and replies with structured
status; further connections are closed without a reply. Version 5 (asynchronous
operations, events and `Server::serve_service`) is specified in
[local operations](local-operations.md). Malformed requests
are closed without a reply. It does not abort an
already submitted network transaction because a local caller disconnects.
`request(path, request)` verifies the server's kernel UID and has a finite
deadline; timeout means outcome unknown.

The server owns its socket path and removes it on drop only when device/inode and
socket type still match. It never removes a replacement or a parent directory.
Malformed/slow clients are closed without terminating the service. Credential
secrets are absent from requests, snapshots and error responses.

- [x] [MOD-API-01] Implement bounded versioned request/reply types and strict framing. Evidence: [local API source](../../crates/l2tunnel-client-core/src/local.rs).
- [x] [MOD-API-02] Implement private Unix socket ownership, peer UID checks and safe cleanup. Evidence: [real socket tests](../../crates/l2tunnel-client-core/src/local/tests.rs).
- [x] [MOD-API-03] Test real local requests, malformed inputs, size limits and path collisions. Evidence: [real socket tests](../../crates/l2tunnel-client-core/src/local/tests.rs).
- [x] [MOD-API-04] Bind local requests to authenticated managed runtime status/switch completion. Evidence: [shared CLI integration](../../crates/l2tunnel-client-core/src/cli.rs).
- [ ] [MOD-API-05] Add GUI/native Windows adapters, structured events and richer lifecycle operations.
- [ ] [MOD-API-06] Add deterministic timeout tests and simultaneous local-client service tests.

Platform split: `transport.rs` holds the shared loop and client exchange;
`transport/unix.rs` binds the private socket, checks peer UIDs and cleans up
the path; `transport/windows.rs` creates pipe instances with the proposed DACL,
`FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, and its
clients require a LocalSystem- or Administrators-owned pipe. On Windows
`Server::bind` and the client `path` take a pipe name (`\\.\pipe\NAME`,
default `\\.\pipe\l2tunnel`). MOD-API-05 stays open until the Windows
endpoint has native evidence (WLS-02..WLS-08).

Executed locally: `cargo test -p l2tunnel-client-core --offline` passed six tests,
including four local API tests. This is Unix transport evidence; cross-platform
GUI and Windows named-pipe service behavior remain separate gates.
