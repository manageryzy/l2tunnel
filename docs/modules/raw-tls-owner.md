# Exclusive raw TLS message owner checkpoint

Status: implemented, independently reviewed and tested in source-stable wave12.
The completed
[bounded record observer](raw-record-io.md) is an envelope observer, not a TLS
freeze authority. This next checkpoint keeps that observer and the entire
maintained TLS object under one owner and parses finite messages using exact
remaining-length reads. It deliberately stops before Seal semantics, the backend
zero-write materialize-and-reject check, FrozenTls, lane pairing, driver handoff,
packet quarantine, old-prefix response and native activation. The overarching
[transition contract](raw-tls-transition.md) remains behind its separate gates.

## Placement, dependencies and original ownership

Implementation: [tls_owner.rs](../../crates/l2tunnel-raw-io/src/handoff/tls_owner.rs) and
[focused tests](../../crates/l2tunnel-raw-io/src/handoff/tls_owner_tests.rs) within
`l2tunnel-raw-io`, with a narrow `handoff` reexport. This is a runtime adapter, not
an addition to a pure protocol crate. The parent approved the existing pinned auth/core/device/ring/tokio-rustls
production dependency moves for this runtime adapter. Device provides explicit
PacketLayer matching; the digest never uses implicit enum discriminants. No
new provider, TLS version, crypto implementation, registry patch or vendor seam
is proposed. These dependencies remain outside pure protocol crates.

Public factories take the original `TrackedStream` and unique `SwitchHandle`.
Inside raw-io, compare their private Arc identities before attachment or any I/O,
then perform `RecordIo::attach` and retain both original owners. The factory has
no public overload accepting an existing TLS stream, AuthenticatedIo, RecordIo,
numeric handle identity or externally claimed boundary. This avoids adopting a
TLS object after arbitrary plaintext operations. Invalid geometry, mismatched
handles, nonfresh endpoints or invalid deadline are rejected synchronously and
return the exact stream and handle; no polling or replacement occurs.

The existing `SwitchDriver<I>` remains with its caller during this small
checkpoint. It must be driven concurrently and retained/joined by that caller.
These factories do not spawn or detach a task, own a raw descriptor, promise
all-worker cleanup or request a handoff. Tests own and cancel/join every finite
mock driver explicitly. The later from-birth all-lane manager must own both this
TLS owner and the original driver/physical owner as one lifecycle; passing this
checkpoint does not satisfy that manager gate.

Use the existing `auth::client_connect_io` / `server_accept_io` functions with
`RecordIo<TrackedStream>` to perform actual TLS and membership authentication.
The current auth constructors enforce TLS 1.3, verified certificate/name, no SNI,
no early data and the configured member allowlist; no caller assertion replaces
those functions. Retain their resulting whole tokio-rustls stream via
`AuthenticatedIo::into_parts`, together with SessionInfo. This consumes only the
auth wrapper; never call `TlsStream::into_inner`, reconstruct a TLS wrapper or
extract traffic secrets in production. Test-only adversarial peers may use the
same maintained public encryption fixture as the earlier regressions.

The existing auth functions intentionally drop their I/O on authentication
failure/cancellation. Their failure cannot return the original TLS object and
must never be represented as a reusable-owner result. Only synchronous
pre-I/O factory rejection returns original owners. After authentication starts,
error/timeout/drop is terminal for this attempt, signals the retained driver
through original endpoint/handle drop and requires that driver's owner to finish
bounded cleanup. No new connection is opened automatically.

## Implemented exact API

The public surface is:

```rust,ignore
pub struct MessageLimits {
    pub records: RecordLimits,
    pub max_payload: u16,             // 1..=4096 plaintext bytes/message
    pub messages_per_direction: u16,  // 1..=256, lifetime; no reset
    pub bytes_per_direction: u64,     // 9..=1 MiB, includes 8-byte headers
}
pub struct Setup<'a>; // Owns pending existing auth future + original SwitchHandle.
pub struct TlsMessageOwner; // Owns whole TLS stream, SessionInfo, handle, offsets.
pub struct StartFailure { /* exact original stream/handle + typed local cause */ }
pub struct SetupFailure { /* terminal cause; no reusable owner assertion */ }
pub struct MessageStatus { /* copied phases/counts/offsets/RecordStatus; no proof */ }

pub fn message_session_config(base: SessionConfig, limits: MessageLimits)
    -> Result<SessionConfig, StartError>;
pub fn begin_client<'a>(stream: TrackedStream, handle: SwitchHandle,
    tls: &'a ClientTls, verification_name: &'a str, member: &'a MemberKey,
    base: SessionConfig, limits: MessageLimits, timeout: Duration)
    -> Result<Setup<'a>, StartFailure>;
pub fn begin_server<'a>(stream: TrackedStream, handle: SwitchHandle,
    tls: &'a ServerTls, members: &'a MemberAllowlist,
    base: SessionConfig, limits: MessageLimits, timeout: Duration)
    -> Result<Setup<'a>, StartFailure>;
impl Future for Setup<'_> {
    type Output = Result<TlsMessageOwner, SetupFailure>;
}
impl TlsMessageOwner {
    pub fn info(&self) -> &SessionInfo;
    pub fn status(&self) -> MessageStatus;
    pub fn deadline(&self) -> Instant;
    pub fn stage_message(&mut self, payload: &[u8]) -> Result<(), MessageError>;
    pub fn poll_send(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<(), MessageError>>;
    pub fn poll_receive(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<(), MessageError>>;
    pub fn message(&self) -> Option<&[u8]>;
    pub fn consume_message(&mut self) -> Result<(), MessageError>;
}
```

No AsyncRead/AsyncWrite implementation, public mutable TLS/record accessor,
unwrap, clone, adopted-owner constructor or switch-handle accessor is exposed.
The owner provides no `is_frozen`, `ready_to_switch` or equivalent boolean.
`Setup` is polled by borrowing its pinned owned value. Cancelling that borrow
retains the same pending auth future and original deadline for later polling;
dropping Setup instead drops that future/endpoint/handle and is terminal. It
never recreates/retries authentication. A completed Setup tracks its own Done
state so accidental repoll does not repoll tokio-rustls's completed handshake.

Factories compute a distinct canonical configuration digest with maintained
SHA-256 over `l2tunnel/raw-tls-message-owner/v1\0`, the base digest and layer,
all RecordLimits and message limits, and fixed envelope version/geometry.
This first profile requires equal incoming/outgoing record budgets and rejects
asymmetry before I/O; encode that common budget once in canonical network order.
Later asymmetric budgets require an explicit direction-normalized version. The
factory recomputes this digest itself before auth; the exported helper is for
configuration inspection/tests, not a supplied proof. A mismatch fails existing
membership/config authentication before application messages are released.

The owner checks the authenticated session configuration and profile, TLS 1.3
and one of the pinned ring AES128-GCM/AES256-GCM/ChaCha20-Poly1305 suites before
publishing setup success. The existing 65,536 record maximum stays below those
TLS limits; cipher selection never extends or resets envelope budgets. No new
exporter or pairing key API belongs to this checkpoint. The later manager must
factor/reuse existing auth exporter derivation while retaining this same TLS
owner; it cannot infer keys from SessionInfo or reconstruct a stream.

## Message format and finite storage

Use one new owner-only envelope, not an advertised transition/Seal protocol:
bytes 0..4 `L2RM`, byte 4 version 1, byte 5 zero, bytes 6..8 a big-endian u16
payload length. Length is 1..=configured max_payload; zero, unknown version,
reserved bits, bad magic and oversized lengths fail terminally. There is no
terminal flag or Seal kind. Payload bytes are opaque authenticated control data
for the future reviewed protocol, not native packet data or a caller-provided
freeze certificate. This format and digest are versioned independently of
existing retained runtime framing; no existing profile wire bytes change.

Reserve one outbound 4104-byte array and one inbound 4104-byte array plus fixed
offsets/counters. No Vec/queue grows from an untrusted length. Only one staged
message per direction is allowed. `stage_message` validates payload, slot state,
whole framed byte budget, message slot and checked arithmetic before copying;
rejection leaves ownership/counters unchanged. A staged message reserves its
entire lifetime allowance and cannot be replaced or cancelled after partial
write. Counter status separates reserved, actually written/read and completed
messages; do not label queued or backend-accepted plaintext as wire bytes.

The receiver checks a next-message slot and full 8-byte header allowance before
any plaintext read, retains partial header bytes, then validates the whole
payload reservation before reading its first byte. Invalid incoming header bytes
were actually consumed and remain charged in terminal status; no untrusted
partial message is returned. Lifetime plaintext bytes include frame headers;
record I/O separately accounts the complete encrypted/authentication prefix.
Total retained message arrays are 8208 bytes, independent of TLS buffer storage.
Existing auth/TLS and finite tracked/raw bridge allocations remain additional
separate bounds, not concealed inside this number.

## Exact I/O and cancellation

Each read presents tokio-rustls a ReadBuf whose capacity is **only the exact
remaining header or payload length**, bounded by 4096. Never issue a speculative
read or use spare capacity after a complete frame. After completing a message,
`poll_receive` returns immediately without reading the next message/record; while
`message()` is occupied, later receive polls return the same completed result
without more TLS I/O. `consume_message` only releases that local slot. It does
not check or consume same-record extra TLS plaintext and does not claim a record
boundary. The owner can have a complete message while the TLS object still has
extra plaintext or deferred output; tests must retain that distinction.

Partial writes resume the original owned frame at its actual accepted plaintext
offset. After the final plaintext byte, `poll_send` drives one actual top-level
TLS flush before declaring that message complete. Plaintext acceptance, wire
acceptance into TrackedStream and physical send/peer ACK remain three different
boundaries. Poll cancellation retains both offsets and the need-to-flush state;
retry never sends the prefix again or constructs a new application frame. Flush
may materialize maintained output normally before any future Seal stage exists.
It proves no cryptographic quiescence and no physical drain.

A service poll performs at most one top-level TLS read, write or flush operation.
If a ready operation leaves more owned work, explicitly wake and return Pending
rather than looping over messages. Maintained TLS may itself call RecordIo more
than once during that top-level operation, as the real counterexamples proved.
Do not claim one physical read per owner poll or hard preemptive CPU timing.
Envelope lifetime caps still bound total bytes/started records; each inner
RecordIo call remains bounded. Tests count both levels separately.

## Original deadline and terminal errors

Validate timeout in 1 ms..=30 s and compute one absolute Instant before creating
Setup. It includes TLS/member authentication and the complete message-owner
lifetime in this bootstrap checkpoint. Setup passes only the remaining duration
to the existing auth API and independently keeps the original deadline. The
message owner never renews it. Duplicate progress, successful I/O and resumed
polls do not create new time. A private Sleep/waker ensures a Pending operation
is polled at that original deadline. Both Setup and the message engine treat a
Ready timer poll as immediate terminal expiry, including when time crossed after
the preceding live-clock check; they never discard a ready timer and return
Pending without a future wake.

Check live time immediately before and after each top-level backend operation,
and again before publishing setup/message completion. A ready operation that
crosses expiry has its actual progress recorded but fails terminally; do not
return success because the operation was Ready. This is a bounded synchronous
operation with before/after checks, not an atomic wall-clock snapshot or a
preemptive timeout inside the maintained backend.

Store the first terminal cause and stop all future TLS I/O. A fresh backend I/O
error caused by an underlying original RecordIo fault is normalized to that
typed record cause after actual progress accounting. This normalization is
reachable only after a successful pre-operation live check, so earlier owner
faults cannot be replaced. A real TLS record-count exhaustion test checks the
root cause, original endpoint counters and repeated rejection. Distinguish timeout,
EOF/close, malformed envelope, record observer fault, byte/message exhaustion,
auth/config mismatch and underlying I/O/TLS failure. Preserve original I/O kind
and errno without storing user payloads/keys in errors. Busy staging, invalid
local payload size and consuming an empty slot are recoverable local errors
with no mutation. EOF anywhere in this bootstrap message protocol is terminal,
including boundary EOF: it is not an implicit successful Seal or peer barrier.
Keep the original TLS object on post-authentication failure until the owner's
terminal cleanup/drop; do not reset, drain hidden input, poll shutdown, send
close_notify or reopen a connection. Ordinary Drop performs no async work and
cannot certify that the separately retained driver has been joined.

## Runtime precondition

Factories and subsequent polling require a Tokio runtime with its time driver
enabled, as the existing auth implementation also requires. Missing runtime
context returns StartError::Runtime before I/O. `Handle::try_current` cannot
prove timer enablement through a supported public API; the factory's `# Panics`
documentation explicitly describes a locally timer-disabled runtime. There is
no catch_unwind, invented timer probe or claim of typed timer validation. Peer
packet/configuration fields never select the runtime's timer setup.

## Gates for this checkpoint

- [x] [MOD-RAWTLSOWN-01] Review placement/dependencies, factory identity, symmetric limit policy, exact API, canonical digest and lifecycle scope before code. Evidence: [approved contract](#implemented-exact-api); parent independently reviewed current auth APIs/dependencies and authorized this bounded checkpoint on 2026-11-12.
- [x] [MOD-RAWTLSOWN-02] Construct actual TLS/member auth from the fresh original tracked endpoint; retain the whole TLS wrapper and unique handle, reject mismatches before I/O, and keep setup cancellation/deadline semantics explicit. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/tls_owner.rs), [focused receipt](../../work/raw-tls-owner-20261112/receipt.json).
- [x] [MOD-RAWTLSOWN-03] Implement bounded exact message ownership with preflight reservations, retained partial read/write/flush offsets, one top-level operation per poll and immutable completed inbound delivery. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/tls_owner.rs), [focused receipt](../../work/raw-tls-owner-20261112/receipt.json).
- [x] [MOD-RAWTLSOWN-04] Test all header/body splits, malformed lengths, lifetime capacities, failed staging, Pending/cancel/resume, EOF, first-fault retention and ready completion at/after the original deadline. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/tls_owner_tests.rs), [focused receipt](../../work/raw-tls-owner-20261112/receipt.json).
- [x] [MOD-RAWTLSOWN-05] Test actual certificate/member/config rejection and complementary identities over original mock raw bridges; preserve both original wire counters and join every test driver explicitly. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/tls_owner_tests.rs), [focused receipt](../../work/raw-tls-owner-20261112/receipt.json).
- [x] [MOD-RAWTLSOWN-06] Retain real TLS counterexamples: same-record extra plaintext, next-record suffixes, fragmented post-handshake work, hidden KeyUpdate and latent TLS error; prove exact message reads do not silently claim freeze. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/tls_owner_tests.rs), [focused receipt](../../work/raw-tls-owner-20261112/receipt.json).
- [x] [MOD-RAWTLSOWN-07] Independently review source, run focused package lint/tests/docs and coordinated stable aggregate; no native or packet-phase activation follows automatically. Evidence: independent review accepted the original owners, exact messages and terminal faults after the timer-ready and underlying-record-fault fixes; [wave12](../../work/implementation-wave12/validation.json) passed 787 Rust and 105 Python cases with unchanged input hashes.
- [ ] [MOD-RAWTLSOWN-08] Separately review actual Seal transcript parsing, public backend zero-write materialize-and-reject, exclusive terminal owner, pairing/exporter integration and the complete pinned-backend freeze argument before adding any FrozenTls capability.

## Executed evidence

The final local package run passed **85 tests**, including **25 new owner tests**,
with the one explicit privileged marked-socket test still ignored and zero
doctests. Strict all-target Clippy and warning-denied rustdoc passed. Commands
actually run were `cargo fmt --package l2tunnel-raw-io`,
`cargo check --offline --package l2tunnel-raw-io`,
`cargo test --offline --package l2tunnel-raw-io`,
`cargo clippy --offline --package l2tunnel-raw-io --all-targets -- -D warnings`, and
`RUSTDOCFLAGS='-D warnings' cargo doc --offline --package l2tunnel-raw-io --no-deps`.
The subsequent coordinated [wave12](../../work/implementation-wave12/validation.json)
passed `python3 tools/check.py` with stable input hashes; wave11 predates both
this owner and the record adapter.

The new tests use actual existing certificate/member authentication over the
original counted raw bridges with finite mocked PacketIo. They cover wrong
certificate root/name, membership and configuration, exact original handle
rejection, borrowed Setup poll cancellation versus terminal Setup drop, original
factory/auth/message deadline, a real auth result becoming Ready after expiry,
partial messages/flushes and every short-body cancellation offset. The timer-ready
regression forces that precise internal branch without depending on a timing
race. The canonical digest is independently pinned to a Python hashlib/struct
vector for this new profile, not claimed as simulator-mode parity.

An exact message read leaves all 34 partial/complete prefixes of a following
real encrypted frame outside the original counted bridge. Same-record trailing
plaintext remains in maintained TLS on both endpoint roles; a requested
KeyUpdate response remains hidden until the test-only backend zero-write check.
The complete package also reran all earlier 16 RecordIo TLS regressions,
including fragmented post-handshake messages and oversized-read counterexamples.
The owner supplies no zero-write check or terminal capability in production.
Test tasks are explicitly aborted/joined; that cleanup is not a clean TCP drain,
physical raw-socket test, native qualification or full all-lane manager result.
