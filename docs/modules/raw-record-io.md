# Bounded TLS record I/O checkpoint

Status: implemented and focused-tested; independently reviewed. Coordinated
aggregate validation is pending. This is only
an envelope-boundary adapter around the original counted endpoint. It performs
no TLS authentication, crypto, Seal parsing, freeze, handoff, transition or native
activation. Retain the entire maintained TLS object. The earlier [scratch evidence](../../work/raw-tls-freeze-feasibility-20261112/REPORT.md)
refutes simple freeze checks; those counterexamples remain applicable even with
this adapter. The complete [transition contract](raw-tls-transition.md) stays
behind its separate ownership, TLS and native gates.

## Source and exact API boundary

The implementation lives in [records.rs](../../crates/l2tunnel-raw-io/src/handoff/records.rs),
with narrow reexports from `handoff.rs`, [envelope tests](../../crates/l2tunnel-raw-io/src/handoff/records_tests.rs)
and [real TLS tests](../../crates/l2tunnel-raw-io/src/handoff/records_tls_tests.rs).
There are no production dependency changes or TLS-specific backend calls in the
adapter. Test-only rustls 0.23.45, tokio-rustls 0.26.5 and rcgen 0.14.10 use the
workspace's pinned ring provider/features. The module depends only on existing
Tokio I/O and the original TrackedStream. Its generic implementation supports
private conforming mock endpoints, but its public constructor accepts only the
tracked endpoint for which freshness and identity can be proved.

```rust
pub const MAX_RECORD_PAYLOAD: u16 = 18_431;
pub const MAX_DIRECTION_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_DIRECTION_RECORDS: u64 = 65_536;
pub const MAX_POLL_BYTES: usize = 4096;
pub const MAX_IO_SLICES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionLimits {
    pub wire_bytes: u64, // 5..=MAX_DIRECTION_BYTES, includes headers
    pub records: u64,   // 1..=MAX_DIRECTION_RECORDS, counts started records
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLimits {
    pub incoming: DirectionLimits,
    pub outgoing: DirectionLimits,
    pub max_payload: u16, // 1..=MAX_RECORD_PAYLOAD, envelope ceiling only
}
pub struct RecordIo<S> { /* private original S, fixed parser states and limits */ }
impl RecordIo<TrackedStream> {
    pub fn attach(stream: TrackedStream, limits: RecordLimits)
        -> Result<Self, (TrackedStream, AttachError)>;
    pub fn belongs_to(&self, handle: &SwitchHandle) -> bool;
}
impl<S> RecordIo<S> {
    pub fn status(&self) -> RecordStatus;
    pub fn limits(&self) -> RecordLimits;
}
// AsyncRead/AsyncWrite when S: AsyncRead + AsyncWrite + Unpin.
// No public generic new/adopt/reset/inner accessor/into_inner/Clone.
```

Defaults are 4 MiB and 16,384 started records per direction, with payload ceiling
18,431. The hard lifetime record ceiling of 65,536 includes plaintext handshake
records, compatibility CCS and every encrypted record; it never resets at a TLS
KeyUpdate. It is below the minimum TLS confidentiality limit of 2^24 records in
the currently selected ring TLS 1.3 AES suites; ChaCha's pinned limit is larger.
Pinned `rustls-0.23.45/src/crypto/ring/tls13.rs:28` sets ChaCha to
`u64::MAX`; lines 48 and 70 set the two TLS AES suites to `1 << 24`.
Lines 56 and 78 instead set their QUIC confidentiality limits to `1 << 23`.
These are TLS limits, not the separate QUIC limits. The future authenticated
owner must bind these finite limits and restrict/verify its supported cipher
profile; this envelope adapter does not negotiate or infer a cipher from bytes.
Total observed bytes across both directions are at most 8 MiB and total started
records at most 131,072. Validated lower per-direction limits are independent;
activity in one direction cannot consume the other direction's reserved body.

`attach` validates limits first, then checks freshness under the original bridge
Gate: endpoint read and written are both zero; state is NotStarted or Running;
no request, EOF, shutdown or terminal status; stream and handle remain alive.
The maintained raw engine may already have performed its TCP handshake or queued
unread bytes: none has bypassed the endpoint's first observation. Reject an
already-used stream even if the caller claims it was at a record boundary.
Failure returns the exact original stream without polling it, replacing it or
altering its gate/counters. The attachment implementation inspects the existing private Gate directly under
its mutex; it exports neither the underlying duplex nor the shared gate.

`belongs_to` compares the original private bridge identity directly with the
borrowed SwitchHandle, without a public numeric ID or identity constructor.
It is an identity query, not proof of authentication/quiescence. RecordIo itself
has unique ownership; copied status cannot construct or replace it. No separate
observer handle can outlive the stream and claim a fresh boundary. Later TLS
owners can inspect the actual RecordIo through their owned TLS object's get_ref;
no API in this checkpoint permits unwrapping/reconstructing that TLS object.

## Status and error contract

The public diagnostic shape is:

```rust
pub enum RecordDirection { Incoming, Outgoing }
pub struct RecordProgress {
    pub wire_bytes: u64,       // actual successful endpoint progress
    pub started_records: u64,  // first positive byte of each header
    pub completed_records: u64,
    pub header_bytes: u8,      // 0..=5, five while body is incomplete
    pub body_remaining: u16,
}
impl RecordProgress { pub fn at_boundary(&self) -> bool; }
pub struct RecordStatus {
    pub incoming: RecordProgress,
    pub outgoing: RecordProgress,
    pub read_eof: bool,
    pub shutdown_started: bool,
    pub shutdown_completed: bool,
    pub fault: Option<RecordFault>,
}
```

`at_boundary` means only zero incomplete envelope bytes; it is independent of
EOF/fault and says nothing about TLS plaintext, deframers or pending KeyUpdate.
Future readiness must inspect all relevant state rather than this one bit.
Counters cannot be set, saturated, reset or wrapped. Fault kinds are
ByteLimit, RecordLimit, Arithmetic, RecordLength, TruncatedRecord, WriteZero and
Io; each records its direction. Io diagnostics retain ErrorKind and optional
raw_os_error, never keys or payload. The first underlying I/O error is returned
unchanged. Later operations return a stable terminal error; no retry performs
more endpoint I/O. AttachError distinguishes invalid limits, nonfresh/lifecycle
state and poisoned gate, while returning the original owner.

The first sticky fault fails both directions and flush/shutdown. Clean read EOF
is separately recorded and keeps ordinary write-side half-close behavior; it is
never a freeze candidate. No fault triggers an implicit flush/shutdown/drop poll,
FIN, RST, TLS alert or replacement connection. The higher owner retains all
cleanup responsibility. Drop merely drops the original endpoint normally.

## No-prefetch parser and pre-I/O budgets

Each direction owns exactly five header bytes, used count, body remaining,
checked lifetime counters and a sticky terminal status. No complete record/body
is allocated or retained. Incoming I/O uses at most one fixed 4096-byte scratch
buffer per call, immediately copying every successful byte into the caller's
ReadBuf before returning; no successful byte is hidden for a later read.
Outgoing I/O borrows at most the corresponding bounded caller prefix.

A poll does at most one underlying I/O call and returns no bytes beyond the
current header or body segment. At a fresh record boundary it first checks room
for one started record and the entire five-byte header, using checked arithmetic.
At a partial header it caps the call to the remaining header bytes. At a body
it caps the call to body remaining. Each cap is additionally at most 4096 and
caller capacity/input length. Counters are charged only for actual Ready success;
Pending and ordinary error charge zero. Empty caller buffers return an empty
success without polling or setting EOF when the adapter is otherwise usable.
A previously sticky fault is still returned for empty operations.

On the first successful positive header transfer, increment started_records once.
On completing the header, decode only the network-order length; type/version and
cryptographic validity remain entirely with maintained TLS. Zero-length envelopes
are framed as complete and charged once; rustls decides whether their content
is legal. Reject a declared payload above max_payload and ensure the entire
remaining body fits the direction's remaining lifetime byte budget before any
body I/O. This is a bounded reservation, not an actual transferred-byte count.
Because that direction has only one in-progress record, no second record can
consume its reserved body allowance. Completion increments completed_records
once and returns to the next header boundary.

A write can examine its offered header bytes before sending them. Preview the
bounded candidate parser state and full-body budget before the inner poll. If
the offered prefix would finish an invalid/unaffordable header, return an error
before writing that prefix and latch the terminal fault. Already accepted bytes
of an earlier partial header remain counted; there is no rollback. On a valid
partial inner write, commit only the actual accepted prefix, never the entire
preview. The next caller must resume its still-owned suffix normally.

A read cannot know an incoming declared length before physically consuming its
header. Therefore an error discovered on the final header byte has an explicit
progress-first rule: charge and return those actually consumed header bytes as
Ready success, latch the terminal length/byte-limit fault, and allow no body I/O
or subsequent endpoint operation. Status already reports Failed on that return;
the next I/O returns its typed error. This preserves successful consumed-byte
accounting without an Err that secretly discarded a header prefix. Earlier
partial header bytes may already have reached rustls; no parser rollback is
claimed. Test this exact rule rather than asserting zero mutation for data that
could only be validated after reading it. Budget failures knowable before a
read, including record count, five-byte-header space and arithmetic exhaustion,
reject without an inner call or output/count change.

At exact byte/record capacity, a completed final record can still be observed
without a fault. The next nonempty attempt fails before I/O; it cannot read an
extra byte merely to discover EOF. Existing flush remains permitted until an
actual fault because it transfers no new counted data. No automatic budget
increase or record reclassification is permitted.

Vectored writes accept at most 64 slices, matching the pinned rustls write_to
bound. More slices return InvalidInput without endpoint I/O or parser mutation;
this is a local caller-shape rejection, not a peer-induced terminal fault. Within
that bound select the first nonempty slice and call the same scalar prefix path.
Report is_write_vectored=false; a partial first-slice write is valid. All-empty
vectors are a zero-byte operation. This avoids concatenation, arbitrary scans
or a second parser and keeps one endpoint call per poll.

## EOF, partial progress, cancellation and lifecycle

A nonempty incoming poll returning zero bytes at a record boundary records clean
EOF and returns it; later reads return real EOF without repolling. Zero bytes in
an incomplete header/body instead latch TruncatedRecord and return UnexpectedEof.
A nonempty outgoing poll returning zero latches WriteZero. No bytes/record
completions are fabricated for EOF or errors. An underlying Pending operation
must not publish tentative header/record reservations or counters.

Cancelling an ordinary pending read/write future leaves all already completed
prefix accounting in the owned adapter. A later poll resumes the exact same
header/body state. It must not restart a cancelled application write or read_exact
from offset zero: the later message owner must retain its own partial offsets.
This checkpoint supplies no message framing or cancellation-safe Seal parser.

Flush delegates to the original endpoint and preserves the same owner, counts
and parser state. It proves neither TLS output emptiness nor physical peer ACKs.
Shutdown is explicit: set shutdown_started before the first delegated shutdown
poll, retain it if Pending/cancelled, and set shutdown_completed only on actual
success. Read-side half-close may continue when no fault exists, but no further
write is accepted after shutdown starts. Repeated shutdown polls finish the
same operation; they do not reset state. A shutdown error preserves the original
error and latches Io. Any shutdown attempt makes later freeze eligibility false.
Dropping an adapter or cancelling its caller does not invoke shutdown implicitly.

## Focused implementation gates

This design does not replace the remaining exact-message parser, whole TLS owner,
zero-write materialize-and-reject check, member/pair binding or phase manager.
Those remain separately reviewed checkpoints. Existing legacy bridge/driver/auth
APIs and the retained TCP default stay unchanged.

- [x] [MOD-RAWREC-01] Review the API, freshness/identity proof, progress-first incoming errors, finite budgets and scope before source changes. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-02] Implement fresh-endpoint-only attachment with same-owner failure, wrong-handle checks, no generic adoption/reset/accessor and unchanged legacy APIs. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-03] Implement incoming/outgoing no-prefetch header/body state with one bounded endpoint poll, exact partial/Pending counters and finite vectored writes. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-04] Test all header/body split positions, zero/maximum/oversized lengths, coalesced records, payload/header byte caps, started/completed record caps and checked exhaustion before knowable I/O. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records_tests.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-05] Test progress-first malformed incoming header, pre-I/O malformed outgoing header, WouldBlock/partial retry, zero writes, EOF in every phase, syscall error preservation, cancellation and shutdown-start state. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records_tests.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-06] Test actual original counted bridge identity/count equality and real TLS handshake/application traffic through the adapter; retain the known oversized-plaintext-read and deferred-KeyUpdate counterexamples. Evidence: [source](../../crates/l2tunnel-raw-io/src/handoff/records_tls_tests.rs), [focused receipt](../../work/raw-record-io-20261112/receipt.json).
- [x] [MOD-RAWREC-07] Independently review source, pass focused tests/strict lint/docs and coordinated stable aggregate without claiming a TLS freeze capability. Evidence: independent source review accepted original ownership, exact progress accounting and sticky failure behavior; [wave12](../../work/implementation-wave12/validation.json) passed 787 Rust and 105 Python cases with unchanged input hashes.
- [x] [MOD-RAWREC-08] Review the subsequent exclusive TLS/message owner checkpoint before adding Seal parsing, backend deferred-output checks or any freeze/transition/native activation. Evidence: [exclusive TLS owner contract and tests](raw-tls-owner.md) were independently reviewed and included in [wave12](../../work/implementation-wave12/validation.json); Seal/freeze/packet-phase authority remains absent.

## Executed checkpoint and remaining evidence

The focused package run passed **60 tests**, with the explicit privileged marked
raw-socket test still ignored, plus zero doctests. Of these, **35 new tests** cover
this checkpoint: 19 envelope/identity/lifecycle tests and 16 real TLS tests. The
TLS tests reuse the same original TrackedStream and SwitchDriver over finite
mock packet I/O; they validate certificates with the pinned ring TLS 1.3 backend,
not member authentication, a native device or a raw socket. The fault-peer fixture
uses only maintained encryption with test-only public secret extraction; the
receiving TLS object remains intact. Explicit task cancellation/join is fixture
cleanup, not a clean TCP drain or successful ownership transfer.

The package tests reproduce every prior freeze counterexample: oversized
plaintext read-ahead, same-record extra plaintext, hidden complete-record
handshake fragments, latent backend error and deferred KeyUpdate. Exact reads
leave all 26 partial/complete next-record prefixes outside the original read
counter; 17 fragmented post-handshake ticket splits are accepted by maintained
TLS. Both directions' normal handshake/application wire counts match the original
bridge. Zero-byte backend writes may materialize a response without admitting an
application byte; this test does not implement or authorize a freeze procedure.

Commands actually run: `cargo fmt --package l2tunnel-raw-io`,
`cargo check --offline --package l2tunnel-raw-io`,
`cargo test --offline --package l2tunnel-raw-io`,
`cargo clippy --offline --package l2tunnel-raw-io --all-targets -- -D warnings`,
and `RUSTDOCFLAGS='-D warnings' cargo doc --offline --package l2tunnel-raw-io --no-deps`.
All final focused checks passed. An earlier strict lint attempt stopped in a
concurrently edited proxy dependency; its owner corrected that issue before the
successful rerun. The parent independently reviewed production ownership,
accounting and terminal behavior and found no blocker. The subsequent coordinated
[wave12 aggregate](../../work/implementation-wave12/validation.json) passed
`python3 tools/check.py` with stable input hashes; wave11 predates this code.
No Windows/Android, native, Seal parser, whole TLS freeze or packet-phase result is
claimed by this checkpoint.

The subsequent [exclusive TLS message owner](raw-tls-owner.md) now has a separately
reviewed and focused-tested implementation. It preserves this adapter and the
whole TLS wrapper; Seal and freeze authority remain unimplemented. The earlier
60-test record-adapter receipt above remains a historical checkpoint.
