# Original-owner raw packet runtime

Status: implemented with finite local integration tests over real maintained TCP,
TLS/member authentication and original mock PacketIo. No native descriptor opener,
CLI/native packet capability, clean protected close, running-session switch,
congestion safety or middlebox qualification is claimed. The ordinary retained
raw TCP/TLS profile and defaults are unchanged. Evidence is recorded in
[checkpoint 16](../../work/raw-runtime16/REPORT.md); the earlier
[startup transition checkpoint](../../work/raw-transition-checkpoint15/REPORT.md)
remains historical evidence for its own exact source.

## Explicit shared runtime API

`l2tunnel_runtime::raw_packet` exports validated `Config`, from-birth
`begin_client/server`, owned `Setup`/`Link`, `run(device, link)` and coalesced
logical `Status`. The Config binds native layer, frame compression/size, queue
counts/bytes, physical duplex, the actual Pipeline flow/channel/QoS policy,
maintained recovery geometry/timing, reassembly and native-confirmation service
into the session digest before the original TLS authentication. Invalid local
policy returns the original unpolled RawInputs. After attachment failure and drop
are terminal; the setup owns the actual packet transition future and never adopts
an independently supplied TLS stream or PacketCarrier.

The caller must keep polling an already-ready Link while another peer's Setup is
pending, exactly as with the underlying packet transition. `run` consumes the
same Link, validates device layer before reading it, and owns every runtime loop
and original carrier without spawning driver tasks. Its timer-enabled Tokio
runtime requirement is an explicit embedding precondition. Peer packet data cannot
select or disable the runtime's timer driver.

The native path is executable:

```text
PacketDevice receive -> existing Pipeline (common MUX + TAP/TUN policy)
  -> unchanged native frame + authenticated channel
  -> existing FrameCodec -> Fragmenter -> SelectiveRepeat or Reliable/Cauchy
  -> original PacketCarrier Data -> original tuple
  -> authenticated recovery inspector/engine -> Reassembler -> FrameCodec
  -> actual PacketDevice transmit -> cumulative protected native confirmation
```

TAP keeps endpoint/system TCP behavior. Transparent TUN uses the existing DRR and
common MUX; it does not take ownership of endpoint TCP cwnd or claim the separate
active-TUN/proxy profile. Endpoint TCP windows, aggregate native-delivery credit,
raw byte retirement/horizon and any future real carrier congestion control remain
distinct. The raw lab allowance is not a congestion controller.

All native frames, including TCP ACK/SYN and latency probes, enter the same
configured Pipeline and channel budget before recovery admission. An opaque
EtherType/MAC or user payload beginning with a control prefix cannot create
session-control authority. Received channel assignment is bounded and learned
only after actual protected/recovery/fragment/frame validation. Native frames are
released only after full validation and in the existing ordered recovery domain;
this checkpoint does not claim independent per-channel ARQ domains or all Python
mode families.

## Recovery, feedback and confirmation

The runtime reuses the existing UDP runtime's crate-private `Engine` adapter,
which delegates to the existing SelectiveRepeat/Reliable implementations and their
authoritative packet inspectors. It adds no ARQ algorithm, FEC simulation, source
identity or copied raw offset. Retries/repairs keep the original source/native
identity and consume a new protected carrier copy.

The fixed eight-byte runtime header is `L2RP`, version 1, kind, two zero reserved
bytes. Kind 1 encloses existing recovery data and travels as PacketCarrier Data.
Kind 2 encloses strictly inspected recovery feedback and travels as Feedback.
Kind 3 encloses one big-endian u64 cumulative successful native-device delivery
count and also travels as Feedback. The bounded native envelope is channel u16,
reserved u16 zero, then the existing FrameCodec bytes. Existing Fragmenter and
Reassembler own message identities and bounds; there is no native-fragment copy
outside those maintained codecs.

Native admission minus confirmed peer-native delivery cannot exceed the declared
per-lane native window. Source receipt/ARQ ACK is not native delivery. Only actual
successful device transmit increments local native delivery; WouldBlock retains
the same native bytes and gives no credit. A confirmation above actual admission
is terminal. Because this carrier reorders, an older cumulative confirmation is
idempotently ignored using a monotonic maximum and cannot grant new credit.
Periodic bounded cumulative confirmations tolerate lost controls.

One independent upper pending data record and one feedback record per lane keep
waiting bulk output from hiding reverse control. Credit and recovery feedback
receive alternating bounded service. Every staged record still uses the original
carrier's shared physical quota, key/counter, queue and packet/byte allowance.
Offset/window policy version 2 reserves eight maximum cells beyond Data admission,
four beyond upper Feedback admission, and the final four exclusively for internal
transition/liveness controls. This authenticated profile change prevents bulk
window exhaustion from also excluding recovery/native feedback; it is not an
unmetered user-data bypass. A peer implementing the earlier version has a different
authenticated policy digest and cannot silently mix the two interpretations.

## Failure, ownership and observations

Config validation checks local queue/codec/recovery bounds, canonical channel
policy, source MTU, fragment-count wire width and duration arithmetic before I/O.
Actual original authentication still enforces the complete raw policy, tuple and
full/half roles. Device/carrier errors retain real I/O categories/errno. Native
counter differences use checked subtraction; malformed confirmation cannot make
them underflow. A native write that completes immediately before a lifetime
failure is counted before the terminal post-I/O check.

The coalesced Status distinguishes common-admitted native frames, unique source
submissions, complete reassembled peer frames, actual device deliveries,
authenticated peer delivery and carrier staging. Staging is not a physical send;
source restoration is not device delivery. Status becomes Stopped on error or
owning cancellation. Dropping the single run future drops the exact original
owners synchronously outside shared locks, without polling shutdown/FIN/RST or
claiming a clean TCP result.

The authenticated raw setup deadline is never restarted after its construction.
Its already-reviewed setup/old-prefix expiry remains inside PacketCarrier. Active
carrier liveness, recovery retry limits and first-fragment reassembly lifetime are
separate finite bounds. There is no native-input API before committed Link
construction and no same-tuple rollback after failure.

## Stable implementation ledger

These checked entries mean only their exact finite deliverable below passed; the
larger raw phase/native gates remain open.

- [x] [MOD-RAWRUNTIME-01] Bind fixed native/codec/MUX/recovery/credit policy before original authentication; canonical mutations and invalid local configuration with zero original-I/O calls pass. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-02] Run original TLS-to-packet startup into the typed runtime with exactly-once original-I/O destruction on cancellation/error; full/half actual owner integration passes. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-03] Forward byte-exact TAP/TUN frames through common Pipeline, existing fragment codecs and maintained SelectiveRepeat/Reliable in finite full/half AEAD/HMAC cases. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-04] Preserve native/source identity through finite loss/reorder/duplicate cases for selective repeat full/half and Cauchy half, without duplicate native delivery or extra native admission. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-05] Keep confirmed native credit bounded during blocked output while reverse half traffic/control progresses; invalid authenticated credit/channel/control and absent active peer fail closed. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-06] Exercise Lz4IfSmaller with actual compressible and incompressible 4000-byte native frames over MTU576 in full/half, including real multi-source fragmentation and exact reconstruction. Evidence: [checkpoint 16](../../work/raw-runtime16/REPORT.md).
- [x] [MOD-RAWRUNTIME-07] Complete independent source review and a source-stable workspace aggregate including required tools/check.py. Evidence: root reviewed original ownership, admission/feedback/credit and bounds; [wave16b](../../work/implementation-wave16b/validation.json) passed 949 Rust/126 Python cases with stable 593-input identity and strict workspace checks. Subsequent native opener/client changes remain separate.
- [ ] [MOD-RAWRUNTIME-08] Add separately reviewed original native PacketIo opening, explicit shared client/service selection/status and an approved immutable native/path qualification experiment.
- [ ] [MOD-RAWRUNTIME-09] Qualify protected clean close, real congestion behavior, all-boundary resource/cancellation matrices and nonzero running-session hot-switch/native fences before broader capability claims.
