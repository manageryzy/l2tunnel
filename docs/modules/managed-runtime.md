# Managed authenticated runtime

Status: implemented and integration-tested on real TCP/TLS loopback and owned
Linux TAP/TUN/VXLAN namespaces. The design below was recorded before implementation.
This module connects the tested
management transaction to actual authenticated TLS streams and injected native
packet devices. It initially supports None/LZ4 compression changes only.

## Public interface and negotiated scope

`managed::mode_config(RuntimeConfig, Duplex)` constructs the implemented profile:
one channel, connection-round-robin assignment (trivial with one channel),
carrier-only recovery, complete frames, ordered delivery and full headers.
`managed::session_config(RuntimeConfig, &ModeConfig)` returns the exact auth
`SessionConfig`. Its domain-separated SHA-256 covers the managed framing version,
packet layer, maximum native packet length, codec version and canonical mode bytes.
It must be used before TLS member authentication on every lane. The unmanaged
runtime's digest is deliberately incompatible.

`managed::channel()` returns a cloneable `ControlHandle` and one `ControlReceiver`.
The fixed eight-request queue is local; requests grant no network authority.
`ControlHandle::switch_compression(Compression)` awaits an applied epoch or an
explicit Busy/NotCoordinator/Aborted/Closed result. `subscribe()` exposes a bounded
watch snapshot of phase, epoch and cumulative admission/delivery counters.
`managed::run_managed(device, link, runtime_config, managed_config, receiver)` owns
the session until EOF, failure or cancellation. `ManagedConfig` contains the
role, exact initial mode and transaction deadlines. Role, duplex, native layer and
digest must match metadata retained from the authenticated Link. Client is the
sole coordinator; server-origin local switching is explicitly rejected.

Both full duplex and paired half duplex retain their original TLS streams. The
logical management session ID is the first authenticated lane: client send lane,
server receive lane. Each direction sends data and control on its bulk lane;
otherwise-unused TLS halves are kept alive and polled for TLS control traffic.
The authenticated outer kind alone selects control dispatch; a user EtherType or
packet payload cannot create a management record.

## Bounded transport and device barriers

Reader and writer futures live for the whole session. Frame reads/writes are never
cancelled and restarted by the inner event loop. The outer record packet counter
includes all kinds and never resets during mode switches. Management request and
packet counters also remain monotonic. Data records carry their admitted epoch;
control and delivery-credit records use a stable bootstrap epoch zero.

A fixed per-direction native-packet window is negotiated from `queue_packets`.
Admission consumes one credit before reading the device; credits return only after
the receiver's device accepts the packet. Cumulative authenticated feedback is
coalesced into a single watch slot. This bounds all admitted packets, including
queued, writing, in-flight, received and device-WouldBlock packets. It lets the
reader continue to service control within a bounded receive window. Control has
its own fixed eight-record queue, at most 4096 bytes per record, and bounded input
rate (256 authenticated control records per second). These fixed runtime credits
are bounded admission, not the planned adaptive per-flow TUN flow-control or QoS
implementation. Control never carries user probes or native TCP control packets.
Logical retries pending real TLS flush are coalesced by immutable request header
and body, excluding the fresh per-transmission replay packet number. Distinct
requests retain the fixed eight-entry bound; conflicting reuse is rejected.

Staging validates/allocates the target stateless codec and stops new data
admission. The local fence is the cumulative exclusive admitted native-packet
count. Drain requires both the writer's cumulative flushed count and the local
device's delivered count to match the two independently negotiated fences.
Neither an empty queue nor receipt by TLS is sufficient. Native transmit returning
WouldBlock retains the exact packet and delays the barrier.

Both peers stop data admission throughout PREPARE through RETIRE. The follower
queues its RETIRE acknowledgement before resuming target-epoch data. The single
ordered writer prioritizes that control queue, and the single reader dispatch
queue preserves ordering; thus the coordinator processes retirement before any
new-epoch payload. No target packet is delivered during uncertain commit. Old
readers are explicitly removed at retirement. Codec selection uses the exact
authenticated epoch, never a guessed payload format.

Clean full-duplex EOF drains complete already-received packets to the device and
flushes their cumulative delivery confirmation, with a five-second bound on
lingering WouldBlock or blocked feedback. Truncated frames, unacknowledged
local data, unfinished transactions and paired-lane closure are errors.
Cancellation tears down the session and outstanding local requests without
claiming a successful switch. Post-COMMIT timeout follows the management module's
uncertain reconciliation policy and never rolls back. Crash/session resume,
lossy UDP/raw carriers, live duplex/channel/recovery changes and GUI integration
remain separate work. The shared CLI uses the private Unix local API.

## Acceptance evidence

- [x] [MOD-MANAGED-01] Validate negotiated digest, role, layer and supported profiles before reading the device. Evidence: [real authenticated runtime tests](../../crates/l2tunnel-runtime/src/managed_tests.rs).
- [x] [MOD-MANAGED-02] Run real authenticated full/half loopback forwarding with monotonic outer/control counters and fixed queue limits. Evidence: [real authenticated runtime tests](../../crates/l2tunnel-runtime/src/managed_tests.rs).
- [x] [MOD-MANAGED-03] Switch None/LZ4 both ways under queued payload and device WouldBlock; prove byte-exact delivery and epoch agreement. Evidence: [real authenticated runtime tests](../../crates/l2tunnel-runtime/src/managed_tests.rs).
- [x] [MOD-MANAGED-04] Reject user-origin control spoofing, unsupported changes, stale epochs and malformed authenticated records. Evidence: [real authenticated runtime tests](../../crates/l2tunnel-runtime/src/managed_tests.rs).
- [x] [MOD-MANAGED-05] Exercise timeout/uncertain failure and EOF with pending requests; never report local-only configuration success. Evidence: [real authenticated runtime tests](../../crates/l2tunnel-runtime/src/managed_tests.rs).
- [x] [MOD-MANAGED-06] Run owned-namespace/native-device compression reload qualification and integrate the local API into clients. Evidence: [nine native cases](../../work/native-managed-logical/receipt.json).

Executed locally: `cargo fmt -p l2tunnel-runtime`,
`cargo test -p l2tunnel-runtime --offline` (12 tests, including four existing
unmanaged tests), and `cargo clippy -p l2tunnel-runtime --all-targets --offline --
-D warnings`. Real loopback tests cover full/half × TAP/TUN, queued payload and
WouldBlock, None→LZ4→None, no counter reset, experimental EtherType user data,
wrong negotiated metadata, credit overrun/forgery, compressed data in an Off epoch,
wrong/retired epoch, oversized/truncated framing, session/sequence mismatch,
malformed management, fragmented reads across timer ticks, orderly EOF delivery,
local queue saturation, cancellation status, lost COMMIT_ACK uncertainty, real
Peer retry coalescing under writer backpressure and final feedback after TLS
half-close. The separate native receipt covers nine TAP/TUN/VXLAN cases: each
layer in clean half/full and impaired half mode, with two peer-confirmed switches
during 512 KiB TCP payload transfer. Windows/Android, UDP/raw recovery, adaptive
per-flow TUN flow control and live changes beyond compression remain unqualified.
