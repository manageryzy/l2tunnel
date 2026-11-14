# Fallible native completion storage

Status: **implemented in the existing driver and locally integration-tested**. This is actual runtime
resource work beneath GSU-05/SRS-07, not a performance qualification or a
redefinition of SW-11. All carrier, profile, lifecycle and platform gates remain.

## Private runtime boundary

Add `secure_udp/transport_native.rs`, selected by the existing transport parent.
`Queue<T>` owns a fully reserved ready FIFO and free-buffer stack, with exactly
`pending_packets` payload vectors, each reserved to `max_native`. The generic T
is fixed metadata (the real parent uses authenticated NativeOrigin and ordered
NativeIdentity), never another payload owner. Construction is fallible and uses
checked Layout/length arithmetic and `try_reserve_exact`. No public Rust protocol
library acquires runtime or OS dependencies.

```rust
Queue::<T>::new(packets: usize, bytes: usize, max_native: usize) -> io::Result<Self>
Queue::{len,is_empty,bytes,capacity_bytes}(&self) -> ...
Queue::can_acquire(&self) -> bool
Queue::acquire(&mut self) -> Option<Lease<'_, T>>
Queue::front(&self) -> Option<&Packet<T>>
Queue::complete_front(&mut self) -> io::Result<()>
Lease::copy(self, metadata: T, since: u64, input: &[u8]) -> io::Result<()>
Packet::{metadata,since,bytes}(&self) -> ...
```

All types/methods are private to the runtime parent; fields stay private.
The lease borrows the queue exclusively. It acquires an existing payload buffer
before Engine extraction and returns it on drop, including empty/error paths.
Copy checks the complete packet before mutation, preserves metadata/first age,
and enqueues without further allocation. Empty or oversized packets are errors.
`can_acquire` preserves the current conservative `bytes + max_native <= limit`
admission and packet bound. No borrowed payload survives extraction reuse.
`complete_front` recycles only after a complete physical device write, never
on EAGAIN. It checks accounting before mutation. `capacity_bytes` reports actual
requested retained heap layouts, excluding allocator rounding, RSS, stack,
kernel memory and the inline owner. It must not be called a full-driver budget.

The parent replaces its VecDeque/byte counter and per-extraction `to_vec` with
this real owner in the existing loop. Keep full authenticated generation/order
preflight and commit physical NativeWritten before clock sampling, expiry or
pool recycling. Preserve first-packet stall age across EAGAIN and completion.
Expose the actual requested native pool heap layout as
`Counters::native_storage_capacity_bytes`, separately from occupied
`native_pending_bytes`. Preserve the strict existing version2 client DTO;
exposing this extra value through the shared version3 API remains NQP-05.
Test-only
FIFO iteration may inspect immutable packet witnesses; production has no mutable
payload escape. Use no second I/O loop, new socket, altered queue ceiling or implicit default.

## Validation and ledger

Root executes formatting, focused cases and the required full check. Worker
owns only the new child source/tests; root owns parent wiring and ledgers.

- [x] [NQP-01] Freeze this interface and original physical-write invariants before edits. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [NQP-02] Implement actual fallible fixed storage, lease recycling and atomic refusals; test all allocation failure positions and retained capacities across reuse. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [NQP-03] Consume the owner in the production transport without packet-time allocation; preserve actual generation, ordering, bytes and stall deadlines under existing focused device fixtures. Evidence: [frozen focused checks](../../work/generic-driver-20261114/focused-attempt-3/validation.json).
- [x] [NQP-04] Run focused and required aggregate checks on the exact checkpoint and record scope. Combined control/Peer resources, generic switching and fresh native/performance gates remain open. Evidence: [required frozen checkpoint check](../../work/generic-driver-20261114/checkpoint-aggregate-attempt-2/validation.json) and [exact WIP restoration](../../work/generic-driver-20261114/checkpoint-isolation-attempt-2/validation.json).

- [ ] [NQP-05] Expose the actual native pool layout through the shared version3
  client/service status alongside exact generic configuration and capability
  limits. Preserve existing strict version1/version2 bytes.

[Focused attempt3](../../work/generic-driver-20261114/focused-attempt-3/validation.json)
passes142 selected UDP cases, including9 new pool cases plus existing actual
protected-socket/native-device failure, ordering, pressure, expiry and policy
fixtures on both covers. This is finite local integration evidence, without a
fresh privileged TAP lab or throughput result. The first two failed attempts
are preserved: attempt1 exposed two fixture errors; attempt2 preserved the
remaining counter baseline error after constructing a genuinely one-slot pool.
The fixed metric fixture uses immutable preconstruction limits and compares
new full-poll work against its actual existing baseline.

The required checkpoint check passes1812 Rust cases including doctests,376 tooling cases and1658 simulator cases with stable inputs. This exact checkpoint excludes/restores the unselected three-file Control bridge; unregistered engine-Bank/State work is not compiled or qualified. Strict workspace Clippy, formatting and rustdoc pass. No fresh native lab, Windows/Android build, device test or performance measurement is claimed. Full generic integration and parent gates remain open.
