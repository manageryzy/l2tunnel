# Owned duplex generations for the generic driver

Status: **implemented; nine focused Bank cases and finite selected-Driver integration pass**. This is a
resource/lifecycle prerequisite for GSU-04/GSU-05 and SRS-07. It does not close
full SW-11, combined control memory admission or any native/performance gate.

The [required source-stable check](../../work/generic-driver-20261114/driver-aggregate-attempt-1/validation.json) passes1878 Rust
cases including doctests,376 tooling cases and1658 simulator cases. This local
Linux result does not close the complete parent resource, fault, shared-API,
profile, native, platform or performance acceptance.

Add `secure_udp/transport_engines.rs`, a child of the existing transport. It
owns one actual Swift storage Set and at most two exact canonical generations.
It never owns a clock, socket, device, crypto record counter or management FSM.

```rust
type C = l2tunnel::swift_configuration::Configuration;
Bank::new(identity: transaction::Identity, epoch: core::Epoch, initial: C,
    limits: swift::storage::Limits, external_bytes: usize) -> io::Result<Bank>
Bank::prepare(&mut self, intent: transaction::Preparation<C>) -> io::Result<Prepared>
Bank::cancel(&mut self, prepared: &mut Prepared) -> io::Result<()>
Bank::stage(&mut self, prepared: &mut Prepared, operation: transaction::Operation)
    -> io::Result<()>
Bank::commit(&mut self, operation: transaction::Operation) -> io::Result<()>
Bank::abort(&mut self, operation: transaction::Operation) -> io::Result<()>
Bank::retire(&mut self, operation: transaction::Operation) -> io::Result<()>
Bank::identity(&self) -> transaction::Identity
Bank::current(&self) -> &C
Bank::epoch(&self) -> core::Epoch
Bank::engine(&self, epoch: core::Epoch) -> io::Result<&records::Engine>
Bank::entry(&mut self, epoch: core::Epoch) -> io::Result<storage::Entry<'_>>
Bank::usage(&self) -> storage::Usage
Prepared::matches(&self, intent: &transaction::Preparation<C>) -> bool
Prepared::{identity,ticket,origin,expires,config}(&self) -> ...
```

Use pub(super) methods/types only. C and all identity/ticket/scope/epoch/digest
fields are exact; local directions come from authenticated Client/Server global
roles and C.descriptor().direction. Initial construction actually reserves its
engine and validates the initial management digest. Prepare validates the full
session/lane/endpoints/role, old origin, exact next epoch and same envelope/native
geometry, then performs the real fallible `Set::prepare(Plan)` before minting a
private non-Clone Prepared. A checked process-local AtomicU64 owner identity
is allocated once per Bank without a heap allocation; include it in every
reservation check. It is a local ownership discriminator only, never a wire
identifier, random credential or authentication input. Exhaustion returns an
error and never wraps. Equal sessions/configurations in two distinct Banks must
still reject each other's guards. It leaves old forwarding untouched. Track the one
outstanding reservation and checked serial; no third slot or fallback allocation.
Prepared is an actual allocation handle, not authentication/admission authority.

Stage revalidates the actual Operation's identity, ticket, original cap and
origin against the actual reservation before exposing the target generation.
A reservation is inaccessible through engine/entry before stage. Cancel releases
only an unconsumed virgin target and invalidates that handle; foreign/reused
handles fail without mutation. Stage consumes it logically and repeated calls
are errors. The Set-local EngineId alone never proves a matching reservation.

Commit promotes the staged generation and keeps old as draining. Retire releases
only the old generation after actual Set drain checks; this does not manufacture
physical native/whole-message proof (the root must obtain both first). Abort
releases only a staged, still-drained target before commit; after promotion it
must fail and preserve both generations. Commit/abort/retire require the original
exact operation, not just a matching epoch. No destructive Engine replacement,
new crypto sender or rollback from Uncertain is allowed. Original operation
custody remains until final retirement/abort; engine invariants are checked
before changing mapping. A foreign stale token must not free a reused slot.

The authenticated combined ceiling is still a root prerequisite. external_bytes
must represent actual owners; this module reports it honestly and cannot prove
that scalar itself reserves control storage. No catalog pruning/default change.

- [x] [EGB-01] Freeze the private interface and actual two-generation invariants before edits. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json).
- [x] [EGB-02] Implement real pre-allocation, exact operation matching and one-way lifecycle with focused refusal/old-state preservation tests using actual leased Peers. Evidence: [source-stable focused check](../../work/generic-driver-20261114/integrated-focused-attempt-6/validation.json).
- [ ] [EGB-03] Consume the bank in the selected actual driver and prove physical native/control barriers. Keep full GSU-04/GSU-05/SRS-07 open until their complete requirements pass.
