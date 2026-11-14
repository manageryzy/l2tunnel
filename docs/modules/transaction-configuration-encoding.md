# Explicit complete configuration encoding

Status: **implemented and protocol-tested; selected runtime integration and full stage acceptance remain open**.
This prerequisite extends the existing pure transaction engine for complete
cross-profile configuration values. It preserves full SW-11 and every mode,
resource, lifecycle, platform and performance gate. It changes no carrier,
cryptographic owner, runtime default or owner decision.

Read [architecture](../architecture.md), [implementation plan](../implementation-plan.md),
[master ledger](../implementation-checklist.md), [mode parity](../mode-parity.md),
[generic transactions](generic-secure-udp.md) and
[directional record owners](directional-record-endpoints.md) first.

## Existing boundary and exact extension

`transaction::Configuration` currently validates `ENCODED_LEN` in1..=512 before
encoding/decoding/allocation. Swift's complete v1 value is304 bytes. Full
independent Aligned/Packed values, common traffic/pipeline/window policies and
immutable envelope binding exceed512; dropping fields or equating directions
would violate their stated semantics. The new complete record configuration is
expected to occupy1304 bytes, with its own L2RC version2 prefix and digest domain.

Add a small trusted-local type contract, not a peer-provided allocation request:

```rust
pub enum ConfigurationEncoding { LegacyV1, CompleteV2 }
impl ConfigurationEncoding {
    pub const fn maximum_bytes(self) -> usize;
}
trait Configuration: Clone + Eq {
    const ENCODING: ConfigurationEncoding = ConfigurationEncoding::LegacyV1;
    // Existing required constants/methods remain unchanged.
}
```

LegacyV1 retains1..=512. Explicit CompleteV2 permits1..=4096. Check that exact
static bound and the existing1..=128-byte domain bound before invoking any
configuration validate/encode/decode callback or allocating canonical bytes.
Zero, one beyond the selected bound and usize::MAX fail at that boundary.
The trusted implementation still owns scalar semantics, exact canonical bytes,
strict decode and unique digest domain; central decode still re-encodes and
compares every byte. No data-controlled length widens the selected contract.

The existing `ModeConfig` and `swift_configuration::Configuration` inherit the
legacy default and keep every byte/digest, parser refusal and constructor.
The new complete value explicitly selects CompleteV2. A digest label or enum
alone does not enable another runtime mode or substitute for a real adapter.
Public libraries gain no OS handles, clocks, Tokio, privileges or crypto.

L2MC's existing112-byte version1 management header and transaction phases stay
unchanged: canonical C is already a fixed, explicitly selected opaque format in
that grammar. Version2 is the complete value contract/prefix/digest, not a new
transaction FSM or inferred packet shape. Initial authenticated setup must bind
that actual selected configuration and full supported catalog before runtime
use. An old selected C cannot silently decode a different-length complete value.

## Dependent lengths and unchanged resources

Add `transaction::maximum_prepare_bytes<C>(sender_channels: u16)` as a checked,
allocation-free actual-wire geometry query:

`management::HEADER_LEN + 8 + C::ENCODED_LEN + 2 + 8 * sender_channels`.

It validates the type contract and width1..=256 before checked arithmetic. The
width is the exact old global sender fence, not the target width or a padded
maximum. It grants no fence/authentication/staging authority. Consumers must
compare the result with their real complete-message/frame bounds and fragment
geometry before constructing selected owners; no existing default limit,
retained-byte budget or timeout is increased by this helper. CompleteV2's maximum
PREPARE with256 channels is6266 bytes, below L2MC's existing65536-byte hard limit.

The existing transaction implementation also has a private4096-byte frame and
16384-byte request gate bound. Explicit CompleteV2 must update every actual emit,
receive, gate, leased preview and final-custody decoder together. Add the checked
pure query `configuration_limits<C>() -> Result<management::Limits, Error>`:
LegacyV1 returns those exact old limits; CompleteV2 sets frame maximum to
`max(4096, maximum_prepare_bytes<C>(256))`, retains four requests and sets gate
retained bytes to checked `4 * frame_maximum`. Thus the1304-byte complete value
still uses4096/16384, while a4096-byte value uses6266/25064. This is an explicit
typed-contract limit, never widened from incoming bytes. No generic default
Limits or existing selected runtime budget changes. Future complete runtime
construction must query and charge these real bounds before selecting that C.

This batch implements and tests the pure type/wire prerequisite. The new common
configuration and real record engines are parallel consumers. Existing selected
Swift runtime/API/CLI remains on its original contract until actual complete
constructor, message/resource plans, canonical catalog, native fences, current/
prepared ownership and observable requested/effective API are integrated.
Root owns those consumers separately; no unused type can close their gates.

## Actual verification and ownership

Root owns `management/src/transaction/config.rs`, its exports, the geometry helper,
a dedicated encoding test module and registration. The configuration worker owns
the new facade record-configuration module; the record-engine worker owns its
new composition module; the refresh worker owns security/handshake/secure_record.
Root owns shared facade exports/manifests/master ledgers and all execution.

Use actual Peer<C> transactions with a complete value larger than512, including
initial/catalog/proposed digest checks, full trailing canonical bytes, PREPARE
and old-sender fences, exact duplicate retries, original lease expiry, staged
readers, commit and retirement. Test both codec boundaries at512/513 and4096/4097,
short/overlong inputs and permissive decoder re-encoding refusal. A trusted local
callback witness can prove that rejected static types never call encode/decode;
it is not authentication or successful runtime evidence. Preserve existing
Mode/Swift fixed vectors and all original negative tests.

Run affected management and actual new configuration/engine/facade checks with
bounded parallelism after source freeze. Reuse unchanged inputs explicitly;
full required workspace/native checks remain stage acceptance. Preserve every
failed attempt. Protocol tests do not qualify same-socket runtime or platforms.

## Stable tasks

- [x] [TCE-01] Freeze the explicit version/bound contract, exact geometry, compatibility, actual tests, file ownership and pre-edit source binding before implementation. Evidence: [original binding](../../work/record-composition-20261114/transaction-encoding-preedit-v0.json), [dependent-bound refinement](../../work/record-composition-20261114/transaction-encoding-pre-production-v1.json).
- [x] [TCE-02] Implement selected static bounds before callbacks/allocation and checked PREPARE geometry through the existing pure configuration codec, preserving all legacy bytes/errors/defaults. Evidence: [actual codec and geometry](../../crates/l2tunnel-management/src/transaction/config.rs), [source-stable affected receipt](../../work/record-composition-20261114/foundation-attempt-1/validation.json).
- [x] [TCE-03] Pass actual oversized-value Peer transactions, canonical/full-tail and static/wire/width/arithmetic boundary tests, original retry/lease/commit/retirement regressions and strict affected checks. Evidence: [59 actual transaction tests](../../work/record-composition-20261114/foundation-attempt-1/l2tunnel_management.log), [119-test foundation and strict checks](../../work/record-composition-20261114/foundation-attempt-1/validation.json).
- [ ] [TCE-04] Integrate actual complete cross-profile values and supported catalog into the selected Driver/service/API/control-resource plans without field loss, inferred defaults, changed caps or fake authority; preserve complete SW-11 acceptance.
- [ ] [TCE-05] Reconcile source-stable affected evidence and required full stage/native/platform acceptance; no passing component check closes broader parents.

## Focused implementation evidence

The source-stable foundation receipt passes all59 selected transaction cases,
including1304/4096-byte values through actual directional and leased Peer phases,
fresh-packet cached retries, original900-tick custody expiry and exact retirement.
Static callback precedence covers size0/512/513/4096/4097/usize::MAX and digest
domains0/128/129. Frame growth is checked at1926/1927 and4096 canonical bytes;
the oversized leased output uses the actual outbound-context decoder. Legacy
mode bytes/digests/default limits remain unchanged. The other60 passing cases
cover shared packet/QoS/pipeline validation and two actual Active consumers.
Strict affected Clippy/rustdoc/format checks pass. This is not a new full
`tools/check.py`, selected runtime, native or platform qualification.
