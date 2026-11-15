# Managed Common runtime handoff

Status: **finite contracts protocol-tested; initial-only carrier path integration-tested;
managed runtime installation remains open**.
This work retains the complete SREF, OCF-05, CTS-07 and SEC parent definitions.
It consumes actual selected managed membership authority rather than deriving it
from public observations. Existing v1 and unselected UDP entry points remain.

The additive managed Common contract selects complete four-stream settings and
explicit fresh-key timing/copy policy. Its first three stream settings must match
the existing complete resource template. The authoritative selected namespace is
v2; no fourth dummy owner or v1 owner is constructed. The fixed Control digest
commits immutable complete control policy independently of the setup digest H0.
A complete managed envelope commits the base trust/carrier policy, actual v2
resources, catalog and explicit fresh-key policy. The initial Noise H0 commits
that envelope and checked refresh selection. Neither envelope nor Control digest
depends on the resulting H0, so there is no digest cycle.

The explicit `CommonTransactionContract::new_managed` takes the preselection
`base_policy`, local role, actual Config/cover/address family, `base_envelope`
(E0), full catalog, transaction settings, complete `SettingsV2` and
`FreshKeyPolicy { exchange_micros, key_micros, overlap_micros,
max_flight_copies }`. `new_managed_on_carrier` additionally requires the genuine
opaque `AuthenticatedOuter` produced by actual outer authentication. No default
fresh capability, periodic schedule or initial-only key timeout is introduced.
The owner has explicitly separated underlying reconnect responsibility from an
initial-only connection without subsequent key exchange. Full runtime refresh
and failure recovery remain required before selecting this capability end to end.

The managed resource commitment reuses the maintained complete shared inventory,
then commits selected version2, its actual four context mappings, exact wrapper
size, security prefix/protection and every complete message-owner limit/lifetime.
The first three settings must exactly equal Config.streams. All four delivery
settings preserve the shared base quota; a fourth dummy owner or multiplied quota
is not admitted. The fixed Control digest commits that resource value and the
original control epoch. E1 commits E0, base policy, full catalog root, managed
resources, fixed Control digest, complete transaction and fresh policy, and the
actual outer binding/policy when selected. The existing checked Selection binds
lane, security limits/protection, control epoch/digest, E1 and exact fresh values.
H0 then commits base policy, E1, Selection canonical bytes, initial complete
C(E1), and catalog root. This forward dependency graph never feeds H0 back into
Control, E1 or Selection. No new Lifecycle crypto domain/version is defined here.

`new_on_carrier` is a distinct initial-only constructor with the same base inputs
and actual outer proof, without SettingsV2 or FreshKeyPolicy. It retains v1
Records/three-stream behavior, adds exactly one carrier opcode byte, and derives
separate carrier E1/H0 commitments. `refresh_selection()` and
`fixed_control_scope()` are absent for that initial-only path. The existing `new`
remains unselected/extra0 with caller H0/E and unchanged legacy resource bytes.
`managed_streams()` exposes only the explicit selected four-stream policy.
`validate_outer()` requires the exact retained genuine proof on a carrier path
and rejects an unexpected proof on UDP/unselected paths. This consistency check
does not manufacture the socket, initial root, membership or Parts authority.
Carrier validation checks actual role/member orientation, immutable native layer,
requested session policy, address family/MTU and complete covered-record capacity.

Three focused contract cases passed in the [exact-case batch](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json): complete
Control/E1/Selection/H0 sensitivity and independence; first-three mismatch,
actual v2 mapping overflow, fresh-policy and prefix geometry refusal; and retained
legacy constructor labels/resource observation/geometry. Actual outer proofs and
runtime handoff are separately exercised by their owning implementation lanes;
this contract source alone does not claim those integrations passed.

Actual common-v2 protection has a larger prefix than v1. Contract geometry,
control reserve, record owner overhead and the optional OpenVPN opcode must all
use that exact selected layout before constructing any owner. The target does
not clamp records or silently change the requested source geometry.

The initial-only carrier entry consumes its distinct real Legacy root and the
actual original carrier Parts. It selects three Control owners and no refresh
selection, controller or key-age timer. The new `run_common_on_carrier` shares
the ordinary Common constructor and sole I/O continuation; its actual socket and
Unix packet-device fixture passed the [final affected cases](../../work/parallel-features-20261115/parallel-wave4-final-checks/validation.json). Reconnection remains underlying runtime/
service work and is not qualified by constructing another driver in a fixture.

Actual managed UDP or carrier Parts preserve their opaque ConfirmedInitial,
original socket owner, clock origin, setup cap and cached ciphertext tails. One
shared Common constructor consumes the selected authority, creates the actual
timed Records and reserved Control owner, and enters the existing sole runtime
loop when the remaining managed handoff/controller integration is installed.
The current shared constructor has the managed material branch, but no public
managed run entry enables periodic exchange or publishes incomplete recovery as
ready. Key, session, setup, transaction, physical-send and native caps remain
separate and use the original time domain. No generic root, fake Parts, new
connection, proxy socket or second crypto/runtime state machine is introduced.

The nested Lifecycle replay-domain issue is under an explicit owner question.
The managed handoff and controller adapters do not decide that protocol extension
or claim pressure qualification while it remains unresolved.

- [ ] [MCR-01] Validate canonical complete managed resource/control/envelope/selection/H0 commitments without cycles or omitted fields; preserve unselected bytes and reject incompatible geometry.
- [ ] [MCR-02] Consume actual accepted managed membership authority into timed Common Records and all four reserved control streams with the original clock/cap/tails, rejecting mismatched selections/roles/endpoints before publication.
- [ ] [MCR-03] Run actual protected socket/Unix packet-device exchanges and all four record-family switches through this managed Common runtime; prove independent liveness and unchanged continuing identities.
- [ ] [MCR-04] Integrate actual fresh-DH controller/key activation/retirement and selected carrier physical tickets in the same loop, including original-cap, replay/pressure/loss, overlap and retained native/transaction/control custody.
- [ ] [MCR-05] Complete actual shared service/CLI and full original resource/fault/retained-recovery/native/platform/performance definitions; finite local fixtures do not close these parents.
- [x] [MCR-06] Execute pure managed UDP commitment sensitivity, first-three/mapping/prefix refusal and unchanged legacy-constructor cases. Evidence: the three `common_contract::managed::tests` cases in the [finite exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json). This does not complete MCR-01's full contract matrix or MCR-02..05's actual managed installation.
