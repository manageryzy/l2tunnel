# Selected connection reuse through the shared service

Status: implemented shared-service composition with finite executed service and DTO
cases; the finite closeout validation passed.
The authenticated runtime is integrated with [the same-owner protocol](connection-records.md#selected-slotreusev1-composition). This module
does not close complete PCO-05/06, PCOR-03, PBA-03 or native/platform/resource gates.

An explicitly selected Profile::new_with_connection_reuse retains the original
Common Prepared/Handle/Run generation and actual CommonControlHandle. One new
Handle::reuse_connection(owner, old_key, next_key, key) uses the same sole command
slot and bounded retained operation history. It does not create a new lifecycle,
security, classifier, recovery, Pipeline or socket owner. Both peers must retain
the old claim and the runtime must prove all original custody/fences.

Fresh admission validates the live selected controller, current owner range and
distinct canonical keys before consuming a service key. Exact retained keys replay
before live-state validation; mismatched bodies conflict. Acceptance creates one
absolute deadline from the existing max_operation_ms and passes that same Instant
to reuse_until. Scheduling, duplicate requests, waiters and protocol phases never
renew it. Cancellation is unsupported; dropping a waiter has no cancellation effect.
The runtime retains authority over peer provenance, old claims, conflict/drain,
incarnation installation and final activation.

The explicit local API4 action reuse_connection contains one bounded request and
request_key. Each key is lowercase hex of the maintained canonical FlowKey (at
most62 actual bytes), decoded only by FlowKey::from_canonical_bytes. No second
packet parser is introduced. This additive action is rejected in API1..3. It is
not permission inferred from user Ethernet/IP metadata. Older strict API4 clients
may refuse the explicitly selected new action/observation; there is no downgrade.

A selected-only optional connection_reuse status reports requested selection,
actual controller selection, actual current authenticated operation/phase/owner/
keys/incarnations/original clock cap, and the separately observed capability.
Capability describes actual negotiated and installed operation availability,
separate from whether a user has exercised it. The service copies the actual
runtime observation; it never infers availability from a request or a completed
operation, and it never blocks the first operation on an unqualified observation.
This does not close broader qualification gates. Optional connection_reuse_result carries
the exact retained service operation/key, original request, observed original
generation and real runtime confirmation/refusal. It is independent of the
current generation/selection, allowing honest cached results after release.
Both fields are omitted when absent, preserving unselected local bytes.

Only actual runtime success reports Confirmed. Closed/unknown ownership, service
termination and dropped in-flight operations report unknown outcome. Expired or
Protocol never implies peer rollback, reset or clean delivery. A service-local
ordinal is not an authenticated peer attempt, epoch or security identity.

The focused executed real-owner case reuses genuine tag8 Noise/member setup,
old TCP and source-free ACK delivery, the same generation's keyed reuse and
peer-confirmed next-incarnation native bytes. It checks exact original acceptance
cap, replay/conflict/cancel refusal, selected/actual capability status distinct
from completed operation outcome,
retained result after actual release and owned port/device cleanup. A separate
bounded DTO case checks canonical/parser/version/unknown-field limits and old
status-request bytes. Both cases passed in the
[first closeout check log](../../work/parallel-features-20261115/closeout-batch-check-1/check.log)
(the API4 DTO case and `selected_reuse_service_keeps_original_cap_key_generation_and_peer_confirmed_new_bytes`).
The [aggregate receipt](../../work/parallel-features-20261115/closeout-batch-check-1/validation.json)
remains failed for other cases; these finite passes are not whole-batch acceptance.
Loss/native/physical holds, full abort and
uncertain completion compositions, all carriers/layers, named Python parity and
all remaining native/platform/resource/performance requirements remain required.

- [x] [PCRS-01] Pass strict bounded maintained canonical flow-key and API4 action parsing, wrong versions/unknown fields/length/case/trailing refusal and unchanged unselected request serialization. Evidence: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).
- [x] [PCRS-02] Pass actual authenticated shared-service old-flow/new-flow bytes on one generation, original accepted cap, exact retained replay/conflicts, real completion/status and observed release; preserve unknown outcomes and full PCOR-03/PCO-05/06 definitions. Evidence: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).

Final finite validation: [closeout evidence](../../work/parallel-features-20261115/parallel-closeout-scoped-validation.json).

Source binding: [staged handoff](../../work/parallel-features-20261115/tcp-staging/connection-reuse-service/handoff-v0.json).

Selected status also reports the actual one-reservation reuse bytes/allocation.
The optional status is boxed so absent selection does not enlarge legacy DTOs.
