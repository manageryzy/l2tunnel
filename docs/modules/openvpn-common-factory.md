# OpenVPN Common factory and member handoff

Status: **implemented; three actual factory cases and four directly affected
managed-initial cases passed with stable source and executable hashes** in the
[affected receipt](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
The enclosing aggregate remains **failed, 51/55 passed**. Affected [strict affected checks](../../work/parallel-features-20261115/parallel-wave3-strict-attempt-2/validation.json) passed. The factory composes the real raw OpenVPN TLS/member owner with
the existing cookie admission, selected Noise and protected managed Joining loops. Full
[OWC-04..06](openvpn-wire-carrier.md#stable-work-and-validation-gates), SW-11,
resource, native, platform, performance and shared CLI/service gates remain open.

## Actual custody and binding

`secure_udp::establish::carrier::Outer::{client, server}` consumes the originally
connected UDP socket and runs the existing raw OpenVPN reset/TLS/member factory.
It retains that exact carrier, sole socket actor and actual TLS stream. The opaque
`AuthenticatedOuter` observation comes only from the completed real proof. Its
binding hashes the fresh TLS session ID, verified certificate identity, accepted
member, complete authenticated raw-policy digest and actual globally ordered
client/server endpoints. The immutable requested raw policy remains observable
separately from this effective binding.

The fresh outer session ID is unknown before TLS. The client factory therefore
accepts a post-TLS builder for the existing effective `establish::Config` and
refresh selection. `Config.binding.outer` must equal the genuine proof binding;
the builder must derive its complete effective configuration digest accordingly.
The static pre-TLS policy does not depend on its future proof, avoiding a circular
digest. `AuthenticatedOuter::expected_binding` provides the corresponding pure
prologue consistency check; copied observations create no Noise/member authority.
The existing bare-UDP `Config::expected_binding` behavior remains unchanged.

`Outer::connect` and `Outer::accept` consume the same owner through the existing
gate/selected Noise FSM. The server constructs and retains
`carrier::ServerAdmission` after authenticating its outer owner; failed or
cancelled inner establishment does not discard that caller-owned quarantine
state. A different TLS session requires its own effective binding and admission
instance. No new bootstrap, recovery or crypto state machine is introduced.

`secure_udp::member::carrier::{connect, accept}` uses the existing real managed
Joining loop and releases opaque `Authenticated`/`Parts` only after acceptance.
The accepted inner member must equal the actual outer TLS-authenticated member.
`Parts` transfers `OriginalDatagram`, the actual `ConfirmedInitial`, cover,
bootstrap/Joining tails, appearance counter, original cap, actual Noise clock
origin and authenticated observations. There is no status-to-Parts conversion.

The private shared `SocketBacking` dispatches both existing loops. Bare UDP keeps
its original borrowed I/O and adds no per-packet payload copy. The carrier branch
uses the existing fallible bounded payload copy and move-only physical send
ticket. Queue `WouldBlock` retries the same bytes under the original cap; queue
admission never becomes send success or simulated loss. Whole-write completion
is checked against the original cap again, retaining an actual late receipt in
the error. Receive storage includes the actual carrier maximum plus one byte.

Geometry checks include exactly one additional DataV1 opcode throughout inner
bootstrap full-IP accounting, the same actual endpoint pair and MTU, and the
actual raw maximum. Inner and outer policy ledgers overlap; summing them does not
measure network bytes. User data has no new outer ARQ or exporter resealing.

## Stable implementation and acceptance leaves

Checked leaves cover only their stated finite factory/handoff deliverable.
Neither their completion nor the positive cases close the complete parent carrier
gate or turn the failed enclosing batch into a passing aggregate.

- [x] [OCF-01] Validate actual TLS/proof-to-effective-config binding, fixed same-owner endpoints, complete raw policy and extra-opcode geometry through the existing selected cookie/Noise factory. (Evidence: [three actual carrier factory passes](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).)
- [x] [OCF-02] Validate actual managed member acceptance, exact outer/inner member agreement, consume-once selected authority and unchanged origin/cap/tails in opaque carrier `Parts`. (Evidence: [actual accepted handoff and member-mismatch refusal](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).)
- [ ] [OCF-03] Validate physical bootstrap/Joining send custody, original caps and retained late facts while preserving the borrowed legacy UDP path and existing managed UDP behavior. **Implemented; success and managed-UDP regressions passed, but the direct carrier-factory blocked/late-send matrix remains unvalidated.**
- [x] [OCF-04] Run the three focused actual carrier factory cases below and directly affected existing establishment/member cases; record exact executed scope and source hashes. (Evidence: [seven exact passes with stable source/executable hashes](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).)
- [ ] [OCF-05] Install these actual carrier `Parts` and physical tickets into the Common Driver and shared Prepared/service/client API, with post-TLS canonical effective settings and observable requested policy. Preserve authenticated control/liveness/fresh rekey, all record families and negotiated SW-11 barriers. **Remaining integration.**
- [ ] [OCF-06] Complete the original OWC-04..06 definitions, including complete resource/failure ownership, native full/half TAP/TUN, platform/impairment/drain, actual PCAP/dissector and controlled ISP-QoS evidence. **Open; unchanged parent scope.**

The following exact `secure_udp::member::carrier::tests` cases passed:

- `actual_openvpn_factory_member_parts_install_common_records_on_original_tuple`: real verified TLS/member, cookie admission, selected IKpsk2 and managed Joining; consume the actual accepted proof into selected Records; exchange User and Control records, reject replay, retain original endpoints/cap/origin and later real TLS service. This is a factory/record integration case, not the full management FSM or Driver/native loop.
- `actual_outer_factory_refuses_unbound_effective_config_before_noise`: actual completed TLS followed by refusal of an effective config not bound to that proof, before consuming Noise entropy.
- `actual_inner_member_cannot_replace_authenticated_outer_member`: actual successful inner protected member verification using a different allowlisted member cannot publish carrier `Parts` for the established outer identity.

The same receipt records these four exact
`secure_udp::member::refresh_tests` passes after the shared I/O change:

- `actual_selected_member_handoff_installs_v2_on_original_socket`.
- `managed_joining_wakes_at_retained_key_cap_without_renewing_outer_deadline`.
- `selected_dropped_acceptance_retries_original_ciphertext_after_key_owner_retirement`.
- `selected_member_denial_and_context_mismatch_do_not_release_authority`.

Each named filter selected one case. The receipt retains the actual commands,
logs and immutable source/executable hashes. The four managed-initial cases use
their existing UDP fixtures; they do not exercise an OpenVPN factory send held
across `WouldBlock` or a late physical factory-send result. Earlier independent
carrier/ticket cases remain their own evidence and do not close OCF-03. The
factory success case uses actual selected Records for User/Control and replay,
but does not install the Common Driver, full management FSM or shared service.

The existing client Settings canonicalization remains the bare-UDP public path;
it is not silently relabeled as OpenVPN. Additive post-TLS effective settings,
Driver ticket adoption and shared service installation remain required. This
slice provides no standard-dissector result, endpoint interoperability,
identification resistance, native/platform qualification or ISP prioritization
guarantee. Historical receipts and failed aggregate results are unchanged.
