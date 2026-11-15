# Original datagram custody in the shared Driver loop

Status: **implemented and finite Linux loopback integration-tested**. The private
I/O adapter and initial-only public Common carrier path have actual socket and
Unix packet-device evidence. Timed Records/refresh installation and the complete
carrier service path remain coordinated integration work. The full
[OWC-04..06](openvpn-wire-carrier.md#stable-work-and-validation-gates) and
[OCF-03/05/06](openvpn-common-factory.md#stable-implementation-and-acceptance-leaves)
definitions remain open.

`transport_carrier::IoOwner` selects the original UDP socket or the actual
`OriginalDatagram` from opaque carrier `Parts`. It creates no socket, proxy,
forwarding task, session authority, crypto, recovery or management FSM. The same
`run_driver_clock`/`next_io` loop drives either owner. Existing public UDP run
signatures, borrowed writes, packet bytes and defaults remain unchanged.

The carrier-only variant fallibly reserves one singleton, one maximum Control
output buffer and one maximum-plus-one receive buffer. `Plan` and actual `Usage`
count the I/O-owner header, singleton layout and both buffer capacities once.
They exclude nested actor/TLS/channel heaps; this is not complete runtime resource
qualification. The bare-UDP path creates no new payload copy or adapter heap.

There is at most one User ticket and one independent Control output/ticket.
Common User ciphertext stays in the existing `PendingWire`, retaining its actual
scope, full security number, cost, original cap and optional rolling carrier
token. Queue admission returns `Pending`. `WouldBlock` preserves exact custody;
it cannot become loss, physical completion, resealing or another policy debit.
The Control slot similarly retains exact already-sealed Control or bootstrap/
Joining tail bytes while gating only further Control output polling. User and
the existing outer TLS actor remain independent.

Original bootstrap and Joining `expiry()` accessors distinguish hard caps from
their retransmission/service wakes. The selected constructor must retain the
actual Noise clock origin and account for exactly one additional DataV1 opcode.
Fixed Control scope comes from the actual Records owner, independently of H0.
Inner and outer policy counters overlap and are not additive network-byte totals.

The sole loop polls actual tickets before checking expiry, records both class
completions before propagating either error, and consumes a rolling carrier token
only after a whole physical write. A late whole-write receipt remains a physical
fact, followed by terminal deadline refusal; it grants no drain, activation or
peer-delivery proof. Ticket readiness remains serviced when receive quota is
exhausted, and completion-only wakes do not consume receive quota. Held-output
wakes retain original caps and actual computation/native/input work while
suppressing packet-service retry wakes that cannot emit another packet.

## Stable acceptance leaves

- [x] [OCI-01] Validate actual carrier singleton/buffer Plan against retained capacities, original endpoints and extra-opcode geometry; keep nested resource totals and allocator coverage separately open. Evidence: both focused adapter cases in the [first exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json), and the actual public carrier case in the [final affected receipt](../../work/parallel-features-20261115/parallel-wave4-final-checks/validation.json). The first aggregate separately failed on a constructor stack regression, preserved below.
- [ ] [OCI-02] Validate same-loop physical User/Control custody, immutable Common ciphertext/PN/debit/cap and after-whole-write rolling token confirmation, including late facts and independent Control progress. **Implemented; the complete Driver blocked/late matrix is unvalidated.**
- [x] [OCI-03] Execute the two focused adapter cases below and directly affected shared-loop/Common/legacy cases with exact source-bound receipts. Evidence: the [scoped receipt chain](../../work/parallel-features-20261115/parallel-wave4-scoped-validation.json) preserves the failed stack/clock attempts and their focused repairs; it does not close OCI-02's full Driver matrix.
- [ ] [OCI-04] Install genuine selected carrier `Parts`, original Noise time, timed Records/refresh and complete authenticated contract into actual Common Driver and shared service/client lifecycle; complete all original negotiated switching barriers and capability observations. **Coordinated integration remains open.**
- [ ] [OCI-05] Complete OWC-04..06, OCF-03/05/06, full resource/native/platform/impairment/PCAP/dissector and controlled ISP gates without replacing them with adapter tests. **Open; full parent scope unchanged.**

The executed `transport::carrier::tests` cases are:

- `actual_outer_io_keeps_separate_tickets_and_only_reports_whole_original_socket_writes`: real TLS/member raw carrier, exact original UDP endpoints, actual bounded adapter capacities, independent pending User/Control tickets, immutable identity refusal, actual whole-write receipts and exact received bytes. Opaque test identities/payloads do not create Common authority; this case does not force kernel or actor `WouldBlock`.
- `physical_late_projection_retains_actual_whole_udp_fact_without_success_relabeling`: an actual kernel UDP write supplies the receipt, then the typed late-result projection is injected to verify physical-fact preservation. It is not measured kernel deadline latency or a complete late Driver test.

The constructor and service consumers must adopt the real opaque owners; copied
`Info`, public status or fabricated socket endpoints cannot create that authority.
Standard parseability, endpoint interoperability, identification resistance and
ISP classification/QoS remain distinct unverified claims for this integration.

The additive initial-only factory/Driver path uses distinct actual `InitialParts`
after TLS, Noise and member acceptance. It retains the original Noise clock and
three-stream common v1 protection, with no refresh selection or key-age timer.
`run_common_on_carrier` uses the same Common constructor/continuation and charges
the actual I/O adapter Plan before publication. This path does not imply the
managed fresh-DH controller or full carrier service selection is installed.

- [x] [ICR-01] Execute actual initial-only TLS/Noise/member handoff, original socket/clock/cap and protected User/Control/replay checks without enabling managed key-age expiry. Evidence: `actual_initial_only_carrier_keeps_original_noise_member_root_and_socket` in the [first exact-case receipt](../../work/parallel-features-20261115/parallel-wave4-cases-attempt-1/validation.json); the unrelated constructor failure keeps that aggregate failed.
- [x] [ICR-02] Execute the actual public Common carrier run loop with Unix packet devices, nonempty bidirectional traffic, authenticated liveness, original endpoints and bounded shutdown; qualify full negotiated carrier switching separately. Evidence: `actual_initial_only_openvpn_common_loop_delivers_both_directions_and_liveness` passed after final injected-clock propagation in the [final affected receipt](../../work/parallel-features-20261115/parallel-wave4-final-checks/validation.json).
- [ ] [ICR-03] Complete shared-service/CLI carrier selection, bounded underlying automatic retained-state recovery and all unchanged OCF/OWC/native/platform/performance gates.
