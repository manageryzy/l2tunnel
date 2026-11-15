# Original datagram physical custody

Status: **implemented and registered; six focused custody cases passed**. This is
an I/O prerequisite for actual OpenVPN Common installation. New six-package
strict Clippy/rustdoc/format checks **passed**. The
[named custody receipt](../../work/parallel-features-20261115/parallel-wave2-datagram-custody-scoped-validation.json)
consolidates six new and seven affected existing cases. The combined
[27-case receipt](../../work/parallel-features-20261115/parallel-wave2-cases-attempt-1/validation.json)
remains **failed, 26/27 passed**; its rolling literal fixture failure is retained.

`l2tunnel_runtime::secure_udp::original_datagram::OriginalDatagram` owns a real
connected UDP socket or the existing raw OpenVPN carrier and its original socket
actor/TLS owner. It creates no proxy socket, Noise session, packet keys, recovery
algorithm or management FSM. Existing UDP/protected factories and defaults remain
available. `begin_send` returns move-only custody; `poll_send`/`wait_send` report an
actual whole socket write. Foreign or consumed tickets are refused before I/O.
`poll_receive` services the unique receive owner into bounded caller storage.
Raw received bytes remain untrusted until the existing common owner opens them.

User and Control retain separate bounded admission and immutable pending output.
UDP pending payload copies are fallible, and aggregate pending geometry has a
checked overflow guard. An OpenVPN ticket follows the existing actor's actual
completion. `WouldBlock` preserves bytes and the original cap without another
encoding, encryption, ARQ operation or wire debit. Before/after write checks return
an expired result with the actual receipt if a whole write crossed the cap; that
receipt cannot authorize a successful drain or renew any operation/native cap.
Dropping an unpolled UDP ticket releases it without sending. Cancelling an actor
ticket may race a real write; observed physical facts remain in its counters.

Checked geometry includes IP/UDP and exactly zero extra bytes for bare UDP or one
DataV1 opcode for OpenVPN. The adapter retains actual endpoint observations, outer
TLS/proof access and outer expiry. Outer wire admissions and `physical_status`
are distinct; both overlap future inner full-IP admission observations and must
not be summed as network bytes. TLS/reset/ACK retransmissions remain visible in
outer physical counters. Raw `client_connect_until`/`server_accept_until` use the
same accepted absolute setup cap, bounded by the configured outer maximum.

The [authored source freeze](../../work/openvpn-send-custody-20261115/source-freeze-v0.json)
records exact APIs, files and limitations before root formatting/build. Root's
additional production edits are runtime module registration and the checked
pending-total overflow guard. The following exact items passed in the combined
receipt; no passing aggregate is inferred:

| Exact test suffix | Finite evidence |
| --- | --- |
| `wire_carrier::common::tests::custody::real_actor_retains_user_wouldblock_while_common_control_and_tls_complete` | Actual retained User WB under a per-construction test gate; real Control/TLS service on the same socket, then User completion. |
| `wire_carrier::common::tests::custody::real_actor_original_packet_expiry_refuses_held_user_without_blocking_control` | Original packet expiry prevents User write and leaves Control usable. |
| `wire_carrier::common::tests::custody::actual_whole_write_crossing_original_cap_retains_late_fact_and_single_debit` | Actual UDP write plus injected pre/post clock observations preserves late receipt, immutable bytes and one debit; no kernel-latency measurement. |
| `secure_udp::original_datagram::tests::actual_udp_ticket_keeps_exact_bytes_foreign_guard_and_separate_class_bounds` | Real UDP tuple/bytes, checked physical cost, separate class bounds, foreign/stale refusal and reuse. |
| `secure_udp::original_datagram::tests::original_udp_expiry_and_unpolled_drop_release_custody_without_any_send` | Expired/unpolled UDP custody releases without a write; later actual send succeeds. |
| `secure_udp::original_datagram::tests::actual_openvpn_ticket_retains_tls_original_tuple_and_extra_opcode_geometry` | Real TLS/member carrier, unchanged tuple, exact opaque bytes, extra-one-byte accounting and later TLS service. |

The same receipt revalidated the seven earlier protected/raw carrier cases. That
opaque fixture is not production common admission/member binding. The later
[Common factory/member handoff](openvpn-common-factory.md) now retains this owner
through actual cookie/selected Noise/managed Joining into opaque carrier `Parts`;
three actual factory and four managed-initial cases passed in their finite scope.
Its enclosing aggregate remains failed and [strict affected checks](../../work/parallel-features-20261115/parallel-wave3-strict-attempt-2/validation.json) passed.
The factory blocked/late-send matrix, Common Driver and shared Prepared/service
installation remain open. Those consumers must retain the same owner and complete
physical tickets before advancing accepted/drain proofs, with exact post-TLS
effective binding and extra-opcode geometry throughout.

Full authenticated management, liveness, fresh rekey, SW-11 switching, every
requested profile/mode and all existing resource/native/platform/performance
requirements remain unchanged. This slice does not close complete resource totals
or allocator-failure coverage, CLI/IPC/GUI support, standard-dissector/PCAP/native
TAP/TUN/impairment qualification, Windows/Android or ISP-QoS gates. The full
[OWC-04..06 definitions](openvpn-wire-carrier.md#stable-work-and-validation-gates)
remain unchecked; no integration or owner decision is inferred from these tests.
