# Original native raw PacketIo opening

Status: implemented with finite local contract tests. This module covers only the Linux descriptor
factory needed by the [original-owner runtime](raw-runtime.md). Native full/half
packet-phase qualification, client selection, middlebox behavior and release
capability remain separate gates. Retained raw TCP/TLS opening keeps its existing
semantics and defaults.

The explicit Linux-only entry point is
`l2tunnel_raw_io::open_packet_marked(Config, Role, mark) -> io::Result<RawSocket>`.
The returned opaque owner implements PacketIo and retains the original raw socket
and unmarked, bound, non-listening TCP port reservation for its lifetime. It has
no socket-cloning, mark-changing or descriptor-adoption interface. The caller
moves it into RawInput before from-birth authentication/classification; no TCP
packet is read or emitted by the factory and no driver is started.

A shared private factory validates configured bounds before external inspection,
requires the existing non-initial namespace and canonical bounded exact-tuple
marked OUTPUT policy, then creates the reservation and marked raw descriptor.
It verifies mark readback and uses the existing safe socket2 options/binding.
Every setup error drops partial resources. Namespace ownership and unchanged RST
policy throughout the owner's lifetime remain caller obligations; this factory
never installs or modifies policy. This checkpoint does not strengthen the
existing non-initial namespace identity check into an ownership oracle.

The implementation plan is recorded in
[checkpoint 17 plan](../../work/raw-native-packet17/PLAN.md), with executed commands and
limits in the [checkpoint 17 receipt](../../work/raw-native-packet17/REPORT.md).

- [x] [MOD-RAWNATIVE-01] Export the opaque original RawSocket and shared validated marked packet-only opener without changing retained opening behavior. Evidence: [checkpoint 17](../../work/raw-native-packet17/REPORT.md).
- [x] [MOD-RAWNATIVE-02] Verify invalid mark/configuration before external I/O, namespace/policy/tuple rejection and finite unmarked port-reservation move/conflict/drop behavior. Evidence: [checkpoint 17](../../work/raw-native-packet17/REPORT.md); actual raw-descriptor probe remains ignored.
- [x] [MOD-RAWNATIVE-03] Pass focused raw adapter suites and strict formatting/Clippy/rustdoc over a verified immutable source overlay. Evidence: [checkpoint 17](../../work/raw-native-packet17/REPORT.md), 131 raw-io and 21 raw-tcp tests passed; two privileged probes ignored.
- [ ] [MOD-RAWNATIVE-04] Separately qualify actual full/half native startup/data paths using the same descriptors, marks and tuples, continuous sequence, bounded peer outcome, no unintended FIN/RST and owned cleanup.
- [ ] [MOD-RAWNATIVE-05] Qualify impairment, PMTU/NAT/middlebox behavior, congestion and protected clean close before broader native capability claims.
- [x] [MOD-RAWNATIVE-06] Pass integrator-owned source-stable `python3 tools/check.py` for the completed bundle before reporting repository aggregate completion. Evidence: [wave18 stable aggregate](../../work/implementation-wave18/validation.json), 987 Rust/142 Python cases with strict workspace lint/docs; all 620 inputs unchanged. Native case acceptance remains separate.
