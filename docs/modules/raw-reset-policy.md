# Owned raw-socket reset policy

Status: additive Linux adapter and explicit helper selection implemented; focused
tests, an actual production-descriptor diagnostic and all four clean TAP/TUN
full/paired-half cases passed. The fixed impaired matrix stopped at its first
TAP IPv6 probe failure; TUN impaired remains unrun. Existing raw constructor and
capture acceptance remain unchanged. This does not implement the ACK-independent
custom packet phase or qualify impaired raw native traffic.

## Observed mechanism and boundary

The [owned syscall control](../../work/raw-rst-policy-diagnostic-corrected/receipt.json)
sent identical raw IPv4/TCP tuples with IP_HDRINCL. A 40-byte ordinary ACK succeeded;
a 40-byte RST returned errno 1/EPERM while the exact-tuple OUTPUT RST DROP counter
increased by 1 packet/40 bytes. Removing only that owned rule allowed the same RST
to send 40 bytes. Namespace cleanup passed. The [initial control attempt](../../work/raw-rst-policy-diagnostic/receipt.json)
used the wrong lane ports and failed its rule-removal step; cleanup passed and the
failed receipt is preserved. Neither control identifies the packet/syscall behind
the earlier bare EPERM in the full impaired tunnel run.

The unconditional suppression rule catches both kernel-generated resets and the
maintained userspace TCP owner's legitimate resets. Ignoring EPERM, counting a
suppressed send as physical transmission, or turning a reset into clean closure
would be incorrect.

## Frozen additive API

`l2tunnel_raw_io::open_marked(config, role, mark: u32)` requires a nonzero explicit
local mark and the same non-initial owned namespace restriction as `open`. It
validates a finite OUTPUT chain containing only ACCEPT policy and 1..64 canonical
exact-IPv4/port TCP-RST DROP rules with `-m mark ! --mark <mark>`. The configured
tuple must occur exactly once. Unknown/broad/jump/ACCEPT rules, duplicate rules,
different marks and non-exact masks are rejected. The adapter changes no rules.

Before returning the capability, set SO_MARK on the owned raw descriptor through
the maintained socket2 API and read it back. Keep the bound, non-listening kernel
port reservation unmarked. Unmarked kernel resets continue matching suppression;
marked maintained-stack packets retain their actual flags and pass that rule.
Send errors remain errors, physical packet counters count only successful sends,
and the existing full native/caller/packet proof remains necessary for clean
driver completion. No ingress/egress reset filtering or timeout extension is added.

The mark is local routing/firewall policy, not a secret, wire field or remote
identity proof. The embedding owned-lab/service manager must reserve it and keep
the verified chain unchanged for the descriptor lifetime. This first marked API
continues to require explicit preprovisioned namespace policy; production host
firewall integration and privileged service lifecycle remain separate work.

## Checklist

- [x] [MOD-RAWRESET-01] Implement additive marked descriptor setup/readback and finite canonical exact-rule validation; preserve legacy constructor and send/close semantics. Evidence: [adapter and bounded policy reader](../../crates/l2tunnel-raw-io/src/linux.rs), [public export](../../crates/l2tunnel-raw-io/src/lib.rs).
- [x] [MOD-RAWRESET-02] Test rule bounds, mark/tuple/order/mask mismatches, broad rules and duplicates with strict focused checks. Evidence: [two policy tests](../../crates/l2tunnel-raw-io/src/linux.rs), [helper option/digest tests (retired in Common cutover)](compact-wire-cleanup.md), [harness tests](../../tools/test_raw_native_smoke.py), [executed checks](#executed-checks-and-first-native-result).
- [x] [MOD-RAWRESET-03] Prove in a fresh owned namespace that unmarked RST is dropped, marked RST is physically observed and ordinary ACK succeeds; preserve original historical failures. Evidence: [actual descriptor test](../../crates/l2tunnel-raw-io/src/linux_native_tests.rs), [owned diagnostic receipt](../../work/raw-marked-descriptor-diagnostic/receipt.json), [independent packet parser](../../work/raw-marked-descriptor-diagnostic/probe.py).
- [ ] [MOD-RAWRESET-04] Qualify marked native traffic under unchanged strict capture/drain gates. Explicit helper selection and all four clean TAP/TUN cases are implemented and passed; the impaired TAP case failed before drain, and impaired TUN is unrun. Evidence remains partial: [fixed matrix](../../work/raw-native-marked-matrix/receipt.json), [failed TAP case](../../work/raw-native-marked-matrix/tap-half-netem.json), [independent audit](../../work/raw-native-marked-audit.json).
- [x] [MOD-RAWRESET-05] Include the adapter in a source-stable aggregate validation; no Windows/Android raw capability is implied. Evidence: [wave7 source-stable validation](../../work/implementation-wave7/validation.json), 549 Rust cases including doctests and 39 Python tool tests.

## Reviewed helper and first diagnostic gate

The isolated `raw-native` helper accepts optional trailing
`--raw-mark NONZERO_U32` (strict decimal or `0x` hexadecimal). Absence preserves
the original eight positional arguments, legacy constructor and exact original
authentication binding. Marked selection appends a separate
`/marked-socket-policy/v1` domain to its carrier context before the existing
finite-drain session digest. The policy kind must therefore agree during member
authentication; the numeric mark remains local metadata, excluded from the
cross-peer digest. Both physical lanes retain the same explicit policy. Readiness
logs and harness receipts record the selected policy and numeric mark.

The raw native harness adds the same explicit option and provisions only canonical
exact tuple rules with `-m mark ! --mark MARK` in its newly journal-owned
namespaces. It verifies the complete expected chain before/after each case and
on failure. Native traffic, 30/45/80-second drain bounds, unchanged maintained
TCP behavior, and strict no-RST/complete-capture predicates stay unchanged.
An actually transmitted reset remains a failed clean-tunnel qualification.

Before any further tunnel matrix, an ignored Linux-only native test calls the
actual production `open_marked`, verifies its raw descriptor's mark and unmarked
port reservation, and sends ordinary ACK and RST through that actual
`RawSocket::send`. A separate unmarked raw descriptor must fail an RST send with
EPERM while the exact rule counter increments. A fresh owned diagnostic captures
both endpoint interfaces and verifies exact packet IDs, flags, tuples, lengths
and checksums: marked ACK/RST physically arrive; the failed unmarked RST does not.
No maintained driver is run in this syscall diagnostic, and no driver physical
counters or clean TCP closure are claimed. Wrong/zero mark and legacy-policy
preflight rejection are included. Production adapter semantics remain unchanged.

The diagnostic uses one predeclared finite execution/capture bound, immutable
binary/harness artifacts, no rule removal after installation, and owned cleanup.
Its receipt is separate from historical EPERM attribution and the future full
raw native/drain qualification gate.

## Executed checks and first native result

Executed focused checks: `cargo test --offline -p l2tunnel-raw-io --lib --examples`
passed seven library tests and three helper tests, with the privileged descriptor
test intentionally ignored in the ordinary suite. Strict raw-io Clippy and
warning-denied public rustdoc passed. `python3 -m unittest
tools.test_raw_native_smoke -v` passed 15 tests, including marked option/chain
validation and every original strict acceptance regression. Structural comparison
also confirmed that the helper's complete `forward_and_drain` function and the
harness's eight native/drain/TLS/capture acceptance functions are unchanged.
A golden digest preserves the original unmarked authentication profile.

The separately invoked ignored test passed under a fresh journal-owned topology:
[receipt](../../work/raw-marked-descriptor-diagnostic/receipt.json). Actual
`open_marked` set/read back mark `0x12aa0001`, retained an unmarked TCP port
reservation, and rejected zero/wrong mark and legacy preflight. The production
`RawSocket::send` successfully handed one 40-byte ACK and one 40-byte RST; both
endpoint captures contain those exact packet IDs, flags, tuples and valid IP/TCP
checksums. The separate unmarked RST returned the original EPERM and increased
the sender rule by exactly one packet/40 bytes; it appears in neither capture.
The complete canonical rules remained unchanged, capture drop counts were zero,
and namespace identity checks plus cleanup passed. The probe used a 10-second
process bound, two-second fixed observation and 32-packet capture cap, with no
retry or deadline extension.

Immutable test binary SHA-256:
`a9eb63cf15b75920c32e32f16641d82b1334556fc28f3fe74ddcbaabf709abdc`.
Helper binary SHA-256:
`9b52679fa87d5c00c26470f5701b4ee933b19b9cfa1da6dcbe3482e116fe2153`.
This validates the descriptor/firewall mechanism only. No maintained TCP driver
ran during the probe, driver sent counters remained zero, and no clean tunnel
closure or historical EPERM cause is inferred from the descriptor probe. The
separate full tunnel results below leave MOD-RAWRESET-04 open.


## Marked native forwarding and drain results

The separately approved [first TAP/full clean case](../../work/raw-native-marked-first/receipt.json)
passed before the [fixed six-case matrix](../../work/raw-native-marked-matrix/receipt.json)
started. Both used the helper hash above, immutable harness SHA-256
`d2688309487eea78c7fd2c91bf9eb3a628a573186be6733594b1e9e0d06e666c`,
mark `0x12aa0001`, the original native probes and 65,536-byte exact TCP payload,
and unchanged 30-second native/TLS, additional 45-second driver and 80-second
combined helper bounds. No capture predicate, timeout or retry changed.

| Fixed matrix case | Result | Drain evidence |
| --- | --- | --- |
| TAP paired half, clean | Passed | Both peers/physical lanes clean; 10.026 seconds |
| TAP full, clean | Passed | Both peers/original lane clean; 10.025 seconds |
| TUN paired half, clean | Passed | Both peers/physical lanes clean; 10.028 seconds |
| TUN full, clean | Passed | Both peers/original lane clean; 10.024 seconds |
| TAP paired half, 70 ms RTT / 15% loss | Failed at eighth IPv6 probe | TCP transfer and drain were not reached |
| TUN paired half, 70 ms RTT / 15% loss | Unrun | Matrix stopped at the first failure |

Every clean case passed all eight IPv4/IPv6 probes and exact TCP SHA-256
`a863d4360888ecceb6f59e575cd4eaa590b127c5a096a43e92d1274b5dccb5c9`.
Both native fences matched the corresponding peer barriers/acknowledgments;
all original TLS lanes and raw drivers completed with helper exit code zero.
The [independent saved-artifact audit](../../work/raw-native-marked-audit.json)
checks immutable binary/harness hashes, exact drain proofs, complete captured TLS
streams, physical FIN/ACK pairs, valid IPv4/TCP checksums and a maximum whole raw
IP length of 1200 bytes. All clean and failed underlay captures contain zero RST
and zero capture-kernel drops. Native captures use bounded 2048-byte snapshots;
large aggregated native frames can be truncated, so those snapshots do not prove
complete native-byte accounting. Exact native delivery in passed cases comes
from the runtime fences and application hash, not inferred native capture counts.

The failed TAP case passed seven probes, then the original 30-second final
B-to-A 1200-byte IPv6 echo bound expired. Its helper logs contain only the two-lane
authenticated readiness records: no syscall error, errno, drain request or clean
completion is recorded. Both underlay captures have 286 packets, four continuous
observed TLS streams and no FIN. This is not a clean-close result. The complete
canonical rules remained unchanged; actual netem drop counters were 23 and 30.
Both journal-owned topology cleanup operations passed.

The audit matches complete native Ethernet frames between both endpoint captures.
Failed echo ID 47293 left B at `21:48:06.732721 UTC` and arrived at A
7.849442 seconds later. B promptly emitted neighbor advertisements, but three
unicast advertisements reached A after 7.238358, 6.216850 and 12.263688 seconds.
A later multicast resolution sent solicitations at `21:48:14.582282`,
`21:48:15.625458` and `21:48:16.650462`; the matching advertisements arrived
at `21:48:22.655377` or later, after 5.966717–7.035793 seconds in transit.
The saved final neighbor table marks A's entry for B as `FAILED`; no echo reply
for ID 47293 occurs in either native capture. These observations establish delayed
neighbor resolution as the immediate forwarding failure. Ordered TCP loss/recovery
and its head-of-line blocking are consistent with the saved retransmission gaps;
this finite trace does not isolate every source of that delay or establish a reset
policy regression. No rerun, deadline extension or reset filtering followed it.

The [historical unmarked drain failure](../../work/raw-native-drained/receipt.json)
and [separate earlier instrumentation failure](../../work/raw-native-drained-diagnostic/receipt.json)
remain unchanged. Neither the clean marked cases nor this new NDP failure identify
the syscall responsible for the historical bare EPERM. Production host firewall
integration, impaired qualification and ACK-independent raw transport remain open.
