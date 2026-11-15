# Explicit native-IP TCP header compression

Status: actual pure codec and Aligned/Packed construction pass finite protocol
checks. Source-stable Build17 passes (53.808 s); Cases11 passes 125 selected cases
in 1.296 s, including all three new L3 cases and affected legacy L2 goldens.
Affected format, strict Clippy and rustdoc checks pass. No selected
Common/client runtime or native L3 execution is claimed. This is a prerequisite
for PBA-05, not completion of its safe ACK/runtime/differential gates.

The explicit IpHeaders native policy3 uses native IPv4/IPv6 bytes. EthernetHeaders1
and RawIp2 retain their original selection and bytes. No Ethernet source/destination
or IPv6 IPID is fabricated. The same maintained checksum/layout/modular-delta core
serves the original fixed66 wrappers and new native-IP wrappers. A selected body
owner holds exactly one actual context; first-touch journals retain that selected
state. Existing channel/record/source identities, packing, delivery, recovery,
physical-send custody and native confirmation remain unchanged.

Context8 is kind8/u16 native-header-length/exact original header, bounded by
MAX_IP_HEADER_BYTES120. Delta9 is kind9/u16 payload-length/8-bit mask followed
by the existing bounded modular LEB128 fields and exact payload. The fields are
IPv4 ID (absent for IPv6), TCP sequence/ACK/flags/window/urgent/timestamp/echo.
Missing fields reject set mask bits. Existing aligned length elision, contiguous
sequence prediction and timestamp dictionary use the actual selected layout;
IPv6 emits no ID delta. These new tags were rejected by the old readers.

IPv4 IHL20..60 and TCP20..60/options are retained exactly. Direct IPv6/TCP is
compressed, with exact original flow/header fields and checksum regeneration.
Changes to static option bytes emit another context. Fragments, IPv6 extension
headers/jumbograms, unsupported protocols/layouts, malformed options and packets
whose original checksums cannot be regenerated retain exact kind2 raw fallback.
This slice does not claim compression of every IPv6 extension chain. No TCP ACK,
ECN, window, sequence, option, payload or duplicate event is rewritten.

Header/body output capacity, context structure, checksum/length and padding checks
precede context commit. Functional and fallible reserved constructors explicitly
select native-IP mode before packets; sender/receiver/Packed plans expose that
selection and count actual enlarged metadata/journals. Scratch lengths remain
maximum-native+29 for encoding and maximum-native+44 for implicit expansion:
a new context plus zero delta adds seven bytes to the original native packet;
a subsequent delta is smaller than the smallest eligible native header. The
120-byte context fragments through the same actual symbol owner. Historical
scalar acceptance keeps explicit original layout accounting; it is not Usage.

Three focused executed cases cover fixed literal IPv4 context/delta bytes and
legacy rejection; IPv6 prediction/options/checksums/fallback and absent-ID refusal;
and actual reserved Aligned/Packed fragment/identity/output/capacity transitions
compared with functional owners. Existing Python L2 goldens are unchanged.
The new native-IP format is additive and has no claimed Python serialized oracle.
See [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json). Existing generic first-touch rollback/storage cases also pass,
but the new selected-IP tests do not specifically exercise an IP-context rollback
inside a failing batch; L3C-02 therefore remains open for its complete wording.

- [x] [L3C-01] Pass exact native-IP context/delta/predictive bytes, arbitrary payloads, IPv4/IPv6/options/checksum preservation, strict context-loss/truncation/output failure and exact unsupported fallback while preserving all legacy golden/default bytes. Evidence: [Batch9 finite checks and preserved failures](../../work/parallel-features-20261115/parallel-batch9-scoped-validation.json).
- [ ] [L3C-02] Pass real selected Aligned/Packed reserved ownership, symbol fragmentation, identities, first-touch context rollback and actual Plan/Usage/capacity/refusal under the unchanged delivery/custody state machine.
- [ ] [L3C-03] Authenticate complete IpHeaders configuration and install the real selected Common/client/runtime path, preserving all other families, native formats, old readers, L2 behavior and transparent endpoint TCP ownership; qualify focused differential and actual runtime/native behavior.

Full PBA-05, all47 mode definitions, SW-11, global8192/local128/copies/coalescing,
RLNC/parity/rolling/packed/proxy, management, complete resources, platforms and
80 Mbit/s retain their complete definitions. No stage checkbox is closed by
authored source, an enum or a successful compile.
