# Complete Ethernet witnesses in packed captures

Status: implemented and focused-test reviewed; strict aggregate pending. This extends only the offline
[packed capture auditor](packed-native.md), not forwarding or authenticated
admission. TAP/VXLAN native qualification remains open. The failed native run13
and its separate lane-scope correction retain their original verdicts.

## Exact observation boundary

Only an exact codec kind-2 body decoded as `BodyKind::Raw` can provide a complete
Ethernet witness. The decoded bytes are the original whole frame, including its
original padding. Use the maintained Ethernet classifier with explicit limits:
1600 packet bytes, four VLAN tags, eight IPv6 extension headers, and 256 extension
bytes. Propagate malformed/truncated supported-header errors. Do not search for
IP headers, assume a fixed Ethernet offset, strip padding, or infer an FCS.

For a known finite IPv4/IPv6 extent, add `EthernetMetadata.header_bytes` to
`IpMetadata.packet_bytes` with checked arithmetic. For standard Ethernet/IPv4 ARP
(`PacketKind::Arp`), add the same header length to `ArpMetadata.packet_bytes`.
Qualify when the raw frame ends exactly at that declared extent, or when the
extent is below 60 bytes and the frame is exactly 60 bytes. This is a conservative
offline witness policy for frames without FCS, not a rejection policy for all
other valid Ethernet padding arrangements. Short unpadded TAP frames are allowed
when they end at the exact declared extent.

Ethernet padding lies outside the declared IP packet length; the IPv4 and IPv6
encapsulation specifications describe this distinction. The auditor preserves
every original padding octet, including nonzero values, and makes no checksum,
padding-conformance or physical Ethernet validity claim.
See [RFC 894](https://www.rfc-editor.org/rfc/rfc894) and
[RFC 2464 section 3](https://www.rfc-editor.org/rfc/rfc2464#section-3).

Successful unknown EtherType, LLC, excessive VLAN depth, unsupported ARP address
format, IPv6 jumbogram and IPv6 extension-walk exhaustion produce zero witness.
An extra suffix of any other length also produces zero witness. These records
remain structurally represented and are never rewritten. Truncation detected
before an opaque result remains an error.

Unknown IP transport and IPv6 NoNextHeader may qualify when the classifier still
provides a complete finite IP extent. This proves whole-packet boundaries, not
transport semantics. Complete native IP fragment packets may likewise qualify;
they do not prove TCP/UDP reassembly. Codec context, delta and fragment units do
not independently provide complete raw frames and never count.

Keep the existing `(channel, absolute record ID)` identity and recovery-source
deduplication. At least two distinct qualifying identities in one source are
required. Direct/systematic copies of the same source count once, and repairs do
not expose reconstructed packet witnesses. All lane/session, epoch, source,
unit-range, FEC and conflicting-copy checks remain mandatory. TUN behavior and
the structural-only JSON schema remain unchanged.

## VXLAN and native evidence

The existing VXLAN packet device already validates its configured fixed peer/VNI
and hands inner Ethernet frames to the protocol. Its packed bodies therefore use
this same Ethernet criterion. The auditor performs no additional VXLAN peeling
and cannot infer that a real VTEP was exercised from inner bytes alone.

The production small-packet burst carries 64 application bytes: untagged IPv4/UDP
frames are 106 bytes and IPv6/UDP frames are 126 bytes. Tests must use the ordinary
encoder to establish their actual raw fallback, rather than only forcing kind 2.
Tagged fixtures may use explicit raw encoding when header growth changes the
production short-frame selection.

Native cases stay individually named and bounded. First complete the corrected
TUN/half acceptance with a fresh stable aggregate and immutable bundle. Then
review the same-parameter clean TUN/full and TAP/full cases, followed by TAP/half
and VXLAN full/half. No successful decoder test implies a native result or
authorizes an impairment/performance claim.

The [reviewed offline audit revision](../../work/packed-native-independent-audit14.py)
requires an explicit native layer and duplex. It binds each case to its exact
native namespaces/subnets, one/full or two/half retained TLS controls, physical
UDP port/direction pairs, unchanged burst and capture bounds, immutable build
provenance and all five absent owned namespaces after cleanup. VXLAN additionally
requires both actual vx0 offload readbacks; VNI/peer placement remains supported
by the source-bound successful setup and native traffic, not an independent VNI
readback. The [independent review](../../work/packed-audit-expansion14-review/REPORT.md)
and [seven focused helper tests](../../work/packed-audit-expansion14-check/receipt.json)
qualify only this read-only acceptance helper. They do not run or qualify a lab.

## Checklist

- [x] [MOD-PACKETH-01] Review actual decoder/classifier/VXLAN boundaries, exact lengths, padding, opaque protocols and native-versus-codec fragments before code. Evidence: [independent source review](../../work/packed-ethernet-review13.md) and root inspection of maintained packet/codec/VXLAN interfaces; this contract fixes extension exhaustion as zero witness while allowing finite unknown-IP-transport extents.
- [x] [MOD-PACKETH-02] Implement the private bounded Ethernet witness without changing TUN acceptance, forwarding or the structural-only counter schema. Evidence: [private predicate](../../crates/l2tunnel-client-core/examples/packed_capture_audit/ethernet.rs), [maintained decoder integration](../../crates/l2tunnel-client-core/examples/packed_capture_audit/audit.rs), and [independent source review](../../work/packed-ethernet-review13/REPORT.md); native qualification remains separate.
- [x] [MOD-PACKETH-03] Test production IPv4/IPv6 UDP raw fallback, VLAN1..4, exact/padded ARP, arbitrary padding preservation, unsupported/suffixed/malformed frames, native fragments, codec-fragment exclusion and duplicate identities through maintained encoders. Evidence: [seven added regressions](../../crates/l2tunnel-client-core/examples/packed_capture_audit/tests/ethernet.rs), [executed test log](../../work/packed-ethernet-check13/tests.log) with 80 client and 19 auditor tests passed, and [independent test inspection](../../work/packed-ethernet-review13/REPORT.md). The encompassing [focused receipt](../../work/packed-ethernet-check13/validation.json) remains failed at strict Clippy on the concurrently unfinished measured runtime; it is not a stable aggregate qualification.
- [ ] [MOD-PACKETH-04] Pass affected focused checks, strict lint/docs and independent source review, then a root-coordinated stable aggregate before native expansion.
- [ ] [MOD-PACKETH-05] Independently audit separately named clean TAP and VXLAN full/half native cases with unchanged burst, payload, MTU/capture and owned-cleanup requirements.
- [x] [MOD-PACKETH-06] Review explicit clean-profile audit selection and test exact native placement, duplex lane tuples, unchanged old-capture extraction and rejection of the original failed native result. Evidence: [independent source review](../../work/packed-audit-expansion14-review/REPORT.md) and [stable focused receipt](../../work/packed-audit-expansion14-check/receipt.json), with five root and two independent synthetic helper tests; no new native qualification.
