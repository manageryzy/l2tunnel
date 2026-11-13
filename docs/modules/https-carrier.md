# Genuine HTTPS streaming carrier

Status: implemented with focused contract tests; root workspace integration is
in progress and aggregate/native gates remain open. This profile is distinct from retained opaque TLS records and
from the custom raw packet phase. No raw-packet traffic is relabelled as HTTPS.
The architecture requires actual HTTP handling, matching negotiated ALPN and
bounded ordinary behavior for unauthenticated requests.

This module describes the separate genuine HTTPS/HTTP2 compatibility profile.
The owner's original HTTPS-like requirement remains a real TCP/TLS handshake
followed by custom TCP-shaped packets on the same ports and sequence space,
without ordinary TCP ACK-driven data transport. This HTTP2 stream does not
complete that deliverable. The [shared secure-session target](secure-session.md)
adds common WireGuard-like internal authentication/protection/control across
carriers while retaining the required real outer TLS and its own-server trust.
Its composition, configurable SNI, raw ownership, privilege/firewall policy and
failure recovery remain explicit gates; neither this module nor its checked
local tasks establishes that new path.

## Proposed concrete profile

Use maintained `h2`0.4.19 and `http`1.5.0, both present in the local registry,
with existing bytes1.12.1, rustls0.23.45 and tokio-rustls0.26.5. TLS1.3 advertises
and requires exactly ALPN `h2`. The first checkpoint explicitly disables SNI,
resumption, server tickets and0RTT while keeping normal CA/name verification.
The verification name, endpoint address and HTTP authority/path are separate
operator inputs. It does not implement accept-all verification or infer trust
from an HTTP Host field. Optional named SNI and certificate pinning remain
separate policy gates.

An HTTP/2 POST request and200 response carry the authenticated bidirectional
application stream in HTTP/2 DATA for its entire lifetime. No CONNECT semantic
switch, bare custom record transition, reconnect or new socket occurs. Maintained
HTTP/2 handles SETTINGS, HPACK, framing and stream/connection flow control, as
specified by [RFC9113](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1).
The configured `https` authority/path is bound into the complete session digest;
HTTP status/header/body behavior remains actual HTTP.

The server must not emit the tunnel member challenge for an ordinary unauthenticated
request. GET and malformed/unknown/unauthorized requests receive a finite ordinary
HTTP response with no tunnel-specific bytes. The proposed tunnel POST first
carries an opaque fixed member signature in a standard Bearer Authorization
header, bound to this verified TLS exporter, server identity, native layer,
complete profile/config digest and fresh nonce. Only verified allowlisted proof
permits the200 streaming response and the existing fresh exporter-bound member
challenge/proof exchange. The preproof uses maintained Ed25519 and existing member
key/allowlist ownership, with a distinct HTTPS request domain; it grants no
application capability by itself. This requires integrator-reviewed narrow auth
helpers and a distinct HTTPS ChannelTransport domain before implementation.
Ordinary rejection remains bounded HTTP handling, not an unprobeability claim.

The new crate will own TLS configurations and generic reliable I/O factories,
retaining the exact TLS/socket and maintained h2 driver. It will not expose a
constructor from copied SessionInfo/exporters or detach driver tasks. Full uses
one independently authenticated HTTP exchange; Half uses two such exchanges and
an all-lane one-time exporter-bound join over their retained HTTP bodies before
bulk direction handles escape. Both original sessions, member/server identity,
roles, lane order and canonical profile must match. Pair setup keeps the original
absolute setup deadline and supervises a locally ready driver until the peer is
ready; local readiness cannot replace an actual subsequent I/O witness.

Finite policy will bound HTTP headers/counts, request count, concurrent streams,
HPACK/frame limits, stream/connection receive windows, send buffer, queued records,
record bytes, per-turn work, setup deadline, operation deadline and session lease.
No pending read releases h2 receive capacity; only consumed body bytes do. Header
or body exhaustion, reset/GOAWAY/EOF, wrong ALPN/name/member/profile and deadline
expiry fail closed and drop original owners. HTTP2 window/HOL behavior and
actual bounded bidirectional progress require tests rather than throughput claims.

## Required evidence

- [x] [MOD-HTTPS-01] Review the concrete maintained HTTP2/TLS/profile API, ordinary unauthenticated handler and distinct request/member/exporter boundaries before implementation. Evidence: [reviewed concrete interface](../../work/https-carrier19/INTERFACE.md); one consumed admission attempt per TLS owner, canonical request/exporter/server/config/member binding and identical ordinary rejection are required.
- [x] [MOD-HTTPS-02] Implement actual verified TLS1.3 with explicit no-SNI/h2 policy and bounded ordinary HTTP request/response handling; reject invalid proof without tunnel-specific response bytes. Evidence: [frozen focused checks](../../work/https-carrier19/validation.json), [actual TLS/HTTP fixtures](../../crates/l2tunnel-https/src/tests.rs).
- [x] [MOD-HTTPS-03] Authenticate member/server/complete profile on the original TLS and retain valid HTTP2 DATA framing through application records, with failure/cancellation owner cleanup. Evidence: [carrier implementation](../../crates/l2tunnel-https/src/lib.rs), [request admission proof](../../crates/l2tunnel-auth/src/https_request.rs), 32 focused auth/carrier cases.
- [x] [MOD-HTTPS-04] Implement full and ordered two-lane half factories with actual exporter-bound one-time joining, all-lane completion and immutable original setup deadline. Evidence: [setup and original owner handling](../../crates/l2tunnel-https/src/setup.rs), [failure/deadline fixtures](../../crates/l2tunnel-https/src/setup_tests.rs), [frozen before/after findings](../../work/https-carrier19/REPORT.md).
- [ ] [MOD-HTTPS-05] Exercise actual TLS/HTTP2 full/half bidirectional bytes, blocked flow control, malformed HTTP/record limits, unauthorized probes, replay/cross-binding, partial I/O, reset/EOF/cancellation and deadline boundaries.
- [ ] [MOD-HTTPS-06] Pass strict focused checks, independent review and source-stable required aggregate before shared runtime/client exposure.
- [ ] [MOD-HTTPS-07] Integrate shared common-MUX/native runtime and explicit client/service selection/status, preserving requested/effective profile and existing defaults.
- [ ] [MOD-HTTPS-08] Separately qualify native paths, intermediary interoperability, concurrency/HOL effects, clean drain, optional named SNI/pinning and broader platforms.

## Focused implementation evidence

The frozen ten-file bundle passes 16 authentication and 16 carrier tests,
strict Clippy, formatting and warning-denied rustdoc. Root integrated exactly
those files, preserving existing dependency versions while adding the maintained
HTTP/2 dependencies. A normal library build passes without the test-only h2
unstable feature. Required workspace aggregate verification remains open.

The tests use real verified TLS and maintained h2 over bounded reliable I/O and
local TCP. They cover fixed ordinary rejections, original full/half ownership,
record bytes, receive-credit hold/reopen, swapped lanes, wrong trust/config,
reset/EOF and cancellation. Preserved failures reproduce a late-ready operation
exceeding its original deadline and repeated END_STREAM after Pending shutdown.
The outgoing DATA witness counts bytes accepted by the original TLS writer and
only publishes them after that owner's successful flush; unrelated control
flushes cannot acknowledge later DATA. These observations grant local setup
completion, not peer application delivery or native graceful-close evidence.
