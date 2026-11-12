# HTTPS HTTP/2 runtime adapter

This crate performs actual TLS1.3 and HTTP/2 POST streaming over original
caller-owned reliable I/O. It uses normal certificate/name verification with h2
ALPN and explicit no-SNI/no-resumption/no-early-data policy. HTTP authority and
path are separate from the certificate verification name.

The server handles one admission attempt per TLS owner. Missing, malformed,
unauthorized or mismatched requests receive the same bounded ordinary404 response
before any tunnel challenge. Only a fixed exporter/server/member/config/request
signature allows the HTTP200 body and fresh member authentication. This is
ordinary bounded HTTP behavior, not an unprobeability claim. Authorized streaming
uses initial stream1; other initial stream IDs receive ordinary rejection.

Full retains one original TLS/h2 owner; Half authenticates two and performs an
ordered one-time exporter-HMAC join on both original bodies. No tasks are spawned.
The caller must keep polling Session::poll_progress to serve every driver. One
incoming and one outgoing record are bounded to16KiB. Incoming h2 capacity is
released only by explicit record consumption. Configured operation timeouts bound
partial records and local HTTP staging. Complete unconsumed records and bytes
already queued in h2 remain bounded by the original total session lease; no API
claims peer delivery, a physical flush fence, clean drain or native qualification.

Setup retains one absolute deadline and rejects late-ready I/O after it. Local
setup flush completion requires the latest cumulative stream1 DATA bytes to be
accepted by the original TLS owner and that owner to complete poll_flush. A
bounded outbound frame observer counts maintained h2's own serialized bytes; it
neither parses peer HTTP nor implements HTTP semantics/framing. An unrelated
control-only or earlier flush cannot satisfy a later DATA target. Shutdown retries
emit END_STREAM once. Every h2 driver poll permits at most64 TLS I/O attempts.

The crate is a runtime adapter and therefore uses Tokio timers and generic
AsyncRead/AsyncWrite. Factories require a Tokio timer driver. Protocol-core
libraries remain independent of those runtime facilities. Shared common-MUX,
client/service selection, native paths and interoperability remain separate gates.
