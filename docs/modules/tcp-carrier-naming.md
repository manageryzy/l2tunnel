# TCP carrier naming and physical send observations

Status: implemented with focused protocol/runtime evidence and affected strict checks. No default carrier or
existing wire format changes. Common raw service integration remains open.

## Explicit SNI with retained own-server verification

Add `auth::ClientSni::{Disabled, Named(String)}` and
`ClientTls::from_der_roots_with_sni(&[Vec<u8>], ClientSni) -> Result<Self, Error>`.
The original `from_der_roots` forwards `Disabled`; TLS 1.3, no resumption and no
early data remain unchanged. `ClientTls::sni() -> &ClientSni` exposes the requested
non-secret policy. Named SNI is a nonempty DNS name of at most 253 bytes, accepted
by maintained DNS parsing, with IP literals and embedded NUL rejected before I/O.

Every existing connect factory's `server_name` remains its certificate verification
identity. A named SNI selects only the actual ClientHello name. A private verifier
delegates chain, time, OCSP and hostname verification to maintained rustls WebPKI
using the original verification identity, and delegates every signature verifier
method. Each connection owns its immutable name binding; reusable ClientTls has
no mutable verification name. There is no accept-all branch, new cryptographic
primitive or certificate/public-key pinning claim. Existing trust-root/name
verification anchors server identity independently of the SNI name.

## Physical facts survive raw-carrier termination

Keep `PacketCarrier::stage_record_tracked`, `RecordToken`, `SentRecord` and the
legacy `take_sent_record` signature. Add public `SentRecordObservation` containing
`sent: Option<SentRecord>` and `failure: Option<packet::Error>`, plus
`take_sent_record_observed(PairLane) -> Result<SentRecordObservation, Error>`.
Invalid lane selection is an error before changing liveness/custody. The explicit
new observation reports the original sticky terminal error alongside one actual
physical-send fact when present. It never reports queue admission as a send.

Before releasing failed Detached owners, preserve at most one existing completed
receipt per actual lane in the carrier's bounded inline two-cell ledger. The
receipt retains its original `PacketIo::send` completion time and exact token.
Taking one lane never consumes the other lane. Repeat observation returns no
receipt and retains the original terminal error. An unsent WouldBlock token
produces no receipt, including when its owner expires. Legacy callers retain
their original terminal-error behavior. No I/O is performed by either observer.

All current TLS/Seal/Hello/Commit authentication, TCP sequence/retirement metadata,
outer packet protection, timers, packet bytes, quota and rollback rules remain
unchanged. No new raw/Common actor or opaque unauthenticated metadata path is
introduced. Common integration will consume the explicit observation and confirm
its real Bank token at the receipt's original timestamp.

## Acceptance ledger

- [x] [TCR-01] Actual maintained TLS handshakes observe configured independent SNI, Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
  retain exporter/member identity and application bytes, preserve original no-SNI
  defaults, reject invalid DNS before I/O, and reject wrong certificate roots and
  verification names. One reusable ClientTls supports concurrent different
  verification identities without shared-name mutation.
- [x] [TCR-02] Real original raw PacketCarrier tracked sends preserve exact tokens Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
  and actual completion times through late expiry/failure, consumed once and
  independently on both lanes; blocked unsent packets have no physical receipt.
  Existing protected wire and legacy terminal behavior remain intact.
- [x] [TCR-03] Integrator applies source-bound patch and runs affected checks after Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
  Wave 8 freeze. Common Bank/service installation, native same-descriptor sequence
  captures, PMTU/NAT/middlebox, clean close, full resource/native/performance and
  Windows/Android gates remain required and open under the original definitions.

The explicit `--sni DNS_NAME` option uses the same validated policy in supported
TCP system/active/fixed-proxy/measured-proxy, raw-packet and Common OpenVPN
client readers. `--server-name` remains the certificate verification identity.
Unsupported combinations are rejected before runtime, file or device effects.
Optional stderr/offline diagnostics report requested naming only, with effective
null and authenticated false; full persistent effective naming in IPC is open.

- [x] [TCR-04] Validate explicit CLI selection, early unsupported/invalid-name rejection and requested-only observations through the actual supported TLS readers; preserve omitted-option behavior and keep unavailable effective IPC status explicit. Evidence: [TCP scoped validation and preserved failures](../../work/parallel-features-20261115/parallel-tcp-scoped-validation.json).
