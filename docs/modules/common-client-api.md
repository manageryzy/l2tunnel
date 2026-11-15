# Complete Common client API and CLI

Status: implemented and finite protocol/parser plus Linux user-space local-IPC
integration tested. This is an engineering interface extension, not an owner
decision or a claim that the full parent CLI, GUI, resource, native, platform or
SW-11 gates pass. The separate [strict affected checks](../../work/parallel-features-20261115/parallel-wave3-strict-attempt-2/validation.json) passed;
full-stage acceptance is not inferred from these finite cases.

APIv4 selects the actual Common shared-service backend. The portable DTO carries
exact 1304-byte CompleteV2 C as 2608 lowercase hex characters, including tag4.
The maintained complete decoder checks every field and inactive padding; it does
not truncate to Swift304 or infer runtime support from a representable family.
Versions1/2/3 retain their original action/reply bytes and explicit selection.
Common status refuses older versions with requires_version_4; v4 against another
backend refuses unsupported_version, with no automatic retry or downgrade.

The same Handle/Run actor, Prepared factories and apply_common operation own all
work. A switch carries an explicit nonzero request_key. An identical retained
key replays before fresh validation; a different target conflicts. An unlisted
configuration is refused without consuming the key. A reply reports the actual
Completed::Common target, result, epoch and accepted operation separately from
current/requested/physical scope. Cancellation and lost custody remain explicit
outcome_unknown; they do not imply rollback. next_request_key is an advisory
read of the actual service counter, not a reserved ordinal.

A catalog request binds generation and the full catalog root and requests one to
four configurations at an offset. All64 entries remain accessible. The original
4096-byte request bound remains; only explicit APIv4 responses use32768 bytes.
Versions1/2/3 retain8192. The server retains the five-second request-read and
response-write bounds; the client retains one65-second overall exchange cap and
requires the response version to equal the explicit request. There is no retry or
downgrade. Local Unix peer UID and private directory/socket checks are reused.
There is no new privileged service.

CLI adds --record-profile common --common-transaction-plan PATH, mutually
exclusive with the old Swift plan. The strict256KiB plan is version1/backend
common_records_v2, initial_index, catalog (one to64 exact2544-character canonical
anchor-free descriptors), transaction and runtime (same complete resource schema
as the old plan), plus required rolling_work:null or {field,copies,metadata}.
Anchored input is refused rather than silently dropping its trust envelope.
Actual Common Profile derives E/H0 from own trust and the complete catalog.
Legacy-shaped resource templates contain explicitly inert Swift directions;
actual selected policy, rates, widths, maxima and digests come from full Common C.
The actual runtime contract validates capabilities before a Prepared is admitted.
The optional rolling caps are authenticated and independently limit send/receive
per live epoch and service turn, at most four directional caps with two epochs.
Actual consumed work and scheduler steps come from CommonSnapshot.

inspect-common-transaction-plan uses existing trust inputs and emits one bounded
header plus at most16 pages of four full configurations. It opens no device,
control socket, admission/cookie input or session. connect/serve use the actual
Prepared::secure_udp_common_client/server and existing Attachment/Run. Runtime
readiness/status/terminal events use the actual same-generation Common frame.
The existing bounded stdout sink remains best effort. Commands are status,
disconnect/reconnect with --api-version4, switch-common-configuration with full C
and --request-key, and common-catalog with generation/root/offset/limit. This
source wiring is not proof of production TAP/TUN CLI startup or external processes.

- [x] [CCA-01] Execute strict full-C/parser/legacy-byte cases, bounded full64 Evidence: [exact passed cases within the preserved failed aggregate](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json).
  inspection, and actual Common Profile construction for both roles.
- [x] [CCA-02] Execute the actual Unix socket APIv4 against authenticated original Evidence: [repaired actual service/socket cases and affected setup regressions](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-2/validation.json).
  UDP and UnixDatagram device owners, including status/catalog/rejection/key
  replay/conflict, real cross-profile bytes, actual release and fresh reconnect.
- [ ] [CCA-03] Qualify actual external CLI connect/serve and native TAP/TUN,
  all required faults/lifecycle/recovery/resource cases, complete catalog/capability
  observations, GUI/platform composition and all existing parent definitions.

The [first functional batch](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-1/validation.json)
remains failed:51 of55 exact cases passed. Its four API/parser cases passed:
canonical full-C length/case/padding and legacy-action refusal; the literal v4
catalog request plus unchanged legacy status request bytes; bounded full64 plan
parsing/refusals; and actual Common Profile construction/complete paged inspection
for both roles. Existing literal legacy schema and old transaction-plan cases
also passed there. These are checked parser/Profile values, not an external CLI
process or native attachment witness.

The two actual Common service cases initially overflowed the standard test stack.
The [debugger trace](../../work/parallel-features-20261115/parallel-wave3-stack-attempt-1/debugger.log)
locates failure during eager reserved Common Driver construction with an unused
backend union poll frame still live in general service setup (about435KiB in that
capture). The repair moves the existing single setup-future box to non-async
backend selection. Only the selected backend future is then polled; the Managed
body is extracted unchanged. Original accepted deadline checks and the transition
to Authenticating still occur on first poll, the same timeout/post-await cap and
actual readiness remain, and cancellation still drops the setup owner before
publication. There is no enlarged stack, extra setup box, task or control actor.

The [repair batch](../../work/parallel-features-20261115/parallel-wave3-cases-attempt-2/validation.json)
passed10 exact cases in2.476s on standard stacks, including the APIv4 socket
lifecycle case (0.568s), existing Swift→Aligned→Packed→Swift Common service case
(1.474s), and directly affected generic, legacy Swift, base UDP and Managed setup
regressions. The v4 case uses a real private Unix socket and actual authenticated
original UDP/UnixDatagram device owners. It checks explicit older-version refusal,
actual full initial/current C, generation/root-bound catalog values, stale-page
refusal without consuming a key, unlisted configuration refusal, actual
Swift→Aligned completion, exact-key replay/conflict, nonzero bidirectional native
bytes and liveness, actual release/status and fresh authenticated reconnect.
Its finite three-member catalog does not replace the separate full64 inspection
case or qualify the full external CLI/native/fault matrix. Tag4 representation and
root's separate rolling runtime evidence do not imply that this v4 case exercised
a rolling service switch.

No check or test was run by this author. Root executed the linked immutable-binary
batches; historical build/functional failures remain preserved. CCA-03 and every
full parent gate retain their complete original definitions.
