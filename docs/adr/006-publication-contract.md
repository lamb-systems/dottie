# 006 — What a verified revision proves, and what publication must record

Status: accepted, 2026-10-31. Amended by ADR 014, which adopts this record's durable attempt contract and
outcome taxonomy as the normative recovery path for vault transitions.

## Context

A verified revision proves record membership at a commit the provider asserted. Reading more into
repository verification overstates the evidence: it does not prove who wrote the records, what policy
applied, or that the commit is globally current.

Recovery must survive a crash. Once a publication attempt leaves the process, its outcome is unknown;
the next process must determine what happened without resending blindly.

Three corrections shaped this contract.

Key binding originally accepted only P-256. The live network publishes `Multikey` records using
secp256k1, so the P-256-only rule rejected signatures the network considered valid. The rule now accepts
P-256 or secp256k1 and validates the value before use.

The request budget counted logical calls. Authentication replays the same `applyWrites` request on a
DPoP nonce or `invalid_token` challenge, so 65 logical calls cost 69 wire requests. A budget at the wrong
layer provides no bound.

HTTP/2 retransmits below any `RoundTripper` on `GOAWAY` or `REFUSED_STREAM`, while HTTP/1 refuses
non-idempotent retries. A per-request cap above the transport could not see those retransmissions.
Budget-counted transports are pinned to HTTP/1.1 with ALPN set explicitly: `ForceAttemptHTTP2=false`
alone still negotiates h2 and then fails parsing h2 frames as HTTP/1.x.

## Decision

A verified revision proves only membership at a PDS-asserted commit. Freshness, rollback resistance and
equivocation defence belong to the independent checkpoints in checkpoints and recovery. No code in the
cloud track may present a verified revision as proof of authorship or global currency.

Wall-clock time never authorizes a vault action. Signed epoch and policy order authorization and
revocation. Clock skew and DPoP nonce handling are separate protocol concerns; they cannot move a device
into or out of an authorized role.

Commit evidence follows the contention measurements taxonomy: `rejected-local`, `not-sent`, `unknown`,
`rejected-pre-blob`, `rejected-other`, `committed`. A 5xx or an unparseable body is `unknown` regardless
of its error name. A 2xx counts as `committed` only when a freshly verified revision proves the presence
of the attempt's unique marker rkey and expected record CID. Head and control records live at rkey
`self`, so their presence proves nothing and is never evidence that our batch landed.

Publication writes the first blob reference, the head and the control record at one revision, with one
active head. There is no blind resend. `unavailable` is terminal for that recovery decision, and retry is
bounded, jittered and gated on classification in crash-safe publication.

Before a send that could create referenced state, durable state records the run identifier, marker
rkey, expected record CID, candidate blob CID, epoch and policy digest. It also records the outcome
when known and the evidence used to determine it. Unknown outcomes survive restart and are resolved
by a verified re-read, never by resending. These fields are not built yet. The state store supplies
the store and its migrations; this record specifies the publication identity so that work does not
have to invent it.

## Consequences

A crash can cost a publication attempt. Durable marker identity and verified resolution let a
restarted process distinguish landed, not-landed and superseded attempts without blind resends.

Whether a provider can accept two identical batches and produce two effects remains unproven. Final
membership could not distinguish one commit from two in the measurement, leaving the accepted-duplicate
invariant unproven. The marker proves the expected record is present; it does not count historical effects.

Providers that do not answer `applyWrites` with a structured fence error cannot be supported, because the
contract depends on the error value. Message text is never parsed.

## Alternatives

Treating a 2xx as success was rejected: the client could return nil error with an empty body, and a commit
CID belonging to an unrelated batch could verify.

Treating presence in the membership set as success was rejected after review: for head and control at
rkey `self` it is always true.
