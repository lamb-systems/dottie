# 006 — What a verified revision proves, and what publication must record

Status: accepted, 2026-10-31.

## Context

Repository verification is easy to over-read. A verified revision proves membership of records at a
commit the provider asserted. It does not prove who wrote them, what policy applied, or that the commit
is globally current.

Recovery also has to work across a crash. A publication attempt that leaves the process has an unknown
outcome, and the next process must decide what happened without resending blindly.

Three corrections are recorded here because they shaped the contract.

The first: key binding originally accepted only P-256. The live network publishes `Multikey` records
using secp256k1, so a P-256-only rule rejected signatures the network considered valid. The rule is now
P-256 or secp256k1, and the value is validated before use.

The second: the request budget counted logical calls. Authentication replays the same `applyWrites`
request on a DPoP nonce or `invalid_token` challenge, so 65 logical calls cost 69 wire requests. A
budget that counts the wrong layer does not bound anything.

The third: HTTP/2 retransmits below any `RoundTripper` on `GOAWAY` or `REFUSED_STREAM`, while HTTP/1
refuses non-idempotent retries. A per-request cap placed above the transport therefore could not see the
retransmission. Budget-counted transports are pinned to HTTP/1.1 with ALPN set explicitly, because
`ForceAttemptHTTP2=false` alone still negotiates h2 and then fails parsing h2 frames as HTTP/1.x.

## Decision

A verified revision is evidence of membership at a PDS-asserted commit. Nothing more. Freshness,
rollback resistance and equivocation defence belong to DOT-V05 independent checkpoints, and no code in
the cloud track may present a verified revision as proof of authorship or global currency.

Wall-clock time never authorizes a vault action. Authorization and revocation are ordered by signed
epoch and policy. Clock skew and DPoP nonce handling are protocol concerns handled separately, and they
cannot move a device into or out of an authorized role.

Commit evidence follows the DOT-F05 taxonomy: `rejected-local`, `not-sent`, `unknown`,
`rejected-pre-blob`, `rejected-other`, `committed`. A 5xx or an unparseable body is `unknown` whatever
error name it carries. A 2xx counts as `committed` only when the attempt's unique marker rkey and its
expected record CID are proven present in a freshly verified revision. Head and control records live at
rkey `self`, so their presence proves nothing and is never evidence that our batch landed.

Publication writes the first blob reference, the head and the control record at one revision, with one
active head. There is no blind resend. `unavailable` is terminal for that recovery decision, and retry is
bounded, jittered and gated on classification in DOT-P05.

Durable state records, before the send that could create referenced state: run identifier, marker rkey,
expected record CID, candidate blob CID, epoch, policy digest, the outcome when known, and the evidence
used to decide it. Unknown outcomes survive restart and are resolved by a verified re-read, never by
resending. These fields are not built yet; the store and its migrations come from DOT-L06, and the
publication identity is specified here so DOT-L06 does not have to invent it.

## Consequences

A crash can cost a publication attempt. Durable marker identity plus verified resolution means a restart
can tell landed from not-landed from superseded, and it never resends blind.

Whether a provider can accept two identical batches and produce two effects is unproven. The measurement
could not distinguish one commit from two by final membership, so the accepted-duplicate invariant is
recorded as unproven. The marker shows that the expected record is present; it does not count
historical effects.

Providers that do not answer `applyWrites` with a structured fence error cannot be supported, because the
contract depends on the error value. Message text is never parsed.

## Alternatives

Treating a 2xx as success was rejected: the client could return nil error with an empty body, and a commit
CID belonging to an unrelated batch could verify.

Treating presence in the membership set as success was rejected after review: for head and control at
rkey `self` it is always true.
