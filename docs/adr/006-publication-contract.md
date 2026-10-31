# 006 — What a verified revision proves, and what publication must record

Status: accepted, 2026-10-31.

## Context

Repository verification is easy to over-read. A verified revision proves membership of records at a
commit the provider asserted. It does not prove who wrote them, what policy applied, or that the commit
is globally current. A provider can equivocate, and a reader who trusts only the provider cannot tell.

We also need recovery to work across a crash. A publication attempt that leaves the process has unknown
outcome, and the next process must decide what happened without resending blindly.

## Decision

A verified revision is evidence of membership at a PDS-asserted commit. Nothing more. Freshness,
rollback resistance and equivocation defence belong to DOT-V05 independent checkpoints, and no code in
the cloud track may present a verified revision as proof of authorship or global currency.

Commit evidence follows the DOT-F05 taxonomy: `rejected-local`, `not-sent`, `unknown`,
`rejected-pre-blob`, `rejected-other`, `committed`. A 5xx or an unparseable body is `unknown` whatever
error name it carries. A 2xx counts as `committed` only when the attempt's unique marker rkey and its
expected record CID are proven present in a freshly verified revision. Head and control records live at
rkey `self`, so their presence proves nothing and is never evidence that our batch landed.

Publication writes the first blob reference, the head and the control record at one revision, with one
active head. There is no blind resend. `unavailable` is terminal for that recovery decision, and retry
is bounded, jittered and gated on classification in DOT-P05.

Durable state records, before the send that could create referenced state: run identifier, marker rkey,
expected record CID, candidate blob CID, epoch, policy digest, the outcome when known, and the evidence
used to decide it. Unknown outcomes survive restart and are resolved by a verified re-read, never by
resending.

## Consequences

A crash can cost a publication attempt, but it cannot silently publish twice, because the marker makes
the second attempt visible as a second effect rather than an accepted commit.

The state schema adds fields to the L06 store and needs a migration. DOT-L06 provides versioned
migrations and generic persistence; this decision supplies the fields, not a new store.

Providers that do not answer `applyWrites` coherently cannot be supported, because the contract depends
on a structured fence error rather than on message text.

## Alternatives

Treating a 2xx as success was rejected: a provider can return nil error with an empty body, and a commit
CID for an unrelated batch can verify. Both were reachable in the existing client.

Treating presence in the membership set as success was rejected after review: for head and control at
rkey `self` it is always true.
