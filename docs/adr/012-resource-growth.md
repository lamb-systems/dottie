# 012 — Bounded proofs, bounded growth, safe pruning

Status: accepted, 2026-10-31.

## Context

Three resources grow without an explicit decision.

Repository proofs read a whole account repository with an 8 MiB CAR limit and a 4096-record membership
limit, and unrelated records in the same account count toward both. Local payloads are retained
indefinitely, with no collection of unreferenced blobs. Epoch keys accumulate, and ADR 005 makes their
retention a confidentiality question as well as a storage one.

Cloud growth is a fourth: each accepted publication adds a referenced snapshot to the account, and
nothing yet decides how much history is kept or what happens when the account's own quota is reached.

## Decision

Proof budgets are explicit defaults, recorded as such and revisited in DOT-P03 when production reads are
designed. A proof exceeding the CAR or record budget fails with `ErrUntrustedCar` or
`ErrUnprovenMembership`; it is not retried at a larger budget silently.

Local and pending byte growth is bounded with an explicit quota-exhaustion state. When the cap is
reached, the tool stops accepting new publications and says so. It does not delete to make room. The
quota error is planned for DOT-P04; it does not exist yet.

Cloud history is bounded by Dottie. The provider decides retention of unreferenced blobs, which is not
ours to collect, but nothing there decides how much referenced snapshot history we keep appending. Production limits and the pruning implementation belong to DOT-P04.

Pruning is explicit and safe. It preserves checkpoint lineage and the last complete recovery point, and
it never prunes the only copy of something a restore needs.

Epoch keys follow ADR 005: the last N epochs required for restore are kept and older ones deleted. N is a
setting, and reduced restore depth is the stated cost of reduced retroactive exposure.

These limits and the quota state are decisions for DOT-P03, DOT-P04 and DOT-L06 work that is not built
yet.

## Consequences

A user with a large account may hit the membership record cap before our own records are reached. That
is a visible failure with a named cause.

A user who keeps publishing eventually reaches a quota, local or remote, and the tool's answer is to stop
and explain. It does not delete their history.

## Alternatives

Unbounded proofs were rejected: they turn a large but ordinary account into an out-of-memory event.

Automatic pruning on quota pressure was rejected: it deletes recovery material exactly when the user is
least able to notice.
