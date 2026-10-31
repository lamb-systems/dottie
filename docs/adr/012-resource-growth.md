# 012 — Bounded proofs, bounded growth, safe pruning

Status: accepted, 2026-10-31.

## Context

Three resources grow without an explicit decision.

Repository proofs read a whole account repository with an 8 MiB CAR limit and a 4096-record membership
limit, and unrelated records in the same account count toward both. Local payloads are retained
indefinitely with no collection of unreferenced blobs. Epoch keys accumulate, and ADR 005 makes their
retention a confidentiality question rather than only a storage one.

## Decision

Proof budgets are explicit defaults, recorded as such and revisited in DOT-P03 when production reads are
designed. A proof that exceeds the CAR or record budget fails with a typed error; it is not retried at a
larger budget silently.

Storage growth is bounded with an explicit quota-exhaustion state. When local or pending bytes reach the
cap, the tool stops accepting new publications and says so, rather than deleting to make room.

Pruning is explicit and safe. It preserves checkpoint lineage and the last complete recovery point, and
it never prunes the only copy of something a restore needs.

Epoch keys follow ADR 005: the last N epochs required for restore are kept and older ones are deleted.
N is a setting, and reducing restore depth is the stated cost of reducing retroactive exposure.

## Consequences

A user with a large account may hit the membership record cap before our own records are reached. That
is a visible failure with a named cause, not a confusing partial read.

Unreferenced blobs on the provider are not our garbage to collect; the provider decides retention, and
we cannot promise deletion.

## Alternatives

Unbounded proofs were rejected: they turn a large but ordinary account into an out-of-memory event.

Automatic pruning on quota pressure was rejected: it deletes recovery material exactly when the user is
least able to notice.
