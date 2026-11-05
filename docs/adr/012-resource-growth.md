# 012 — Bounded proofs, bounded growth, safe pruning

Status: accepted, 2026-10-31.

## Context

Three resources have no explicit growth policy.

Repository proofs read the whole account repository under an 8 MiB CAR limit and a 4096-record
membership limit. Unrelated records in the account count toward both. Local payloads remain
indefinitely, with no collection of unreferenced blobs. Epoch keys accumulate; under ADR 005, their
retention affects confidentiality as well as storage.

Cloud storage is a fourth resource: each accepted publication adds a referenced snapshot to the
account. No decision yet limits retained history or defines what happens at the account's own quota.

## Decision

Proof budgets are documented defaults, to be revisited in the read path when production reads are
designed. A proof that exceeds the CAR or record budget fails with `ErrUntrustedCar` or
`ErrUnprovenMembership`; the tool must not silently retry with a larger budget.

A cap bounds local and pending byte growth, with an explicit quota-exhaustion state. At the cap, the
tool stops accepting new publications and reports why. It does not delete to make room. The quota
error is planned for publication; it does not exist yet.

Dottie bounds cloud history. The provider controls retention of unreferenced blobs; we cannot collect
them. That does not determine how much referenced snapshot history Dottie keeps appending. Publication
owns the production limits and pruning implementation.

Pruning is explicit and must preserve checkpoint lineage and the last complete recovery point. It
must never prune the only copy of material a restore needs.

**ADR 014** governs epoch keys and supersedes the count-based rule previously stated here: a device
keeps the epochs its retained recovery points need and deletes the rest. Retention binds every
authorized device; it is not a local setting.

These limits and the quota state are decisions for the read path, publication and state store work,
which is not built yet.

## Consequences

A large account may reach the membership record cap before the proof reaches our records. The tool
reports that failure with a named cause.

Continued publication eventually reaches a local or remote quota. The tool stops and explains why;
it does not delete the user's history.

## Alternatives

Unbounded proofs were rejected: they turn a large but ordinary account into an out-of-memory event.

Automatic pruning on quota pressure was rejected: it deletes recovery material exactly when the user is
least able to notice.
