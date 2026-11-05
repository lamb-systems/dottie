# 005 — Confidentiality has one defense per threat, and none of them is implemented

Status: accepted, 2026-10-31. Amends a claim made in ADR 002.

## Context

An earlier draft claimed two mechanisms enforced confidentiality: staging only under a new epoch, and
encryption. Three reviewers independently showed that claim was wrong.

Those mechanisms address different threats. None of the defenses listed below exists in the code today.

| Threat | What it obtains | Defense | Status |
| --- | --- | --- | --- |
| Anonymous holder of a CID | the staged blob | encryption before upload | not implemented |
| Revoked device | a ciphertext staged under an epoch it holds | never stage under an epoch a revoked device holds | planned, the epoch-transition work |
| Provider without the epoch key | ciphertext only | encryption before upload | not implemented |
| Colluding provider holding the epoch key | plaintext | none available | recorded as accepted risk |

Staging under a new epoch selects the epoch that encrypts a candidate; it does not cause a rejected
candidate to be non-promoted. The contention measurements measured disclosure under non-promotion, so
this key-selection rule cannot defend against that disclosure.

Independent checkpoints address a different property: authenticated history and rollback detection.
They therefore do not appear in the table. A checkpoint cannot stop a provider from handing out bytes
it already stores or stop a key holder from decrypting them.

Encrypting after disclosure does not help. A CID already obtained stays readable by whoever holds
that epoch key. Rotating the epoch cannot undo disclosure of an old ciphertext.

## Decision

The client encrypts a candidate under the currently authorized epoch before upload. Staging must never
use an epoch that a revoked device holds.

A candidate staged before an epoch or policy change, or staged without an envelope, is discarded and
never promoted. Promotion after a rejected or ambiguous attempt requires revalidation against the exact
current policy and epoch.

Epoch granularity is now defined in **ADR 014**, which supersedes this paragraph: an epoch is one
administrative transition plus a bounded publication count or age. This record retains the achievable
constraint: no candidate is promoted under a stale epoch, and a candidate transmitted during a concurrent
revocation is disclosed to the pre-revocation recipient set. ADR 014 states the three linearization
points and explains why transmission cannot be undone.

Epoch keys are pruned once superseded. **ADR 014 supersedes the retention rule here**: a device keeps the
epochs its retained recovery points need and deletes the rest, so the tunable is a recovery-point count
rather than an epoch count. The reasoning below about what deletion does and does not achieve still
applies, and ADR 014 states it more precisely. Pruning costs restore depth: with N retained, a working restore
reaches back N epochs and no further. Without pruning, a device compromised in a year would expose every
candidate from every epoch it ever held, and accepting disclosed ciphertext would not be defensible.

`ErrCandidateMayBeDisclosed` remains attached to every post-submission failure except a lost fence.
The implementation already enforces this: `publish.go` joins it with `ErrAmbiguousTransport` on a
transport failure and on any 5xx, so callers cannot mistake an unknown outcome for a clean one.

## Consequences

Nothing is protected today. `internal/vault` has neither encryption nor signing. The contention
measurements measured exact staged bytes, with no envelope.

Real data and cloud release remain held against the complete checklist in ADR 013; this record alone
is not the gate. Synthetic use of the transport requires explicit disposable-account authorization.
The work from account authorization to the native settings boundary ran under that authorization.

## Risk ledger

- A rejected candidate stays anonymously retrievable for at least five minutes, and no end of that
  window has been measured.
- A colluding provider together with a revoked keyholder can reference temporary blobs outside our
  writes.
- A disclosed ciphertext remains readable by the holder of that epoch key indefinitely. This is
  harvest-now, decrypt-later, which is why epoch keys are pruned and never long-lived.

## Alternatives

Relying on provider access control alone was rejected: it is enforced by the provider, so it is not
end-to-end encryption, and a colluding provider can reference a blob it stored.

Encrypting once under a long-lived key was rejected: a single leaked key would expose every snapshot the
user ever staged, and revocation would mean nothing.

Staging plaintext during development was not rejected outright because synthetic fixtures do that.
For the same reason, real data remains held.
