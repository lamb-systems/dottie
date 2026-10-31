# 005 — Confidentiality has one defense per threat, and none of them is implemented

Status: accepted, 2026-10-31. Amends a claim made in ADR 002.

## Context

An earlier draft of this decision argued that confidentiality was enforced twice: by staging under a
new epoch only, and by encryption. Three reviewers independently showed that argument was wrong.

Those mechanisms address different threats. The threats are listed below, and no row has a defense that
exists in the code today.

| Threat | What it obtains | Defense | Status |
| --- | --- | --- | --- |
| Anonymous holder of a CID | the staged blob | encryption before upload | not implemented |
| Revoked device | a ciphertext staged under an epoch it holds | never stage under an epoch a revoked device holds | planned, DOT-V04 |
| Provider without the epoch key | ciphertext only | encryption before upload | not implemented |
| Colluding provider holding the epoch key | plaintext | none available | recorded as accepted risk |

Staging under a new epoch is a key-selection rule. It decides which epoch encrypts a candidate, and it
does not cause a rejected candidate to be non-promoted. Non-promotion is precisely the condition under
which DOT-F05 measured disclosure, so the rule cannot be a defense against that disclosure.

Independent checkpoints are not on this table. They address authenticated history and rollback
detection, which is a different property. A checkpoint cannot stop a provider from handing out bytes it
already stores, and it cannot stop a key holder from decrypting them.

Encrypting after the fact does not help. A CID already obtained stays readable by whoever holds that
epoch key, and rotating the epoch does not un-disclose an old ciphertext.

## Decision

A candidate is encrypted before it is uploaded, under the currently authorized epoch. Staging must
never use an epoch that a revoked device holds.

A candidate staged before an epoch or policy change, or staged without an envelope, is discarded and
never promoted. Promotion after a rejected or ambiguous attempt requires revalidation against the exact
current policy and epoch.

Epoch granularity is not decided here. The plan requires the currently authorized epoch and revalidation
after an ambiguous result; it does not specify whether epochs are scoped to a rotation or to a shorter
unit. That choice belongs to DOT-V04, and this record states only the constraint on top of it: an epoch
a revoked device holds is never used for staging.

Epoch keys are pruned once superseded. We keep the last N epochs required for restore and delete older
ones, where N is a configuration value. Pruning costs restore depth: with N retained, a working restore
reaches back N epochs and no further. Without pruning, a device compromised in a year would expose every
candidate from every epoch it ever held, and accepting disclosed ciphertext would not be defensible.

`ErrCandidateMayBeDisclosed` stays attached to every post-submission failure except a lost fence. The
implementation already does this: `publish.go` joins it with `ErrAmbiguousTransport` on a transport
failure and on any 5xx, so a caller cannot mistake an unknown outcome for a clean one.

## Consequences

Nothing is protected today. `internal/vault` has neither encryption nor signing, and DOT-F05 measured
exact staged bytes, with no envelope.

Real data and cloud release are held against the complete checklist in ADR 013. This record is not the
gate by itself. Synthetic use of the transport requires explicit disposable-account authorization, which is how
DOT-F02 to DOT-F06 were run.

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

Staging plaintext during development was not rejected outright, because that is what synthetic fixtures
do. It is also why real data is held.
