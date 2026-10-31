# 005 — Confidentiality has one defense per threat, and only one exists today

Status: accepted, 2026-10-31. Supersedes nothing. Amends the confidentiality claim in ADR 002.

## Context

A previous draft of this decision argued that confidentiality was enforced twice: by staging under a
new epoch only, and by encryption. Three reviewers independently showed that argument was wrong, and
they were right. Those mechanisms address different threats, and only one of them is implemented.

The threats are distinct.

| Threat | What it gets | Only defense | Status |
| --- | --- | --- | --- |
| Anonymous holder of a CID | the staged blob itself | encryption before upload | not implemented |
| Revoked device | a ciphertext staged under an epoch it holds | stage under the new epoch only | planned, DOT-V04 |
| Colluding provider | anything it stores | independent checkpoints, DOT-V05 | undefendable in design |

Staging under a new epoch is a key-selection rule. It decides which epoch encrypts a candidate, so that
a device being revoked cannot read it. It does not cause a rejected candidate to be non-promoted, and
non-promotion is precisely the condition under which DOT-F05 measured disclosure. Treating it as a
second guard was a category error.

Encrypting later does not help. A CID already obtained stays readable by whoever holds that epoch key,
and rotating the epoch does not un-disclose an old ciphertext.

## Decision

Every candidate is encrypted under the currently authorized epoch before it is uploaded. A candidate
staged without an envelope, or staged before an epoch or policy change, is discarded and never promoted.
Promotion after a rejected or ambiguous attempt requires revalidation against the exact current policy
and epoch.

Epochs are per publication attempt and are never reused across attempts. An epoch key is never derived
from a long-lived account secret, because that would make every disclosed ciphertext readable by anyone
holding the account secret.

Epoch keys are pruned once superseded. We keep the last N epochs required for restore and delete older
ones. Pruning costs restore depth: with N epochs retained, a working restore can reach back N epochs and
no further. N is a configuration value, and the trade-off is stated to the user rather than hidden.

`ErrCandidateMayBeDisclosed` stays attached to every post-submission failure except a lost fence, so no
caller can mistake a rejected batch for a clean one.

## Consequences

Nothing is protected today. `internal/vault` has no encryption and no signing, and DOT-F05 measured
exact staged bytes, not envelopes. Real data and cloud release are held until DOT-V02 and DOT-V04 land.
Synthetic fixtures may use the transport freely, which is what DOT-F02 to DOT-F06 did throughout.

Pruning bounds the retroactive exposure. Without it, a device compromised in a year would expose every
candidate from every epoch it ever held, and the acceptance of disclosed ciphertext would not be
defensible.

## Risk ledger

Accepted and recorded, not hidden:

- A rejected candidate stays anonymously retrievable for at least five minutes, and no end of the
  window has been measured.
- Per DOT-F04 and ADR 002, a colluding provider together with a revoked keyholder can reference
  temporary blobs outside our writes.
- A disclosed ciphertext remains readable by the holder of that epoch key indefinitely. This is
  harvest-now, decrypt-later, which is why epoch keys are pruned and never long-lived.

## Alternatives

Relying on provider access control alone was rejected: it is enforced by the provider, so it is not
end-to-end encryption, and a colluding provider can reference a blob it stored.

Encrypting once under a long-lived key was rejected: a single leaked key would expose every snapshot the
user ever staged, and revocation would mean nothing.

Staging plaintext during development was not rejected outright. It is what synthetic fixtures do. It is
also why real data is held, because that combination is exactly what the F05 measurement exposed.
