# 011 — "Local only" is not one state

Status: accepted, 2026-10-31.

## Context

A single "local-only mode" message hides situations that need different responses. A publication may
never have been sent, may be queued, may have committed without us hearing back, or may have exposed a
candidate blob. Reporting the same thing for all four invites the worst outcome: a resend after an
unknown result, or an abandoned publication that actually landed.

Outcome and exposure are separate dimensions, and the implementation already treats them that way.
`publish.go` joins `ErrAmbiguousTransport` with `ErrCandidateMayBeDisclosed` on a transport failure and on
any 5xx. An exposure warning is therefore not conditional on proven post-blob rejection; it accompanies
an unknown outcome whenever a submission may have reached the provider.

## Decision

| Situation | True state | Next permitted action |
| --- | --- | --- |
| Nothing dispatched | not sent | retry is safe |
| Dispatched, nothing confirmed | queued | retry on next run |
| Dispatched, no response | outcome unknown, candidate may be disclosed | verified re-read only, no resend |
| 4xx after blob processing | rejected, candidate may be disclosed | no automatic retry, report the exposure |
| 4xx before blob processing (`InvalidSwap`) | rejected before exposure | retry is safe after a fresh revision |

Messages state what happened in words, with a code alongside. Two of them must be worded as: outcome
unknown, pending work retained, no resend until verified; and candidate may be publicly retrievable,
deletion is not guaranteed.

Errors reused from the implementation, all present in `internal/remote/atproto/proofs.go`:
`ErrRevisionMoving`, `ErrUnprovenMembership`, `ErrUntrustedCar`, `ErrSignature`, `ErrKeyBinding`,
`ErrWrongKeyPurpose`, `ErrMalformedPublicKey`, `ErrUnsupportedSigningAlgorithm`, `ErrFenceLost`,
`ErrBatchRejected`, `ErrAmbiguousTransport`, `ErrCandidateMayBeDisclosed`.

Errors that do not exist yet and must be added by named tasks: a policy digest or epoch mismatch error
(DOT-V03), a quota exhaustion error (DOT-P04), and a keyring or reauthorization failure (DOT-P02). These
are listed as planned so no reader assumes they are available.

Stops that must be represented, each with a message and a resume condition: keyring unavailable or
reauthorization required; provider outside the support matrix; advertised limit missing; signature or key
binding invalid; policy or epoch mismatch; proof revision moving or exceeding its CAR or record budget;
quota exhausted; and ambiguous submission. Permanent unavailability, such as an unsupported provider, is
distinguished from a pause that resolves without intervention.

## Consequences

Every new failure path owes a row. A path without one is an unfinished error.

Unsupported browserless or device-flow login needs its own row when DOT-P02 lands, because a
headless user currently has no way forward and no way to see why.

## Alternatives

A single exit condition and a generic message was rejected: it recreates the ambiguity that produced the
F04 disclosure limit, where a rejected batch and a clean one looked the same to the caller.
