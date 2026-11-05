# 011 — "Local only" is not one state

Status: accepted, 2026-10-31.

## Context

A single "local-only mode" message hides situations that require different responses. A publication
may never have been sent, may be queued, may have committed without a response, or may have exposed a
candidate blob. Reporting all four alike risks the worst outcome: resending after an unknown result
or abandoning a publication that actually landed.

The implementation already treats outcome and exposure as separate dimensions. `publish.go` joins
`ErrAmbiguousTransport` with `ErrCandidateMayBeDisclosed` on a transport failure and on any 5xx. An
exposure warning does not require proven post-blob rejection: it accompanies an unknown outcome
whenever a submission may have reached the provider.

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

Reuse these existing errors from `internal/remote/atproto/proofs.go`:
`ErrRevisionMoving`, `ErrUnprovenMembership`, `ErrUntrustedCar`, `ErrSignature`, `ErrKeyBinding`,
`ErrWrongKeyPurpose`, `ErrMalformedPublicKey`, `ErrUnsupportedSigningAlgorithm`, `ErrFenceLost`,
`ErrBatchRejected`, `ErrAmbiguousTransport`, `ErrCandidateMayBeDisclosed`.

The named tasks must add errors that do not yet exist: a policy digest or epoch mismatch error
(device enrollment), a quota exhaustion error (publication), and a keyring or reauthorization failure
(persistent authorization). These remain planned, not available.

Each of these stops requires a message and a resume condition: keyring unavailable or reauthorization
required; provider outside the support matrix; advertised limit missing; signature or key binding
invalid; policy or epoch mismatch; proof revision moving or exceeding its CAR or record budget; quota
exhausted; and ambiguous submission. Distinguish permanent unavailability, such as an unsupported
provider, from a pause that resolves without intervention.

## Consequences

Every new failure path requires a row. Without one, its error handling is unfinished.

Unsupported browserless or device-flow login needs its own row when persistent authorization lands.
A headless user currently has no way forward or explanation of why login cannot proceed.

## Alternatives

A single exit condition with a generic message was rejected. It recreates the ambiguity that produced
the F04 disclosure limit: a rejected batch and a clean one looked the same to the caller.
