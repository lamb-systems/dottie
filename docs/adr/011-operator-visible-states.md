# 011 — "Local only" is not one state

Status: accepted, 2026-10-31.

## Context

A single "local-only mode" message hides four situations that need different responses. A publication
may never have been sent, may be queued, may have committed without us hearing back, or may have
exposed a candidate blob. Telling an operator the same thing in all four cases invites the worst
outcome: a resend after an unknown outcome, or an abandoned publication that actually landed.

## Decision

Every stop is a row, not a sentence. Each row names the trigger, the typed status, the message the
operator sees, what they may do next, and what would lift the state.

The four states that must not be merged:

| State | What is true | Permitted next |
| --- | --- | --- |
| Not sent | nothing left the machine | retry is safe |
| Queued | pending work is durable, nothing sent | retry on next run |
| Outcome unknown | a request may have committed | verified re-read only, no resend |
| Candidate may be disclosed | a submission was rejected after blob processing | no automatic retry, report the exposure |

Messages carry the substance, not a code. Two of them must exist worded as: outcome unknown, pending
work retained, no resend until verified; and candidate may be publicly retrievable, deletion is not
guaranteed.

Existing typed errors are reused rather than invented: `ErrSignature`, `ErrKeyBinding`, `ErrPolicy`,
`ErrRevisionMoving`, `ErrAmbiguousTransport`, `ErrCandidateMayBeDisclosed`, and the budget and quota
errors. A stop caused by an unsupported provider is distinguished from a pause with pending work,
because one is permanent until the provider changes and the other resolves on its own.

## Consequences

Operators see more text and make better decisions.

Every new failure path owes a row. A path without a row is an unfinished error, not a minor gap.

## Alternatives

A single exit code and a generic message was rejected: it is the specific ambiguity that produced the
F04 disclosure limit in the first place.
