# 009 — Describe providers, do not label them

Status: accepted, 2026-10-31.

## Context

"Supported" is a word that hides its own evidence. A provider can accept our transport calls and still
reject a large blob, answer a missing blob with a 500, or expose a rejected candidate for longer than
another provider does. A single label flattens all of that into a claim nobody can check.

## Decision

Every provider is described by requirement, not labeled. Each row records the observed pass, the
observed failure, the advertised limit, and the requirement that remains unmeasured.

Facts pinned by measurement so far:

- The blob ceiling is advertised by the resolved PDS. The entryway descriptor is not the PDS descriptor
  and must not be used as the source.
- A missing blob answers 500 on one provider and 4xx on another. Neither is evidence of absence.
- Upload rejection for `text/plain` is a scope limitation, not a MIME policy finding.
- After last-reference removal the blob is no longer fetchable or enumerated. Physical deletion was not
  observed and is not claimed.
- Size, MIME and account-quota enforcement are unmeasured.
- Accepted-duplicate behaviour is unproven, because the two-acceptance case never occurred.
- `applyWrites` latency at n=50 is exploratory and not decision-grade, and the two providers differ by
  roughly five times: about 307 ms p50 against about 56 ms p50.

A provider is usable for the transport primitives when it passes the blob, fence and contention
probes. It is not thereby certified for confidentiality or for snapshots above its advertised ceiling.

Freshness is a separate limitation and is stated wherever a provider is described: the only claim we
can make is membership at a commit the provider asserted. Rollback and equivocation defence require
independent checkpoints in DOT-V05.

## Consequences

Support statements become longer, and that is the point: a reader can see which requirement is proven
and which is assumed.

A provider advertising no limit cannot be used for uploads at all, because admission fails closed rather
than guessing.

## Alternatives

A boolean "supported" flag was rejected because it makes the unmeasured parts invisible, and because
the existing provider differences are exactly the kind that a flag would erase.
