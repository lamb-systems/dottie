# 010 — Spaces stays out of scope, with a dated reassessment and two standing constraints

Status: accepted, 2026-10-31.

## Context

AT Protocol Spaces is the protocol-native answer to some of what we are building by hand, particularly
access control over private data. It is also immature, unevenly supported across providers, and not the
same thing as end-to-end encryption.

This task must reassess it without implementing it, and must not let the reassessment become a quiet
plan to migrate.

## Decision

Spaces is not implemented in this scope and no code may depend on it.

The reassessment must be dated and source-backed. Where primary-source evidence is unavailable, it is
recorded as unavailable rather than inferred from a blog post or from the design's plausibility.

Two constraints hold regardless of how mature Spaces becomes:

- End-to-end encryption is still required. Spaces access control is enforced by a provider, so it is not
  E2EE and does not cure a malicious provider.
- A private Spaces vault must never silently fall back to public storage. If private storage is
  unavailable, the answer is a stop, not a downgrade.

The reopening trigger is broader than disclosure. Maturity, supported providers, addressing and proof
differences, publication semantics and migration cost all count. A single improvement does not reopen
it.

## Consequences

We carry our own epoch and encryption design, with the costs recorded in ADR 005.

If Spaces later provides per-record access control that removes the staging-disclosure problem, the
staging design should be re-evaluated rather than defended. That is the point of recording a trigger.

## Alternatives

Adopting Spaces now was rejected: provider support is not uniform, the confidentiality story would still
need E2EE, and the migration cost is unknown.
