# 010 — Spaces stays out of scope, with a dated reassessment

Status: accepted, 2026-10-31.

## Context

AT Protocol Spaces provides protocol-native permissioned data and overlaps directly with what this
project builds itself. Its assessment must rest on evidence.

The assessment is dated 2026-10-31. It uses the primary source, the AT Protocol announcement
"Atproto Spaces Alpha is Live", published 2026-08-20, and the protocol proposal it links (proposals
`0016-permissioned-data`).

As of that date:

- Spaces are in **alpha**, released with running code, SDKs, a sample app and a hosted development PDS.
  The announcement warns that there will be breaking changes and that production code must not run
  against it.
- "Spaces give you access control not confidentiality. The data in a space is readable by any user or
  application with access to that space, it's not encrypted." This is the assessment's most relevant
  statement.
- The code has not undergone careful security review, no backups are taken, destructive migrations are
  possible, and the hosted alpha PDS is deleted at the end of the alpha.
- The protocol design, SDKs and database schema are not final, with launch targeted for later in 2026.
- A space is a mini atproto network with its own authority DID and per-space permissioned repos on the
  author's PDS. There is no relay for space data, so applications sync directly from PDS hosts.
- Ecosystem implementations exist beyond the reference: ZDS in Zig, atproto-crates and rsky in Rust, and
  a spaces-aware AppView framework.

## Decision

This scope does not implement Spaces. No code may depend on it.

Two constraints apply regardless of Spaces maturity:

- End-to-end encryption remains required. The announcement explicitly states that Spaces provide
  access control, not confidentiality. Access control cannot replace encryption or address a malicious
  provider holding the epoch key.
- A private Spaces vault must never silently fall back to public storage. If private storage is
  unavailable, stop rather than downgrade.

Reopening requires all of these criteria together: a stable release, a completed security review,
evidence of provider support, addressing and proof differences from public repositories, publication
semantics, and the cost of migrating an existing synthetic vault.

## Consequences

We retain our own epoch and encryption design and the costs recorded in ADR 005.

If Spaces later provides per-record access control mature enough to remove the staging-disclosure
problem, re-evaluate the staging design rather than defend it against newer evidence.

## Alternatives

Adopting Spaces now was rejected on the evidence above: alpha status without security review, an explicit
warning not to run production code, and no confidentiality property even when it works as designed.
