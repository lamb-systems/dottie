# 010 — Spaces stays out of scope, with a dated reassessment

Status: accepted, 2026-10-31.

## Context

AT Protocol Spaces is the protocol-native answer to permissioned data, and it overlaps directly with what
this project builds by hand. It has to be assessed on evidence.

The assessment below is dated 2026-10-31 and based on the primary source: the AT Protocol announcement
"Atproto Spaces Alpha is Live", published 2026-08-20, plus the protocol proposal it links (proposals
`0016-permissioned-data`).

As of that date:

- Spaces are in **alpha**, released with running code, SDKs, a sample app and a hosted development PDS.
  The announcement states plainly that there will be breaking changes and that production code must not
  run against it.
- "Spaces give you access control not confidentiality. The data in a space is readable by any user or
  application with access to that space, it's not encrypted." This is the sentence that matters most
  here.
- The code has not undergone careful security review, no backups are taken, destructive migrations are
  possible, and the hosted alpha PDS is deleted at the end of the alpha.
- The protocol design, SDKs and database schema are not final, with launch targeted for later in 2026.
- A space is a mini atproto network with its own authority DID and per-space permissioned repos on the
  author's PDS. There is no relay for space data, so applications sync directly from PDS hosts.
- Ecosystem implementations exist beyond the reference: ZDS in Zig, atproto-crates and rsky in Rust, and
  a spaces-aware AppView framework.

## Decision

Spaces is not implemented in this scope and no code may depend on it.

Two constraints hold regardless of how mature Spaces becomes:

- End-to-end encryption is still required. The announcement is explicit that Spaces provide access
  control, not confidentiality, so access control cannot replace encryption and does not cure a
  malicious provider holding the epoch key.
- A private Spaces vault must never silently fall back to public storage. If private storage is
  unavailable, the answer is a stop, not a downgrade.

Reopening criteria, all of which matter together: a stable release, a completed security review,
provider support with evidence behind it, addressing and proof differences from public repositories,
publication semantics, and the cost of migrating an existing synthetic vault.

## Consequences

We carry our own epoch and encryption design, with the costs recorded in ADR 005.

If Spaces later provides per-record access control mature enough to remove the staging-disclosure
problem, the staging design should be re-evaluated. Defending it against newer evidence would be the
wrong response.

## Alternatives

Adopting Spaces now was rejected on the evidence above: alpha status without security review, an explicit
warning not to run production code, and no confidentiality property even when it works as designed.
