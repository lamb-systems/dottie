# 009 — Describe providers, do not label them

Status: accepted, 2026-10-31.

## Context

The label "Supported" hides the evidence behind it. A provider can accept our transport calls and
still reject a large blob, answer a missing blob with a 500, or keep a rejected candidate reachable
longer than another provider. A single label obscures those differences and leaves no checkable claim.

## Decision

Describe every provider by requirement rather than a label. The matrix records observations by hosting
category and identifies what remains unmeasured. The observations date from 2026-10-30 and 2026-10-31.

| Requirement | Bluesky-hosted (shard) | Independently hosted |
| --- | --- | --- |
| Unreferenced blob retrievable | no | no |
| Referenced blob returns exact bytes | yes, 200 | yes, 200 |
| Blob still enumerated after last-reference removal | no | no |
| Advertised `blobUploadLimit` | 300 MiB on the resolved shard; none on the entryway | 100 MiB |
| Size rejection boundary | unmeasured | unmeasured |
| MIME policy | unmeasured; `text/plain` rejection was a scope limitation | unmeasured |
| Account quota | unmeasured | unmeasured |
| Missing blob status | 500 | 4xx |
| Stale writer loses on the structured fence | yes | yes |
| Two accepted identical batches | unproven | unproven |
| Rejected candidate reachable after 5 minutes | yes | yes |
| `applyWrites` p50, n=50 | about 307 ms | about 56 ms |

Read the ceiling from the resolved PDS. The entryway descriptor is not the PDS descriptor; this
entryway advertises no limit.

A provider is usable for the transport primitives when its blob, fence and contention rows pass.
Passing those rows does not certify confidentiality or use above the advertised ceiling.

Every provider description must state the freshness limit: the only available claim is membership at
a commit the provider asserted. Rollback and equivocation defence require the independent checkpoints
in checkpoints and recovery.

## Consequences

Readers can distinguish requirements proven on a given host from assumptions.

A provider that advertises no limit cannot be used for uploads. Admission fails closed rather than
guessing.

## Alternatives

A boolean "supported" flag was rejected: it erases exactly the provider differences recorded above.
