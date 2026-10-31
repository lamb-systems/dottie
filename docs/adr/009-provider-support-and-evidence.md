# 009 — Describe providers, do not label them

Status: accepted, 2026-10-31.

## Context

"Supported" is a word that hides its own evidence. A provider can accept our transport calls and still
reject a large blob, answer a missing blob with a 500, or keep a rejected candidate reachable longer than
another provider does. A single label flattens all of that into a claim nobody can check.

## Decision

Every provider is described by requirement, not labeled. The matrix below records what was observed, on
which hosting category, and what remains unmeasured. Observations are from 2026-10-30 and 2026-10-31.

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

The ceiling must be read from the resolved PDS. The entryway descriptor is not the PDS descriptor, and
the entryway in this case advertises no limit at all.

A provider is usable for the transport primitives when its blob, fence and contention rows pass. It is
not thereby certified for confidentiality, and not certified above its advertised ceiling.

Freshness is stated wherever a provider is described: the only claim available is membership at a commit
the provider asserted. Rollback and equivocation defence require independent checkpoints in DOT-V05.

## Consequences

A reader can see which requirement is proven, on which host, and which is assumed.

A provider advertising no limit cannot be used for uploads, because admission fails closed rather than
guessing.

## Alternatives

A boolean "supported" flag was rejected: it erases exactly the provider differences recorded above.
