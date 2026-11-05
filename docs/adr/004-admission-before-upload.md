# 004 — Admit a snapshot before uploading it, on the encrypted length

Status: accepted, 2026-10-31. Supersedes nothing.

## Context

The earlier comparison conflated three different quantities.

`MaxTotalBytes` is 256 MiB of plaintext entry payload. The provider receives more: tar headers, a
manifest, padding, and after encryption an envelope. The provider's ceiling is a third quantity: the
advertised `blobUploadLimit` read from the resolved PDS. The resolved Bluesky shard advertises 300 MiB;
the independently hosted provider advertises 100 MiB. The entryway advertises no limit, so the value
must come from the resolved PDS, not the handle's host. None of these values is a tested rejection boundary.

The order of operations matters more than the arithmetic. The fence work showed that rejecting a batch
after blob processing leaves the candidate anonymously retrievable, while a never-referenced control
stays unreachable. By `applyWrites` time, the data is already disclosable by CID.

## Decision

The client checks admission before the first `uploadBlob` request. It compares the final serialized
encrypted blob length, or a proven conservative upper bound on that length, against the resolved
provider's advertised limit and the local cap. The smaller limit applies.

The tool fails closed when the advertised limit is missing, unparseable, zero or negative. A missing
limit never means unlimited.

The tool must not split silently, truncate a snapshot or retry automatically at a smaller size.
When a snapshot does not fit, the tool refuses it with a typed error naming the effective limit.
The user decides whether to reduce the snapshot's scope.

The length must not change between admission and upload. The comparison must include framing and
envelope overhead.

## Consequences

A snapshot larger than the discovered ceiling cannot be published to that provider even if it passes
local validation. This refusal is intentional: uploading instead would expose an encrypted blob before
the provider rejects it.

The 300 MiB and 100 MiB figures are recorded as advertised limits. Size, MIME and account-quota
enforcement remain unmeasured, and account quota may reject a blob that fits the per-blob ceiling.

## Alternatives

Lowering `MaxTotalBytes` to 100 MiB was rejected as a fix. It compares plaintext against an encrypted
ceiling, so a maximal snapshot could still exceed the limit after framing and encryption.

Checking at publish time is rejected for the disclosure reason above.

Splitting one snapshot across several blobs would change the snapshot schema and the publication
contract, and is out of scope here.
