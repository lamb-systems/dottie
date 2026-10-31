# 004 — Admit a snapshot before uploading it, on the encrypted length

Status: accepted, 2026-10-31. Supersedes nothing.

## Context

Three different quantities were being treated as comparable, and they are not.

`MaxTotalBytes` is 256 MiB of plaintext entry payload. What actually goes to the provider is larger:
tar headers, a manifest, padding, and after encryption an envelope. The provider's ceiling is a third
number again, an advertised `blobUploadLimit` read from the resolved PDS. The advertised values we
have observed are 300 MiB on one provider and 100 MiB on another, and neither is a tested rejection
boundary.

The ordering matters more than the arithmetic. DOT-F04 showed that a batch rejected after blob
processing leaves the candidate anonymously retrievable, while a never-referenced control stays
unreachable. A check performed at `applyWrites` time therefore happens after the data is already
disclosable by CID. Too late to be a protection.

## Decision

Admission is a client-side comparison performed before the first `uploadBlob` request. It compares the
final serialized encrypted blob length, or a proven conservative upper bound on that length, against
the resolved provider's advertised limit and the local cap. Whichever is smaller wins.

When the advertised limit is missing, unparseable, zero or negative, the tool fails closed. Absence is
never read as unlimited.

No silent splitting, no truncation, no automatic retry at a smaller size. A snapshot that does not fit
is refused with a typed error naming the effective limit, and reducing its scope is the user's
decision.

## Consequences

A snapshot larger than the discovered ceiling cannot be published to that provider, even if it passes
local validation. That is the intended outcome; the alternative is publishing an encrypted blob the
provider rejects after we have already exposed it.

The 100 MiB and 300 MiB figures are recorded as advertised limits, not as verified boundaries. Size,
MIME and account-quota enforcement remain unmeasured, and account quota may reject a blob that fits the
per-blob ceiling.

## Alternatives

Lowering `MaxTotalBytes` to 100 MiB compares plaintext against an encrypted ceiling, so a maximal
snapshot could still exceed the limit after framing and encryption. Rejected as a fix.

Checking at publish time is rejected for the disclosure reason above.

Splitting one snapshot across several blobs would change the snapshot schema and the publication
contract, and is out of scope here.
