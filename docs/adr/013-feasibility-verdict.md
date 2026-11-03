# 013 — The feasibility verdict, in three permissions

Status: accepted, 2026-10-31.

## Context

The task asks for a feasibility gate with a single verdict. One verdict is the wrong instrument here,
because three different decisions were being collapsed into one word: whether the design is feasible,
whether development may continue, and whether real data may be released.

An earlier draft answered "accept with conditions", which reads as permission, and asked the owner
whether the confidentiality question was a blocker while declaring it resolved. Reviewers caught both.

## Decision

Three separate permissions.

**Design feasibility: accepted.** The primitives we depend on have positive evidence on two hosting
categories. Blob lifecycle, the exact-revision fence, contention behaviour, OAuth and the native settings
boundary are understood well enough to design against, and the failure modes are written down. ADR 009 lists what is proven and what is not.

**Synthetic-only development: allowed.** Work continues with synthetic fixtures against disposable
accounts, which is what the cloud tasks did throughout.

**Real data and cloud release: held.** Not accepted, and not accepted with conditions that read as
permission.

Release prerequisites, each with an owner and a pass rule:

| Condition | Owner | Passes when |
| --- | --- | --- |
| Encryption precedes upload | the envelope implementation | A test proves no candidate reaches `uploadBlob` without an envelope under the authorized epoch, and the stop fires for a plaintext candidate |
| Epoch discipline | the epoch-transition work | An upload-precondition test proves no candidate is promoted under a stale epoch, that a policy or epoch change forces discard and re-encryption, and that stale-candidate transmission is reported as a disclosure rather than prevented, as ADR 014 defines the bound |
| Retention and attrition | the epoch-transition work | A test proves retained material — cached ciphertext and rollback copies — beyond the retained recovery points is deleted, that the live head's epoch and the boundary snapshot with its verified checkpoint are never pruned, and that the device publishes a device-signed attestation of its declared floor and retained recovery points, with the attestation path available to restore-only devices as ADR 014 defines it. Dottie does not persist content keys, so there is no key material to delete; that is recorded in ADR 014 rather than assumed |
| Vault authorization | device enrollment | Signed device role, exact policy digest and recipient set are checked at one revision, and a revoked device cannot publish |
| Disclosure remeasured | provider verification | A dedicated experiment measures rejected-candidate disclosure with fresh candidates, verified unreferenced state, exact-byte probes and recorded ages; a still-reachable result is recorded as such, not as a pass |
| Ceiling conformance | the read path, publication | Admission compares the final encrypted blob length against the discovered limit before upload, and fails closed when the limit is unadvertised |
| Independent review | the pre-real-data security gate, the manual-restore milestone | The pre-real-data and secure-restore gates pass |

The disclosure condition is separate from the staged-blob referenceability measurement. An earlier draft
treated the long expiry run as covering disclosure; that run ages fresh specimens at +15 and +60 minutes,
while disclosure probes are fixed at +1 and +5 minutes.

## Consequences

The cloud track proceeds without treating the confidentiality question as settled.

Each condition names an owner and an artifact, so a later reader can check it directly. The epoch key pruning condition exists because the owner accepted disclosed
ciphertext on that basis and nothing else would have proven it.

## Alternatives

"Accept with conditions" was rejected as a verdict, because conditions attached to an acceptance are read
as permission by whoever picks the work up next.

Rejecting feasibility outright was rejected: the measured evidence is positive on the parts that exist,
and the unbuilt parts have named owners.
