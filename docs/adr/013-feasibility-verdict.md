# 013 — The feasibility verdict, in three permissions

Status: accepted, 2026-10-31.

## Context

The task asks for a feasibility gate with a single verdict. A single verdict is the wrong instrument
here, because three genuinely different decisions were being collapsed into one word: whether the design
is feasible, whether development may continue, and whether real data may be released.

The earlier draft answered "accept with conditions", which reads as permission. It also asked the owner
whether the confidentiality question was a blocker while simultaneously declaring it resolved. Both were
errors, and reviewers caught them.

## Decision

Three separate permissions.

**Design feasibility: accepted.** The primitives we depend on have positive evidence on two providers.
Blob lifecycle, the exact-revision fence, contention behaviour, OAuth and the native settings boundary
are understood well enough to design against, and the failure modes are documented rather than assumed.

**Synthetic-only development: allowed.** Work continues with synthetic fixtures, which is what the
cloud tasks did throughout.

**Real data and cloud release: held.** Not accepted, and not accepted with conditions that read as
permission.

Release prerequisites, each with an owner and a pass rule:

| Condition | Owner | Passes when |
| --- | --- | --- |
| Encryption precedes upload | DOT-V02 | A test proves no candidate reaches `uploadBlob` without an envelope under the authorized epoch, and the stop fires for a plaintext candidate |
| Epoch discipline | DOT-V04 | An upload-precondition test proves staging uses the current epoch only, and a policy or epoch change forces discard and re-encryption instead of promotion |
| Vault authorization | DOT-V03 | Signed device role, exact policy digest and recipient set are checked at one revision, and a revoked device cannot publish |
| Disclosure remeasured | DOT-R03 | A dedicated experiment measures rejected-candidate disclosure with fresh candidates, verified unreferenced state, exact-byte probes and recorded ages; a still-reachable result is recorded as such, not as a pass |
| Ceiling conformance | DOT-P03, DOT-P04 | Admission compares the final encrypted blob length against the discovered limit before upload, and fails closed when the limit is unadvertised |
| Independent review | DOT-V08, DOT-P08 | The pre-real-data and secure-restore gates pass |

The disclosure condition is deliberately separate from the staged-blob referenceability measurement. An
earlier draft wrongly treated the long expiry run as covering disclosure; it ages fresh specimens at
+15 and +60 minutes, while disclosure probes are hard-coded to +1 and +5 minutes.

## Consequences

The cloud track can proceed without pretending the confidentiality question is settled.

Any reader can check a condition without trusting this document, because each names an artifact and a
pass rule.

## Alternatives

"Accept with conditions" was rejected as a verdict, because conditions attached to an acceptance are
read as permission by everyone downstream.

Rejecting feasibility outright was rejected as unsupported: the measured evidence is positive on the
parts that exist, and the unbuilt parts have named owners.
