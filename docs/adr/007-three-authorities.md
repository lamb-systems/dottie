# 007 — Account, device and recovery authority are separate

Status: accepted, 2026-10-31.

## Context

Three authorities grant different powers in this system. Conflating them overstates the authorization
evidence.

The OAuth account authority is real and proven: four-hop discovery, PKCE, PAR, DPoP, `iss` and `sub`
binding, strict scope enforcement, one atomic Secret Service envelope. The account-authorization work
exercised it live on two identities.

The vault device authority does not exist yet: signed roles, recipient authorization and exact
signed-policy binding are absent. The fence work simulated the control transition. `proofs.go`
authenticates repository membership, not authorship or role, as the atproto README also states.

The offline recovery authority does not exist yet either; checkpoints and recovery owns that work.

## Decision

Code, documentation and every release decision must name the three authorities separately. No artifact
may cite one as evidence for another.

Credentials stay in Secret Service only: one atomic envelope per session, no plaintext fallback, items
scoped to `application=dottie`, tokens and response bodies redacted structurally. If the keyring cannot
deliver a session, the tool fails closed with a typed error rather than degrading.

The provider-required atproto base scope does not widen write access. The blob-lifecycle work
demonstrated that out-of-scope writes are denied, resolving the question left by the account-authorization work.
Out-of-scope reads are public data, so denial is not implied; the anonymous control also returned 200.

Wall-clock time does not participate in authorization. Role and revocation order come from signed epoch
and policy, as pinned in ADR 006.

Vault authorization, revocation and role checking are release prerequisites, not existing evidence. A
revoked device must be unable to publish. Device enrollment must prove that; this record does not.

## Consequences

Until device enrollment lands, the system can publish to an account but cannot determine which device
should be allowed to publish. That is acceptable for synthetic development and unacceptable for real data.

Revocation cannot be described as working. The existing repository fence stops a stale writer, not a
writer holding valid account credentials.

Key separation remains intact: the OAuth token, the epoch keys and the recovery material are distinct
secrets with distinct lifetimes. Losing one does not grant the others.

## Alternatives

One credential for everything was rejected: losing the OAuth token would then also grant the epoch keys
and the recovery material, and no revocation could be scoped to the thing that leaked.

Deriving publish rights from the account token alone was rejected for the same reason. A stolen token
would publish as the user, and there would be no device role to revoke.
