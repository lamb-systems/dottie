# 007 — Account, device and recovery authority are separate

Status: accepted, 2026-10-31.

## Context

Three different things grant power in this system, and conflating them produces authorization claims
that look stronger than the evidence.

The OAuth account authority is real and proven: four-hop discovery, PKCE, PAR, DPoP, `iss` and `sub`
binding, strict scope enforcement, one atomic Secret Service envelope. DOT-F02 ran it live on two
identities.

The vault device authority does not exist yet. There are no signed roles, no recipient authorization, no
exact signed-policy binding. DOT-F04's control transition was simulated, and `proofs.go` authenticates
repository membership, not authorship or role. The atproto README says the same.

The offline recovery authority does not exist yet either. DOT-V05 owns it.

## Decision

The three authorities are named separately in code, in documentation and in every release decision. No
artifact may cite one as evidence for another.

Credentials are stored in Secret Service only: one atomic envelope per session, no plaintext fallback,
items scoped to `application=dottie`, tokens and response bodies redacted structurally. When the keyring
cannot deliver a session the tool fails closed with a typed error rather than degrading.

The provider-required atproto base scope does not widen write access. DOT-F03 demonstrated that
out-of-scope writes are denied, which closes the question DOT-F02 left for this task. Out-of-scope reads
are public data, so a denial is not implied, and the anonymous control returned 200 as well.

Wall-clock time does not participate in authorization. Role and revocation order come from signed epoch
and policy, as pinned in ADR 006.

Vault authorization, revocation and role checking are release prerequisites, not existing evidence. A
revoked device must be unable to publish, and proving that is DOT-V03's job rather than a claim made here.

## Consequences

Until DOT-V03 lands, the system can publish to an account but cannot say which device should be allowed
to. That is acceptable for synthetic development and unacceptable for real data.

Revocation cannot be described as working. What exists is a repository fence that stops a stale writer. A
writer holding valid account credentials is not stopped by it.

Key separation is preserved: the OAuth token, the epoch keys and the recovery material are distinct
secrets with distinct lifetimes, and losing one does not grant the others.

## Alternatives

One credential for everything was rejected: losing the OAuth token would then also grant the epoch keys
and the recovery material, and no revocation could be scoped to the thing that leaked.

Deriving publish rights from the account token alone was rejected for the same reason. A stolen token
would publish as the user, and there would be no device role to revoke.
