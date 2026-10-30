# Native AT Protocol OAuth boundary

The package implements the OAuth identity boundary only. It does not publish records, blobs,
heads or controls, and it does not prove that records belong to one repository revision. Those
operations remain subject to the remote transaction and ciphertext rules owned by later work.

## Discovery and identity binding

Discovery is four ordered hops: handle to DID using HTTPS `/.well-known/atproto-did` with
`_atproto.<handle>` TXT fallback; DID to the DID document (`plc.directory` for `did:plc`, HTTPS
DID web document for `did:web`); DID document to the `#atproto_pds` service; then PDS to
`/.well-known/oauth-protected-resource`, its advertised authorization server and that server's
`/.well-known/oauth-authorization-server`. DID document `id` and `alsoKnownAs` must bind the
resolved DID to the requested `at://` handle. The protected-resource `resource` must bind to the
PDS, and metadata `issuer` must exactly equal the advertised server identifier. Handle, PDS and
issuer hosts may differ; a sharded PDS can advertise an authorization server on another host.
Unsupported DID forms and every discovered non-HTTPS endpoint fail closed. Discovery and
credential-bearing requests do not follow redirects.

Authorization uses PAR, a retained verifier-derived PKCE S256 challenge, independently generated
state, and the actual loopback listener address `http://127.0.0.1:<port>/callback` in both PAR and
the token exchange. Callback state is compared in constant time; callback issuer and token subject
are checked against discovery before code exchange and session storage respectively. Grants are
parsed as `atproto`, `repo:<nsid>` and `blob:<mime>` scopes. Any unrequested grant or missing
required scope rejects the session before storage.

## DPoP and storage

Every proof uses ES256 with an EC P-256 public JWK, compact JWS and fixed-width `R || S` signature.
Proof timestamps come from the injected clock; each proof gets a fresh identifier. Resource proofs
include `ath`; target URIs omit query and fragment. DPoP nonces are origin-scoped in memory only,
retried once, and never written to session storage.

A single keyring item contains one versioned session envelope with DID, issuer, validated token
endpoint, scopes, refresh token and DPoP private key. The item name is derived from client id and
DID. Linux storage uses the Secret Service **default** collection (the only alias gnome-keyring
accepts; a purpose-named collection cannot be created portably) and replace-on-match item
creation. A locked or unavailable keyring is a hard failure; there is no file fallback. Partial or
unknown-version envelopes require a new login. Refresh rediscovers and checks issuer and token
endpoint before sending the refresh token, and stores a rotated refresh token in the same item.

The `Secret` wrapper redacts string, formatting and text/JSON serialization. This prevents normal
formatting paths from printing codes, tokens or private-key material, but is not a memory-isolation
boundary: secrets remain exposed to the running process, core dumps, ptrace and swap. A code visible
in browser history is non-replayable without the retained PKCE verifier. The loopback listener is
reachable by other local users; state, one-time authorization codes and PKCE are the defense against
the shared-loopback threat. The callback listener has a bounded attempt count and closes after the
first state-valid callback. There is no device flow. Periodic reauthorization is required when the
provider expires or revokes the refresh token.

All default tests are offline and use fake endpoints, deterministic clocks, temporary homes and an
injected keyring. The live owner-runnable harness is opt-in with `DOTTIE_LIVE_OAUTH=1` and
`DOTTIE_HANDLE`; it opens the browser only when explicitly selected and reports identifiers only.

## Keyring collection policy

Dottie stores its session envelope in the Secret Service **default** collection and identifies
its own items by the attributes `application=dottie` and `name=<session item>`. It does not
create, rename or relabel a collection: `CreateCollection` with a custom alias fails on
gnome-keyring with `Only the 'default' alias is supported`, and relabelling the user's login
keyring would be an unacceptable side effect. If no default collection exists or it is locked,
opening the keyring fails with a typed error and the flow pauses; there is no file fallback.
Underlying D-Bus errors are preserved in the message so an operator can diagnose the session
without guessing.

## Scope notes from the live provider

`bsky.social` rejects a request that carries only granular scopes with
`invalid_scope: The "atproto" scope is required`. `atproto` is therefore a **required base
scope**, not an alternative to the granular `repo:`/`blob:` scopes. The client requests
`atproto` plus its granular collections, and the token response's granted scope is recorded so
the effective width of the grant can be verified rather than assumed.

The authorization server's own `scopes_supported` is treated as informational: it currently
advertises `atproto` and the `transition:*` family only, and a client that validated that list
with its own grammar would refuse to start.
