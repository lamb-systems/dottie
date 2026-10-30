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

## DPoP, resource authorization and storage

Every proof uses ES256 with an EC P-256 public JWK, compact JWS and fixed-width `R || S` signature.
Proof timestamps come from the injected clock; each proof gets a fresh identifier. Resource proofs
include `ath`; target URIs omit query and fragment. DPoP nonces are origin-scoped in memory only,
retried once, and never written to session storage.

`NewAuthMethod` binds the normalized handle, DID, discovered issuer, token endpoint and exact
HTTPS PDS origin. It rejects a loaded session whose DID, issuer or token endpoint differs from
discovery. The resource-auth state machine is:

1. Refuse any non-HTTPS request or request outside the bound PDS origin with a typed error.
2. If the in-memory envelope has no access token, refresh before sending the resource request.
3. Set `Authorization: DPoP <token>` and a fresh DPoP proof containing the token's `ath`.
4. On a 400/401 `use_dpop_nonce` challenge with `DPoP-Nonce`, save that nonce and retry once with
a fresh proof. This path never refreshes credentials.
5. On an `invalid_token` 401, refresh once and retry once with the new token and proof.
6. If a challenge requires replay but the body has no `GetBody`, do not retry and return a typed
non-replayable error. A repeated challenge also returns a typed error; the resource request never
exceeds two attempts.

Refresh and transport failures are returned as `*AuthMethodError` values with an error kind usable
through `errors.Is`. Ordinary non-challenge HTTP responses are returned unchanged for the API caller
to inspect.

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

## AT client transport policy

The PDS matrix harness creates both its authenticated and anonymous `atclient.APIClient` values
with Dottie's own `*http.Client`; it does not use Indigo's `http.DefaultClient`. The client is
TLS-only and its RoundTripper allows requests only to the discovered PDS HTTPS origin. Redirects
return `http.ErrUseLastResponse`, so credentials or probe traffic are never carried to a redirect
target. Connect and TLS handshake timeouts are five seconds, response-header timeout is ten
seconds, and the complete request timeout is thirty seconds. Response bodies are limited to 2 MiB
and over-limit reads fail. The authenticated client uses the native `NewAuthMethod`; the anonymous
client has no auth method. An offline integration test proves redirect targets are not followed.

## Probe isolation and live PDS matrix

The PDS probe code exists only in `tests/integration`. `internal/remote/atproto` contains no generic
record or blob CRUD helpers, and an integration test scans production Go imports to guard that
boundary. Blob uploads use `atclient` request primitives and set `Content-Type:
application/octet-stream`; the generated `RepoUploadBlob` helper is not used because it sends
`*/*`.

The live test is `TestLivePDSMatrix`. It skips unless `DOTTIE_LIVE_PDS=1`, uses an existing scoped
session from the Secret Service keyring, and accepts only `dottiethrowaway.bsky.social` or
`dottie.wallera.computer` as `DOTTIE_HANDLE`. Any other handle fails closed. It must be run only
with explicit disposable-account authorization; no live run was performed for this implementation.

The controlled D2 experiment runs in this order on the selected PDS: fetch the unreferenced
uploaded blob anonymously; create the single D3 probe record; repeat the identical anonymous fetch
and require status 200 plus exact byte equality; enumerate `listBlobs` while the record exists and
check for any separately advertised blob host; delete the record, verify record deletion, fetch the
blob again as a reachability observation, and enumerate `listBlobs` again. The two list results
record whether the CID appears while referenced and whether it remains after record deletion; no
blob-deletion claim is made. If the CID appears in the listing even though the earlier unreferenced
anonymous fetch returned 404, that is recorded as a metadata-exposure finding. The PDS descriptor
has no blob-host field, so no separately advertised blob host is a protocol fact; the harness does
not guess CDN or AppView media hosts. If record creation rejects the unknown probe lexicon shape,
the harness records the finding and stops rather than inventing a schema. The probe record is exactly
`{"$type":"systems.lamb.dottie.vaultSnapshot","probe":"<32 random bytes, base32>","blob":<blobRef>,"createdAt":"<timestamp>"}`. Record cleanup runs in a deferred path even after a test assertion fails. Blobs are never claimed deleted; each uploaded CID gets a post-run reachability row.

D4 records `blobUploadLimit` verbatim or `unadvertised` (never interpreted as unlimited), expects
`text/plain` to be rejected and `application/octet-stream` to be accepted, and reports a size
boundary as unmeasured unless explicitly enabled. To enable it, both environment variables are
mandatory: `DOTTIE_LIVE_PDS_BYTES=1` and `DOTTIE_LIVE_PDS_BYTE_CEILING=<positive plain decimal
bytes>`. If the flag is set while the ceiling is absent, empty, non-decimal, zero or negative, the
test fails with an error naming both variables; there is no default or limit inference. The harness
attempts at most `min(advertised blobUploadLimit, ceiling)`, or the ceiling when the provider
advertises no limit, and never uploads beyond the ceiling. It performs only the baseline upload and
at most one ceiling-sized upload. If the upload exactly at the ceiling succeeds, it reports
`boundary above ceiling <N>, unmeasured` and stops; it does not increase, bisect or retry at a larger
size. The matrix row includes the advertised limit, ceiling, attempted size, result and latency.

D6 uses a known-valid `app.bsky.feed.post` write fixture outside the granted collection and a
valid `listRecords` read request for that collection; results are classified as authorization,
validation, transport or success, and validation failures do not count as evidence of least
privilege. Any successful out-of-scope repository access is recorded as a provider limitation for
DOT-F07, and a successfully created out-of-scope record is deleted and verified by deferred cleanup.
The read-only `com.atproto.server.getSession` request is a data-minimisation observation, not a
scope-widening test: the harness does not request `account:email`, and records only whether
unrequested fields such as `email`, `emailConfirmed`, `phone` or similar are present. Their field
names, never their values, appear in the matrix; their presence is a widening signal. A mutating
identity write is deliberately not attempted because it could damage a disposable account or
change its handle.

Run only after owner authorization, one disposable provider at a time:

```sh
DOTTIE_LIVE_PDS=1 DOTTIE_HANDLE=dottiethrowaway.bsky.social go test -count=1 -run TestLivePDSMatrix ./tests/integration -v
DOTTIE_LIVE_PDS=1 DOTTIE_HANDLE=dottie.wallera.computer go test -count=1 -run TestLivePDSMatrix ./tests/integration -v
```

When `DOTTIE_LIVE_PDS_BYTES=1`, append an owner-approved `DOTTIE_LIVE_PDS_BYTE_CEILING` to the
command. Every printed matrix row contains provider, experiment, status, a redacted body prefix and
timing. The checked-in matrix is intentionally unmeasured until its owner runs the harness:

| Provider | Experiment | Status | Redacted body prefix | Timing |
| --- | --- | --- | --- | --- |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 unreferenced anonymous blob fetch | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D3 probe-record creation | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 referenced anonymous positive control and byte equality | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 authenticated `listBlobs` while record exists | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 other advertised blob hosts | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 `listBlobs` after record deletion | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D7 probe-record deletion verification | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D2 post-delete blob reachability | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D4 `blobUploadLimit` advertisement | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D4 `text/plain` rejection | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D4 `application/octet-stream` acceptance | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D4 optional size boundary | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D6 out-of-scope known-valid write | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D6 out-of-scope valid read | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D6 `getSession` data-minimisation field names | not yet measured | not yet measured | not yet measured |
| Bluesky-hosted (`dottiethrowaway.bsky.social`) | D6 identity write | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 unreferenced anonymous blob fetch | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D3 probe-record creation | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 referenced anonymous positive control and byte equality | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 authenticated `listBlobs` while record exists | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 other advertised blob hosts | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 `listBlobs` after record deletion | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D7 probe-record deletion verification | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D2 post-delete blob reachability | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D4 `blobUploadLimit` advertisement | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D4 `text/plain` rejection | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D4 `application/octet-stream` acceptance | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D4 optional size boundary | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D6 out-of-scope known-valid write | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D6 out-of-scope valid read | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D6 `getSession` data-minimisation field names | not yet measured | not yet measured | not yet measured |
| Independently hosted (`dottie.wallera.computer`) | D6 identity write | not yet measured | not yet measured | not yet measured |

A failed criterion writes a mode-0600 `failure.json` into a printed temporary directory. Its fields
are `provider`, `intended_pds`, `criterion`, `redacted_evidence`, `decision_required_at_DOT_F07` and
`cloud_release_hold: true`. The DOT-F07 decision is provider-specific; cloud release is held for
the failing provider. This task does not implement local-only fallback and never silently switches
providers.

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
