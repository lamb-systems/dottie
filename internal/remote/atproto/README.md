# Native AT Protocol remote boundary

The package implements the OAuth identity boundary, bounded repository proofs and one fenced
`applyWrites` publication operation. It does not provide generic record or blob CRUD, encrypt
snapshot content, or wire synchronization into the CLI.

## Vault record binding

The seven `systems.lamb.dottie` Lexicon records are represented by typed Go values in `records.go`.
`DecodeRecord` and `EncodeRecord` use AT Protocol DAG-CBOR and reject unknown or missing fields;
`VerifyRecordBinding(record, envelopeOrObject)` is pure comparison code with no transport or I/O.
It checks every field duplicated between a record and its V02 signed envelope/object, including
object-signature equality and the snapshot blob reference, length and envelope-signature digest.
It does not prove signature authenticity.

`VerifyRecordContext` performs the separate cross-record checks. Its policy, control, certificate,
snapshot and previous-policy context values are DAG-CBOR record bytes; a non-nil empty snapshot
slice denotes the bootstrap empty head. Missing required context fails with a typed error.
`SnapshotRecordSigningPreimage`, `SignSnapshotRecord`
and `VerifySnapshotRecordSignature` define the independent Ed25519ctx record signature as
`dottie/v1/recordsig` followed by canonical DAG-CBOR of all snapshot record fields except
`signature`; `$type`, `schemaVersion` and the typed blob reference are included. A future field
addition changes every signature preimage, so it is a signature-compatibility break even if the DTE
wire version stays the same. V02 uint64 record values use Lexicon integers capped at 9007199254740991;
`EncodeRecord` refuses larger values rather than truncating them. Resolving the record and envelope
signatures to the same trusted device key requires the caller's certificate chain, which these
binding functions deliberately do not accept.

The policy stores recipient X25519 public keys by value and roles by device ID. A policy
recipient's `keyId` identifies the X25519 wrapping key; a certificate's `keyId` identifies the
Ed25519 signing key, so the two identifiers must never be compared. The policy does not duplicate
signing public keys: policy role authorizes the device, the certificate chain binds that device to
its Ed25519 key, and the certificate record binds both public keys to the signed certificate object.

## Discovery and identity binding

Discovery is four ordered hops: handle to DID using HTTPS `/.well-known/atproto-did` with
`_atproto.<handle>` TXT fallback; DID to the DID document (`plc.directory` for `did:plc`, HTTPS
DID web document for `did:web`); DID document to the `#atproto_pds` service; then PDS to
`/.well-known/oauth-protected-resource`, its advertised authorization server and that server's
`/.well-known/oauth-authorization-server`. DID document `id` and `alsoKnownAs` must bind the
resolved DID to the requested `at://` handle. The protected-resource `resource` must bind to the
PDS, and metadata `issuer` must exactly equal the advertised server identifier. Handle, PDS and
issuer hosts may differ; a sharded PDS can advertise an authorization server on another host.
An advertised `revocation_endpoint` is optional, but when present it must be an absolute HTTPS URL with no
query or fragment. Unsupported DID forms and every discovered non-HTTPS endpoint fail closed. Discovery and
credential-bearing requests do not follow redirects.

Authorization uses PAR, a retained verifier-derived PKCE S256 challenge, independently generated
state, and the actual loopback listener address `http://127.0.0.1:<port>/callback` in both PAR and
the token exchange. Callback state is compared in constant time; callback issuer and token subject
are checked against discovery before code exchange and session storage respectively. Grants are
parsed as `atproto`, `repo:<nsid>` and `blob:<mime>` scopes. `VaultScopes()` is the canonical sorted
set: `atproto`, all seven `repo:systems.lamb.dottie.*` collections, and `blob:application/octet-stream`.
The metadata scope-set test compares it with `docs/client-metadata.json`. Any unrequested grant or missing
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
5. On an `invalid_token` 401, refresh once and retry once with the new token and proof. If refresh
   discovers a different PDS HTTPS origin, return `ErrAuthMethodRelocated` before retrying against either
   the old or the newly discovered resource origin.
6. If a challenge requires replay but the body has no `GetBody`, do not retry and return a typed
non-replayable error. A repeated challenge also returns a typed error; the resource request never
exceeds two attempts.

Refresh and transport failures are returned as `*AuthMethodError` values with an error kind usable
through `errors.Is`. Ordinary non-challenge HTTP responses are returned unchanged for the API caller
to inspect.

A single keyring item contains one version-1 session envelope with DID, optional handle, issuer, validated
token endpoint, granted scopes, refresh token and DPoP private key. Missing/empty state means `usable` for
legacy compatibility; `refresh-pending` carries no refresh token or private key and is not usable. Access
tokens and DPoP nonces stay in process memory only. Linux storage uses the Secret Service **default**
collection (the only alias gnome-keyring accepts; a purpose-named collection cannot be created portably)
and replace-on-match item creation. A locked or unavailable keyring is a hard failure; there is no file
fallback. Partial or unknown-version envelopes require login, while local logout can delete an envelope by
DID without decoding it.

Refresh resolves the handle (or the stored handle), checks discovered DID/issuer/token endpoint before any
credential request, acquires the session lock, reloads the current item and checks those bindings again. It
writes a secret-free `refresh-pending` marker before the token POST. A marker-save error sends no token. The
marker is the point of no return for the old token: every failure after it and before the final save, including
a transport error with no observed write notification, a lost response or a cancellation after dispatch, leaves
the marker. A final save that applies but loses its reply leaves the new usable envelope, never the consumed
token, and returns `ErrSessionPersistenceUncertain` because durability is unconfirmed. A final save that fails
before applying leaves the marker. Later refresh on a pending item fails with `ErrSessionRefreshPending`. The
public save API is intentionally absent; login and locked refresh are the persistence paths. Login checks
cancellation after callback selection, token response, and before persistence. Only the actual storage call is
wrapped in `ErrSessionPersistenceUncertain`; a busy or unavailable lock keeps its own typed error. After token
dispatch a code may already be consumed even though no session is stored; the user must log in again. OAuth
endpoint errors expose status and an allow-listed code only; raw provider bodies and `error_description` are
discarded, except internal nonce detection.

The CLI coordinates cooperating processes with an advisory file lock named `dottie-session-<uid>.lock` in
`XDG_RUNTIME_DIR`, `/run/user/<uid>`, or the temporary directory, in that order. It does not depend on
`XDG_STATE_HOME`; different runtime directories and non-cooperating/manual keyring changes are outside the
lock guarantee. Remote logout requires a usable, binding-matched session and an advertised revocation
endpoint. Its DPoP proof has no access-token `Authorization` header or `ath`; a nonce challenge is retried
once. A 2xx is reported as a **revocation request accepted**, not global token invalidation. Local deletion
occurs only after acceptance, and the CLI reports the split outcome if the keyring deletion then fails.

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

## Bounded repository proofs and fenced publication

Verification is not hand-rolled: bounded CAR/MST/signature checking uses Indigo's
`atproto/repo`, `atproto/repo/mst` and `atproto/atcrypto` plus `go-car`, which grows `go.sum`
from 118 to 360 lines and the module graph to 264 modules. That footprint is the price of not
writing our own MST and signature verification, and it must be revisited if the dependency set
ever becomes a release concern.

A revision read has at most three attempts. Each attempt obtains `getLatestCommit`, streams a full
`getRepo` response without `since`, then obtains `getLatestCommit` again. The CAR root must equal
the authenticated commit CID and both advertised CIDs before the revision is returned. The commit
must pass Indigo structure and signature verification, and its DID must equal both the requested
DID and the DID-document id. Exactly one DID verification method with the `#atproto` id (document-
relative or `<DID>#atproto`), matching controller and a `publicKeyMultibase` is accepted;
`Multikey` and the legacy
`EcdsaSecp256r1VerificationKey2019`/`EcdsaSecp256k1VerificationKey2019` type names are accepted, then
the parsed multibase key must be one of the curves Indigo verifies: **P-256 or secp256k1**. The live
network currently publishes secp256k1 `Multikey` entries, so a P-256-only rule breaks interop while
adding no security; the binding that matters is the DID-scoped `#atproto` method plus a verified
commit signature. Other curves are rejected. No `getRecord` call contributes to proof membership.

The CAR is capped while its response stream is read, before `LoadRepoFromCAR` can materialise it.
`DefaultBudgets()` uses 8 MiB total CAR bytes, 8192 blocks, 1 MiB per block, 4096 membership
records and MST depth 32. The bounded pre-pass rejects malformed roots, duplicate blocks and
oversized blocks. After loading, a partial MST is rejected; every membership key is unique, its
record bytes must exist in the CAR, and the bytes are re-hashed to the membership CID. Any bound or
integrity failure returns a typed error and no partial revision. These defaults are proof-task
limits sized for a small preferences repository; a real account CAR may be larger. The read path must
revisit the defaults before production reads.

A verified revision carries a read-only `(NSID, rkey) -> record CID` membership view and record
bytes sourced only from that CAR. The package-private `publishFenced` primitive emits one
`com.atproto.repo.applyWrites` batch for administrative transitions: the first blob-reference record,
head, control and explicitly supplied policy/certificate writes are atomic. It is called by
`CommitTransition` only after the concrete adapter has authenticated and revalidated the predecessor.
Ordinary publication uses a separate package-private fenced sink reachable only through
`CommitPublication`; it writes only the snapshot reference and head and cannot encode a control write.
Both paths use the verified revision CID as `swapCommit`, with no unfenced fallback.
A structured `{"error":"InvalidSwap"}` maps to `ErrFenceLost`; message text is never used for this
classification. A 5xx, timeout or transport failure is `ErrAmbiguousTransport`, not absence, and
is never blindly retried.

The live fence harness uses provisional test-only records: `systems.lamb.dottie.vaultSnapshot` at
`probe-<base32>` with `{$type, probe, blob, createdAt}`; `systems.lamb.dottie.vaultHead` at
`self` with `{$type, snapshotRkey, snapshotCid, updatedAt}`; and `systems.lamb.dottie.vaultControl`
at `self` with `{$type, devices:[{did,role}], policyEpoch, updatedAt}`. These fixtures are not
the record schemas schemas and must not be used as production vault records. They are confined to integration
tests and are deleted and verified by deferred cleanup.

The error categories are `ErrFenceLost` for structured `InvalidSwap`, `ErrRevisionMoving` after
three changing reads, `ErrUnprovenMembership` for partial trees or unprovable record bytes/CIDs,
`ErrUntrustedCar` for malformed or over-budget CARs, `ErrSignature` for an invalid repository
signature, `ErrKeyBinding` for DID/key-purpose/algorithm binding failures, `ErrBatchRejected` for
record preparation or definitive non-fence rejection, and `ErrAmbiguousTransport` for unknown
transport outcomes and server failures.

The only current revision claim is membership at a PDS-asserted commit, not global freshness.
Rollback and equivocation defence require independent checkpoints in checkpoints and recovery. A fence prevents
exposure through our writes under an honest-but-racing provider; a malicious PDS colluding with a
revoked keyholder can still reference temporary blobs outside our writes. Device authorship and
role enforcement remain device enrollment/V04.

## Contention and ambiguous-failure measurement

`tests/integration/contention_harness_test.go` is a test-only measurement harness.
`TestLiveContention` skips unless `DOTTIE_LIVE_CONTENTION=1`, and uses only the F03/F04
disposable identity allowlist. It must not be run without explicit disposable-account
authorization. The separately budgeted long referenceability run additionally requires
`DOTTIE_LIVE_EXPIRY=1`; it has its own context and timeout. Before opening credentials or sending
requests, the test requires at least 30 minutes remaining for the short schedule, or 110 minutes
when short and long schedules are selected together. No live F05 result has been measured by this
implementation.

Authorized invocations, only after explicit disposable-account approval, are:

```sh
DOTTIE_LIVE_CONTENTION=1 DOTTIE_HANDLE=dottiethrowaway.bsky.social go test -count=1 -timeout=35m -run TestLiveContention ./tests/integration -v
DOTTIE_LIVE_CONTENTION=1 DOTTIE_HANDLE=dottie.wallera.computer go test -count=1 -timeout=35m -run TestLiveContention ./tests/integration -v
DOTTIE_LIVE_CONTENTION=1 DOTTIE_LIVE_EXPIRY=1 DOTTIE_HANDLE=dottiethrowaway.bsky.social go test -count=1 -timeout=2h -run TestLiveContention ./tests/integration -v
DOTTIE_LIVE_CONTENTION=1 DOTTIE_LIVE_EXPIRY=1 DOTTIE_HANDLE=dottie.wallera.computer go test -count=1 -timeout=2h -run TestLiveContention ./tests/integration -v
```

The 35-minute short command covers up to 5 minutes of setup, the 20-minute measurement context
(including the two possible five-minute waits), and 2 minutes for cleanup. The 2-hour long command
covers the short schedule, the 75-minute long-expiry context, and cleanup allowance.

The D1 outcome classifier is ordered and assigns one state to each attempted publication:

1. `rejected-local`: client-side validation stopped the attempt before sending.
2. `not-sent`: a failure was positively established before transport dispatch. A missing
   `WroteRequest` callback after dispatch is not proof of no send and resolves as `unknown`.
3. `unknown`: transport error after send, any 5xx, unparseable body, or a 2xx with no commit CID.
   This precedence wins over an error name in the body, including `InvalidSwap` in a 500 response.
4. `rejected-pre-blob`: a structured 4xx `error` field is exactly `InvalidSwap`.
5. `rejected-other`: every other 4xx; treat as possible staged-blob disclosure.
6. `committed`: a 2xx has a commit CID and the publication marker is proven in a fresh verified
   revision.

The D2 marker is the unique snapshot `(collection, rkey)` plus its locally computed expected
record CID. A fresh verified revision containing that exact key-to-CID pair resolves to `committed`;
if head/control no longer bind to that publication it is recorded as `committed-but-superseded`,
never retried. After `unknown`, a verified revision with the marker absent resolves to `not-landed`
and records retry evidence eligibility; a revision read that cannot be fully verified resolves to
`unavailable` and stops. A response-suppression decorator's verification result is carried into that
attempt, so unavailable evidence is terminal and does not trigger a second read. A known `not-sent` outcome is also retry-evidence eligible because no
request bytes reached the provider. The harness records eligibility only and has no retry loop.

The live matrix records two separate atclient/HTTP clients, a rendezvous barrier, successful
request-write-to-first-response-byte intervals measured after release, and a distinct DPoP-nonce
contention stratum. Incomplete or inconsistent trace intervals are inconclusive; the race is
inconclusive if the observed intervals do not overlap. Replay-after-success and racing-identical-
batch rows retain every HTTP result and each validated returned commit CID, including the required
`2xx/2xx` row. Final exact-marker membership and individual CIDs are evidence; they do not prove the
historical at-most-one-effect invariant when they cannot distinguish one commit from two. Experiment
4 uses a test-only transport decorator to verify commit before synthetic response loss, verify absence
before suppressing a forwarded response, and record live cancellation as `INCONCLUSIVE` when its
processing point is unknown. Experiment 4a reports the committed-but-response-lost claim only
when the forwarded publication was verified committed and response suppression actually occurred;
failed construction is explicitly unmeasured/inconclusive. The rejected-batch duration fixture
contains a valid staged blob plus a valid-shaped reference to a never-uploaded blob, matching F04. Duration is measured only if a fresh
verified revision establishes that no record references the candidate CID and the exact staged bytes
first become anonymously reachable after rejection; every aged probe compares exact bytes and reports
its timestamp and elapsed age from the rejection response. Any failed prerequisite is `unmeasured`.

Latency repetition count is registered by `DOTTIE_LIVE_LATENCY_N` (default 50, hard maximum 100);
each update uses one dedicated snapshot rkey, a fresh verified revision and its own `swapCommit`.
The effective N is printed and capped by the remaining verified-revision budget at two reads per
sample (the fresh revision plus outcome resolution). A typed budget stop prints the partial profile
and its caveat rather than failing the test. Success and error samples are separate. Percentiles use nearest rank: sorted ascending, rank
`ceil(p*n)`, one-indexed. The decision-grade minimum is 200 observations per provider; below it the
record reports the measured percentiles next to the literal
`insufficient sample - not decision-grade`. Thus the default 50-sample profile is exploratory, not
decision-grade.

The enforced per-provider short-run budget has a 120-call logical applyWrites cap and a separate
120-request wire cap at the HTTP dispatch boundary, including authentication replays and cleanup.
Every budget-counted transport clones `http.DefaultTransport` and disables HTTP/2 while retaining
TLS and request `GetBody`; this prevents Go's HTTP/2 transport from silently retransmitting a POST
below the cap, while the authentication layer's explicit nonce/token replay remains supported. The
latency stratum is therefore measured over HTTP/1.1 and its reported percentiles are h1 measurements,
not provider HTTP/2 behavior.
Two wire dispatches are held for the cleanup batch, allowing its single authentication replay; it also
allows 12 contention/ambiguity publication attempts, 12 such cleanup deletes, 160 verified revision
reads and 600 HTTP dispatches. Logical calls and wire requests are reported separately. The long expiry run has a separate 34-request HTTP/wire budget, a two-dispatch applyWrites cleanup
reserve, and an 8-request HTTP cleanup reserve. The arithmetic for both ages, even when both
references commit, is 3 initial verified-read requests + 2 blob-staging requests + 2 x (1 anonymous
probe + 3 verified-read requests + 1 applyWrites + 3 post-commit verification requests) = 21
measurement requests, including 6 resolution reads. Cleanup reserves 8 requests (initial verified
read 3 + challenged delete and one nonce replay 2 + final verified read 3), for 29 of 34 total and
5 requests of headroom. Those 5 remaining requests are the entire allowance for DPoP nonce
challenges and auth replays across the run. The eight-request cleanup reserve is the minimum for
its initial read, one challenged delete/replay and final verification; additional refreshes or a
moving revision may still require manual reconciliation. If the five-slot allowance is exceeded, the
expiry run stops and reports `referenceability=unmeasured: budget exhausted` for remaining ages rather
than overrunning. It has no per-run override. A typed budget stop
prints `referenceability=unmeasured: budget exhausted` for every remaining age and returns cleanly.
No cap is increased without owner approval recorded in Logseq. Expiry is measured by referenceability
with one attempt per fresh randomized specimen at immediate, +1m and +5m; the optional long run adds
+15m and +60m.
The checked-in result remains **unmeasured until run** for every provider and age:

| Provider | Immediate | +1m | +5m | +15m | +60m |
| --- | --- | --- | --- | --- | --- |
| Bluesky-hosted | unmeasured until run | unmeasured until run | unmeasured until run | unmeasured until run | unmeasured until run |
| Independently hosted | unmeasured until run | unmeasured until run | unmeasured until run | unmeasured until run | unmeasured until run |

D8 viability is not inferred from the harness source. The measurement record must decide whether
(a) stale/duplicate writers lose deterministically on both providers, (b) every attempt has exactly
one D1 state and no outcome is silently treated as success, and (c) no post-blob disclosure beyond
the F04-measured window was observed, while recording how long a rejected candidate remains
reachable. Failure of any criterion means `not viable as designed`, with the alternative named.
Expiry of a never-referenced blob is reported separately from rejected-candidate disclosure
duration.

Every applyWrites target is tracked and printed with a run identifier before its first send. If
cleanup cannot verify or delete, output includes the complete run-id tracked pair set and instructs
reconciliation against a fresh verified revision without deleting unrelated records. An aborted run
can therefore be reconciled from output alone. The test refuses to overwrite a pre-existing
head/control `self`; this is an intentional restart hazard because those records may belong to a
prior aborted run. These are integration-test mechanisms only: **no production retry or recovery loop
exists**.

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

The F04 live harness is `TestLiveFence` in `fence_live_test.go`; it skips unless
`DOTTIE_LIVE_FENCE=1`, uses the same allowlist and existing keyring sessions, and was not run for
this implementation. Run only with explicit disposable-account authorization, one provider at a time:

```sh
DOTTIE_LIVE_FENCE=1 DOTTIE_HANDLE=dottiethrowaway.bsky.social go test -count=1 -run TestLiveFence ./internal/remote/atproto -v
DOTTIE_LIVE_FENCE=1 DOTTIE_HANDLE=dottie.wallera.computer go test -count=1 -run TestLiveFence ./internal/remote/atproto -v
```

Its six rows report initial atomic creation, two stale-writer losses (including the simulated
control transition), stale-cache rejection, bounded mixed-view retries and blob-processing
rollback. Stale rows include captured `swapCommit` and the competing commit; the fence rejection
must be `InvalidSwap`, and post-failure rows verify both unreferenced membership and anonymous CID
unreachability. Failures write the existing redacted mode-0600 failure artifact with provider,
criterion, evidence, the feasibility gate decision and cloud-release hold. Deferred cleanup deletes and verifies
every record created or unexpectedly created by a publication.

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
the feasibility gate, and a successfully created out-of-scope record is deleted and verified by deferred cleanup.
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
`cloud_release_hold: true`. The the feasibility gate decision is provider-specific; cloud release is held for
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

## Candidate disclosure on a rejected batch (measured, owner-accepted)

Live experiments on both the Bluesky-hosted shard and an independently hosted PDS showed that a
batch rejected **after** blob processing leaves the referenced blob anonymously retrievable by
CID, while no record references it and a never-referenced control blob stays refused
(`200` with the exact staged bytes, versus `400` for the control). A fence lost to `InvalidSwap`
is checked before blob processing and does **not** expose the candidate.

Consequences encoded in this package:

- `publishFenced` reports `ErrCandidateMayBeDisclosed` for every post-submission failure except a
  lost fence, so commit callers can never treat "the batch failed" as "nothing is public".
- Publication is validated exhaustively before sending (record shapes, required writes, duplicate
  targets, blob reference presence) so that the only expected provider-side failure is
  `InvalidSwap`. Anything else must be treated as possible disclosure of the staged candidate.
- Staged ciphertext must be encrypted under the **new** epoch only. Uploading under an epoch a
  revoked device can still decrypt would turn this provider behaviour into a real leak; that
  constraint belongs to the vault epoch work and is recorded here because this task is where the
  window was measured.

## Fenced vault publication and transitions

`CommitPublication` accepts a publisher- or root-authorized `vault.Publication`, a signing key, a
concrete `ATProtoPublicationIO` value and a durable attempt store. Requiring this concrete adapter
is intentional: callers cannot supply an outside I/O implementation or override its concrete verified
reader and fenced-write path. It uploads the already-sealed current-epoch snapshot with
`application/octet-stream`, after the sink independently decodes its envelope and checks the expected
vault, epoch and policy digest. It then invokes the unexported fenced sink with exactly two writes:
the snapshot reference and a head whose `publication_count` is the predecessor count plus one. It
writes no control and changes no epoch. The prepared policy digest and predecessor head are checked
before staging and against a fresh verified read after staging. A superseded policy is a typed
`ErrPreparedPolicyMismatch`; the candidate must be discarded and prepared again.

`CommitTransition` accepts a `vault.Transition`, the root signing key, a concrete
`ATProtoTransitionIO` value and a `TransitionAttemptStore`; its private test seam cannot be
implemented outside this package. The adapter uses `RevisionReader` for verified repository reads,
uploads the already-sealed successor-epoch snapshot with `application/octet-stream`, and commits
with one `publishFenced` `applyWrites` call. The adapter requires caller-held predecessor policy
record evidence in `PreviousPolicies`; it selects the exact record named by the current policy digest,
then verifies that evidence's record binding, signature, chain and one-epoch relationship just as the
read path does. The policy evidence is not taken from the repository under verification. Its durable
`ObservationStore` is also required whenever a head is accepted. Enrollment writes the snapshot blob reference, head,
control, policy and certificate together. Revocation writes the snapshot reference, head, control
and policy only. The revoked certificate remains a historical record; its device is added to the
control revoked set and removed from successor roles and recipients. Both prepared transitions are
checked against an initial verified predecessor before staging and a second verified predecessor
after staging and immediately before the fenced write. A policy digest mismatch is a typed
`ErrPreparedPolicyMismatch`; no stale bundle is reused.

The local attempt row is committed before the blob upload request for both ordinary publication and
transitions. It stores the unique snapshot marker, expected DAG-CBOR record CID, candidate blob CID,
epoch, policy digest, outcome and resolution evidence, but no snapshot bytes or key material.
`TransitionAttempts` enumerates rows for restart recovery; `ResolvePublicationAttempt` and
`ResolveTransitionAttempt` verify current repository membership and do not send another batch. A
verified marker plus matching head CID is the evidence for ordinary publication; transition commit
additionally requires matching control CID. A present marker no longer bound by the current head/control is recorded as
`committed-but-superseded`. The caller must throw away every candidate after a lost fence and
prepare again from the latest verified policy and head; neither commit path has an internal retry
loop. Every other failure after candidate transmission joins `ErrCandidateMayBeDisclosed`, including
an unknown result resolved as not landed or unavailable.

`TestLiveLedgerSharedRootRace` is gated by `DOTTIE_LIVE_LEDGER=1` and the existing disposable
identity allowlist. `TestLivePublicationVersusRootRevocationSharedDeviceKeys` is separately gated
by `DOTTIE_LIVE_PUBLICATION=1`. It races the ordinary publication path against root revocation
authority using two clients but the same root device key material, tracks every record target
before send, and prints identifiers only. It reports the winning write, whether any record references the
loser's candidate blob, and the control's epoch-start snapshot CID beside the live head snapshot
CID. Both live harnesses skip by default; neither was run for this implementation.


## Coherent reads and authenticated retrieval

`VaultReader.Read` returns only a complete result from one `RevisionReader` proof. The repository
commit signature and DID verification key are checked before any vault record is considered. The
reader then checks record-to-object bindings, fetches the envelope named by the head's snapshot CID
(the envelope CID, not the snapshot-record CID), verifies the envelope and snapshot-record
signatures and binding, checks cross-record context, and authenticates the vault state. Every
repository record used by the result comes from the same verified CAR revision. The result exposes
the authenticated publication count and head snapshot CID. Before returning, `VaultReader.Read`
requires a durable observation store and calls `CheckPublicationCount` only after the final
latest-commit stability check. `ATProtoTransitionIO.ReadCurrent` verifies the referenced snapshot
and envelope, including the envelope-parent to signed-head-predecessor join, and enforces persisted
publication-count and signed head-ancestry checks before returning a publication or transition
predecessor. It does not enforce policy `max_publications`; the read-side bound remains deferred. The
state store rejects decreases, conflicting equal counts and same-epoch increments that skip a count;
a higher epoch starts a new count sequence. Migration 0004 stores epoch, count and head CID per vault. The final latest-commit
check covers the blob fetch and all validation; a moved revision discards the candidate and restarts
within a bounded retry count. There is no older-revision fallback or partial result.

The repository proof uses `DefaultBudgets`: 8 MiB CAR bytes, 4096 membership records, plus the
existing block, MST-depth and per-block limits. Blob reads are capped before allocation by the
smaller of the configured maximum and the V02 envelope limit; the signed snapshot record's declared
size must also match exactly. The response is streamed through that cap, then its raw CID is
verified. The current reader does not consume a held checkpoint, so every successful result carries
`freshness-unverified`. This is a statement that membership was proven at a PDS-asserted revision,
not that the revision is globally current or rollback-resistant.

A non-genesis policy overwrites the `literal:self` policy record, so its predecessor cannot be read
from the same current revision. `ReadRequest.PreviousPolicy` accepts the caller-held DAG-CBOR policy
record only for this case; its signed-object digest must equal the current policy's
`prevPolicyDigest`, and its root must authorize the current policy signer. The field is required for
a nonzero predecessor digest and rejected at genesis when supplied. Missing or mismatched context
fails closed. In particular, without a predecessor policy the reader cannot authenticate a rotated
root and does not guess.

The reader is read-only. Supplying no device key returns authenticated ciphertext metadata and no
plaintext. Supplying a device key invokes the existing vault opener only after record binding,
record signature, envelope signature, policy, certificate-chain, role, epoch and revocation checks
succeed. Read failures expose a `ReadError.Stage` and support `errors.Is` for distinct causes:
record binding/context/signature, envelope signature, blob missing/transport/size/truncation/CID,
vault authorization and decryption. `ErrRevisionMoving`, `ErrUntrustedCar` and
`ErrUnprovenMembership` remain the repository-proof failures. Tests use synthetic signed fixtures
and a fake transport only; they make no live or network requests.
