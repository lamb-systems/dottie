# Security model

What Dottie protects, what it does not, and which limits were measured rather than assumed. This page is
for someone deciding whether to trust the tool with their configuration.

## Public metadata visibility

Vault records are encrypted at the snapshot-envelope layer, but their typed repository records are
public plaintext. The recursive key inventory asserted by the synthetic tests is:

| Record type | Allowed recursive keys |
| --- | --- |
| `vaultSnapshot` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.publicationId`, `$.epochSeq`, `$.policyDigest`, `$.parent`, `$.blob`, `$.signerDeviceId`, `$.signerKeyId`, `$.envelopeSignatureDigest`, `$.signature`, `$.blob.$type`, `$.blob.ref`, `$.blob.mimeType`, `$.blob.size`, `$.blob.ref.$link` |
| `vaultHead` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.epochSeq`, `$.policyDigest`, `$.snapshotCid`, `$.blobCid`, `$.publicationCount`, `$.prevHeadCid`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature` |
| `vaultControl` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.epochSeq`, `$.policyDigest`, `$.headSnapshotCid`, `$.revoked`, `$.prevControlCid`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature`, `$.revoked[].deviceId`, `$.revoked[].certEpoch` |
| `vaultPolicy` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.epochSeq`, `$.roles`, `$.recipients`, `$.policyRetentionFloor`, `$.retainedRecoveryPoints`, `$.maxPublications`, `$.maxEpochAge`, `$.recoveryAnchor`, `$.prevPolicyDigest`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature`, `$.roles[].deviceId`, `$.roles[].role`, `$.recipients[].deviceId`, `$.recipients[].keyId`, `$.recipients[].publicKey` |
| `vaultCertificate` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.deviceId`, `$.keyId`, `$.signingPublicKey`, `$.encryptionPublicKey`, `$.role`, `$.certEpoch`, `$.issuer`, `$.revocationRef`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature` |
| `vaultCheckpoint` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.snapshotCid`, `$.epochSeq`, `$.policyDigest`, `$.anchor`, `$.controlCid`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature` |
| `vaultAttestation` | `$.$type`, `$.schemaVersion`, `$.vault`, `$.deviceId`, `$.policyDigest`, `$.retentionFloor`, `$.retainedRecoveryPoints`, `$.recoveryPoints`, `$.controlCid`, `$.signerDeviceId`, `$.signerKeyId`, `$.signature`, `$.recoveryPoints[].epoch`, `$.recoveryPoints[].snapshotCid` |

These record fields disclose vault and publication identifiers, epochs and counts, policy and control
digests, device labels, key identifiers and public keys, signatures, CIDs, recipient roles and recovery
positions. Device ids are user-supplied labels published in plaintext and must be treated as public.
Records carry no timestamps. Repository revision `rev` and commit identity/CID are separately visible
repository metadata; server-side request timing is separate metadata as well. The recursive inventory
test fails if any unlisted key is added.

Dottie has no log facility. For this client, routine output is the CLI/coordinator reporting surface.
Routine status, read, push, history, export, recovery, device and administrative output omits relative
entry locators. Candidate preview intentionally shows each target id and relative file path or setting
schema/path/key so a user can give informed per-file consent. Restore output shows each relative entry
locator and status; it omits target id because `restore --target ID` is single-target and the invocation
already fixes that target. Both consent surfaces omit file content and setting values. Retention-prune
output may show local payload/backup references; any absolute reference is confined to the state
directory. All these renderers must exclude file contents, setting values, kit bytes, private keys,
session material and absolute home/config/cache/data/temp roots.

A client cannot observe hosted provider logs or server-side storage; neither is covered by local
renderer or synthetic repository tests.

An owner-authorized read-only observation on a disposable identity found that
`com.atproto.sync.listBlobs` required an authenticated request, while
`com.atproto.repo.listRecords` and `com.atproto.sync.getBlob` were public. This is an observation on
that disposable identity, not a protocol guarantee. The observed provider enumerated only live blobs,
so the live retained set is unobservable; enumeration must not be presented as retained bytes. These
observations do not establish provider compatibility.

## Archive recovery boundary

Export produces a ciphertext-only archive. `dottie import --archive` and `ImportExportArchive` validate it without decrypting or changing application state. `dottie restore --archive FILE --kit-file FILE --anchor HEX --target ID` uses the ordinary preview, review-mode digest confirmation, journaled apply and rollback path, but takes its candidate from the archive's kit-signed checkpoint position only. It makes no provider call. Positions above that checkpoint are lineage, not permission to restore them; the archive may not be the newest state.

The checkpoint signature authenticates that position, not global freshness. The snapshot still requires a compatible surviving device recipient private key; the kit verifies/authorizes the checkpoint but cannot decrypt. The offline source-loss and archive-restore tests use synthetic archives and temporary homes. Archive member SHA-256 digests are a layered integrity check; the tamper test proves refusal of a modified archive rather than isolating that check.

## Present and target, stated separately

| Capability | Present | Target |
| --- | --- | --- |
| Directory selection and consent | yes, `targets` and preset onboarding | — |
| Filesystem capture with containment | yes, `status`, `preview`, `pull`, `restore` | — |
| Bounded snapshots | yes, encrypted envelopes | — |
| OAuth account authorization and local session management | yes, `account login`, `status`, `logout`; live providers not tested | live provider validation |
| Blob lifecycle and fenced publication | yes, `push`/`sync` through the coordinator; synthetic in-memory provider only | live provider validation |
| Encryption and signatures | yes, wired into publication and restore; live provider not tested | live provider validation |
| Device roles, revocation, epochs | yes, public-key `devices enroll`/`revoke` and `account bootstrap`; synthetic transitions only | live provider validation |
| Recovery kit and checkpoints | yes, `account recovery`/`verify`; restore proven synthetically | live provider validation |
| Vault export, import and archive restore | yes, `export`, validation-only `import`, and checkpoint-only `restore --archive` | live archive-to-files restore is unrun |
| Remote vault sync | yes, `pull`/`push`/`sync` through the coordinator; synthetic in-memory provider only | live provider validation |
| Retention and manual pruning | yes, per-point inventories and `prune --plan|--apply --confirm`; no automatic GC | scheduled maintenance (B09) |
| GNOME settings capture and apply | selected-key capture, apply and the category matrix, wired to CLI targets; real desktop not validated | real desktop validation (R03) |

The opt-in GNOME boundary reads only explicitly selected keys and never copies a dconf database
wholesale. Its library-level settings apply adapter uses the journaled schema/path/key identity, observes only
user overrides, canonicalizes present values against the schema key, and synchronizes GSettings after Set or
Reset before read-back. A fixed-path schema accepts only its resolved schema path; a relocatable schema uses
the explicit journaled path. This synchronization is backend completion, not filesystem `fsync`, and it does
not prove durability across a crash. `g_settings_sync` has no deadline; a stalled backend can delay
cancellation or recovery. Setting values remain plaintext in the local journal/backup while retained; pruning
an eligible setting backup clears the stored value fields in the same transaction. Capture and apply are wired
to CLI targets in the tagged `gsettings` build; builds without that tag expose no settings backend. The default backend
refuses memory and any backend outside the persistent keyfile/dconf allowlist; synthetic native tests use
temporary homes and isolated keyfile data, not real preferences.

Setting preimages and postimages in the local journal and rollback backups are plaintext while retained. They
follow the existing bounded rollback-material and backup-retention policy; backup pruning removes the
associated retained journal values. This library boundary does not change account authority or grant remote
configuration access to local settings.

The CLI exposes target and preset onboarding, `status`, `preview`, `pull`, `push`, `sync`, `restore` (including `restore --archive`),
`recover`, `devices`, `history`, `export`, validation-only `import`, and confirmed `prune`. Account commands
manage OAuth authorization and local device keys; they do not capture target data by themselves. All
application-data and retention mutations route through the coordinator and its journal; the CLI does not edit
application state or target configuration directly. `account enroll` may prepare local selection metadata and device keys; bootstrap records trusted selection/checkpoint/evidence through the coordinator's single state store. These local metadata cannot authorize application data or apply.

Offline end-to-end demonstrations use disposable synthetic data, in-memory AT Protocol fixtures and temporary homes. Separately authorized live gates exist for publication privacy, archive export/validation and the two-home restore milestone. The restore milestone uses an existing authenticated Dottie vault and never invokes genesis; it refuses an absent or unreadable vault and refuses a current snapshot with any application entries. It writes only synthetic content and enrollment records to an allowlisted disposable account and does not delete records or blobs. Each live gate skips by default; a skipped gate is not provider evidence. Hosted provider logs and server-side retention remain unobservable. No live result is claimed by this document. Real-data use remains prohibited until the owner accepts the evidence matrix in `docs/acceptance.md`. Do not use Dottie with real dotfiles or preferences before that acceptance.

## Authorities

Three separate things grant power, and none of them substitutes for another.

**Account authority** is the OAuth session: discovery, PKCE, PAR, DPoP, `iss` and `sub` binding, strict
scope enforcement, and one atomic Secret Service envelope. It grants repository access and nothing else.
`account login`, `status` and `logout` operate on that authorization; they do not capture or sync target data.

**Device authority** is a root-signed certificate naming a signing key, a recipient key, a role and the
epoch at enrollment. Root, publisher and restore-only are distinct. Enrollment, revocation and epoch
rotation are implemented and wired to the CLI; they are proven synthetically, not against a live provider.

**Recovery authority** is the kit, held offline and independent of the account. It authorizes root recovery and signs checkpoints; it cannot decrypt content. Content requires a surviving compatible device recipient private key, or an independent complete archive together with that key. Losing all device keys without an independent export is data loss. Bootstrap, kit-signed checkpoints and verification are implemented; live recovery is unproven.

## Genesis bootstrap custody and outcomes

`account bootstrap --vault-name NAME --device-id ID (--did DID | --handle HANDLE)` requires a signed-in account. Before minting a kit, device keys or local state, it authenticates a repository revision and refuses a non-empty repository with exit 3. Genesis checks the empty predecessor again immediately before publication, so a competing write remains a possible race. This is a hard product boundary: one account can hold one published Dottie vault because genesis requires an empty repository. Multi-vault selection means only locally recorded vaults, not multiple published vaults on one account.

After preflight, bootstrap stores root device keys in Secret Service, writes the recovery kit once to stdout and flushes any buffered writer, then resolves the advertised blob limit and composes/submits genesis. A failed or short kit write/flush aborts before publication and pending keys are deleted best-effort. The kit is never written to state, keyring, manifest, logs or artifacts. A concurrent-write refusal after delivery means the printed kit belongs to no published vault. A rejected fenced batch may leave an unreferenced encrypted blob on the provider; no local trust or referenced genesis batch is created.

A verified commit is followed by one transaction in the coordinator's existing state store for the local selection, epoch-zero kit-signed checkpoint and complete authenticated position evidence, including the genesis checkpoint position. The genesis reader reuses that store for observations; bootstrap does not open a second state database. Trust is never promoted from record membership alone.

Bootstrap reports four publication outcomes. A verified commit plus successful local trust transaction exits 0. A definite pre-commit failure exits 3 and deletes pending keys best-effort. Verified absence after submission also exits 3 and deletes pending keys best-effort. A submitted result that cannot be resolved exits 4, retains keys and prints the six record targets with inspection instructions; if membership verified but final vault read-back failed, that phase is preserved and still reported unresolved. Up to three bounded verified re-reads with short backoff precede an unresolved result. A local trust-finalization error after a verified remote commit is non-success (exit 4); the single transaction leaves either the full trust set or none, and keys are retained for recovery. The account bootstrap command has hermetic MemoryPDS coverage; live bootstrap and provider compatibility remain separately authorized validation.

## Account session lifecycle

Login discovers the handle, DID, PDS and authorization server, requests PKCE with PAR, and requires the
canonical `atproto` plus seven vault `repo:` scopes and `blob:application/octet-stream` grant. The refresh
token and DPoP private key are stored together in one Secret Service item; access tokens, authorization
codes and DPoP nonces are not persisted. A locked or unavailable keyring is a hard failure with no file
fallback. Endpoint errors expose only HTTP status and an allow-listed OAuth error code; descriptions and raw
provider bodies are never surfaced.

Refresh runs under a per-session advisory lock and reloads the envelope while holding that lock. It replaces
the usable envelope with a secret-free `refresh-pending` marker before sending the refresh request. The marker
is the point of no return for the old token: every failure after it and before the final save, including a
transport error with no observed write notification, a lost response or a cancellation after dispatch, leaves
the marker. A final save that applies but loses its reply leaves the new usable envelope, never the consumed
token, but the command still reports the persistence outcome as uncertain because durability is unconfirmed. A
pending session cannot be refreshed again and requires login. This deliberately fails closed because an absent
write notification does not prove the request was not sent. Cancellation before the marker stores nothing;
cancellation after dispatch and before the final save may consume the old token and requires login. Cancellation
during the final save is a persistence-uncertainty case: the new usable envelope may be present, so run status
before logging in again. Pending local synchronization work is not opened or modified by account commands.

A login cancellation before persistence is attempted stores nothing. A keyring persistence failure or
cancellation during the save attempt is reported as uncertain, not as "nothing was stored": a lost reply can
follow an applied write, so the CLI points to status and local logout instead. Once the token response has been
received, a cancellation may consume the authorization code even though no session is stored.

The runtime lock is selected from `XDG_RUNTIME_DIR`, `/run/user/<uid>`, then the OS temporary directory; it is
not under `XDG_STATE_HOME`. It coordinates cooperating Dottie processes in the same login session, not manual
keyring edits, non-cooperating clients or a process deliberately given a different runtime directory. A locked
or unavailable keyring and an interrupted refresh are reported with recovery guidance, while status itself is
offline when addressed by DID and never exposes a token.

Local logout takes a DID and deletes its item without decoding it, so corrupt, unknown-version and pending
items can be removed offline. Remote logout requires a usable session and a validated discovery-advertised
revocation endpoint. It sends a DPoP proof without an access token, retries a nonce challenge once, and deletes
the local item only after a 2xx. The result means **revocation request accepted by the authorization server**,
not that every access token or other device session has been globally invalidated; issued access tokens may
remain valid until expiry. If the provider accepts the request but local deletion fails, both outcomes are
reported and the item remains for local cleanup.

`AuthMethod` checks a discovered PDS HTTPS origin before resource use after a refresh. If a changed PDS origin
is discovered while refreshing (including an `invalid_token` retry), it refuses to retry the resource request
through the stale auth method. An auth method constructed from stale discovery can still send a currently
valid access token to the old PDS before it learns of relocation; callers own discovery freshness. No live
authorization, refresh or revocation test was run for this implementation.

## What the transport guarantees

A verified revision proves membership of records at a commit the provider asserted. It does not prove who
wrote them, what policy applied, or that the commit is current.

`VaultReader` authenticates one control edge over caller-supplied history and joins later observations to the
control CID durably recorded by this device. A same-epoch re-read must preserve the exact control CID, and an
epoch advance must name the stored control as its predecessor; a changed same-epoch control returns
`ErrVaultPublicationControlReplacement`. The first observation has no older local floor, and an epoch advance
that skips the stored control fails closed. A held checkpoint remains the independent recovery anchor.

The publication fence is measured on two providers: a stale writer loses on a structured error rather than
silently overwriting. Whether a provider can accept two identical batches and produce two effects is
**unproven**, because the measurement could not distinguish one commit from two by final membership.

Publication preparation enforces `max_publications` before evaluating age. With a trusted clock, it compares
against the persisted epoch first-seen time and returns `ErrEpochRotationRequired` at the age threshold. With no
clock, the age trigger is not evaluated and the returned `Publication.AgeTriggerStatus` is
`PublicationAgeTriggerNotEvaluatedNoTrustedClock`; the count trigger alone applies. Refusing solely because a
legitimate caller supplied no clock would block a publication whose available count trigger permits it.

The fence does not protect bytes already uploaded, because the upload precedes the fenced commit that would
reject them.

## Publication retries (P05 library boundary)

`PublishWithRetry` is a transport-library API for ordinary publications; it is not wired into the CLI or
`internal/syncengine`. `CommitPublication` remains a one-attempt primitive, and administrative
`CommitTransition` remains resolve-only. Retry defaults are three observation/write cycles, a 250 ms base
delay, a 5 s cap and 10 s maximum elapsed time. These are unmeasured code defaults, not provider tuning.

The durable logical identity is the snapshot marker plus its locally computed expected DAG-CBOR record CID.
Every retry operation first reads a current verified revision. A matching marker and expected record CID is
committed only when the proven head's `snapshotCid` and `blobCid` bind the requested sealed snapshot; a
marker with another CID is ID reuse, and a matching marker no longer bound by the head is superseded. A
terminal historical `committed` row is not current success. Versioned retry dispositions persist ambiguous,
rejected, quota, rate-limited, upload-size, batch-size and fence-lost outcomes before attempt status updates;
the terminal `committed` outcome itself is authoritative. Only an ambiguous disposition plus a fully verified
current absence permits another write; missing or unknown disposition fails closed. Quota, rate-limit and
auth/offline conditions remain queued; an HTTP 401/403 is an auth hold recorded as ambiguous/queued and may be
retried only after renewal and a verified current absence, never as a data rejection. Exhausted repeated
ambiguous absence is starved; unverifiable reads are unavailable; invalid swap is fence-lost;
policy/size/definitive rejection is rejected. A committed result has nil error only with current marker/head
evidence. If a definitive disposition or terminal status cannot be persisted, the invocation returns
`ErrPublicationState` and does not retry; a later restart can only see the last durable ambiguous row, so a
lost classification is indistinguishable from a timeout and remains a documented limit.

The restart guarantee is conditional on the caller re-supplying the same sealed publication and marker.
P05 does not persist candidate bytes or provide an outbox; candidate ownership remains with the caller until
P06/B03. Every eligible attempt uploads the same bytes and therefore the same content CID. This can restore
availability when a temporary upload expired, but is not a privacy repair and does not undo a measured
post-rejection disclosure window. An explicit expired/missing-blob 4xx at apply time is a definitive
other-rejection, not a retry trigger; re-upload availability comes from ambiguous/restart retry cycles. A
provider-side upload 413 is treated as possible disclosure and rejected; a local pre-upload size refusal is
not. Pending quota/rate work is reported as queued but cannot be resumed automatically until the
outbox/workflow integration exists. Same-marker serialization is process-local for `PublishWithRetry`,
`CommitPublication` and `ResolvePublicationAttempt`; the state database lock coordinates its own store access,
not an invented distributed marker lock. The concrete authentication method's serialization is
context-cancelable, so a publication operation's bounded context also bounds waiting behind another request.
Underlying transport errors are reduced to fixed classifications before they reach returned errors or durable
attempt evidence; arbitrary provider text is not propagated. The retrier proves its marker/head observation,
not global freshness or the provider's at-most-one-effect behavior.

## Measured limits

From live runs on two hosting categories.

- A batch rejected after blob processing leaves its candidate anonymously retrievable by exact bytes. A
  never-referenced control blob stays unreachable, so the negative result is meaningful.
- A rejected candidate was reachable at one minute and at five minutes. The end of that window has not been
  measured and nothing here bounds it. These are the historical the fence work/F05 rejected-candidate observations;
  the checked-in harness's long referenceability schedule has not been run, and it measures a different
  property.
- A lost response cannot be distinguished from a request that was never sent without a re-read.
- Advertised blob ceilings differ: 300 MiB on one provider, 100 MiB on another. Neither is a tested
  rejection boundary. The entryway advertises no limit at all; only the resolved PDS does.
- `applyWrites` latency differed by roughly five times at n=50, which is exploratory rather than
  decision-grade.

## Threats

**A malicious provider** controls what it serves and keeps. It can withhold records, serve a stale but
correctly signed state, and retain blobs. Checkpoints reject a state below a held checkpoint and reject
ancestry that does not reach it. They cannot detect a provider that withholds newer history after the
checkpoint, which is an equivocation and availability limit rather than rollback. A provider colluding with
a revoked keyholder can reference temporary blobs outside our writes.

**A revoked device** keeps whatever keys it already had. Revocation stops it publishing; it does not make
ciphertext it can already decrypt unreadable, and no client-side protocol can.

**A stolen recovery kit** can mint a new root certificate and administer the vault. That is the cost of an
anchor independent of the provider. A kit-signed root replacement is accepted only above the last
kit-announced checkpoint, and reissuing a kit retires the old one at that checkpoint.

**An attacker with account credentials but no device key** still controls remote storage: it can delete,
corrupt, withhold and replace records and blobs. What it must not achieve is decrypting protected plaintext
or forging content that passes signature and policy checks as an authorized publication. Availability of
the remote copy is lost in either case.

**An attacker with an offline, read-only copy of the filesystem** reaches the state database, the
configuration, captured payloads and the local journal, which are plaintext on disk today. It does not reach
the session token or the vault keys, which live in Secret Service.

That exclusion is narrower than it sounds. Secret Service protects a key at rest, not a running process: an
attacker who can read process memory, a dump, swap, or who can replace a binary in the writable path, is
inside the session and is not excluded by this row. Collapsing those two attackers into one would turn a
real limit into a comforting sentence.

## Retention and deletion limits

Retention declarations are stored per vault and device with the policy digest, declared floor, and retained
recovery points. Each point carries its own authenticated `(epoch, snapshot CID, policy digest, control CID)`
position and is verified independently; the held checkpoint point is retained exactly and never replaced by a
later same-epoch publication. Later epochs add their latest authenticated snapshot, capped by the policy's
retained-point count; admission is refused at the cap rather than evicting material. A below-policy floor is
recorded and surfaced as a confidentiality-compromise signal rather than refused. Re-declarations preserve the
previous declaration and its digest so the change remains visible.

The coordinator is the production producer. On a verified read or successful publication read-back it caches
the exact CID-matching envelope body for every retained point in the durable payload store (never plaintext,
never the keys), verifies that the decoded envelope's parent equals the point's signed head predecessor, and
records the point and its associations atomically. If any required body is missing, unavailable or fails
verification the point stays incomplete and pruning refuses; absence is never an empty complete inventory.
Authentication evidence in the position tables carries policy, control, head, certificates and signed
checkpoint positions but no snapshot ciphertext. Journal rollback backups are bound to their point when they
are created and associated in the same transaction; a new backup demotes the point to incomplete until the
next refresh re-verifies the closure.

A position is recorded once its record, envelope and blob authenticate, which happens before the snapshot
payload is unpacked. A validly signed snapshot whose payload cannot be unpacked therefore leaves authenticated
position evidence and lineage history while applying nothing locally, and it stays unusable until a later
publication supersedes it. Validating the payload first would instead leave no evidence for an authenticated
remote position, which would weaken export lineage, so the current ordering is deliberate.

The automatic journal age prune runs during recovery and rollback and consults the same point associations.
Backup eligibility is explicit on both prune paths: a backup bound to a currently retained point is protected
at every age; one bound to an evicted point below the boundary whose association is present is eligible after
the usual terminal/age and revalidation checks; a bound row whose association is missing, and a migrated
legacy-unbound row, are ineligible. A backup is therefore never prunable before association.

Pruning deletes a payload only when its recovery-point epoch is known and strictly below the oldest retained
recovery-point boundary, it is not associated with any retained recovery point, and it is unreferenced by
applied bases, outbound intents, conflicts and non-prunable journal backups. Material tied to any retained
point in any subject is protected at every age, and material at or above the boundary is not eligible. A
candidate with no classifiable recovery-point epoch is reported as unclassified and preserved. Plan and apply
re-read and re-hash every referenced file, so a stale completion marker cannot authorize deletion. The
dry-run plan lists each candidate's epoch and the rules that made it eligible or protected.

The boundary must be the oldest retained point and match a stored checkpoint's epoch, snapshot CID, policy
digest and control CID. The observed live head must be later than that boundary. The checkpoint pins the
boundary but does not prove that every remote blob is present; this local inventory is not a claim that the
snapshot is reconstructable. The live-head observation also fails closed when no head epoch has been observed
locally.

Two floors are reported. The recovery floor is the oldest epoch with a complete inventory and authorizes
pruning. The confidentiality floor is the oldest epoch with any known surviving retained material, including
protected backups and undeleted evicted bodies. When holdings are known, the signed attestation floor is the
confidentiality floor, never a compliant-looking recovery floor. The current wire schema cannot carry an
unknown status, so attestation building and coordinator publication refuse unknown or incomplete inventory
instead of signing a compliant claim. The policy count bounds selected epochs, not total disk use: storage can
grow until a confirmed prune succeeds, and migrated legacy rows are intentionally never age-pruned.

No content-key store exists. Publication content keys and nonces are caller-supplied, used, and discarded.
Retained recovery-point payloads are the exact encrypted envelope bodies (ciphertext), while applied bases, journal
preimages/postimages and rollback backups remain plaintext in the local state store. Local filesystem access is
therefore equivalent to reading the plaintext material, and it can also copy the ciphertext envelopes. A device's
X25519 private key can still unwrap archived wrappers for epochs where it was a recipient, so pruning locally held
bytes does not revoke a secret someone already kept. Export and onboarding fetch required predecessor bodies by CID
through the verified reader, so they depend on provider availability and on the locally retained authenticated
history for lineage rather than on ciphertext kept in evidence.

## Freshness-unverified inspection policy

Authenticated content and global freshness are distinct. If freshness/currency cannot be verified against a local checkpoint, restore refuses with `ErrFreshnessUnverified`; no risk flag or consent bypass grants apply authority. The operator may use the existing consent path to inspect the candidate or continue an export/verification workflow, but that path does not mutate target data, advance the checkpoint or create an apply journal. Invalid signatures, wrong keys and failed policy checks remain unconditional refusals.

## First restore

A device restoring onto a machine with no prior state has no local checkpoint, so the supplied kit-signed checkpoint is its trust anchor and state below it is rejected. Archive restore is restricted to that signed checkpoint position; it does not contact a provider or prove that no newer state exists. Applying archived plaintext still requires a compatible recipient private key held by the selected device. A recovery kit without that key authorizes but cannot decrypt.

Regaining authorization is not regaining data. A kit cannot retrieve bytes the provider no longer holds. All-devices-lost without an independent complete export is data loss; an archive also requires a compatible surviving recipient private key. A repository CAR alone is not a complete blob backup.

## Residual risks

- Disclosed ciphertext stays readable indefinitely by whoever holds that epoch key.
- A candidate uploaded during a concurrent revocation is readable by the pre-revocation recipient set. The
  staging interval can be narrowed; the decryption capability cannot be revoked retroactively.
- A revoked or offline device that ignores its deletion obligation retains access to what it held.
- The end of the post-rejection disclosure window is unmeasured.
- Global freshness is not provided. The only remote claim is membership at a provider-asserted commit.
- A stolen recovery kit is equivalent to administrative control of the vault.

## Stored secrets

| Secret | Where it lives | Lifetime | If stolen |
| --- | --- | --- | --- |
| OAuth session and refresh token | Secret Service, one atomic envelope | until logout or reauthorization | writes and deletes repository records; cannot decrypt vault content |
| Device signing key (Ed25519) | Secret Service | until the device is revoked | forges publications accepted as that device, until revocation lands |
| Device recipient key (X25519) | Secret Service | until the device is revoked; **not** erased by epoch rotation | unwraps every epoch ever wrapped to that device, including keys deleted locally |
| Epoch content key | caller-supplied process memory; not persisted by Dottie | used to seal and discarded by the caller | decrypts snapshots under that epoch while held |
| Recovery kit | offline, not on the machine | until reissued | administrative control of the vault |
| Local state and captured payloads | filesystem | until deleted | plaintext configuration, as in the filesystem row above |

The recipient key row is the one people get wrong: revoking a device stops it publishing, and it does not
take away its ability to unwrap ciphertext that was already wrapped to it.

## Adversarial corpus (DOT-V07)

ADR 014 and ADR 015 define the target contract. The DOT-V07 corpus attacks the vault authorization and
decoder paths with runtime constructors in `internal/vault/hostile_test.go`,
`internal/vault/hostile_export_test.go` and `internal/remote/atproto/hostile_reader_test.go`; the case matrix
and each case's first mandatory check live in those files as the `caseMatrix` table. The fourteen DOT-V07a
findings are closed: their tagged refusal tests remain in the frozen inventories and the security gate passes.

Case 1a now refuses the head/envelope parent mismatch with `ErrReadHeadEnvelopeLinkage` on both observed and
empty observation stores. Its refusal tests assert hostile fields on decoded inputs, not plaintext or a result
returned alongside an error.

### Proven refusals

The reader and the vault library refuse these, with the sentinel and stage named in each test:

- a snapshot with no membership in a valid revision, before any blob fetch (`ErrReadRecordMissing`);
- a restore-only device that signs a snapshot (`ErrReadRecordContext`, field `role`);
- a revoked device's envelope at its successor epoch (`ErrReadVaultAuthentication`);
- a successor policy signed by a root the predecessor never authorized (`ErrReadVaultAuthentication`);
- an epoch-mixed object, an epoch-1 envelope under an epoch-2 record (`ErrReadRecordBinding`, field `epochSeq`);
- a current policy naming an unrelated predecessor (`ErrReadRecordContext`, field `prevPolicyDigest`);
- opening a recipient the policy does not name (`ErrRecipient`);
- an export whose kit-signed checkpoint names a root the archive chain does not contain (`ErrAuthorization`),
  and an export whose member inventory is over its cap or whose first member header disagrees with its entry,
  each refused before any member payload is read (the case 12 guard asserts no payload is read past the manifest).

### Closed defect gate

`make known-defects` passes with the fourteen tagged refusal tests intact, all fourteen matrix rows at
`new-refusal`, both package registries empty, and `TestCaseSecurityGateIsClosed` passing. The matrix and
frozen inventories remain the record of each case and its refusal test.

| Package | Closed case IDs |
| --- | --- |
| `internal/remote/atproto` | 1a, 3b, 3c, 5b, 5c, 10, 11, 18 |
| `internal/vault` | 1b, 13, 14, 15, 19, 20 |

Checkpoint verification joins signer certificates to the policy role for the policy/control authorization
checks. It also checks every derivable control predecessor edge: the predecessor epoch must advance by exactly
one without uint64 overflow, and the successor policy's `PrevPolicyDigest` must equal the predecessor policy
digest. This covers direct descendant and stale shortcuts, each supplied walk link including its terminal
target, and every edge examined before `conflicting` can be returned. Each control position is authenticated
with its matching policy evidence; missing predecessor policy evidence remains unverifiable rather than being
treated as a proven edge.

### Recipient-wrap guarantees

`SealPrepared` requires the policy evidence and enforces exact `(KeyID, PublicKey)` pairs against its
recipients; substitution, omission, extra and duplicate pairs are refused with `ErrRecipient`. It
also requires the prepared vault, epoch and policy digest to match that policy. Production transition
and publication preparation pass their current or successor policy directly to this primitive.
`SealAuthorized` performs the signer-role checks and delegates sealing with that policy.

`VaultReader` separately enforces equality of the envelope's recipient key-ID set with policy,
returning `ErrReadRecipientSet` whether or not a device key was supplied. This is defence in depth;
the wire format carries no recipient public key (`envelope.go:93-98`), so reader set validation alone
cannot prove which public key built another recipient's wrap. `TestRogueWrapDisclosesContentKeyOutsideReader`
and `TestRogueWrapUnderPolicyKeyIDStillDisclosesContentKey` now prove the hostile wraps are refused by
the production sealing primitive. The earlier framing of recipient substitution as an accepted residual
risk was wrong.

### Integrity of ingested CAR blocks

Content integrity of a repository CAR — block bytes against their CIDs, and record bytes against the MST membership
CID — is provided by the pinned `go-car` reader used by repository loading (`CarReader.Next` recomputes each block's
CID and refuses a mismatch), together with the blockstore being keyed by the CIDs the MST names. Dottie does not
duplicate those recomputations: a local check after that reader would be unreachable, because the reader refuses
first. The dependency is covered end to end by the corrupted-CAR tests, so a future parser upgrade that stops
verifying fails a test rather than silently weakening ingestion. If the parser is replaced, restore the local
recomputations deliberately.

### Undetectable limits

- A coherent, correctly signed, older revision is undetectable without an independent freshness floor. Global
  freshness is not provided; the only remote claim is membership at a provider-asserted commit.
- `max_epoch_age` is a **local rotation trigger, not a validity rule** (ADR 014:148-164). It is a local-clock
  trigger persisted in state, and a device treats the trigger as met when its state is lost. A reader that
  accepts an old epoch is therefore correct, and no refusal case is claimed for epoch age. This is separate
  from `max_publications` and `max_epoch_age` *numeric range* (ADR 014:158-159), which the vault wire decoder
  now refuses with `ErrLimit` when the bounds are out of range (case 20).
- `ATProtoTransitionIO.ReadCurrent` enforces publication count, head and control ancestry, predecessor
  authentication, and verification of the referenced snapshot envelope — including its parent linkage, signer
  agreement and signature under the epoch-authorized certificate. It does not enforce the policy
  `max_publications` bound (P04): a transition read can observe a head above the policy maximum, and the
  publication path is where that bound is refused.
- Availability: withheld blobs and refused reads are `unavailable`, not a rollback signal.
