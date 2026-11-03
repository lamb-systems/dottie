# Security model

What Dottie protects, what it does not, and which limits were measured rather than assumed. This page is
for someone deciding whether to trust the tool with their configuration.

## Present and target, stated separately

| Capability | Present | Target |
| --- | --- | --- |
| Directory selection and consent | yes | — |
| Filesystem capture with containment | yes, library only | reachable from the CLI |
| Bounded snapshots | yes | encrypted envelopes |
| OAuth account authorization and local session management | yes, `account login`, `status`, `logout`; live providers not tested | account authority wired into sync |
| Blob lifecycle and fenced publication | yes, harness and library | wired into a product command |
| Encryption and signatures | yes, vault library (ADR 015) | wired into a sync command |
| Device roles, revocation, epochs | yes, vault library (ADR 014); `account bootstrap`, `enroll`, `recovery`, `verify` | transitions driven end to end against a provider |
| Recovery kit and checkpoints | yes, vault library; `account recovery` and `account verify` | restore driven end to end |
| Vault export and import | yes, library only (`EncodeExportArchive`/`ReadExportArchive`); no command | a product export/import command |
| Remote vault sync | no; `dottie plan` previews a local view bundle only | a sync command that publishes and reads a vault |
| GNOME settings capture and apply | boundary only, opt-in cgo | the GNOME capture work to G04 |

The CLI exposes target selection, `dottie plan`, and the `account` command group (`login`, `logout`, `status`,
`bootstrap`, `enroll`, `recovery`, `verify`). The first three manage OAuth authorization only. No command
publishes or reads a vault against a provider, and vault export and import are library functions only. Target
capture, apply and synchronization are not wired; do not use this build to back up real data.

## Authorities

Three separate things grant power, and none of them substitutes for another.

**Account authority** is the OAuth session: discovery, PKCE, PAR, DPoP, `iss` and `sub` binding, strict
scope enforcement, and one atomic Secret Service envelope. It grants repository access and nothing else.
`account login`, `status` and `logout` operate on that authorization; they do not capture or sync target data.

**Device authority** is a root-signed certificate naming a signing key, a recipient key, a role and the
epoch at enrollment. Root, publisher and restore-only are distinct. Not implemented.

**Recovery authority** is material held offline, independent of the account. It can re-establish a root
device. Not implemented.

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
recovery points. A below-policy floor is recorded and surfaced as a confidentiality-compromise signal rather
than refused. Re-declarations preserve the previous declaration and its digest so the change remains visible.

No epoch-scoped ciphertext cache exists yet. Migration 10 records associations from `(vault, device, epoch,
snapshot CID)` recovery points to local payload and journal-backup references. Recovery-material registration
exists as a state API, but the current sync/cache path has no production producer that associates snapshot
material with local payloads or backups. A newly declared point starts with an incomplete inventory, and
`PlanRetentionPrune` refuses with `ErrRetentionRecoveryPointInventoryUnknown` until a caller records a complete
inventory. The authenticated complete-inventory producer is a blocking prerequisite and does not exist until the
sync path is wired (P06). Consequently, manual recovery-point pruning is unavailable in production by design.
V08 is blocked on that producer rather than passing; this is an unmet in-contract prerequisite, not an accepted
limit. Absence of a link is not treated as proof of a complete inventory.

The automatic journal age prune is separate and runs during recovery and rollback. It now checks registered
material against currently retained recovery points before detaching a backup; a matching backup remains
attached and its payload remains available. This automatic journal prune was the actual deletion risk because
it ignored retained-point associations; that path is fixed, even though no production producer currently
populates those associations.

Pruning deletes a payload only when its recovery-point epoch is known and strictly below the oldest retained
recovery-point boundary, it is not associated with any retained recovery point, and it is unreferenced by
applied bases, outbound intents, conflicts and non-prunable journal backups. Aged backups are detached only
after their verified age bound and the same reference/recovery-point checks. Material tied to any retained
point is protected at every age, and material at or above the boundary is not eligible. A material candidate
with no classifiable recovery-point epoch is reported as unclassified and preserved. The dry-run plan lists
each candidate's epoch and the rules that made it eligible or protected it.

The boundary must be the oldest retained point and match a stored checkpoint's epoch and snapshot CID and the
declaration's policy digest. The observed live head must be later than that boundary. The checkpoint pins the
boundary but does not prove that every remote blob is present, because downloads are transient; this local
inventory is not a claim that the snapshot is reconstructable. The live-head observation also fails closed
when no head epoch has been observed locally.

No content-key store or epoch-scoped ciphertext cache currently exists. The local payload store is plaintext
and rollback backups are plaintext. A device's X25519 private key can still unwrap archived wrappers for
epochs where it was a recipient, so pruning locally held bytes does not revoke a secret someone already kept.

## First restore

A device restoring onto a machine with no prior state holds no local checkpoint, so the kit's checkpoint is
its only anchor and everything below it is rejected. With no kit checkpoint the device stays
freshness-unverified and is restricted to inspection and export.

Regaining authorization is not regaining data. A kit cannot retrieve bytes the provider no longer holds;
data recovery needs the independent complete export, and a repository CAR alone is not a complete blob
backup.

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
