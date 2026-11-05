# Integration suites

The default integration suite is offline and hermetic. It uses synthetic fixtures, temporary homes,
synthetic device keys and an in-memory AT Protocol `MemoryPDS`; it does not use a network, real home,
keyring service, GNOME session or real account.

## Genesis bootstrap

`bootstrap_test.go` drives `Coordinator.InitializeVault` through the real genesis composition and `atproto.CommitGenesis` over an empty synthetic `MemoryPDS`. It asserts custody-before-publication ordering, then explicitly checks `history`, `pull`, ciphertext-only `Export` and no-op `Push` against the finalized trust state. The account CLI path is tested separately with an injected authenticated provider; it prints the kit once and verifies the kit is absent from state and keyring. A repeated bootstrap is refused by the verified empty-repository preflight before minting: keyring contents, state database bytes and the first remote revision remain unchanged. The state interruption test fails one local position-history write and proves selection, checkpoint and evidence all roll back together. No live PDS, real keyring, network, GNOME session or real home is used.

## Publication privacy and failure coverage

`pds_audit_harness_test.go` and `pds_publication_test.go` build a real coordinator-backed synthetic
vault, publish canary-bearing file and settings snapshots, and inspect the anonymous repository and
blob surfaces. The audit covers the bounded repository CAR and individual blocks, `repo.listRecords`
projections, blob enumeration and body reads. It checks raw and reversible canary encodings, bounded
compressed-body scans, recursive record-key inventories, and the distinct retained, referenced and
publicly retrievable blob sets. Positive controls seed plaintext records/blobs, compressed content, an
orphan and an exposed orphan. Publication cases exercise malformed authenticated content, wrong roles,
missing data, quota rejection, auth expiry and the modeled post-blob-processing disclosure window.
All payloads, homes, credentials and provider state in these cases are synthetic.

The offline command and renderer checks cover the surfaces available without a remote account. The
renderer test checks the per-surface disclosure contract: routine status/read/push/history/export/
recovery/device/administrative output excludes relative entry locators; candidate preview displays
target ids and the relative file or setting locator needed for user consent; restore displays each
relative locator and status but omits target id because `restore --target ID` is single-target. Neither
consent surface prints file content or setting values. Retention output may display local payload or
backup references, with absolute references confined to the state directory.

## Archive recovery boundary

`TestArchiveRecoveryAfterSourceLoss` exports through the service coordinator to a fixture cache path,
then removes the synthetic source repository records and all source blobs. It checks that online read
and restore refuse without changing local application state, the validated archive imports with the
independently supplied vault/anchor/kit, and the parsed archive alone supplies the current policy,
control, certificates and envelope used to recover the exact published plaintext with the retained
recipient private key in a fresh temporary home. It also checks wrong-kit, wrong-anchor, missing-blob
(no archive file written) and tampered-member refusals.

`TestArchiveRecoveryAfterSourceLoss` is archive-to-plaintext recovery, not destination restoration. A retained recipient key is required; kit-only decryption is impossible by design. `internal/service/archive_restore_test.go` test `TestRestoreFromArchiveAppliesOnlyKitCheckpointThroughSharedApply` proves checkpoint-only selection and no provider calls; `tests/integration/restore_milestone_test.go` test `TestRestoreMilestoneOfflineTwoHomeAndRecovery` applies an archive into a fresh home after deleting the synthetic source repository and blobs, then rolls back while preserving a newer edit. Archive validation authenticates the archive but does not establish global freshness.

## Opt-in live gates

`TestLivePublicationPrivacy` skips by default. It requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1`, an
allowlisted disposable identity in `DOTTIE_HANDLE`, and explicit authorization. Before writing its
manifest or any record, it calls `com.atproto.repo.describeRepo` and skips if the repository has any
collections. The live publication gate requires a pristine disposable repository because genesis refuses
a non-empty repository. A previous owner-authorized attempt on a used disposable account stopped at this
genesis precondition. A used account, including one carrying ordinary `app.bsky.*` records, is an
environment limitation, not a privacy result. The corrected gate creates synthetic canary records and
attempts cleanup of records. A successful live privacy run leaves its uploaded ciphertext blobs on the
provider permanently because the provider exposes no blob delete; this is expected and recorded in the
run manifest rather than cleaned. The run manifest is written atomically with mode 0600 and records each
unique uploaded blob CID. Every live attempt writes a redacted privacy artifact, including successful
runs; the artifact contains the run id, provider label, audit counts, `retained_set=unobservable`, and the
standing visibility and deletion limits without CIDs or account identifiers.

An owner-authorized read-only observation on a disposable identity found that
`com.atproto.sync.listBlobs` required an authenticated request, while
`com.atproto.repo.listRecords` and `com.atproto.sync.getBlob` were public. This is an observation on
that disposable identity, not a protocol guarantee. The observed provider enumerated only live blobs,
so the live retained set is unobservable. These observations do not establish provider compatibility.

`TestLiveArchiveExportAndValidation` skips by default. It requires `DOTTIE_LIVE_ARCHIVE=1`, an
allowlisted disposable identity in `DOTTIE_HANDLE`, and `DOTTIE_RECOVERY_KIT_FILE` naming a regular
file with no group/world permission bits that decodes to exactly 32 kit bytes. The kit is cleared
after use, and neither it nor its path is written to the artifact or test output. The gate uses the
existing local vault selection and checkpoint, writes an archive only under a temporary directory,
validates it through the coordinator,
and blocks/asserts all repository write endpoints. A named-CID export refusal is recorded redacted and
is not counted as provider evidence.

The archive gate is read-only and uses an existing local vault selection and checkpoint; it does not
invoke genesis, so it does not depend on the publication gate's pristine-repository precondition.
A skipped live gate is not provider evidence. Hosted provider logs and server-side storage are not
observable from a client. No real account, provider, desktop session or user dotfiles are used by the
default suite.

`TestLiveRestoreMilestoneTwoHome` is a separate opt-in live publication-and-restore gate. It requires
`DOTTIE_LIVE_MILESTONE=1`, an allowlisted disposable identity in `DOTTIE_HANDLE`,
`DOTTIE_RECOVERY_KIT_FILE` naming a private regular file with no group/world access that decodes to 32
bytes and authenticates the selected checkpoint, an authorized live account session, an existing local
vault selection/checkpoint and incumbent root device key in Secret Service, plus a live repository that
already authenticates as that Dottie vault.
The test refuses an absent/unreadable remote vault, missing local trust/key material, or a current snapshot
containing any application entries; it never invokes genesis. It copies only trust metadata into temporary
state, creates synthetic file and settings targets in a temporary incumbent home, publishes them, enrolls
a restore-only newcomer, imports the public bundle into a blank temporary home, pulls/previews/restores,
and verifies exact bytes and setting values. The test transport blocks every write endpoint except the
intended `repo.uploadBlob` and `repo.applyWrites` calls, asserts exactly one publication and one enrollment
batch, and audits current head/snapshot/blob linkage plus the fenced write batches. It does not delete any
records or blobs; the uploaded ciphertext and new repository records remain, including a public enrollment
for an ephemeral test device whose private key is not retained. Its redacted artifact contains
only outcome, counts, position epoch, content-match status and standing limits at
`DOTTIE_LIVE_ARTIFACT_DIR/restore-milestone.json` (or the chosen temporary artifact directory). The kit
is an authorization input, not a decryption key; same-host kit use is not independent custody. Skipping
this test is not evidence.

`make test-gnome` also runs `TestRestoreMilestoneGNOMEKeyfileTwoHome` from `tests/local`. That tagged
twin uses the real keyfile backend, synthetic compiled schemas and temporary homes; it demonstrates the
checkpoint-backed incumbent/newcomer restore without network access or a desktop profile.
