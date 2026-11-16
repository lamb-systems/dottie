# Integration suites

The default integration suite is offline and hermetic. It uses synthetic fixtures, temporary homes,
synthetic device keys and an in-memory AT Protocol `MemoryPDS`; it does not use a network, real home,
keyring service, GNOME session or real account.

## Genesis bootstrap

`bootstrap_test.go` drives `Coordinator.PreflightVault` and `Coordinator.InitializeVault` over an empty synthetic `MemoryPDS`. It asserts that bootstrap publishes no repository record: the verified revision is byte-identical before and after, device keys are stored in the injected keyring, and the local vault selection is the only trust state written (no vault checkpoint). It also asserts that bootstrap succeeds on a repository that already holds an `app.bsky.actor.profile` record and a third-party record, that the preflight refuses a repository holding a v2 Dottie collection, and that the refusal writes no selection, stores no device key and leaves the repository unchanged. Bootstrap mints no recovery kit and prints no secret, and the account CLI path is tested separately with an injected authenticated provider. The end-to-end gate that bootstraps a used account, publishes through v2 and pulls into a second home lives in `tests/local/bootstrap_publication_gate_test.go`. No live PDS, real keyring, network, GNOME session or real home is used.

## Publication privacy and failure coverage

`publication_v2_privacy_test.go` is the v2 payload-privacy gate. It publishes through the real coordinator
path (`PreparePublicationPush`, `ConfirmPublicationPush`) to an in-memory `MemoryPDS` and then scans every
repository record twice, once as the stored DAG-CBOR bytes and once as the `repo.listRecords` JSON
projection, for canaries generated per run: the plaintext of the published target file, a credential-shaped
string, an absolute local path, the account DID and the local review approval digest that stands in for the
retired recovery anchor. Records must contain none of them. The gate also pins a recursive record-key
inventory for both collections, checks that only `systems.lamb.dottie.vaultSnapshotV2` and
`systems.lamb.dottie.vaultHeadV2` are written at the expected record keys and that no
`systems.lamb.dottie.vault*` v1 collection appears, and resolves every `$type: blob` reference plus the
head's `snapshotCid` and `blobCid` against the blobs the publish actually uploaded, so no record points at
a blob that does not exist.

The blob is deliberately not asserted canary-free: the v2 profile publishes packed plaintext, so the payload
is expected to hold the file's bytes and the credential string. The gate instead proves the blob is the
canonical packed payload — the provider returns exactly the published blob size, `VerifyPayload` matches its
CID, and re-packing the decoded snapshot reproduces the stored bytes, so the blob carries no trailing bytes
and no extra members.

Failure cases inject a provider failure at the blob upload, at the record batch, in the modeled
post-blob-processing window, and after the batch commit with a lost response. Each asserts the typed
refusal (`service.ErrPublishMaterial` with its stage and reason), the provider state that remains, the
attempt lifecycle and the unchanged accepted floor, and that no error text carries candidate bytes. The
batch rejection is where the disclosed residual is measured: the plaintext blob is uploaded before its
record batch, so it stays at the provider with no record referencing it, and in the post-processing window
the modeled provider serves it. A scan control injects a canary into a head record through a wrapping test
transport and requires the same scan to report it, so the gate cannot pass by finding nothing.

The retired v1 audit harness is gone; this gate replaces the repository- and blob-surface canary scan,
recursive record-key inventory and publication failure modelling that it provided. All payloads, homes,
credentials and provider state in these cases are synthetic.

Offline command and renderer checks cover the output available without a remote account. The
renderer test checks the per-surface disclosure contract: routine status/read/push/history/export/
recovery/device/administrative output excludes relative entry locators, and the retired v1 candidate
and restore consent renderers are gone with their commands. No retained renderer prints file content or
setting values. Retention output may display local payload or backup references, with absolute
references confined to the state directory.

## Authenticity boundary

There is no archive recovery boundary in this tree. The export/import archive primitives, their
coordinator entry points, their CLI commands and the tests that exercised them were retired with the
v1 product, and this change removed the last of the kit-anchored material they depended on. Nothing
here validates an archive or recovers plaintext from one.

Authenticity is repo-scoped: a published record set is authentic because it lives in the account's
own AT Repository and was written by an authenticated session. Dottie adds no vault signature over a
published position and no offline anchor, so no test can demonstrate offline authorization. Recovery
of published bytes requires a surviving device key and a live provider; losing every device key is
data loss.

## Opt-in live gates

`TestLivePublicationPrivacy` skips by default. It requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1`, an
allowlisted disposable identity in `DOTTIE_HANDLE`, and explicit authorization. Before writing its
manifest or any record, it calls `com.atproto.repo.describeRepo` and skips if the repository has any
collections, so a used account, including one carrying ordinary `app.bsky.*` records, is an
environment limitation for this gate, not a privacy result: this skip precondition is stricter than
the bootstrap preflight, which accepts an account holding other applications' records. The gate
creates synthetic canary records and
attempts cleanup of records. A successful live privacy run leaves its uploaded ciphertext blobs on the
provider permanently because the provider exposes no blob delete; this is expected and recorded in the
run manifest rather than cleaned. The run manifest is written atomically with mode 0600 and records each
unique uploaded blob CID. Every live attempt writes a redacted privacy artifact, including successful
runs; the artifact contains the run id, provider label, audit counts, `retained_set=unobservable`, and the
standing visibility and deletion limits without CIDs or account identifiers.

An owner-authorized read-only observation on a disposable identity found that
`com.atproto.sync.listBlobs` required an authenticated request, while
`com.atproto.repo.listRecords` and `com.atproto.sync.getBlob` were public. That observation applies to
the disposable identity; it is not a protocol guarantee. The observed provider enumerated only live blobs,
so the live retained set is unobservable. These observations do not establish provider compatibility.

A skipped live gate is not provider evidence. Hosted provider logs and server-side storage are not
observable from a client. No real account, provider, desktop session or user dotfiles are used by the
default suite.

The opt-in live publication-and-restore milestone gate and its tagged keyfile twin were deleted with the
retired v1 restore command. Their recorded 2026-11-05 results remain in `docs/acceptance.md` as historical
evidence; no test in this tree reproduces them, and the deleted two-machine pull-apply gate has no
replacement yet.
