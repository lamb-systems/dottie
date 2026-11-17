# Acceptance record

What has actually been measured, what has not, and what the owner has accepted. If a claim in the
README is not backed by something here, treat it as unverified.

## Current decision

v2 publication has been run against a real provider from two independent installs, and the evidence
is below. Using it on real dotfiles still requires an explicit owner decision, which has not been
recorded. The 2026-11-05 acceptance covered the v1 build; that build's commands no longer exist and
its permission does not carry over.

## Live v2 publication run (2026-11-16)

Run by the owner against a disposable account (`dottiethrowaway.bsky.social`) in disposable homes with synthetic
content. It is the first observation of the v2 path against a real provider; it is not a re-run of the 2026-11-05
milestone, which described the retired v1 path.

Observed, in one session:

- `account login` granting `atproto`, `blob:application/octet-stream`, and `repo:systems.lamb.dottie.vaultHead`,
  `vaultSnapshot`, `vaultPolicy`, `vaultControl`, `vaultCertificate`, `vaultCheckpoint`, `vaultAttestation`,
  `vaultHeadV2` and `vaultSnapshotV2`.
- `account bootstrap` refusing a used repository, then succeeding once the preflight was narrowed to "no existing
  Dottie publication"; it wrote no repository record and recorded only the local vault selection.
- `push` preparing a retained proposal, printing its confirmation, and `push --confirm` publishing it:
  `floor: revision=1 generation=1 sequence=0`, `push: committed`.
- `pull` reporting `pull: matches` against that publication, and a subsequent `push` reporting `push: no-op`.
- A fresh home resolving the vault from the published `vaultHeadV2` record instead of requiring `--vault`, and
  planning a first-use join of two files without applying anything until confirmed.
- `push` and `pull` succeeding **from both homes**, so each side both published and consumed the other's position and
  each advanced its own accepted floor. This is the first two-machine observation of the v2 profile.

What the run proved: the blob upload, the record batch, the view validation, the accepted-floor readback and the
consent token all behave against a real PDS as the in-memory provider models them, once six provider-behaviour
differences were corrected (blob media-type canonicalisation, the record's declared media type, the record-batch
rejection classification, the preflight's emptiness rule, first-use provisioning of the position store, and selection
of a retained proposal alongside a consumed one).

The two directions were then repeated, each side pulling what the other had just published.

What it did not prove, and must not be read as proving:

- Both homes ran on one physical machine. "Two machines" here means two independent installs: separate state
  stores, position stores, journals and configurations. It does not exercise two hosts, concurrent operation, clock
  skew, or a network interruption mid-apply.
- The confirmed join was observed once per direction. It does not establish behaviour under repeated concurrent
  publication from both sides, which remains refused rather than reconciled.
- It says nothing about power-loss durability, provider-side at-most-once effects, hidden provider logs, or
  server-side retention.
- Provider blobs cannot be deleted. Rejected attempts uploaded real payloads that remain retrievable by CID while
  unreferenced, which is the residual above in practice, not a theoretical case.
- One account, one day, synthetic content. A skipped or single observation is not a general claim about provider
  behaviour.

The owner must record explicit acceptance of these boundaries, every matrix result, and the residual limits before real user data is used. Until that acceptance is recorded, do not use Dottie with real dotfiles or preferences.

## Measured provider behaviour

These came from live runs against real providers, not from the in-memory test double. Each one
changed code; they are recorded here because a future reader will otherwise assume the double
models the provider.

- **Blob media types are canonicalised.** A provider sniffs the uploaded bytes and reports the type
  it derived, not the one you declared. `vault.Pack` emits a USTAR archive, so the provider reports
  `application/x-tar` even though the upload declares `application/octet-stream`. The v2 snapshot
  record therefore declares `application/x-tar`, and publication verifies the provider's report
  against the sealed record and refuses locally on a mismatch. Earlier the record declared
  `octet-stream` while the bytes were a tar archive, and `applyWrites` refused it with
  `400 InvalidMimeType`.
- **Uploading a blob does not make it public.** A batch rejected *after* blob processing leaves the
  referenced blob retrievable by CID while no record points at it; a blob that was never referenced
  stays refused. A fence lost to `InvalidSwap` is checked before blob processing and does not expose
  the candidate. Every post-submission failure except a lost fence is therefore treated as possible
  disclosure of the staged bytes.
- **`atproto` is a required base scope**, not an alternative to granular `repo:` and `blob:`
  scopes. `bsky.social` answers a granular-only request with
  `invalid_scope: The "atproto" scope is required`. The client requests the base scope plus its
  collections and records the granted set rather than assuming it.
- **The authorization server's `scopes_supported` is informational.** It advertises `atproto` and
  the `transition:*` family while granting the granular scopes a client asks for, so a client that
  validated that list against its own grammar would refuse to start.
- **A used repository is not a hostile repository.** Every account any client has opened carries
  `app.bsky.actor.profile`, so the bootstrap preflight refuses only an existing Dottie
  publication, not any record at all.
- **The keyring must be the default collection.** `gnome-keyring` refuses a custom alias with
  `Only the 'default' alias is supported`, and relabelling the user's login keyring is not an
  acceptable side effect. Session items are identified by attribute instead.

## Plaintext v2 publication residual (accepted by the owner 2026-11-14)

The plaintext v2 profile uploads the packed snapshot payload before it attempts the atomic
snapshot-reference and head record batch. The provider therefore holds the payload before any record
references it, and a rejected, refused or ambiguous batch can leave an unattached plaintext blob that
remains retrievable at the provider and cannot be deleted through Dottie.

Dottie itself never exposes candidate bytes for a publication that did not succeed: no command, log,
error, report or archive surfaces them, and the local accepted position does not advance. The residual
is provider-side only. It is accepted as a recorded limit for the plaintext model; the equivalent
encrypted-v1 exposure was ciphertext, and no v2 profile change re-introduces an envelope.

Owner acceptance of this residual is what permits the plaintext v2 write path to be implemented. It does
not authorize any live provider run, which still requires explicit disposable-account authorization.

## Historical: the 2026-11-05 v1 acceptance

The owner reviewed and accepted the v1 evidence matrix on 2026-11-05, and real-data use of that
build was permitted under its limits. That build has since been retired: `preview`, `restore`,
`recover`, `export`, `import`, `prune`, `history`, `devices *`, `account enroll`,
`account import-bundle`, `account recovery` and `account verify` were removed, along with vault
signing, the recovery kit, the encrypted read-and-publish engine and the v1 apply engine.

The matrix is kept as the record of what was measured then. Rows naming deleted tests or commands
are history, not coverage of this tree. In particular the v1 publication-privacy audit and the live
archive gate no longer run and have no live v2 replacement.

## Requirement evidence matrix

Live evidence comes from the 2026-11-05 runs against the owner-authorized disposable identity. The P07
publication audit artifact is retained alongside that evidence. Rows marked synthetic were not
exercised live; the matrix identifies them as such.

| Requirement | Evidence kind | Exact command or test name | Artifact | Residual limit |
| --- | --- | --- | --- | --- |
| Trust chain | synthetic and live | `TestRestoreMilestoneOfflineTwoHomeAndRecovery`; `TestLiveRestoreMilestoneTwoHome` | Test output; live `restore-milestone.json` | Live row used the operator's existing vault, checkpoint, Secret Service device key and session; it does not prove kit custody independent of the machine, and the enrollment record for an ephemeral device remains on the provider |
| Publication fence and ordering | synthetic and live | `TestPublishSnapshotFencedKeepsAllPackReferencesInsideOneBatch`; `TestRestoreMilestoneOfflineTwoHomeAndRecovery`; `TestLiveRestoreMilestoneTwoHome` | Test output; live `restore-milestone.json` write counts | The live run observed one `applyWrites` per publication and per enrollment with a swap commit; it does not prove provider-side at-most-once effects, hidden logs or staged-blob visibility |
| Checkpoint-backed restore | synthetic, native and live | `TestRestoreMilestoneOfflineTwoHomeAndRecovery`; `make test-gnome` (`TestRestoreMilestoneGNOMEKeyfileTwoHome`); `TestLiveRestoreMilestoneTwoHome` | Test output; live `restore-milestone.json` with `content_matched` and applied counts | Live row restored into temporary prepared directories with synthetic content and read it back; it does not exercise a real desktop profile or real user data |
| Freshness-unverified refusal and consented inspection | synthetic | `TestRestoreMilestoneOfflineTwoHomeAndRecovery` | Test output; no persistent artifact | Refusal and inspection-only consent proved in the fixture only; the live gate does not construct an unverifiable floor, and consent never applies data |
| Archive restore without the provider | synthetic | `TestRestoreFromArchiveAppliesOnlyKitCheckpointThroughSharedApply`; `TestRestoreMilestoneOfflineTwoHomeAndRecovery` | Test output; the integration test removes its temporary archive | Applies only the kit-signed checkpoint position; the archive may not be newest and a compatible retained recipient private key is required |
| Rollback preserving newer edits | synthetic | `TestRestoreMilestoneOfflineTwoHomeAndRecovery` | Test output; temporary home and journal removed by the test | Production rollback path in a temporary home; not evidence of recovery from hardware or filesystem failure |
| Metadata disclosure | synthetic and live | `TestPublicationMetadataDisclosure`; `TestLivePublicationPrivacy` | Test output; live `publication-privacy.json` | Inspects repository and blob surfaces the client can fetch; provider logs and server-side retention remain unobservable, and provider blobs cannot be deleted |
| Security gate V08 | synthetic | `make known-defects` | Command output | Frozen known-defect inventories do not replace independent security review |

The `DOTTIE_LIVE_MILESTONE=1` gate has run once, with outcome `passed`, `content_matched`
true, position epoch 1, and exactly two `applyWrites` and two `uploadBlob` calls (one publication and
one enrollment). It requires an allowlisted `DOTTIE_HANDLE`, a private regular
`DOTTIE_RECOVERY_KIT_FILE`, an existing local vault selection with checkpoint and authenticated
evidence, a root device key in Secret Service, an authorized account session, an advertised blob
limit, and a live repository that authenticates as that vault with an empty current snapshot. It
refuses to bootstrap, refuses an absent or foreign vault, blocks every endpoint except `uploadBlob`
and `applyWrites`, and deletes nothing. Its records and ciphertext remain on the provider, including
an enrollment for an ephemeral restore-only device whose private key was not retained. A second run
against the same vault refuses by design because the current snapshot now carries application
content. A skipped gate would not have been evidence.

## Settled boundaries

- Authenticity is repo-scoped. A record set is authentic for the account that holds it, because
  writing to that repository requires an authenticated session. Dottie adds no signature of its
  own over a published position.
- There is no global freshness guarantee. A provider that withholds later history cannot be
  detected from the client side.
- Losing this machine's Dottie keys is not losing the data. The account session can read the
  published plaintext back; the provider is the only copy Dottie knows about, so a provider that
  loses it loses it.
- Freshness-unverified remote state is refused for apply. An inspection path may report a position;
  it never grants apply authority.
- Conflict resolution is manual. Pull names the conflicting files and applies nothing.

Until the owner records the v2 decision above, do not point Dottie at real dotfiles.
