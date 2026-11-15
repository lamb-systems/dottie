# Secure manual restore acceptance

**Decision: accepted by the owner on 2026-11-05.** The owner reviewed this evidence matrix, including
its distinction between synthetic and live rows, and accepted the milestone with the residual
limits below. Real-data use of this build is permitted under those limits. Acceptance does not
remove the limits. A future change that invalidates a row must not assume
this acceptance still applies.

> **Retirement note, added 2026-11-15 (v1 kit retirement).** `recover`, `export`, `import`, `prune`,
> `history`, `devices list`, `devices enroll`, `devices revoke`, `account enroll`, `account import-bundle`,
> `account recovery` and `account verify` were removed, together with the v1 encrypted read-and-publish
> engine and its audit harness. The owner retired cross-machine recovery without a live PDS: v2 publication
> replaces it. Rows below that name those commands, kits, archives, retention sweeps, device administration
> or history summaries describe the retired path and are no longer exercised; they are retained unchanged
> as historical evidence and must not be read as coverage of the current tree. In particular the v1
> publication-privacy audit and the live archive gate no longer run, and no v2 equivalent exists yet.
>
> **Kit material removal, added 2026-11-15.** The remaining vault-signing material was removed too:
> `account bootstrap` no longer mints, prints or stores a recovery kit, `internal/vault` no longer
> derives or validates kit signing keys and checkpoints, and the export/onboarding archive primitives
> and their tests were deleted. Authenticity is repo-scoped through AT Protocol account authority;
> Dottie adds no vault signature over a published position and offers no offline anchor. The
> plaintext provider residual recorded below is unchanged and still applies.

> **Retirement note, added 2026-11-15.** `dottie preview` and `dottie restore` were removed with the
> v1 read and apply authority, so the rows below that name `TestRestoreMilestoneOfflineTwoHomeAndRecovery`,
> `TestLiveRestoreMilestoneTwoHome`, `TestRestoreMilestoneGNOMEKeyfileTwoHome` or
> `TestRestoreFromArchiveAppliesOnlyKitCheckpointThroughSharedApply` record the evidence behind the
> 2026-11-05 decision, not coverage of the current tree: those tests no longer exist and the live gate is
> unreproducible. Archive contents can still be validated with `dottie import --archive` but cannot be
> applied by any command. The decision itself is unchanged; a row whose mechanism is gone must not be read
> as coverage of this build.

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

## Settled recovery and restore boundaries

- There is no recovery authority. No offline secret authorizes a root replacement, signs a position or
  restores data; content and publication both require a surviving device key.
- Authenticity is repo-scoped: a record set is authentic for the account that holds it. Dottie makes no
  client-side claim of global freshness, and a provider that withholds later history is not detectable.
- Losing every device key is data loss, and Dottie cannot retrieve bytes the provider no longer holds.
- Freshness-unverified remote state is refused for apply. A freshness-unverified inspection path reports
  a position only; it never grants apply authority.

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

The owner must record explicit acceptance of these boundaries, every matrix result, and the residual limits before real user data is used. Until that acceptance is recorded, do not use Dottie with real dotfiles or preferences.
