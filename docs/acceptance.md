# Secure manual restore acceptance

**Decision: pending owner acceptance. Real-data use remains prohibited until the owner explicitly accepts this document and its evidence matrix.** A passing synthetic test or a skipped live test does not lift that prohibition.

## Requirement evidence matrix

Live evidence was produced on 2026-11-05 against the owner-authorized disposable identity, and the P07
publication audit artifact is retained alongside it. Rows whose evidence kind says synthetic were not
exercised live, and say so.

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

The `DOTTIE_LIVE_MILESTONE=1` gate has now been run once, with outcome `passed`, `content_matched`
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

- The recovery kit authorizes root recovery and signs checkpoints. It does **not** decrypt content. Decryption needs a surviving compatible device recipient private key.
- An independent archive plus that compatible recipient key can recover the archive's checkpoint snapshot without contacting the provider. The archive may not contain the newest provider state. A kit alone, or an archive without a compatible recipient key, cannot recover plaintext.
- Losing every device key without an independent complete export is data loss. A repository CAR is not a complete blob archive.
- Freshness-unverified remote state is refused for apply. The existing consent path permits inspection/export continuation only; it never grants apply authority.
- The live milestone's same-host kit file is an explicitly limited disposable demonstration, not evidence of independent/offline kit custody or machine-loss recovery.

The owner must record explicit acceptance of these boundaries, every matrix result, and the residual limits before real user data is used. Until that acceptance is recorded, do not use Dottie with real dotfiles or preferences.
