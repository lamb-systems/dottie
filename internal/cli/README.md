# CLI commands

## Manual coordinator workflows

`dottie status` is local-only. `dottie pull` inspects the v2 publication position and applies a reviewed, confirmed plan, described with the push and sync commands below; it is not the legacy read path and never reconciles. Without a vault override, the manual read, preview, restore and recovery commands require exactly one local `(vault, device)` selection; otherwise they refuse and instruct the operator to pass `--vault` (and `--device-id` when needed). Remote reads require a usable local account session; `--did` and `--handle` are mutually exclusive.

`dottie preview --target ID ...` prints names, action/reason, sizes and a candidate digest, never file contents or GSettings values. The digest covers the verified remote snapshot, local target policy/selection, captured observations, reconciliation decisions and resulting action set. It changes when any same-size candidate content or intended postimage changes. `dottie restore --target ID [--confirm DIGEST] ...` reads and recomputes the candidate before mutation. `backup-only` refuses; `review` requires a matching `--confirm`; `auto-apply` still re-verifies. Apply is limited to current/verified-descendant checkpoints, prepared roots and journaled syncengine operations. Pending journals are recovered before apply. A failed operation reports the applied prefix, failed item and untouched suffix. `dottie recover` runs journal recovery without a remote session.

Local checkpoint absence, missing predecessor evidence, invalid trust, keyring failures, stale/conflicting/unverifiable checkpoints, pending GNOME approval and unapproved remote keys are fail-closed. Unverifiable freshness is inspection-only; risk consent never authorizes apply. The reader reports PDS revision membership, not global freshness. Checkpoint comparison is separate. The tagged Linux keyfile gate exercises the coordinator with real reader authentication and fixture trust, including candidate-bound review refusal and partial/base-record failure reporting, with synthetic fixtures only. This evidence is coordinator-level; the foreground CLI/unprivileged execution witness remains part of acceptance review. The historical gate does not constitute live PDS evidence. The CLI surface is described below; the final export and import gate covers the history/export/import coordinator path over synthetic MemoryPDS and does not establish provider compatibility.

`dottie history [--did DID | --handle HANDLE] [--vault HEX] [--device-id ID]` always prints redacted local journal counts by state/stage, the latest journal state/reason and applied-base count/latest timestamp/digest, plus local checkpoint metadata. Without account flags it is local-only and offline. With exactly one account selector it attempts a verified read and prints current head, publication count, policy digest, freshness and checkpoint currency; remote unavailability and authentication expiry are distinct visible states and do not change exit 0. Output contains no content, setting values, absolute paths, tokens or keys. Journal stages are summary reasons, not descriptions of item contents.

`dottie prune --plan (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` reads a verified current/descendant position, uses the locally held checkpoint as the exact epoch/snapshot/policy/control boundary, and reports separate recovery, confidentiality and unknown-holding floors. It prints retained point CIDs/epochs and each payload or backup reference, eligible state and reasons; it does not print file contents or absolute paths. Incomplete inventories, a non-oldest/mismatched boundary or a live head that is not later refuse.

`dottie prune --apply --confirm (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` repeats the verified plan and deletes only currently eligible payloads and aged journal backups. `--apply` without `--confirm` prints the plan and refuses with exit 3 without deleting anything. Plan/no-op and successful apply return 0; usage errors return 2; incomplete inventory, boundary/live-head and confirmation refusals return 3; partial/indeterminate apply returns 4. Pruning is manual foreground work only; there is no scheduler or automatic garbage collection. The retained-point cap bounds selected epochs, not disk usage: staged/orphaned payloads and unknown-epoch leftovers can remain and make the confidentiality floor unknown. The recovery floor is the oldest complete inventory; the confidentiality floor is the oldest surviving known material, including protected backups. A backup bound to a retained point is protected at every age; an aged backup associated with a point evicted below the boundary can be pruned; a bound backup with missing association and legacy unbound backup rows are preserved.

`dottie export --out FILE --kit-file FILE (--did DID | --handle HANDLE) [--vault HEX] [--anchor HEX] [--overwrite]` calls the coordinator's ciphertext-only complete-closure writer. An omitted export anchor is taken from the selected local checkpoint; a supplied anchor must match it. The coordinator checks the output against selected roots and writes it atomically with mode 0600. It refuses an existing output unless `--overwrite` is explicit; overwrite is limited to regular files, never symlinks. `--kit-file` must be a regular non-symlink file with group/world permissions removed and contain the grouped recovery-kit text decoding to exactly 32 bytes. The kit is cleared from command buffers, never echoed, and never stored or archived. Success reports positions, unique snapshot blobs and omissions; export either writes the complete required closure or refuses (exit 3), not a partial file (exit 4).

Export and onboarding fetch required snapshot bodies by CID through the verified remote reader. Missing bodies refuse rather than being inferred from position evidence. Export completeness depends on the authenticated history the exporting machine has retained. A device that received only an onboarding bundle and has not observed required prior publication heads can refuse export; no missing head is synthesized. Required missing records/blobs and missing local lineage refuse without publishing an archive. Version-1 count-only attestations with nonzero retained-point counts cannot be enumerated and therefore refuse export. This is an explicit limitation, not an optional omission.

`dottie import --archive FILE --kit-file FILE --anchor HEX --vault HEX` is validation-only. The vault, anchor and kit are independently supplied; neither expected identity is inferred from the archive or local selection. Import reads the archive, validates it in the defined refusal order, reports contained positions/omissions and refuses wrong identities, unsupported versions, wrong kits or corruption. It changes no state, configuration, target, preference or applied base. Validation does not decrypt contents or establish global freshness. Import has no success-with-partial state.

`dottie restore --archive FILE --kit-file FILE --anchor HEX --target ID [--vault HEX] [--device-id ID] [--confirm DIGEST]` restores files from an archive offline. `--archive` is mutually exclusive with `--did`/`--handle`; kit and anchor require archive mode. The expected vault defaults to the local selection, while the anchor and kit are explicit. Restore validates the archive and opens the kit-signed checkpoint position with the selected device recipient private key from Secret Service. Only that checkpoint epoch is eligible: positions above it are lineage, the archive may not be the newest state, and no provider/session transport is constructed or contacted. A kit authorizes/checks the checkpoint but cannot decrypt content; without a compatible surviving recipient private key restore refuses. The archive path uses the same preview/candidate digest, review-mode confirmation, journaled apply and rollback path as remote restore. It does not relax freshness-unverified inspection-only policy.

For `history`, `export` and `import`, exit 0 means the read/validation or export succeeded (history still succeeds when its optional remote read is unavailable), exit 2 is a usage error, and exit 3 is a refusal. Exit 4 remains for partial/indeterminate push and device operations; export refuses rather than publishing an incomplete archive.

## Publication position status

`dottie position status --did DID --vault HEX` inspects the local publication position store under
`$XDG_STATE_HOME/dottie/publication-state` and prints exactly one line: `position: revision=N generation=N
provenance=first|replace sequence=N`, or `position: empty` when the store is recognized but holds no accepted
floor. Inspection is read-only: it never creates, upgrades, repairs, unlinks or checkpoints anything, and it never
takes the store's lifetime lock. It refuses an absent store (`position_absent`), a directory that is not an owned
`0700` non-symlink directory, a foreign binding, a schema that is not the current schema 3 (`upgrade_required` for
schema 1 and 2), a store whose lifetime lock is held by a running writer (`locked`), and a store whose WAL still
holds uncheckpointed frames (`io`) instead of reporting a floor that may not be current. The lock probe is shared and momentary, so two inspections never refuse each other, but a writer that
loses the race to it refuses `locked` and is safe to retry. Reads use a read-only
immutable connection, so a writer that acquires the store after the lock probe can make the reported floor older
than the newest committed floor; that staleness is bounded to the accepted floor and is disclosed here rather than
hidden. Output never contains the account DID, vault, binding, repository, CIDs, absolute paths, directory names,
counts, tokens or payload bytes. Refusals exit 3 with the redacted class/stage/reason string; exit 2 is usage only
and this command never exits 4.

## Push, sync, devices and onboarding

`dottie push --did DID [--vault HEX] [--device-id ID] [--confirm HEX]` publishes the reconciled
snapshot of every configured target through the v2 publication profile. It is a two-invocation command.
The first invocation acquires the stored account session for `--did`, validates that the grant covers the
v2 publication collections before any discovery or provider contact, composes exactly one candidate from
the local capture plus the accepted position and the observed head, and prepares a proposal. It prints a
summary — target and entry counts, the accepted floor, the candidate record and payload CIDs and the
review digests and revisions — and a `confirmation:` line holding the 32-byte store confirmation in hex.
It publishes nothing and exits 3 so the operator can review. The summary never contains entry content,
setting values, absolute paths or the vault fingerprint.

`dottie push --did DID --confirm HEX` repeats the same preparation and compares the freshly computed
confirmation with the supplied value. Equality publishes exactly that proposal and prints the accepted
floor; a difference is a stale proposal, exits 3 and dispatches nothing, and the retained proposal is
left untouched so an unchanged re-run still works. Any difference in the candidate, the view context, the
store database identity or generation, the state token, the attempt identity or the review identity
produces a different confirmation and refuses the old value. `--confirm` is the same flag and meaning the
other destructive commands use; there is no second token.

The service owns the retained proposal at `$XDG_STATE_HOME/dottie/publication-state/proposal-<id>.json`:
it is written with mode 0600, it is marked consumed before the first durable publication write, and it is
deleted only after the attempt reaches a terminal state. The command reads it and never rewrites it. A
consumed record refuses `--confirm` with the instruction to re-run `dottie push` without `--confirm`; an
attempt that has not passed submission is abandoned automatically during the failed run, so the next run
prepares cleanly without an extra flag; a proposal whose planned attempt identity is
already retired refuses as stale and marks the record consumed; and a creation that reports
`commit_unknown` keeps the record and exits 4 instead of inferring absence.

Exit codes: 0 committed or no-op, 2 usage (missing or invalid flags, malformed confirmation), 3 refusal
(session or scope, unusable or consumed or foreign or stale proposal, config drift before submission,
store mismatch), 4 partial or indeterminate (unresolved submission, commit-unknown,
queued/starved/fence-lost/unavailable outcomes, and a rendering failure after a committed publication,
which is stated as committed on stderr).
A queued or indeterminate publication is never reported as success. The command requires an already
provisioned v2 position store; an absent store refuses with exit 3 and no substitute setup path is
offered, because the legacy bootstrap creates v1 material that the v2 profile rejects.

`dottie sync` refuses. The reconciled pull-then-push path needs a crash-safe v2 apply journal, which is the
open owner decision D11; `sync` prints a typed refusal naming D11, contacts no provider and never reaches the
legacy orchestration. Downloads are reviewed with `preview` and applied with `restore`.

`dottie pull --did DID --vault HEX` is a read-only inspection of the v2 publication position. It acquires the
stored account session and validates the publication scope before any discovery or provider contact, takes the
vault from `--vault` instead of resolving a v1 selection, refuses `--handle` for the same reason `push` does, and
compares the provider's validated view with the locally recorded accepted floor. It prints exactly one line:
`pull: matches`; `pull: absent` when the provider holds no v2 records; `pull: diverges (record_cid)` or
`pull: diverges (payload_size)`; or `pull: unreadable (reason)` with the typed reason (`position_absent`,
`floor_absent`, `binding`, `locked`, `io`, `schema`, `upgrade_required`, `corrupt`, `record` or the reader's view
reason). The comparison reads the position through the authenticated `PublicationReader.ReadView` and the local
floor through the immutable `publicationstate.Inspect`: the comparison never opens the position store, never takes
its lifetime lock, never fetches the payload blob, applies and reconciles nothing, establishes no base and writes
no file, row or WAL.

After the comparison, `pull` composes the apply plan for the configured files targets from the authenticated base
snapshot at the accepted floor and the provider's terminal view. It never applies without confirmation: a
non-empty plan is printed with a `confirmation:` token, and `--confirm TOKEN` repeats the run with that token to
apply it. Before printing, `pull` stages the acceptance for the material the plan was built from and binds the
selection binding, the plan digest, the staged acceptance state token and the observation digest into the token, so
a changed plan, a different vault, a moved provider observation or a moved local position refuses instead of
applying or accepting something that was not shown. An empty plan and an `absent` position apply and accept
nothing and exit 0. Applying goes through the same journal, admission, apply lease, containment, captured preimage
and backup-only refusals the engine enforces, and a backup-only selection always refuses to apply.

A confirmed run applies the plan first and accepts the material second, never one transaction for both. After a
fully applied plan it re-validates that the accepted floor revision is still the one the plan used, then accepts
the applied material into the position store with mode `advance` when a floor exists and `first-use` only when the
store reports none; a replacement floor is never offered by `pull`. The run prints the new `floor:` revision, so
the next `pull` reports `matches` instead of re-planning the same apply. A refusal at accept leaves the applied
files and the unchanged floor behind, prints `pull: applied but not accepted` with the typed reason and exits 3; an
accept whose outcome cannot be proven exits 4 without claiming success. Exit 2 is usage, exit 3 is a local refusal
(unusable store, unusable plan, backup-only, lease held, unusable acceptance) and exit 4 is an indeterminate
provider read or an unproven acceptance. `pull` takes `--did`, optional `--vault` and `--confirm`; no other flag is
new.

Divergence is a finding, not a failure, so a completed comparison exits 0; exit 2 is usage,
exit 3 is refusal (session, scope, account or store binding mismatch, unusable local store, no accepted floor,
unreadable or invalid position, invalid provider view) and exit 4 is an indeterminate provider read. Output never
contains the vault, account DID, absolute paths, tokens or payload bytes. `restore`, `preview`, `status`,
`history`, `prune`, `recover`, the export/import commands and the device commands keep their existing paths.

`dottie devices list (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` uses a verified read and lists device ID, role, current epoch, revoked status and a SHA-256 fingerprint of the public recipient key when present. It does not print keys, secrets or absolute paths.

On the newcomer, `dottie account enroll --vault HEX --device-id ID --role publisher|restore_only [--confirm HEX] [--request FILE]` retains the transcript-fingerprint confirmation. After confirmation it can write a versioned JSON request containing only vault, device ID, key ID, signing and recipient public keys, requested role and the approval fingerprint. It does not put private keys in the request. Transfer that file to the administrative device. On the administrative/root device, `dottie devices enroll --request FILE --kit-file FILE --bundle-out FILE (--did DID | --handle HANDLE) [--vault HEX] [--root-device-id ID] [--overwrite]` passes the verified public request and kit to the coordinator. It writes the resulting public onboarding bundle and prints approval/checkpoint fingerprints. Existing bundle outputs are refused unless `--overwrite` is explicit.

`dottie devices revoke --device-id ID --kit-file FILE [--confirm HEX] (--did DID | --handle HANDLE) [--vault HEX] [--root-device-id ID] [--bundle-out FILE] [--overwrite]` requires the coordinator to verify the local administrative root. Without `--confirm`, it performs only a verified read and prints an approval transcript bound to vault, device ID, role, public-key fingerprints, current/successor epochs and recovery-kit signing-key fingerprint; it makes no transition and exits nonzero with the exact repeat command. With confirmation it recomputes the transcript, refuses a mismatch, then asks the coordinator to compare the expected fingerprint against its own fresh verified read before any transition. Success reports the successor epoch/checkpoint and states that revocation cannot erase historical ciphertext or keys already obtained. The optional bundle is public.

Recovery-kit files must be regular files containing the existing grouped recovery-kit text, decode to exactly 32 bytes, and must not be group/world-readable. Restrict a saved kit with `chmod 600 FILE`. Dottie never echoes the kit, stores it in state/config/keyring, or transfers it in an onboarding bundle; command buffers are cleared after use. The coordinator refuses wrong kits and non-root/restore-only administrators.

On a newcomer, `dottie account import-bundle --bundle FILE --anchor HEX [--vault HEX]` requires an independently supplied root fingerprint; the anchor is never inferred from the bundle. This is separate from `dottie import`, which validates a ciphertext export archive and mutates nothing. Onboarding-bundle import transactionally persists the selection, checkpoint and authenticated predecessor evidence. The first subsequent pull authenticates the chain. It does not apply downloaded data. The S2 two-machine gate is a coordinator-level synthetic integration proof, not an execution of the full onboarding CLI sequence. The S3 gate adds coordinator export/import evidence and runs the local history command; full export/import CLI-binary acceptance remains subject to review. Neither gate establishes live PDS compatibility.

`dottie account bootstrap --vault-name NAME --device-id ID (--did DID | --handle HANDLE)` requires a signed-in account and a verified empty repository. It preflights emptiness before minting the recovery kit or device keys, stores root keys in Secret Service, prints and flushes the kit exactly once before publication, then resolves the advertised blob limit and publishes genesis. A verified commit is followed by one coordinator-owned transaction for selection, the kit-signed epoch-zero checkpoint and full authenticated position evidence including the genesis checkpoint position. The kit is never written to state, keyring, logs or artifacts. A non-empty repository refusal exits 3 before minting; a competing write after preflight can cause a definite refusal after kit delivery, deletes pending keys best-effort, and may leave an unreferenced staged blob. Verified absence after submission also exits 3 and deletes pending keys best-effort. A submitted but unresolved result exits 4, retains keys and prints the six record targets plus inspection instructions; membership verified but final read-back failure is reported as unresolved, not success. Verified commit exits 0. No second state store is opened for bootstrap. One account supports one published Dottie vault because genesis requires an empty repository; multi-vault selection refers only to locally recorded vaults.

`dottie plan --from FILE [--json]` renders a preview from one explicit JSON bundle. `--from` is
required: there is no implicit local view, target scan, state lookup or capture step. The bundle
provides input for a later capture/state task. Rendering a supplied bundle does not mean capture
or synchronization is implemented.

The version-1 JSON object requires all of these fields, including arrays that may be empty:

| Field | Meaning |
| --- | --- |
| `version` | Integer `1` |
| `base_status` | `known`, `missing` or `stale` |
| `targets` | Array of `model.Target` definitions |
| `base` | Array of `model.Entry` values in the base view |
| `observations` | Array of validated `model.Observation` values |
| `remote` | Array of `model.Entry` values in the current remote view |
| `coverage` | Target IDs whose local subtree was completely observed |

The command uses the model JSON field names as-is. Go's JSON encoding of `[]byte`
base64-encodes regular-file `content` fields. A present observation must include its matching entry; a missing,
unknown or untracked observation must not include one. Base and remote entries are supplied
separately; the command never assumes that remote equals base. Unknown fields, invalid model
entries, duplicate identities, missing required fields, trailing JSON values and unsupported
bundle versions are rejected. The command parses the input as data only: it never opens or scans paths inside it
or treats them as authority to access a target.

The reconciler remains the decision source. Preview entries are ordered by target ID and item
identity. Reconcile upload/download decisions become create/change as appropriate, delete
decisions become delete, and untracked observations are shown as create. Unknown is a separate
state and never an action. Conflicts and missing observations remain distinct outcomes and reason
codes. The v1 model cannot express a reset observation: `ObservationPresent` rejects a
`SettingReset` entry, so reset is not a preview action yet. Unsupported file kinds are rejected
before reconciliation returns a decision; unsupported is therefore not a v1 preview outcome.
Unapplied is journal state for a later task and is not represented here.

Per-entry `size` counts transfer payload bytes, and per-entry `resulting_snapshot_bytes` counts
its contribution to the currently resolvable present entries. Both use `vault.Estimate`. The plan
also reports `transfer_bytes` for create/change entries that would move and
`resulting_snapshot_bytes` for resolved present entries including unchanged ones; deletes add no
payload. `complete` is false when a conflict, unknown item or unmatched entry remains, and
`unresolved_entries` gives the count. In that case the text output says `resulting snapshot at
least N bytes, incomplete: M unresolved`; this is an estimate over known resolved entries, not a
constructed candidate snapshot or a promise about the remote. When complete, text output labels
the resulting snapshot estimate complete. Preimages are emitted only when the local observation
has an entry; they contain its digest and mode, not its content. Missing and unknown observations
have no fabricated preimage.

Text output escapes terminal control characters in target IDs and item names. JSON output uses
JSON string escaping. Both output formats contain names, actions, states, reason metadata, sizes
and preimage metadata only; they never emit file contents or GSettings values. The command reads
the specified bundle and writes stdout only. It does not write state, mutate targets, inspect a
PDS account or make network calls.

## Account authorization commands

`dottie account login --handle HANDLE [--no-browser] [--timeout DURATION]` performs OAuth discovery,
PAR/PKCE loopback callback handling, strict scope validation and one-item Secret Service persistence. It
requests `atproto`, all seven `repo:systems.lamb.dottie.*` scopes and
`blob:application/octet-stream`. The default callback timeout is five minutes; `--timeout` accepts 1s
through 15m. Login prints the authorization URL and non-secret discovered identifiers before opening
`xdg-open`. Browser-start failure is a warning: the user can still use the printed URL. `--no-browser`
skips browser launch. Successful output prints granted scopes and exact `status --did` and `logout --did`
follow-up commands; codes, access/refresh tokens and DPoP keys are never printed. If the keyring write is
attempted but its reply is lost, login reports the persistence outcome as uncertain and points to status and
local logout; it does not claim that nothing was stored. A busy session lock is reported as busy, not as an
uncertain write. For `status --refresh`, the same uncertainty means the final save may have applied; run status
again to see whether the item is usable.

`dottie account status --did DID` reads the stored non-secret status offline. It prints only state, handle,
DID, issuer, token endpoint, scopes and whether a refresh token is present. `--handle HANDLE` performs
read-only discovery to resolve the DID. `--refresh` is explicit and uses the same serialized refresh path;
it does not open or modify the state database. A pending refresh is displayed as interrupted and requires
login. Busy locks, keyring failures, relocation and provider rejection produce actionable errors that say
pending local changes are preserved.

`dottie account logout --did DID` removes the local item under the session lock without decoding it, so it
works for corrupt, unknown-version and pending envelopes. `--handle HANDLE` resolves the DID first.
`--remote` also requires a usable session, discovered binding and advertised revocation endpoint;
local deletion follows only a 2xx response. Output says the revocation request was accepted and warns that
previously issued access tokens may remain valid until expiry. An accepted remote request with failed local
delete is reported as a split outcome. `--did` is the offline local logout path.

These commands only manage account authorization. They do not publish or read vault records, touch target
data, or interact with the state database. All command tests use synthetic OAuth endpoints and temporary
stores; live accounts, browser launches and Secret Service are not exercised.

## Live integration gates

Live tests skip by default and require explicit authorization for an allowlisted disposable identity. `TestLivePublicationPrivacy` also requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1` and a pristine repository because that gate exercises genesis. `TestLiveArchiveExportAndValidation` requires `DOTTIE_LIVE_ARCHIVE=1`, the allowlisted `DOTTIE_HANDLE`, and a private regular `DOTTIE_RECOVERY_KIT_FILE`; it reads an existing local selection/checkpoint and blocks repository write endpoints. `TestLiveRestoreMilestoneTwoHome` requires `DOTTIE_LIVE_MILESTONE=1`, the allowlisted handle, a private kit file that authenticates the held checkpoint, existing local root trust/device keys and an already-readable Dottie vault whose current snapshot contains no application entries. It never invokes genesis, uses temporary homes and synthetic content, publishes one snapshot plus one restore-only enrollment, blocks any other write endpoint, and never deletes repository records. The redacted artifact is written under `DOTTIE_LIVE_ARTIFACT_DIR` (or a temporary artifact directory). Provider records and uploaded ciphertext blobs remain after the live restore run, including a public enrollment for an ephemeral test device whose private key is not retained. A skipped gate is not live or provider evidence; a live artifact records only the measured outcome and residual limits.

Other commands and current implementation status are described in the repository README.
