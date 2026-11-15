# CLI commands

## Manual coordinator workflows

`dottie status` is local-only and writes nothing. `dottie pull` is the only apply path: it inspects the v2 publication position and applies a reviewed, confirmed plan, described with the push and sync commands below; it never reconciles. Without a vault override, the coordinator commands that act on a selection require exactly one local `(vault, device)` selection; otherwise they refuse and instruct the operator to pass `--vault` (and `--device-id` when needed). Remote reads require a usable local account session; `--did` and `--handle` are mutually exclusive.

`dottie recover` resolves interrupted journal entries without a remote session. There is no other write authority in this CLI: `preview` and `restore` were retired with the v1 read/apply path, so a v1 plan can no longer be inspected or applied from the command line.

Local checkpoint absence, missing predecessor evidence, invalid trust, keyring failures, stale/conflicting/unverifiable checkpoints, pending GNOME approval and unapproved remote keys are fail-closed. Unverifiable freshness is inspection-only; risk consent never authorizes apply. The reader reports PDS revision membership, not global freshness. Checkpoint comparison is separate. The tagged Linux keyfile gate exercises the retained journaled apply engine and the GNOME settings backend against synthetic fixtures only. This evidence is coordinator-level; the foreground CLI/unprivileged execution witness remains part of acceptance review. The historical gate does not constitute live PDS evidence. The CLI surface is described below; the final export and import gate covers the history/export/import coordinator path over synthetic MemoryPDS and does not establish provider compatibility.

`dottie history [--did DID | --handle HANDLE] [--vault HEX] [--device-id ID]` always prints redacted local journal counts by state/stage, the latest journal state/reason and applied-base count/latest timestamp/digest, plus local checkpoint metadata. Without account flags it is local-only and offline. With exactly one account selector it attempts a verified read and prints current head, publication count, policy digest, freshness and checkpoint currency; remote unavailability and authentication expiry are distinct visible states and do not change exit 0. Output contains no content, setting values, absolute paths, tokens or keys. Journal stages are summary reasons, not descriptions of item contents.

`dottie prune --plan (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` reads a verified current/descendant position, uses the locally held checkpoint as the exact epoch/snapshot/policy/control boundary, and reports separate recovery, confidentiality and unknown-holding floors. It prints retained point CIDs/epochs and each payload or backup reference, eligible state and reasons; it does not print file contents or absolute paths. Incomplete inventories, a non-oldest/mismatched boundary or a live head that is not later refuse.

`dottie prune --apply --confirm (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` repeats the verified plan and deletes only currently eligible payloads and aged journal backups. `--apply` without `--confirm` prints the plan and refuses with exit 3 without deleting anything. Plan/no-op and successful apply return 0; usage errors return 2; incomplete inventory, boundary/live-head and confirmation refusals return 3; partial/indeterminate apply returns 4. Pruning is manual foreground work only; there is no scheduler or automatic garbage collection. The retained-point cap bounds selected epochs, not disk usage: staged/orphaned payloads and unknown-epoch leftovers can remain and make the confidentiality floor unknown. The recovery floor is the oldest complete inventory; the confidentiality floor is the oldest surviving known material, including protected backups. A backup bound to a retained point is protected at every age; an aged backup associated with a point evicted below the boundary can be pruned; a bound backup with missing association and legacy unbound backup rows are preserved.

The v1 archive, retention, history and device-administration commands were retired with the v1
product: `export`, `import`, `prune`, `history`, `recover`, `devices *`, `account enroll`,
`account import-bundle`, `account recovery` and `account verify` do not exist. There is no
`--kit-file` flag anywhere in the CLI, and no command reads, writes, renders or stores recovery-kit
material. `account bootstrap` and `account finalize` are the only genesis-time operations that remain,
alongside `account login`, `status` and `logout`.

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

`dottie sync --did DID [--vault HEX] [--confirm TOKEN]` is the reconciled path: it prepares the pull half, prepares
the push candidate from the post-pull state, prints both and one `confirmation:` token that binds the selection
binding, the pull plan digest, the staged accept state token, the observation digest, the provider view digest and
the post-pull push identity (payload digest and size, review selection and approval digests with revisions).
Without `--confirm` it prints and changes nothing. With a matching token it applies and accepts the pull half, then
recomposes the push snapshot from the actual post-pull state and requires the digest set to equal what was printed
before it prepares and submits the push attempt. A pull refusal stops everything before any publication; a push
refusal after a successful pull leaves the files applied and the floor advanced, exits 4 and never partially
submits; a direction conflict refuses at planning and `sync` never chooses a side. The retained push record is
issued and consumed inside the confirmed run, so an unconfirmed sync leaves none. When the pull half has nothing to
do and the floor already matches the provider head, `sync` is a plain push with the same token shape.

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
contains the vault, account DID, absolute paths, tokens or payload bytes. `status`, `history`, `prune`,
`status` and `position status` are the only local inspection commands that remain.

`dottie account bootstrap --vault-name NAME --device-id ID (--did DID | --handle HANDLE)` requires a signed-in account and a verified empty repository. It preflights emptiness before minting device keys, stores root keys in Secret Service, resolves the advertised blob limit and publishes genesis. It mints no recovery kit, prints no secret and flushes nothing before publication; the only failure that can precede publication is the keyring custody step. A verified commit is followed by one coordinator-owned transaction for selection, the root-device-signed epoch-zero checkpoint and full authenticated position evidence including the genesis checkpoint position. A non-empty repository refusal exits 3 before minting; a competing write after preflight can cause a definite refusal, deletes pending keys best-effort, and may leave an unreferenced staged blob. Verified absence after submission also exits 3 and deletes pending keys best-effort. A submitted but unresolved result exits 4, retains keys and prints the six record targets plus inspection instructions; membership verified but final read-back failure is reported as unresolved, not success. Verified commit exits 0 and prints the genesis outcome, vault fingerprint, commit and checkpoint identifiers. No second state store is opened for bootstrap. One account supports one published Dottie vault because genesis requires an empty repository; multi-vault selection refers only to locally recorded vaults. The six published records are authentic because they live in the account's own repository under AT Protocol account authority; Dottie adds no vault signature over that position, no offline anchor and no kit.

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

Live tests skip by default and require explicit authorization for an allowlisted disposable identity. `TestLivePublicationPrivacy` also requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1` and a pristine repository because that gate exercises genesis. `TestLiveArchiveExportAndValidation` requires `DOTTIE_LIVE_ARCHIVE=1`, the allowlisted `DOTTIE_HANDLE`, and a private regular `DOTTIE_RECOVERY_KIT_FILE`; it reads an existing local selection/checkpoint and blocks repository write endpoints. The live two-home publication-and-restore gate was deleted with the retired `restore` command; its 2026-11-05 result remains in `docs/acceptance.md` as historical evidence. A skipped gate is not live or provider evidence; a live artifact records only the measured outcome and residual limits.

Other commands and current implementation status are described in the repository README.
