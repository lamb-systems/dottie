# CLI commands

## Manual coordinator workflows

`dottie status` is local-only. `dottie pull (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` reads a verified repository revision, checks it against the locally recorded trust checkpoint and persists authenticated read evidence. It does not publish. If no vault override is supplied, exactly one local `(vault, device)` selection must exist; otherwise the command refuses and instructs the operator to pass `--vault` (and `--device-id` when needed). Remote reads require a usable local account session; `--did` and `--handle` are mutually exclusive.

`dottie preview --target ID ...` prints names, action/reason, sizes and a candidate digest, never file contents or GSettings values. The digest covers the verified remote snapshot, local target policy/selection, captured observations, reconciliation decisions and resulting action set. It changes when any same-size candidate content or intended postimage changes. `dottie restore --target ID [--confirm DIGEST] ...` reads and recomputes the candidate before mutation. `backup-only` refuses; `review` requires a matching `--confirm`; `auto-apply` still re-verifies. Apply is limited to current/verified-descendant checkpoints, prepared roots and journaled syncengine operations. Pending journals are recovered before apply. A failed operation reports the applied prefix, failed item and untouched suffix. `dottie recover` runs journal recovery without a remote session.

Local checkpoint absence, missing predecessor evidence, invalid trust, keyring failures, stale/conflicting/unverifiable checkpoints, pending GNOME approval and unapproved remote keys are fail-closed. Unverifiable freshness is inspection-only; risk consent never authorizes apply. The underlying reader reports PDS revision membership rather than global freshness, so checkpoint comparison is separate. The tagged Linux keyfile S1 gate exercises the coordinator with real reader authentication and fixture trust, including candidate-bound review refusal and partial/base-record failure reporting, with synthetic fixtures only. S1b evidence is coordinator-level; the foreground CLI/unprivileged execution witness remains part of acceptance review. The S1 historical gate does not constitute live PDS evidence. The S2 CLI surface is described below; the final S3 gate covers the history/export/import coordinator path over synthetic MemoryPDS and does not establish provider compatibility.

`dottie history [--did DID | --handle HANDLE] [--vault HEX] [--device-id ID]` always prints redacted local journal counts by state/stage, the latest journal state/reason and applied-base count/latest timestamp/digest, plus local checkpoint metadata. Without account flags it is local-only and offline. With exactly one account selector it attempts a verified read and prints current head, publication count, policy digest, freshness and checkpoint currency; remote unavailability and authentication expiry are distinct visible states and do not change exit 0. Output contains no content, setting values, absolute paths, tokens or keys. Journal stages are summary reasons, not descriptions of item contents.

`dottie export --out FILE --kit-file FILE (--did DID | --handle HANDLE) [--vault HEX] [--anchor HEX] [--overwrite]` calls the coordinator's ciphertext-only complete-closure writer. An omitted export anchor is taken from the selected local checkpoint; a supplied anchor must match it. Output is atomic, mode 0600, and checked against selected roots by the coordinator. An existing output is refused unless `--overwrite` is explicit; overwrite is limited to regular files, never symlinks. `--kit-file` must be a regular non-symlink file with group/world permissions removed and contain the grouped recovery-kit text decoding to exactly 32 bytes. The kit is cleared from command buffers, never echoed, and never stored or archived. Success reports positions, unique snapshot blobs and omissions; export either writes the complete required closure or refuses (exit 3), not a partial file (exit 4).

Export completeness is bounded by the authenticated history retained on the exporting machine. A device that received only an onboarding bundle and has not observed required prior publication heads can refuse export; no missing head is synthesized. Required missing records/blobs and missing local lineage refuse without publishing an archive. Version-1 count-only attestations with nonzero retained-point counts cannot be enumerated and therefore refuse export. This is an explicit limitation, not an optional omission.

`dottie import --archive FILE --kit-file FILE --anchor HEX --vault HEX` is validation-only. The vault, anchor and kit are independently supplied; neither expected identity is inferred from the archive or local selection. Import reads the archive, validates it in V06 order, reports contained positions/omissions and refuses wrong identities, unsupported versions, wrong kits or corruption. It changes no state, configuration, target, preference or applied base. Validation does not decrypt contents or establish global freshness. Import has no success-with-partial state.

For `history`, `export` and `import`, exit 0 means the read/validation or export succeeded (history still succeeds when its optional remote read is unavailable), exit 2 is a usage error, and exit 3 is a refusal. Exit 4 remains for partial/indeterminate push, sync and device operations; export refuses rather than publishing an incomplete archive.

## Push, sync, devices and onboarding

`dottie push (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` asks the coordinator to verify the current remote position, reconcile all selected local targets, and publish local changes through the fenced publisher. The output distinguishes committed, no-op, queued, starved, fence-lost, superseded, unavailable, rejected, conflicted and base-recording-failed outcomes. Only committed and no-op return exit 0. Exit 2 is a usage error, exit 3 is a refusal/conflict/rejection, and exit 4 is queued, starved, fence-lost, superseded, unavailable or another partial/non-success outcome. An uncertain or queued result is never reported as success. Output contains status only, not entry content, values or paths.

`dottie sync` performs a verified pull and then push as one foreground operation. It reports verified remote entries as pending explicit restore review and does not apply downloaded files or settings. `pull`, `push` and `sync` never apply downloads implicitly; inspect with `preview` and use `restore` explicitly.

`dottie devices list (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]` uses a verified read and lists device ID, role, current epoch, revoked status and a SHA-256 fingerprint of the public recipient key when present. It does not print keys, secrets or absolute paths.

On the newcomer, `dottie account enroll --vault HEX --device-id ID --role publisher|restore_only [--confirm HEX] [--request FILE]` retains the transcript-fingerprint confirmation. After confirmation it can write a versioned JSON request containing only vault, device ID, key ID, signing and recipient public keys, requested role and the approval fingerprint. It does not put private keys in the request. Transfer that file to the administrative device. On the administrative/root device, `dottie devices enroll --request FILE --kit-file FILE --bundle-out FILE (--did DID | --handle HANDLE) [--vault HEX] [--root-device-id ID] [--overwrite]` passes the verified public request and kit to the coordinator. It writes the resulting public onboarding bundle and prints approval/checkpoint fingerprints. Existing bundle outputs are refused unless `--overwrite` is explicit.

`dottie devices revoke --device-id ID --kit-file FILE [--confirm HEX] (--did DID | --handle HANDLE) [--vault HEX] [--root-device-id ID] [--bundle-out FILE] [--overwrite]` requires the coordinator to verify the local administrative root. Without `--confirm`, it performs only a verified read and prints an approval transcript bound to vault, device ID, role, public-key fingerprints, current/successor epochs and recovery-kit signing-key fingerprint; it makes no transition and exits nonzero with the exact repeat command. With confirmation it recomputes the transcript, refuses a mismatch, then asks the coordinator to compare the expected fingerprint against its own fresh verified read before any transition. Success reports the successor epoch/checkpoint and states that revocation cannot erase historical ciphertext or keys already obtained. The optional bundle is public.

Recovery-kit files must be regular files containing the existing grouped recovery-kit text, decode to exactly 32 bytes, and must not be group/world-readable. Restrict a saved kit with `chmod 600 FILE`. Dottie never echoes the kit, stores it in state/config/keyring, or transfers it in an onboarding bundle; command buffers are cleared after use. Wrong kits and non-root/restore-only administrators are refused by the coordinator.

On a newcomer, `dottie account import-bundle --bundle FILE --anchor HEX [--vault HEX]` requires an independently supplied root fingerprint; the anchor is never inferred from the bundle. This is separate from `dottie import`, which validates a ciphertext export archive and mutates nothing. Onboarding-bundle import transactionally persists the selection, checkpoint and authenticated predecessor evidence. The first subsequent pull authenticates the chain. It does not apply downloaded data. The S2 two-machine gate is a coordinator-level synthetic integration proof, not an execution of the full onboarding CLI sequence. The S3 gate adds coordinator export/import evidence and runs the local history command; full export/import CLI-binary acceptance remains subject to review. Neither gate establishes live PDS compatibility.

`account bootstrap` generates a new recovery kit and vault on every invocation; it is not idempotent and repeat invocations with the same name/device create distinct selections. Local selection metadata contains only vault ID, device ID and timestamp, never a kit or key. Multi-vault selection is explicit workflow support, not an MVP product promise.

`dottie plan --from FILE [--json]` renders a preview from one explicit JSON bundle. `--from` is
required: there is no implicit local view, target scan, state lookup or capture step. The bundle
is an input seam for a later capture/state task; the fact that the command can render a supplied
bundle does not mean capture or synchronization is implemented.

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

The model JSON field names are used as-is. Regular-file `content` fields are base64-encoded by
Go's JSON encoding of `[]byte`. A present observation must include its matching entry; a missing,
unknown or untracked observation must not include one. Base and remote entries are supplied
separately; the command never assumes that remote equals base. Unknown fields, invalid model
entries, duplicate identities, missing required fields, trailing JSON values and unsupported
bundle versions are rejected. The input is parsed as data only: paths inside it are never opened,
scanned or treated as authority to access a target.

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
through 15m. The authorization URL and non-secret discovered identifiers are printed before opening
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
`--remote` additionally requires a usable session, discovered binding and advertised revocation endpoint;
local deletion follows only a 2xx response. Output says the revocation request was accepted and warns that
previously issued access tokens may remain valid until expiry. An accepted remote request with failed local
delete is reported as a split outcome. `--did` is the offline local logout path.

These commands only manage account authorization. They do not publish or read vault records, touch target
data, or interact with the state database. All command tests use synthetic OAuth endpoints and temporary
stores; live accounts, browser launches and Secret Service are not exercised.

Other commands and current implementation status are described in the repository README.
