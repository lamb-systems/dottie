# Three-way reconciliation

`Reconcile` is a pure, deterministic decision function. It consumes an explicit `BaseView`, a
`LocalView`, remote entries, and caller-supplied validated target bindings. It performs no I/O,
uses no clock or randomness, and starts no goroutines. The result is a preview/decision plan. The
separate journaled `Apply` consumer accepts only supported file operations and does not change the
reconciliation function or authorize target roots.

## Input and ownership

`LocalView.Entries` contains the captured present entries and any explicit file tombstones or
GSettings resets. `Unknown` identifies keys that could not be observed; `Untracked` identifies
keys no longer selected; `Coverage` lists target subtrees fully observed by the caller. A missing
local entry is classified as `known-absent`, but absence from `Coverage` prevents a deletion
action. `BaseView.Status` is caller-supplied provenance: `known` means the exact remote parent is
known, `missing` means no base exists, and `stale` means the base is not an ancestor of the current
remote head. Content is never used to infer that provenance. A missing base cannot carry entries.

`Options.Bindings` is the input view of validated target authority. Obtain a binding with
`NewTargetBinding`; its fingerprint covers the complete portable target binding. Every input key
must match one of those bindings. Each decision carries that binding, an entry fingerprint for
each side that had an entry, and copied entries. Fingerprints contain the validated state,
kind, mode, link target or typed value, size and digest; downstream code must use those values and
must not reconstruct target authority or entry digests.

The caller boundary must supply canonical GVariant `Type` and `Text` for settings. This model does
not parse or canonicalize GVariant text. Reconciliation compares setting state, `Type`, and `Text`
exactly; differently represented text is not equal even if another layer might interpret it as an
equivalent value.

## Preview

`BuildPreview` consumes the existing reconciliation `Plan`, the supplied target definitions and
observations. It does not reconcile again, read data, write state or mutate its inputs. The result
is a content-free `Preview` with targets ordered by target ID and entries ordered by the existing
identity order. It retains names, actions, states, reason codes, sizes and, when available, the
local observation's digest and mode; it never retains an entry's file content or setting value.

The reconciler remains authoritative for decisions. Preview keeps the exact reconciliation action
(upload, download, delete-local, delete-remote, unchanged, blocked or conflict) separately from its
create/change/delete display action. Upload/download decisions map to create or change, delete
decisions map to delete, conflicts remain a conflict state with a conflict reason, and local absence
is represented as missing with a missing reason. Unknown remains a state with no action. An
untracked observation can have a create display action, but retains its blocked decision. There is
no `unapplied` state in this version because no journal result supplies one.

Entry and total bytes use `vault.Estimate`, the same payload accounting used by snapshot packing.
Per-entry `size` and `transfer_bytes` account create/change payloads that would move; deletes add no
payload. Per-entry `resulting_snapshot_bytes` and the plan's `resulting_snapshot_bytes` account
resolved present entries, including unchanged entries. `complete` is false while any conflict,
unknown or unmatched entry remains, and `unresolved_entries` gives the count. The resulting size is
then a lower bound over resolved entries, not a constructed candidate snapshot or a promise about
the remote.

The current observation model cannot express a reset: `ObservationPresent` accepts only present
file or setting entries, and a `SettingReset` is rejected. Reset is therefore not a preview action
in v1. Unsupported file kinds are likewise rejected during model validation before a reconciliation
decision exists, so unsupported is not a preview outcome here. A later model/reconciler change must
make each state representable before preview can distinguish it. This pure layer does not inspect
target roots, so it cannot infer a disappeared-root risk from supplied decisions. The CLI's JSON
bundle is only a caller-supplied seam; it does not make capture or synchronization operational.

## State classification and precedence

Every key has exactly one classified state per side:

| State | Meaning |
| --- | --- |
| `present` | Present file or present setting entry |
| `tombstone` | Explicit deleted file entry |
| `setting-reset` | Explicit GSettings reset entry |
| `known-absent` | No entry for the key in that side's view |
| `unknown` | Local observation failed or was blocked |
| `untracked` | Local key is no longer selected |

Base and remote sides can be `present`, `tombstone`, `setting-reset`, or `known-absent`. Local
state can use all six. An unknown key blocks itself and every descendant file key; unknown `.`
blocks all file-key decisions for the target. An untracked key blocks that key. An unknown ancestor
takes precedence over an untracked descendant. A target absent from `Coverage` blocks any otherwise-selected `delete-local` or `delete-remote`
action.

Decision precedence is fixed: unknown/untracked blocks first; structural inconsistency then
promotes affected actionable decisions to structural conflicts; the base-missing table applies
next; then equality; then one-sided change; then two-sided divergence; deletion handling and the
coverage gate are last.
The rows below are mutually exclusive and exhaustive after the blocking and structural checks.
`=` means exact equality under the per-kind rules below. `D` means a file-side value with no live
file (`known-absent` or `tombstone`). `entry` means an explicit entry, including tombstones and
resets. A one-sided `known-absent` setting value is also a deletion when compared with a present
base; an explicit setting reset is a value, not a deletion. In all rows, a deletion action is
changed to `blocked / coverage-incomplete` if the local target is not in `Coverage`.

| Row | Base provenance | Local | Remote | Condition | Action | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| B1 | any | any | any | local key is unknown or below an unknown key | blocked | unknown |
| B2 | any | any | any | local key is explicitly untracked, and B1 did not match | blocked | untracked |
| S1 | any | any | any | structural pass finds parent non-directory/deletion with a surviving child; key is not already blocked | conflict | structural |
| M1 | missing | any | any | local `=` remote | unchanged | equal |
| M2 | missing | D | D | file values differ, but both sides have no live file | unchanged | both-deleted |
| M3 | missing | known-absent | entry | remote has an entry and M1/M2 did not match | download | base-missing |
| M4 | missing | entry | known-absent | local has an entry and M1/M2 did not match | upload | base-missing |
| M5 | missing | any | any | no preceding M row matches | conflict | base-missing |
| K1 | known or stale | any | any | local `=` remote | unchanged | equal |
| K2 | known or stale | D | D | file values differ, but both sides have no live file | unchanged | both-deleted |
| K3 | known | any | any | local differs from base; remote equals base; local is not a deletion | upload | local-changed |
| K4 | known | deletion | any | local differs from base; remote equals base | delete-remote | local-changed |
| K5 | known | any | any | remote differs from base; local equals base; remote is not a deletion | download | remote-changed |
| K6 | known | any | deletion | remote differs from base; local equals base | delete-local | remote-changed |
| K7 | known | any | any | local and remote both differ from base and no preceding K row matches | conflict | divergence |
| T1 | stale | any | any | local differs from base; remote equals base; local is not a deletion | upload | local-changed |
| T2 | stale | deletion | any | local differs from base; remote equals base | conflict | stale-base |
| T3 | stale | any | any | remote differs from base; local equals base; remote is not a deletion | download | remote-changed |
| T4 | stale | any | deletion | remote differs from base; local equals base | conflict | stale-base |
| T5 | stale | any | any | local and remote both differ from base | conflict | stale-base |
| C1 | any | any | any | a preceding row selects `delete-local` or `delete-remote`, and the target is absent from `Coverage` | blocked | coverage-incomplete |

The table ordering resolves the formerly overlapping case `base=A, local=tombstone, remote=A`
exactly once as `delete-remote` (K4). `base=A, local=tombstone, remote=B` is a two-sided change
and resolves to `conflict / divergence` (K7), never a deletion. When the base is missing, a local
absence does not imply deletion: a remote entry is downloaded (M3), and a local entry is uploaded
when remote is absent (M4). A setting reset is an explicit setting operation, not a file deletion;
it is uploaded or downloaded by the one-sided-change rules. Stale-base divergence uses the
separate `stale-base` reason and stale provenance never emits either deletion action.

## Equality

- Regular files compare state, kind, mode, link target, and SHA-256 payload digest.
- Directories compare state and mode.
- Symlinks compare state, kind, and target text.
- Settings compare state and canonical `Type` and `Text` exactly.

Entries must validate before reconciliation. Target keys are processed in target/source/key order,
and each key receives one decision. Repeated calls with identical inputs produce the same plan.

## Structural consistency

After the per-key decisions, each file target is checked on both resulting sides. If a parent is
changed to a non-directory while a descendant survives, or a parent is deleted while a descendant
survives, the parent and affected descendant decisions become `conflict / structural`. Existing
blocked decisions remain blocked. This prevents a plan from asking a consumer to publish or apply
an internally contradictory tree.

## Plans and diagnostics

A `Plan` contains copied entries, including regular-file content, so routine logging or serializing
a plan is a plaintext data leak. Do not log a `Plan`. `Plan.Diagnostic` and `EncodeDiagnostic`
produce the redacted diagnostic form; it contains only entry keys, actions, reasons, and digests.
That diagnostic form is the only representation suitable for logs.

`conflict` and `blocked` are non-actionable. Consumers must not apply either automatically. The
journaled local apply path permits only `download` and `delete-local` reconciliation actions;
uploads, remote deletes and blocked, untracked, unknown or conflict entries are not local writes.
An entry's supplied postimage digest checks that the bytes match the caller-supplied digest; it does
not independently establish that those bytes are the right candidate for the reconciled action.

## Precedence, as implemented

The prose list above is ordered for reading; the code applies them in this sequence: blocking
(unknown/untracked/coverage), then the base-missing, equality, one-sided-change, divergence and
deletion rows, and **only then** the structural promotion pass over the resulting decisions. A
structural conflict can therefore override a per-key decision that was already resolved.

## Coverage is per target, and the caller carries the obligation

`LocalView.Coverage` names targets whose subtree was observed completely. For filesystem targets
the observed subtree bounds what can be concluded. **Settings keys are not enumerable**: a GSettings
key that was never read cannot be inferred absent from target coverage, so a caller that observes a
GNOME target MUST list every key it did not successfully read in `LocalView.Unknown`. A key that is
neither in `Entries` nor in `Unknown` is treated as known-absent and can drive a deletion, which is
correct only if the caller's observation really covered it. This is the contract L10 relies on.

## Journaled filesystem apply

`Apply` consumes the content-free preview together with caller-resolved destination roots, an exact
set of postimage bytes/digests/modes for create and change entries, a local `ModePolicy`, and an
injected filesystem boundary. It refuses settings entries, directories, symlinks, root deletion,
unmatched content and unsupported actions before writing a journal row. The mode policy has a
restrictive `0600` default and optional per-target overrides; an incoming content mode must match
that local choice and is never transplanted.

Before acting, apply observes all requested paths and compares each available preview digest and
mode; it repeats the comparison immediately before each journaled operation. The filesystem operation
also receives the expected preimage and re-hashes/re-checks its mode immediately before rename or
remove. A mismatch returns `ErrPreconditionChanged` and leaves the destination and staged replacement
untouched. For replacement, this moves the check past temporary-file writing and fsync, shrinking the
race window from that whole interval to the final stat-to-rename instant; deletion has the equivalent
stat-to-remove interval. These are check-then-mutate operations, not atomic conditional writes: a
concurrent edit in that final syscall window is still possible and cannot be guaranteed impossible.
Each file operation records a pending state row and an immutable backup before touching the
destination. The journal stores the resolved destination directory and its device/inode identity, so
recovery does not re-resolve a target from changed configuration. Replacements use same-directory
temp-and-rename, then read back the bytes and mode. Success marks the entry applied and retains its
backup for seven days. Failure marks an entry failed only when the preimage is still present;
otherwise it remains indeterminate with its backup retained. A caller must invoke
`RecoverInterrupted(ctx, store, filesystem, clock)` before beginning new apply work; `Apply` returns
`ErrRecoveryRequired` while pending rows remain. Recovery classifies every pending row independently:
a preimage match means failed, a destination matching neither fingerprint is indeterminate, and a
postimage match is also indeterminate because a user's identical edit cannot be distinguished from
Dottie's completed write using the current journal evidence. Missing or changed destination roots
are indeterminate and untouched. Re-running recovery is idempotent. Older journal rows without a
resolved root are reported indeterminate rather than redirected through current target configuration.

`RollbackApplied` is also local-only and reports one result per entry. It restores an entry only
while the destination still matches that entry's postimage; a newer edit is left untouched and
reported as `skipped-newer-edit`. That skip is durable, blocks restoration of older journal history
for the same destination, and retains the backup. Rollback intent is persisted before mutation;
interrupted or indeterminate restores are not retried as successful restores and their backups are
not expired. Each restore is verified against the recorded preimage before being marked rolled-back.
Verified rolled-back material is pruned; verified applied backups expire after seven days. Failed
and indeterminate backups are never pruned. The global rollback-material
limit is 256 MiB until targets are associated with vaults; an apply that would exceed it fails with
a typed error naming the entries holding existing material, and no existing backup is dropped to
make room. Age cleanup and bound checks use the injected clock. If a future case is unclear, retain
the backup rather than deleting it on a judgment call.

Apply and rollback are per-entry operations, not a transaction. A failing entry stops the apply
sequence; earlier entries may already be applied and later entries are not. A rollback may restore
some entries and skip or fail others, and its report states the result for each. The apply path
never infers deletion from absence and never deletes directories or files absent from the preview.
