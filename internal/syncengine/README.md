# Three-way reconciliation

## Reachability

`Reconcile`, `BuildPreview`, `Preview` and `PreviewEntry` are reached from `internal/service` for v2
publication planning. `dottie pull --confirm` is the only apply path; it journals and applies through
`publicationstate`, not this package. `RecoverInterruptedWithSettings` is reached from
`internal/service` by `dottie recover`, with `RecoverInterrupted` as the file-only wrapper. The v1
`Apply` and `RollbackApplied` engines, their apply and rollback internals, and their package test files
were deleted with the retired `dottie preview` and `dottie restore` commands, as were the `tests/local`
v1 apply, rollback and publication-reconcile suites. `go test ./internal/cli -run
TestRemovedV1ApplyEngineHasNoProductionReference` fails if any non-test file under `cmd/`,
`internal/cli` or `internal/service` references a removed v1 apply or rollback symbol again, or if this
package redeclares one. The two-machine v2 gate and the single-machine `publication_apply` tests cover
the replacement path.

`Reconcile` is a pure, deterministic decision function. It takes an explicit `BaseView`, a
`LocalView`, remote entries, and caller-supplied validated target bindings. It performs no I/O,
uses no clock or randomness, and starts no goroutines. The result is a preview/decision plan.

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

The caller must supply canonical GVariant `Type` and `Text` for settings. This model does
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

An `ObservationPresent` carrying a `SettingReset` entry represents an explicit GNOME reset.
Present file observations retain their existing validation. `BuildPreview` treats present and
reset settings as transferable candidates and can represent reset-to-present or present-to-reset
upload/download changes without retaining a setting value in the preview. Unsupported file kinds are
rejected during model validation before a reconciliation decision exists, so unsupported is not a
preview outcome here. This pure layer does not inspect target roots, so it cannot infer a
disappeared-root risk from supplied decisions. The CLI's JSON bundle supplies input only; it does not
make capture or synchronization operational.

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
| M3a | missing | setting-reset | present setting | inbound reset exception | download | base-missing |
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
when remote is absent (M4). A setting reset is an explicit setting operation, not a file deletion; it remains a value wherever a base exists. With a missing base, local `setting-reset` plus remote present setting is the narrowly scoped inbound exception and resolves to `download / base-missing`; the explicit reset stays in the decision and the local fingerprint is preserved. The other missing-base rows are unchanged: nil plus reset downloads, reset plus nil uploads, equal resets are unchanged, and present-versus-reset or divergent present values conflict. Stale-base behavior is unchanged. Stale-base divergence uses the
separate `stale-base` reason and stale provenance never emits either deletion action.

## Equality

- Regular files compare state, kind, mode, link target, and SHA-256 payload digest.
- Directories compare state and mode.
- Symlinks compare state, kind, and target text.
- Settings compare state and canonical `Type` and `Text` exactly.

Entries must validate before reconciliation. Target keys are processed in target/source/key order,
and each key receives one decision. Repeated calls with identical inputs produce the same plan.

## Structural consistency

After making per-key decisions, the reconciler checks each file target on both resulting sides. If a parent is
changed to a non-directory while a descendant survives, or a parent is deleted while a descendant
survives, the parent and affected descendant decisions become `conflict / structural`. Existing
blocked decisions remain blocked. This prevents a plan from asking a consumer to publish or apply
an internally contradictory tree.

## Plans and diagnostics

A `Plan` contains copied entries, including regular-file content, so routine logging or serializing
a plan is a plaintext data leak. Do not log a `Plan`. `Plan.Diagnostic` and `EncodeDiagnostic`
produce the redacted diagnostic form; it contains only entry keys, actions, reasons, and digests.
That diagnostic form is the only representation suitable for logs.

`conflict` and `blocked` are non-actionable. Consumers must not apply either automatically. The v2
local apply path in `internal/service` permits only `download` and `delete-local` reconciliation
actions; uploads, remote deletes and blocked, untracked, unknown or conflict entries are not local
writes. An entry's postimage digest in that journal checks that the bytes match the caller-supplied
digest; it does not independently establish that those bytes are the right candidate for the
reconciled action.

## Precedence, as implemented

The prose above presents precedence in reading order; the code applies the checks in this sequence: blocking
(unknown/untracked/coverage), then the base-missing, equality, one-sided-change, divergence and
deletion rows, and **only then** the structural promotion pass over the resulting decisions. A
structural conflict can override an already-resolved per-key decision.

## Coverage is per target, and the caller carries the obligation

`LocalView.Coverage` names targets whose subtree was observed completely. For filesystem targets
the observed subtree bounds what can be concluded. **Settings keys are not enumerable**: a GSettings
key that was never read cannot be inferred absent from target coverage, so a caller that observes a
GNOME target MUST list every key it did not successfully read in `LocalView.Unknown`. A key that is
neither in `Entries` nor in `Unknown` is treated as known-absent and can drive a deletion, which is
correct only if the caller's observation really covered it. This is the contract L10 relies on.

## Recovery

`RecoverInterruptedWithSettings` is the recovery entry point used by `dottie recover` through
`internal/service`; `RecoverInterrupted` is the file-only wrapper that supplies a nil settings
backend. The journal stores the resolved destination directory and its device/inode identity, so
recovery does not re-resolve a target from changed configuration.

Recovery classifies every pending row independently: a preimage match means failed, a destination
matching neither fingerprint is indeterminate, and a postimage match is also indeterminate because a
user's identical edit cannot be distinguished from Dottie's completed write using the current journal
evidence. Missing or changed destination roots are indeterminate and untouched. Re-running recovery
is idempotent. Older journal rows without a resolved root are reported indeterminate rather than
redirected through current target configuration.

Pending GNOME rows need a settings backend. Without one, a setting that cannot be observed or is
locked, or a setting matching neither fingerprint, is indeterminate; a setting still matching its
preimage is failed. A setting matching its postimage remains indeterminate for the same reason as a
file destination matching its postimage. Recovery then prunes expired journal backups. Failed and
indeterminate backups are never pruned; eligible applied backups expire after seven days. Pruning an
eligible setting backup atomically detaches the backup and clears its preimage/postimage value type
and text fields; unresolved rows retain their recovery material. If a future case is unclear, retain
the backup rather than deleting it on a judgment call.
