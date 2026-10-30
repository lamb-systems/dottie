# Three-way reconciliation

`Reconcile` is a pure, deterministic decision function. It consumes an explicit `BaseView`, a
`LocalView`, remote entries, and caller-supplied validated target bindings. It performs no I/O,
uses no clock or randomness, and starts no goroutines. The result is a preview/decision plan; this
package does not publish, apply, resolve conflicts, or authorize filesystem access.

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

`conflict` and `blocked` are non-actionable. Consumers must not apply either automatically. DOT-L10
must refuse a plan containing either action unless the user has explicitly resolved it. This package
does not implement that consumer-side enforcement.

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
