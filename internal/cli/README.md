# CLI commands

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

Other commands and current implementation status are described in the repository README.
