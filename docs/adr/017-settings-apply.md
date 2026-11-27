# 017 — Apply GNOME settings by converging to an accepted image

Status: proposed, 2026-11-26. Implements the settings writer that ADR 016 left as a segment form with
no destination. Applies to the `settings` segment of the v2 snapshot record.

## Context

ADR 016 gave the vault a per-target `settings` segment: a record carries one ordered list of
approved `(schemaId, path, key, state, value?)` entries per settings target, authenticated by the
snapshot record itself. Pull fetches, verifies and accepts those entries. Nothing writes them back:
`planPublicationApply` refuses any target whose source is not `files`, so a configured settings
target blocks a plan and a settings target cannot be provisioned by `pull --settings`.

That was tolerable while settings were a proposal. They are now the reason the product exists: one
command should provision a machine, and half of that machine is GSettings.

The obstacle is that GSettings is not a filesystem. It has no revision, no compare-and-set and no
transaction. `g_settings_set_value` writes a value and replies nothing about who won a race. The
Dottie journal lease serialises Dottie runs, not other clients: a session daemon, `gsettings set`
in a terminal, a vendor tool, or the user's own control center can write the same key at any moment,
before or after we do.

## What we want to achieve

1. A reviewed plan lists exactly which keys change, per target, before anything is written.
2. Apply converges each approved key to the accepted image, and reports what it actually changed.
3. A crash leaves enough local record that the next run can classify what happened without guessing
   and without replaying stale values.
4. Nothing a remote record contains can widen local authority: approval stays a local category
   selection, and the record only chooses values for keys the local policy already covers.
5. The design admits unattended apply later (one command provisions everything) without a redesign.

Non-goals: confidentiality (settings travel inline in the record and are already public), a settings
watcher, bidirectional merge, a settings form for non-GNOME sources, per-key approval.

## Decision

### Authority

Settings are applied from the **verified terminal record the same confirmation will accept**, and
only under that confirmation: the bytes the reader resolved from the signed chain, the same bytes the
accept stage binds, and the record CID the command carries into both the settings plan and the accept
stage. A plan whose record does not hash to the bound CID is refused, so a settings write and a floor
advance cannot describe different records.

The provider's head is not an independent authority: the record is only reachable through the chain,
scope and CID checks the pull already performs, and the floor does not advance unless the settings
and files both applied. The local binding is the authority for *what is already accepted* — recovery,
carry-forward and the reviewed position all come from it — but a first application has no accepted
material yet, so it cannot be the source of the values being written.

The journal records intent and the image that was being written. It is never a source of values.

### Image model

A key has two observable states:

- **no user override** — the key is absent from the writable layer and the default applies. This is
  what a `reset` entry converges to.
- **present** — a canonical `(type, text)` pair.

`Canonicalize` runs before comparing and before digesting, because canonicalization rewrites forms
(`[]` becomes `@as []`, `0` may become `0.0`). A comparison of raw record text against raw observed
text is not a comparison of values.

Unobservable is not a state. A missing schema, a failed observation, a locked backend or an
unreadable key is a refusal, never a match, never a reset. `Writable` is checked where the decision is
made: the plan refuses a non-writable key, apply re-checks before journaling, and recovery treats one
as unobservable so it cannot classify a row.

### Journal

Settings intents live in the existing apply journal database, under a second table, in the same
lease and the same admission budget:

```text
settings_journal
  entry        INTEGER PRIMARY KEY     append-only, one row per operation
  vault        BLOB
  target_id    TEXT
  schema_id    TEXT
  path         TEXT
  key          TEXT
  prior_state  TEXT                    "present" | "absent"
  prior_type   TEXT
  prior_text   TEXT
  written_state TEXT                   "present" | "absent"
  written_type TEXT
  written_text TEXT
  state        TEXT                    pending | applied | failed | indeterminate
  stage        TEXT
  seen_floor_revision INTEGER
  created, updated INTEGER
```

Rows are keyed by operation, never by setting identity: a publication may set the same key again,
and two rows must both exist. The identity columns are indexed for reporting, not for identity.

Prior values are stored inline. They are small, bounded and already present in the local store's
accepted material, so a managed backup object would add a second copy for no confidentiality gain.

The journal schema version becomes 3. A journal written by an older build is refused like an older
position store: this tree rebuilds rather than upgrades. A refused journal is preserved with its
rows, because a live row can be the only record of an interrupted mutation.

### Mutation

Per key, in the accepted record's order, after the files plan has been applied:

1. check that the key is approved by the target's local GNOME policy (`approval = approved`, matrix
   version match, key in the selected set, digest matches), and that the policy's path for a
   relocatable key matches the record's;
2. observe and refuse unless the key is writable;
3. canonicalize, journal the intent with the observed image;
4. observe again: if the written image is already visible the row is completed without a write, and if
   the image moved anywhere else the unexecuted intent is settled as failed and the run refuses;
5. `Set` the canonical `(type, text)` or `Reset` for a reset entry;
6. observe again and settle the row as applied when the written image is visible.

A mutation that reports an error is settled from observation rather than assumed: the written image
means applied, the prior image means failed, and anything else stays indeterminate. None of this rolls
back other keys, and none of it advances the floor.

The configuration is read once at review time and carried through apply; a concurrent configuration
change does not revoke approval mid-run, because the confirmation binds the selection and approval
revisions it was printed against and a changed configuration changes the token. Holding the
configuration lock across the write is a future refinement, not a claim this build makes.

The plan digest covers every operation, including the ones that turn out unchanged, so the
confirmation binds the reviewed set of keys.

### Recovery

Recovery never writes from a journal row. It settles rows:

- the written image is visible → applied;
- the prior image is visible → failed, and the next plan re-issues the operation because the accepted
  image still names it;
- anything else → indeterminate, which blocks further apply until a later run observes a settled
  image.

The next plan always converges to the accepted image; a settled-but-stale row is therefore harmless.

Because GSettings has no revision, convergence can restore an older value: a key that another client
changed after our write is overwritten by the next apply. That is what owning a category means, and
it is documented in `docs/security.md` rather than hidden.

### Ordering and scope

Files apply first, then settings: a settings failure cannot leave a files plan half-applied behind a
floor advance, and a files failure stops the run before any key is written. Both plans are composed
from the same accepted binding and confirmed by one token.

`--remote-only` applies remote-origin set and reset operations and defers nothing for settings: a
settings change has no upload side. Sync therefore converges settings on the pull half like files.

The apply plan covers the published settings segments whose target ids local configuration selects.
Unselected targets keep being reported as skipped. Only the local GNOME policy can widen the set.

### Unattended apply

The design contains no state that only a human can clear: rows settle from observation, and the next
plan converges. Review mode stays the default for a newly adopted target, and ADR 018 will cover the
local grant that lets a configured `auto` target be applied without a person echoing a token. Auto
apply is not consent to adopt, publish or prune.

## Consequences

- Settings become the second thing the product actually does, next to files, with the same review and
  confirmation contract.
- The apply journal grows a second table and a schema version, and the forward-only journal policy
  means an in-flight journal from an older build refuses instead of upgrading.
- A concurrent external writer can undo an apply silently. That risk is accepted because the
  alternative — a settings backend with a conditional write — does not exist.
- Nothing in the record can grant authority. A record can only propose values for keys the local
  category selection already covers, and an unapproved key refuses the whole plan.
