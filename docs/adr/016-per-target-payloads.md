# 016 — Publish payloads per target, not per snapshot

Status: accepted, 2026-11-25. Implemented. Supersedes the
whole-snapshot payload form in the v2 snapshot record; the NSID and `schemaVersion: 2` stay.

## Context

The v2 snapshot record carries exactly one payload for the whole publication, in one of two forms:
one packed USTAR blob, or one ordered file-set whose entries each name a file blob. The form is
chosen once, by `selectPublicationForm`, asking whether the snapshot has exactly one files target
whose entries are all regular, non-empty, 0600/0644 and deletion-free.

That question is about the snapshot, but its answers are about individual targets. The form falls
back to packed when any of the following appears anywhere in the vault:

- a GNOME settings target (settings are not files, and a settings entry is not a regular file);
- any symlink, including an absolute link outside the target root;
- a directory whose mode is carried;
- a file whose mode is neither 0600 nor 0644;
- a deletion relative to the accepted position;
- more than one target at all.

So one settings target, or one symlink in `~/.config/nvim`, demotes every dotfile in the vault to a
single tar. The file-level layout at the provider disappears, every file becomes one member of one
opaque blob, the whole snapshot is bound to the single-blob ceiling (402 MiB), and pull fetches the
entire vault to show a plan. The recorded motivation for the file-set form — browsing the layout,
fetching only what changed — is lost for the files that most need it.

The reverse is also true: a vault that only holds GNOME settings ships a tar whose data members are
empty and whose manifest is the only content, purely because settings are not files.

GNOME settings are the immediate case. A future settings source (KDE, if it turns out not to be
file-backed) would hit the same wall, and the current model has no place to put it beside files.

## What we want to achieve

1. A vault that holds dotfiles **and** GNOME settings publishes the dotfiles as per-file plaintext
   blobs and the settings inline, with no tar anywhere.
2. A vault that holds a target the file-set form cannot represent (symlinks, odd modes, deletions)
   publishes that target packed while the eligible targets stay per-file. Ineligibility is scoped
   to the target that caused it.
3. Payload granularity follows the target: browsing, selective fetch and partial failure stay where
   the data allows them, and a single oversized target no longer constrains the rest of the vault.
4. Per-target provenance stays the adoption unit: the record already names each target, so what a
   machine adopts, and how it confirms it, matches how the payload is published.
5. A non-file source can be added later as another segment form instead of another reason to pack
   everything.

Non-goals: confidentiality (the publication stays plaintext), per-target form settings in local
configuration, changes to adoption consent (`--settings` remains the local gate for settings
targets), multi-vault support.

## Decision

The v2 snapshot record replaces the `blob` XOR `entries` union with an ordered list of payload
**segments**, one per target. The NSID and `schemaVersion: 2` are unchanged; the record shape is
replaced in place because the publication contract has no other users and the tree is a prototype.

```text
snapshot record
  schemaVersion  2
  vault          32 bytes
  publicationId  16 bytes
  publicationSeq integer
  parent         CID bytes
  segments       array, sorted by target id, at least one

segment
  target         { id, source, source_version, root? }
  form           "entries" | "settings" | "packed"
  entries        present exactly when form = "entries"
  settings       present exactly when form = "settings"
  blob           present exactly when form = "packed"
```

The head record loses `blobCid`. It names the snapshot record CID only; the snapshot record is the
single authority for which payload objects exist. A packed segment is one blob, an entries segment
is one blob per entry, and a settings segment is carried inline in the snapshot record.

### Validation

- Exactly one payload member per segment, matching `form`. Unknown or extra keys are rejected.
- Targets are unique within the record, sorted by id, and validated by the existing model rules.
- `entries` and `packed` require a files target with a root. A file-kind root carries exactly one
  entry whose path is the basename of the root path. Entries keep the current rules: regular,
  present, non-empty, mode 0600 or 0644, ascending unique paths, at most 64.
- `settings` requires a GNOME target (no root). Entries are sorted by schema id, settings path and
  key; each carries `state` `present` or `reset`, with a typed `value` exactly when present. The
  same bounds that already constrain a settings capture apply, plus the record byte cap.
- `packed` keeps the current blob rules: `application/x-tar`, positive size within the blob ceiling.
- The record stays within the current file-set record cap; settings values are bounded individually
  and in aggregate so the cap is enforceable before encoding.

### Form selection, per target

The publisher selects a form for each target independently:

- files target, eligible under the rules above, no deletion relative to the accepted position for
  that target → `entries`;
- GNOME target whose settings fit the inline bounds → `settings`;
- everything else → `packed` for that target only.

Deletion across a target still keeps that target packed; it no longer affects its siblings. A
vault with one files target and one settings target therefore produces two segments, neither of
them a tar.

### Verification and failure

The reader verifies each segment against the snapshot record: entry blobs by CID and size, packed
blobs by CID and size, inline settings by the record itself and the bounds check. A missing or
mismatched blob fails that segment and therefore the snapshot; it cannot be silently skipped,
because the accepted position would otherwise claim data it never fetched.

The publication rules that currently hold for one blob extend to N payload objects: the first blob
reference for a candidate is created before any head/control publication, and a failed publication
must not surface candidate bytes through any Dottie command, log, error or archive. A rejected or
ambiguous batch can still leave unattached, provider-held plaintext blobs; with per-file segments
that residual is one blob per entry that was already uploaded, exactly as it already is for the
file-set form, and it stays disclosed in `docs/security.md`.

### Publication state and adopters

The local position store currently records a floor as either one payload blob CID or one file-set
entry list. It becomes a per-segment summary: target id, form, and the blob reference or entry
list or settings digest that the accepted record named. The store schema changes and, as with the
`file_set` rename, the prototype store is rebuilt rather than migrated.

`dottie pull` still adopts per target. A files target is adopted by canonicalised root, a settings
target only when the user names it with `--settings <id>=CATEGORY[,CATEGORY]`, and the confirmation
binds either the resolved root or the derived settings policy. With segments, one pull can adopt
several targets of different kinds under the same confirmation rules; `sync` still does not adopt.

## Rollout

The change lands in slices that each compile and pass their own tests:

1. Wire contract: `publication` record codec, head change, lexicon v2 rewrite, JSON conversion,
   bounds and refusal tests.
2. Resolution: per-segment verification and the resolved snapshot the rest of the tree consumes.
3. Candidate and push: per-target form selection, segmented candidate material, upload of entry
   blobs, inline settings, packed fallback per target.
4. Local state: per-segment floor and retained summaries, store schema rebuild, acceptance and
   comparison, attempt wire version.
5. CLI, reporting, adoption, documentation and deletion of the whole-snapshot form code.

## Consequences

- Existing v2 records stop decoding. Chain verification decodes every block, so the current
  published chain becomes unreadable and must be abandoned: publish a new chain from an empty
  repository state, or clear the PDS. This is accepted only because the tree is a prototype with
  no other users.
- A publication is now several blobs. The shared managed-object custody limit (64) counts entry
  blobs and packed blobs, so an entries segment can exhaust it; settings inline do not count.
  This is the same limit the file-set form already has.
- Inline settings put setting values in the snapshot record, which is public plaintext metadata.
  They were already in the tar manifest, so the disclosure is not new, but the location changes and
  `docs/security.md` must say so.
- Per-file blobs make each dotfile independently retrievable at the provider, exactly as the
  file-set form already does. A vault that wants fewer provider objects can still force packed by
  making a target ineligible, but there is no explicit per-target form setting.
- The lexicon description, the record JSON mapping, the attempt wire version and the frozen
  `testdata/attempts-v2` fixtures all need checking; fixtures that embed old-format record bytes
  are upgrade sources and stay valid only as long as nothing decodes those records.

## Alternatives

- **Keep the whole-snapshot form.** Rejected: it is the problem. One settings target or one symlink
  costs every dotfile its per-file blobs, and the loss grows with the vault.
- **Bump to `vaultSnapshotV3`.** Rejected for now: a second NSID implies both versions are supported
  and maintained. The contract has no other users, so replacing v2 in place is simpler and honest
  about the break. If a second implementation appears, a version bump becomes mandatory.
- **Add a third member `settings` beside `entries` and keep the union.** This removes the tar for
  GNOME and is smaller, but the snapshot would still be all-or-nothing for files: a symlink or a
  0755 file keeps demoting the whole vault. It also has no place for a future non-file source
  beside an ineligible files target. Kept as the minimal fallback if the segmented form slips.
- **Per-target packed without inline settings.** Smaller than segments, but settings stay opaque in
  a tar, so browsing and diffing settings is lost and every settings change rewrites one blob.
- **Per-entry form tags inside one flat entry list.** Rejected: an entries segment needs a target
  root and ordering rules, a packed segment needs one blob for a whole target, and settings need
  schema/key identity. One segment per target keeps each form's invariants local and makes the
  target the unit for provenance, adoption and bounds.
- **Store settings in a per-target JSON blob.** Deferred, not rejected: if inline settings turn out
  to make the record too large or too slow to diff, `settings` can reference one small blob instead
  of inlining, without changing the segment model.

## Open questions

- Exact inline settings bounds (per value, aggregate, entry count) once the record cap is measured
  against real GNOME key sets.
- Whether the head keeps any payload hint at all for optimistic fetch; today the plan says no.
- Whether `entries` should later allow symlinks as inline values (they are small, like settings),
  which would move another tar trigger into the record.
- Attempt wire version naming once segments replace the file-set attempt payload.
