# Dottie

Dottie keeps directories in sync between Linux machines through an existing AT Protocol
account. You choose a directory, it publishes the files as a snapshot to your repository, and
other machines pull it back. There is no Dottie server: your PDS holds the data and your account
authorises the writes.

It is early software. It works, it has been run against a real PDS from two independent
installs, but almost nobody has used it and the limits at the bottom of this file are real.

## What it does today

- `push` publishes a snapshot of the directories you selected.
- `pull` compares your local accepted position with the provider's, shows you a plan, and applies
  it only after you pass back the confirmation token it printed.
- `sync` does both, pull first, then push, under one confirmation.
- `status` shows your targets and which vault this install knows about, locally.
- `position status` reads the publication position without changing anything.

Files are synced as plaintext. Dottie chooses a form for each target independently: an ordered
file-set that names one blob per regular file, one packed tar for that target, or inline GNOME
settings. The file-set form is used for a files target that holds only non-empty regular files with
mode `0600` or `0644`: a single selected file, or a directory whose every directory holds at least
one published file and carries no mode of its own. The change may not delete a file relative to the
accepted position, and that holds whether the accepted position published the target as an entries
segment or as a packed blob: a target that drops a file it had accepted is published packed again.
Anything else falls back to packed for that target only, including a directory that holds no file at
all, a selected file that is empty, a symlink or an unusual mode; a settings target never affects its
sibling targets. There is no per-target form setting. Snapshots are content addressed and chained, so
a reader can tell a snapshot belongs to the publication it claims to.

## Install

Requires Go 1.25 or newer on Linux. GNOME settings support needs a build with the `gsettings`
tag and the GIO development files.

```
make build          # writes ./bin/dottie
make check          # formatting, vet, tests
make lint           # golangci-lint, currently clean
```

CGO is optional. Without `gsettings` the files provider is all you get.

## Getting started

```
dottie account login --handle you.example.com
dottie targets add --id niri ~/.config/niri
dottie account bootstrap --vault-name main --device-id laptop
dottie push
dottie push --confirm <token from the previous output>
```

On a second machine, log in and run `pull`. It resolves the vault from your published position, so
you do not need to copy a fingerprint around. A packed position names the targets it carries: files
targets with portable roots, and settings targets without one. Pull proposes adopting the targets
this machine does not configure yet, without reading the proposed directories first; confirming
that proposal creates them, and the following run plans and applies under its own token. Files
targets are adopted only when their root already exists, and a settings target only when you name
it with `--settings <id>=CATEGORY[,CATEGORY]`, which resolves from the local catalog into an
approved category set and key digest shown in the plan; anything else is reported and skipped. A
target that already matches a configured one is left alone. Adoption is refused before a
confirmation token is printed when the resulting configuration would have to apply a settings
target, because this build cannot write settings. If your local files differ from the
published ones and there is no history to compare, pull refuses and tells you which files
conflict. That is deliberate: it will not overwrite a file you edited, and it will not merge.

`push` and `pull` take `--did` only when more than one account is authorised. `--vault` exists
for installs that know several vaults.

## How it works

A publication is two records in your repository. `vaultSnapshotV2` is an immutable link in a
chain: it carries one payload segment per target, points at its predecessor, and carries a
publication id and sequence. A segment names its target and picks one form: an ordered list of file
entries with their paths, modes, sizes and blob CIDs; one packed tar blob for a single target; or
inline GNOME setting entries. `vaultHeadV2` is the single mutable pointer at `self` naming the
current snapshot record. `pull` reads the head, walks back through the chain, then fetches and
verifies every payload blob against its CID and size and reads the inline settings from the record.

Every segment names the target it was captured from: an id and, for files segments, a portable root
of base, relative path and kind. A record is only a proposal: a target is created on its own
confirmation, before any proposed directory is read, in review mode and without excludes, for a
files target through the same checks and canonicalization as `targets add`, and for a settings
target through the local category selection and its resolved digest. A published target whose id is
already configured is left alone. `pull` plans and applies only the targets the position names: a
configured target the position does not name is reported as skipped and is not planned, captured or
mutated, though the root safety checks and any interrupted-apply recovery still visit the paths they
recorded. A
publication whose single segment is an entries file-set is still re-projected onto the sole local files
target, so it can be applied to the root of your choosing; a multi-segment publication applies each
segment to the local target with the same id and root, and a configured target whose root differs from
the published one refuses the apply instead of being rebound. A
single-file target publishes its file under the basename of its configured path, for example
`init.lua`, and pull maps that one entry back to the selected file. Several targets can be adopted
under one confirmation, each under its own rules.
The pull confirmation binds the local target id, portable root and configuration revisions, so a
local target or root change between review and confirmation refuses. The target root must already
exist; parent directories absent from an entries segment are created with mode `0755` during apply,
a packed segment creates the directories it names with their recorded modes, and a single-file
target synthesizes none.

Applying files is the part with the sharp edges, so it is journaled. Before touching a file,
Dottie records the intent and a copy of the previous contents in a separate journal database,
writes atomically, then confirms by observing the result. If the process dies mid-write, the
next run resolves the journal against what is actually on disk: matching postimage means it
applied, matching preimage means it did not, anything else stays indeterminate and blocks further
applies until you resolve it. This is tested by killing the process at five real points, but not
by pulling the power.

Authenticity is repo-scoped. A record set is authentic for the account that holds it, because
writing to that repository requires an authenticated session. Dottie adds no signature of its own
over a published position, which means it cannot prove anything against a provider that rewrites
or withholds history. It also means losing your machine's keys does not lose the data: your
account can read it back.

## Limits

- Plaintext. Every packed blob and every entry blob is uploaded before any record references it.
  A rejected or ambiguous batch can leave unattached, retrievable plaintext blobs at the provider;
  Dottie cannot delete them, and it never prints candidate bytes for a publication that failed.
  Inline settings are record metadata, not blobs. The custody object limit is shared across
  retained publications, not per publication: a representable successor that changes a CID can
  still be refused by custody, and Dottie does not retry another form after an attempt starts.
- No offline verification. If you do not trust the provider to serve honest history, this is not
  the tool for that threat model.
- No recovery story of its own. A backup is `cp -r`. Earlier versions tried to build one from a
  recovery kit and it was not worth the complexity.
- Conflict resolution is manual by design. `pull` names the conflicting files and stops.
- Prototype breaking change. A `config.toml` that still sets `targets.form` no longer loads: the key
  was removed, so the file fails with an unknown configuration key instead of being ignored. The v2
  snapshot record also changed shape in place (one payload segment per target, and the head no
  longer carries `blobCid`), so a chain or a local publication store written by an earlier build
  cannot be read: publish a new chain from an empty repository state, or clear it, and rebuild the
  local store.
- Applying settings needs a build with the GNOME backend. `pull` plans the approved keys of a
  published settings target, journals each intent, sets or resets the key and verifies the written
  value before the floor advances; without the backend the whole pull refuses before a token is
  printed. `docs/adr/017-settings-apply.md` records the model, including the external-writer race.
- A push from a machine that configures only some of the published targets composes a snapshot from
  its own targets, so the targets it does not configure are not carried forward into the next head.
  Pull them on that machine first, or push from a machine that configures them.
- A target's portable root is part of its identity. A machine that moves a configured target, or
  adopts one whose path resolves to a different portable root than the published one, is refused;
  re-adopt the target at the published path.
- Concurrent publication from two machines at once is refused rather than merged.
- No power-loss evidence. Process death, yes; sudden power loss, untested.

## Documentation

- `docs/security.md`: what the trust model actually guarantees, and what it does not.
- `docs/adr/`: design decisions, with their reasoning and the alternatives that lost.
- `docs/operations.md`: publishing the docs site, lexicons and release packaging.

## License

Apache 2.0. See `LICENSE`.
