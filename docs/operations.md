# Operations

Things that are not product behaviour: publishing the docs site, publishing lexicons, and what
goes into a release.

## The docs site

`docs/` is served directly by GitHub Pages at `https://dottie.lamb.systems`. Everything in this
directory is public.

- `client-metadata.json` is the AT Protocol OAuth client metadata. Its `client_id` is
  `https://dottie.lamb.systems/client-metadata.json`, which is this file's own URL, so GitHub must
  serve it byte for byte. No redirects, no markup, no processing. Changing the URL invalidates
  every existing authorisation; changing the contents does not.
- `CNAME` pins the custom domain. Remove it and the site moves to `<org>.github.io`, which breaks
  the `client_id`.
- `.nojekyll` stops Jekyll from touching the files.
- `adr/` holds the decision records. They are published, and they contain identifiers and
  measurements, never tokens, session material or plaintext. Adding one publishes it from `main`.

Deployment is a plain branch-source build from `docs/` on `main`. There is no workflow, no deploy
token and nothing fork-triggerable.

## Lexicons

Schemas live in `lexicons/`. Before publication, schema authority comes from DNS alone: a
`_lexicon.dottie.lamb.systems` TXT record naming the publishing DID. The site does not serve it.

The v2 schemas are `systems.lamb.dottie.vaultSnapshotV2` and `systems.lamb.dottie.vaultHeadV2`.
If a published schema changes, existing records do not follow it: bump the schema version in the
record and keep the old schema resolvable.

## Packaging

`packaging/` holds the files a distribution needs: the desktop entry, the systemd user unit for
the background sync service, and the preset data. Nothing there is generated; edit it directly.

## Lint

`make lint` runs golangci-lint with the repository configuration. The `exhaustive` linter lists its
program elements as `switch` and `map`; a value outside that set makes the whole run fail before any
analysis, which is why the configuration is checked with the gate itself rather than assumed. Lint
also needs a golangci-lint built with the same Go minor as the toolchain in use: a binary built with
an older minor cannot decode the installed standard library's export data and reports only
`typecheck` failures, which are an environment mismatch and not repository findings.

## A local store written by an older build

The position store is refused, not upgraded. `dottie` reports `rebuild_required` for a store whose
schema version it no longer writes, and leaves the directory exactly as it found it, including
`journal.db` and every apply backup: a backup may hold the only copy of a file's preimage for an
interrupted apply, so a rebuild is a fresh state directory that you create by moving the old one
aside yourself. Nothing in the tool suggests deleting the state directory, and a refusal never
resolves, rewrites or clears a journal row. Resolve pending or indeterminate rows with the build
that wrote them first; if that build is gone, keep the directory as evidence.

A database that is not a Dottie store at all is refused as `schema`, not as `rebuild_required`, so a
wrong directory is never mistaken for an outdated one.

## Frozen legacy store images

The rebuild refusal is tested against images written by the builds that produced those schemas, kept
under `internal/publicationstate/testdata/`:

| Image | Schema | Source |
| --- | --- | --- |
| `positions-v1/schema1-baseline.db` | 1 | the pre-attempt position store |
| `positions-v2/schema2-mixed.db` | 2 | pinned schema-2 fixture produced by the baseline commit `f5387d6`, restored from this repository's history (`cb4e881`); SHA-256 `e9560148…a0939` matches its manifest |
| `positions-v2/schema2-pending-genesis.db` | 2 | same provenance; SHA-256 `d2e446ca…5f108` |
| `positions-v3/schema3-empty.db` | 3 | written by the build at commit `479b2c5`, the tree that wrote schema 3 |
| `positions-v3/schema3-upgraded.db` | 3 | same build, produced by its own supported upgrade from the pinned schema-2 `mixed` image |
| `journals-v2/schema2-pending.db` | 2 | written by the build at commit `ca8451f`, the last tree whose apply journal had no `settings_journal` table; one live pending row with a stored preimage |

The v2 and v3 inventories are frozen constants rather than the current table definitions: the current
`attemptSchemaStatements` describe the schema-4 `retained_publications` and `attempt_payload_refs`, so
deriving a legacy inventory from them would identify nothing.

## Recovery is per file, not per run

The apply journal makes an individual file write or delete recoverable: a row records the intent and
the preimage before the change, and the next run classifies the row from what is on disk. It is not a
whole-run rollback, and it does not order or undo the files that a run already changed. A run that
stops after one file's postimage but before the run's remaining operations leaves the earlier files
applied; the journal settles that one row and the next run plans the rest against the settled state.

A pull resolves those rows before it accepts a floor, including on the acceptance-only path where no
file would be written and the configured targets are not the ones the row wrote. An indeterminate row
blocks the run and the floor does not advance. A pull with nothing configured to resolve the row
refuses and says the row is still recorded rather than reporting a clean state.
