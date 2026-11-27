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
