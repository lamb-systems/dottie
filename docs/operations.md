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
