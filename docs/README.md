# Published site root

This directory is the GitHub Pages source for `https://dottie.lamb.systems`. GitHub serves
its contents at the site root, so the files here are public.

- `client-metadata.json` — the atproto OAuth client metadata. Its `client_id` is
  `https://dottie.lamb.systems/client-metadata.json`, which is this file's public URL. Served
  byte-for-byte: do not add redirects, rewrites or markup. Changing the URL invalidates every
  existing authorization; changing the contents does not.
- `CNAME` — the custom domain. Removing it silently moves the site back to
  `<org>.github.io`, which breaks the `client_id`.
- `.nojekyll` — disables Jekyll processing so files are served exactly as committed.
- `adr/` — architecture decision records. Public by construction: they carry identifiers and
  measurements, never tokens, session material or plaintext. Adding a decision here publishes it
  from `main`, so review it for disclosure before committing.

Deployment is a plain branch-source Pages build from `docs/` on `main`. There is no deploy
workflow, no write permission and nothing fork-triggerable; pushing to `main` is the deploy.

Before publishing lexicons, the schema authority is DNS only (`_lexicon.dottie.lamb.systems`
TXT naming a publishing DID) and is not served from this directory.
