# Published site root

GitHub Pages uses this directory as the source for `https://dottie.lamb.systems` and serves
its contents at the site root. Every file here is public.

- `client-metadata.json` — the atproto OAuth client metadata. Its `client_id`,
  `https://dottie.lamb.systems/client-metadata.json`, is this file's public URL. GitHub serves it
  byte-for-byte: do not add redirects, rewrites or markup. Changing the URL invalidates every
  existing authorization; changing the contents does not.
- `CNAME` — the custom domain. Removing it silently moves the site back to
  `<org>.github.io`, which breaks the `client_id`.
- `.nojekyll` — disables Jekyll processing so files are served exactly as committed.
- `adr/` — architecture decision records. These records are public: they carry identifiers and
  measurements, never tokens, session material or plaintext. Adding a decision here publishes it
  from `main`, so review it for disclosure before committing.

Pages deploys through a plain branch-source build from `docs/` on `main`. There is no deploy
workflow, no write permission and nothing fork-triggerable; pushing to `main` deploys the site.

Before lexicons are published, DNS alone provides the schema authority (`_lexicon.dottie.lamb.systems`
TXT naming a publishing DID); this directory does not serve it.
