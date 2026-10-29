# Public client metadata — not yet deployed

`public/client-metadata.json` is the atproto OAuth client metadata for Dottie. It is a
**native public client**, so its `client_id` is the HTTPS URL where this exact file must be
served: `https://dottie.lamb.systems/client-metadata.json`.

The file is authored here and deployed by the operator to a static HTTPS host at that path.
Until it is served, native OAuth cannot be validated and this directory is configuration, not
a working endpoint.

## Deployment contract

- Serve the file byte-for-byte at the `client_id` URL with a valid TLS certificate for
  `dottie.lamb.systems`. Any rewrite, redirect or injected markup breaks client resolution.
- Keep the URL stable. `client_id` is the client's only identity; changing it invalidates
  existing authorizations.
- No server, no PDS and no dynamic code is required — DNS plus static files are enough.
- The `scope` value must name the NSIDs the release actually publishes. The current entries
  are the intended Dottie record types and remain provisional until the schema publication
  task replaces them with validated lexicons.
- `redirect_uris` lists the loopback callback used by the CLI. Provider acceptance of the
  port-less loopback form is verified in the OAuth proof task, not assumed here.

## Remaining before this is real

- Deploy the file and confirm retrieval over HTTPS.
- Reconcile the NSIDs above with the published lexicon schema; the earlier scaffold used a
  `vault/head/snapshot` collection layout, which the current names replace.
- CI does not yet validate this file; that arrives with the schema publication task.
