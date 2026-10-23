# AT Protocol transport — not implemented

DID/PDS discovery, SDK-based OAuth, same-revision record membership proofs, blob
lifecycle and conditional publication.

Stage ciphertext only as temporary, unreferenced blobs. Publish the first typed
blob references and accepted head/control changes atomically with `applyWrites`
and `swapCommit`. A stale writer must refetch policy and re-encrypt when needed;
it must not publish an old-epoch candidate before checking the transaction.

Verify temporary-blob nonvisibility, failed-transaction atomicity and coherent record
reads against supported providers. Valid signatures alone do not prove records
belong to the transaction's repository revision. Provider failures must not trigger
unconditional retries, broadened permissions or silent identity changes.

This scaffold reads no credentials and contacts no services.
