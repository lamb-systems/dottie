# Remote boundary — not implemented

Expose coherent-read/stage/conditional-publication operations, not unrelated CRUD
that lets a caller accidentally publish before checking policy. Only ciphertext and
minimal public references enter this boundary. Do not add a speculative Spaces
implementation or silently fall back from private to public storage.
