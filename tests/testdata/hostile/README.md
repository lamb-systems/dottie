# Generated hostile filesystem fixtures

Filesystem capture tests create adversarial trees in `t.TempDir()` at runtime. They generate symbolic links (including dangling, external and looping links), FIFOs and Unix sockets instead of committing those objects. Git checkouts configured with `core.symlinks=false` can materialize committed symlinks as ordinary text files, and Git cannot store FIFO, socket or device nodes. Block and character device classifications are tested with injected file modes rather than privileged device creation.
