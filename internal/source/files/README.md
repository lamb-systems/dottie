# Filesystem capture

A selection is captured recursively as a deterministic set of per-path observations. Present regular files preserve their bytes and permission bits; empty files carry an explicit empty payload. Directories below a selected directory are present entries with their permission bits, while the selected directory itself is not an entry. A captured regular single-file selection emits one observation at `.`. For that case, the anchored directory is `filepath.Dir(selectedPath)`, the handle-relative name is `filepath.Base(selectedPath)`, and the emitted identity remains `.`.

Captures are bounded by `DefaultBudget()`:

- `MaxEntries`: 20,000 paths captured below the selection (a single-file selection counts its one file)
- `MaxDepth`: 32 path components below the selection
- `MaxFileBytes`: 8 MiB per regular file
- `MaxTotalBytes`: 256 MiB of regular-file content

Crossing any limit returns a typed budget error identifying the limit, path, and observed value. No partial capture is returned with a budget error.

The selected directory, or the parent of a selected file, is opened once as an `os.Root`. Classification, link reading, directory listing, and file opening use that anchored handle. Link targets are read only with `root.Readlink(name)`; capture never reconstructs a host path and calls `os.Readlink`. Final-component no-follow opens and post-open device/inode checks ensure a regular file swapped for a link or special file is not read. Directory opens also refuse a final-component symlink. Stability is judged from device, inode, size and modification time: a single unstable regular-file read is retried once, a second instability becomes unknown, and a concurrent rewrite that preserves all four of those attributes within one capture is not detected.

Lexical link containment is only a representation decision. The anchored `os.Root` remains the I/O authority; a link target is never opened or descended into, whether or not an external relative link was approved. Internal links are represented as symlink entries with their verbatim target text. This includes dangling internal links and lexically internal loops, because capture never follows them. A relative target that resolves lexically above the root is external: it is skipped unless its root-relative link-entry path appears in `Root.AllowExternal`, in which case it is represented without following it. Absolute targets are always skipped, even when allowlisted, because the portable model rejects absolute link targets. Supporting absolute link representation requires a separate model-contract change.

`Root.Exclude` contains local-only root-relative slash-path patterns. It has no built-in defaults: hidden files, `*.lua`, `plugin/` and `.git` are retained unless an exclude says otherwise. Syntax is `*` (within one path segment), `**` (a complete recursive segment), `?` (one non-separator character), and `[class]`. Examples and boundary behavior:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `*.log` | `a.log` | `dir/a.log`, `a.log.bak` |
| `**/*.log` | `a.log`, `dir/a.log`, `a/b/a.log` | `a.log.bak` |
| `a/**` | `a`, `a/x`, `a/b/c` | `ab`, `b/a` |
| `a/**/b` | `a/b`, `a/x/b`, `a/x/y/b` | `a/x/bb`, `b` |
| `**` | every path below the root | — |
| `?` | `a` | `ab`, `a/b` |
| `[a-c]x` | `ax`, `cx` | `dx`, `Ax` |

Empty patterns, `.`, braces, `!`, backslash, leading `/`, any `..` segment, trailing `/`, `//`, patterns over 4096 bytes, more than 16 `**` segments per pattern and lists over 64 patterns are rejected. The matcher is compiled once per capture and configuration validation delegates to the same `internal/ignore` implementation. Matching uses the pinned doublestar v4.10.3 implementation against root-relative slash paths.

The first matching pattern in configuration order wins. When a directory matches, capture records one excluded skip for that directory and prunes its entire subtree without visiting descendants. A matching file is skipped while other entries remain capturable. A pattern that matches a descendant is not inherited by the matcher; pruning makes descendants unreachable, so they produce no separate skip. Budget accounting happens before the exclude decision, so an entry that is about to be pruned still counts once against `MaxEntries` and `MaxDepth`, while its pruned subtree is never counted.

Skip reasons emitted by this capture path are `external-link`, `excluded`, and `special-file`. The `symlink` reason value is not emitted: links are represented or classified as external. `Detail` contains the external target text or winning exclude pattern; it is bounded to 4096 bytes, valid UTF-8, and control bytes are escaped. `Detail` is untrusted input and every consumer must escape it for its output context. I/O errors, permission failures, races and disappearance produce an `unknown` observation, never a missing observation. Policy skips likewise never imply deletion.

| Reason | Meaning | Detail |
| --- | --- | --- |
| `external-link` | Absolute target, or relative target that lexically escapes and is not approved | Link target text |
| `excluded` | Entry matched a local exclude pattern | First matching pattern |
| `special-file` | FIFO, socket, block device or character device | Empty |

Budgets, deterministic parent-before-child ordering, opaque file contents and the unknown-on-failure rule remain unchanged. DOT-B04 owns external-link approval UX and persistence; approvals here are caller-supplied only. Link apply/restore is deferred to DOT-L10.
