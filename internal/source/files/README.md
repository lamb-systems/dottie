# Filesystem capture

A selection is captured recursively as a deterministic set of per-path observations. Present regular files preserve their bytes and permission bits; empty files carry an explicit empty payload. Directories below a selected directory are present entries with their permission bits, while the selected directory itself is not an entry. A captured regular single-file selection emits one observation at `.`. For that case, the anchored directory is `filepath.Dir(selectedPath)`, the handle-relative name is `filepath.Base(selectedPath)`, and the emitted identity remains `.`.

Only symbolic links and special files are skipped by policy. Links are not followed or represented as present entries; special files such as FIFOs are not read. Filesystem errors, unreadable paths, disappearance, and detected races produce an unknown observation for the affected path, never a missing observation. A failed or incomplete capture therefore cannot imply deletion.

Captures are bounded by `DefaultBudget()`:

- `MaxEntries`: 20,000 paths captured below the selection (a single-file selection counts its one file)
- `MaxDepth`: 32 path components below the selection
- `MaxFileBytes`: 8 MiB per regular file
- `MaxTotalBytes`: 256 MiB of regular-file content

Crossing any limit returns a typed budget error identifying the limit, path, and observed value. No partial capture is returned with a budget error.

The selected directory, or the parent of a selected file, is opened once as an `os.Root`; classification, directory listing, and file opening all use that handle. This keeps path resolution anchored beneath that directory and prevents ancestor swaps from escaping it. Final-component no-follow opens and post-open device/inode checks ensure a file swapped for a link or special file is not read. Regular-file reads are bounded to one byte beyond the per-file limit, and nonblocking mode is cleared only after the descriptor has been verified. Stability is judged from device, inode, size and modification time: a single unstable read is retried once, a second instability becomes unknown, and a concurrent rewrite that preserves all four of those attributes within one capture is not detected.

Directory entries are sorted by name. Observations are returned with parents before children and lexical ordering within each depth, so unchanged trees produce deeply equal captures. File contents are opaque bytes and are never interpreted or executed.

A later filesystem extension will add link representation, an explicit approval boundary for external links, and glob-based excludes. Those behaviors are not part of capture here.
