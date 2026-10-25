# Bounded portable snapshots

`Pack` and `Unpack` encode complete `model.Snapshot` values in a deterministic, uncompressed
USTAR container. The manifest carries the snapshot version, codec (`none`), complete target
records and a lossless wire entry for each file or GSettings entry. Tar member names are
opaque six-digit ordinals: `000000` is the manifest and later ordinals identify entries in
canonical order. Logical paths and symlink targets remain in the manifest. All tar records
use a pinned regular-file header; PAX/GNU extensions, other record types, non-ordinal names
and trailing data are rejected.

`Pack` accepts an already-reconciled desired snapshot. Omitted paths stay omitted; packing
does not observe a filesystem or invent tombstones. Explicit deleted entries remain
tombstones. `Estimate` reports plaintext bytes by target in target-id order and identifies
relative symlink targets that lexically escape the selected root. `Unpack` returns only an
in-memory snapshot; this package has no extraction API and performs no symlink containment
check. DOT-L10 owns re-containment and fresh external-link consent at apply time.

Default bounds are aligned with filesystem capture where applicable:

| Bound | Default |
| --- | ---: |
| Entries | 20,000 |
| Relative nesting depth (`.` is depth 0) | 32 |
| One payload member | 8 MiB |
| Total payload bytes | 256 MiB |
| Manifest | 16 MiB |
| Path | 4,096 bytes |

`PackWithLimits`, `UnpackWithLimits` and `EstimateWithLimits` allow callers and tests to
apply a tighter `Limits` set. Any exceeded bound returns `*BoundError` with its kind, path,
limit and observed value; no partial snapshot is returned. Unpack rejects oversized tar
header declarations before allocating a body, reads each body through a size-limited reader,
and counts bytes actually read.

Per-entry SHA-256 values and the whole-container digest detect accidental corruption and
truncation. These digests are integrity-only, not authenticity: until DOT-V02, an attacker
who can replace a blob can also replace its manifest and digests. No encryption, signing,
compression, remote publication, reconciliation, merging or apply operation is implemented
here.

## Size measurements

Measurements use the canonical `codec = none` archive. The synthetic tree contains one
`config/` directory and the specified number of files, each with deterministic 256-byte
content; the large-file case contains one 4 MiB file and its parent directory. Packed sizes
include the manifest, tar headers and padding. The gzip column is a standard-library
measurement only; no compressed codec is implemented or emitted.

| Tree | Entries | Plaintext payload | Uncompressed blob | Gzip reference |
| --- | ---: | ---: | ---: | ---: |
| `tests/testdata/neovim` fixture | 8 | 388 B | 9,728 B | 984 B |
| Synthetic, 1,000 files | 1,001 | 256,000 B | 1,239,552 B | 23,281 B |
| Synthetic, one 4 MiB file | 2 | 4,194,304 B | 4,197,888 B | 8,683 B |

The committed golden fixture pins exact uncompressed archive bytes. The gzip comparison is
informational only; this lane adds no compression dependency and keeps the codec `none`.
