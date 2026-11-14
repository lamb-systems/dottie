# Local target configuration

The CLI persists target selections and destination-local consent in
`$XDG_CONFIG_HOME/dottie/config.toml`. If `XDG_CONFIG_HOME` is unset, empty or
relative, the CLI uses the standard `$HOME/.config` location. The file uses schema version 2;
unknown keys and unsupported versions fail closed. Version-1 files upgrade in memory before
validation; writes use version 2. Reading an absent file returns an
in-memory default and creates no directories or files. The configuration directory is
owned by the current user and mode `0700`; the file is mode `0600`.

A target records an identifier, source and, for file selections, a logical base
(`home` or `xdg-config`), relative path and file/directory kind. Absolute paths and an
expanded home directory are never serialized. The XDG configuration base takes
precedence when it is nested under the home directory. A target may store local mode
consent (`auto-apply`, `review` or `backup-only`) and file-root excludes. Without a
per-target mode override, the target inherits the default; an absent default means `review`.
A file target requires a root; a GNOME target is rootless. For example:

```toml
config_version = 2

[defaults]
mode = "review"

[[targets]]
id = "xdg-config-nvim"
source = "files"

[targets.root]
base = "xdg-config"
path = "nvim"
kind = "directory"
exclude = [".git", ".git/**"]

[[targets]]
id = "desktop"
source = "gnome"

[targets.gnome_policy]
approval = "approved"
categories = ["appearance", "fonts", "clock"]
matrix_version = 1
key_digest = "<64 lowercase hex characters>"
```

Target identifiers are portable and remain part of snapshot identity, but local modes
and excludes do not enter portable target records. Remote metadata cannot grant local
filesystem access; roots are resolved from destination-local bases and relative paths.
A GNOME target records its approval state, category IDs, matrix version and lowercase
SHA-256 digest of resolved schema/path/key references. File targets cannot carry this
policy. A pending policy is explicitly unapproved. It has no categories, matrix version
or digest.

Whole-base selections are refused. A selected root must resolve inside one of the two
portable bases, must not overlap another selected root, and must not equal, contain or
be contained by Dottie's configuration, state, cache or data directory. Comparisons
resolve the longest existing ancestor, including symlinked ancestors, and compare path
components rather than textual prefixes. Unavailable or ambiguous stored roots cause a
new addition to fail closed; loading and listing do not require roots to exist.

Adding an already-selected logical root is a no-op unless the supplied identifier,
mode or excludes would change its stored entry; such changes require the explicit mode
or remove command. Removing a selection only stops tracking it and never deletes user
files. `internal/ignore` validates excludes when a config is loaded or validated;
normalization deduplicates them in order. The shared matcher supports `*`, `**`,
`?` and `[class]`; braces and `!` negation are rejected instead of being silently treated
as non-matching text. Validation errors identify the target id, pattern index and pattern
text. Capture applies these local patterns; they are not serialized into portable targets.

Each update writes to a same-directory temporary file, synchronizes it and atomically
renames it. Rename is the visibility commit point: pre-rename errors preserve the previous
file and clean up the temporary file; a directory-sync error after rename reports
uncertain durability and does not claim rollback. A configuration file that is a symlink
to a regular file is read normally, but is never replaced; writes fail with an actionable
error. Directories, FIFOs and other non-regular paths, and dangling or unresolvable
symlinks, are refused on read. Existing owned configuration directories are tightened to
`0700`; foreign-owned or non-directory paths are refused.

## Writes are transactions

`Update` is the only write path. It takes a caller token — the SHA-256 of the exact
configuration bytes the caller read, and zero for an absent file — re-reads the file,
refuses `ErrConfigStale` when the token moved, applies the mutation, validates the
result, encodes it, and publishes it with the atomic write above. A refusal or a
mutation error leaves the previous bytes untouched. Callers re-read and re-apply their
mutation instead of retrying a stale write.

Writes hold `flock(LOCK_EX)` on `<config dir>/config.toml.lock`. The write path creates
the lock file `0600` and, when absent, the configuration directory `0700`; the read path
creates nothing. `AcquireReader` takes `flock(LOCK_SH)` and returns the same snapshot, so
a reader can fence writers for as long as it holds the returned guard. The first write
creates the lock file too, so the fence covers a configuration that predates this contract;
only an absent configuration directory yields a guard that holds nothing.
Locks are advisory and cover one machine and one user: another host, or a process that
writes the file without taking the lock, is not excluded.

Lock order is a leaf rule with one edge: the coordinator mutex is taken before the
configuration lock, and the configuration lock is taken before store calls, so a holder may
use the publication store while holding the configuration lock. Nothing may acquire the
configuration lock while holding store state, and no path takes the two in the opposite
order, which is what keeps the graph deadlock-free.

Acquisition blocks without a timeout: a publication holds the shared lock through its
single submission dispatch, so a concurrent configuration write waits for the transport
call to finish or fail. That wait is bounded only by the caller's transport timeout; it is
documented rather than hidden, and no timeout is invented in the lock itself. A refused
publication leaves its attempt at upload-started with the submission reservation
unconsumed, so the caller must abandon that attempt before preparing another; the service
exposes no abandonment yet and the CLI cutover must add it.

## Digests and revisions

A snapshot carries the content token, the normalized configuration and two identities:
the selection digest with its revision and the approval digest with its revision. The
selection digest covers the default mode and, per target sorted by id, the id, source,
effective mode, root (base, path, kind, excludes) and GNOME policy (approval, categories,
matrix version, key digest). The approval digest covers only the approval fields of
targets that carry a policy, so a selection-only change cannot move it.

The canonical encoding has a fixed field order, an explicit marker for an absent optional,
length-prefixed strings, sorted and de-duplicated exclude and category lists, and modes
canonicalized to the effective value. Reordered targets, reordered or repeated excludes
and categories, comments and an omitted default mode therefore cannot move a digest while
any semantic change does.

`Update` refuses `ErrConfigStale` before touching the file, and then derives both
revisions itself: the first use sets 1, and a change bumps only the counter whose digest
changed. Exhausted counters refuse with `ErrConfigRevisionExhausted` at `math.MaxInt64`
instead of wrapping, and a stored revision above that range is invalid, so it cannot
round-trip through TOML. A revision-only edit is still a content change: it moves the
token and makes a prepared write stale.

Unless supplied explicitly, target identifiers derive deterministically from the logical
base and path. Normalized or truncated collisions are errors. The portable target
conversion retains its identifier, source and logical root while
excluding modes and excludes.

A version-1 GNOME target upgrades to version 2 with approval `pending`; no categories,
keys or digest are inferred. Saving and loading preserve that state. It must be explicitly
re-approved through a later local workflow before use. Version-1 configurations without
GNOME targets upgrade without changing file selections.

The configuration package does not capture files or GNOME settings, interpret excludes, enforce
consent modes, synchronize or restore data, load presets, remap devices, or support
profiles. It does not decide whether a publication may proceed; it only supplies the
identity, token and lock that a publication fences itself with.
