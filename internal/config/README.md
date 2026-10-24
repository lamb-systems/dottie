# Local target configuration

The CLI persists target selections and destination-local consent in
`$XDG_CONFIG_HOME/dottie/config.toml`. If `XDG_CONFIG_HOME` is unset, empty or
relative, the standard `$HOME/.config` location is used. The file uses schema version 1;
unknown keys and unsupported versions fail closed. Reading an absent file returns an
in-memory default and creates no directories or files. The configuration directory is
owned by the current user and mode `0700`; the file is mode `0600`.

A target records an identifier, source and, for file selections, a logical base
(`home` or `xdg-config`), relative path and file/directory kind. Absolute paths and an
expanded home directory are never serialized. The XDG configuration base takes
precedence when it is nested under the home directory. A target may store local mode
consent (`auto-apply`, `review` or `backup-only`) and file-root excludes. An absent
per-target mode override inherits the default, whose absent value means `review`.
A file target requires a root; a GNOME target is rootless. For example:

```toml
config_version = 1

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
```

Target identifiers are portable and remain part of snapshot identity, but local modes
and excludes do not enter portable target records. Remote metadata cannot grant local
filesystem access; roots are resolved from destination-local bases and relative paths.

Whole-base selections are refused. A selected root must resolve inside one of the two
portable bases, must not overlap another selected root, and must not equal, contain or
be contained by Dottie's configuration, state, cache or data directory. Comparisons
resolve the longest existing ancestor, including symlinked ancestors, and compare path
components rather than textual prefixes. Unavailable or ambiguous stored roots cause a
new addition to fail closed; loading and listing do not require roots to exist.

Adding an already-selected logical root is a no-op unless the supplied identifier,
mode or excludes would change its stored entry; such changes require the explicit mode
or remove command. Removing a selection only stops tracking it and never deletes user
files. Excludes are validated by `internal/ignore` when a config is loaded or validated,
and are deduplicated in order when normalized. The shared matcher supports `*`, `**`,
`?` and `[class]`; braces and `!` negation are rejected instead of being silently treated
as non-matching text. Validation errors identify the target id, pattern index and pattern
text. Capture applies these local patterns; they are not serialized into portable targets.

Updates are written to a same-directory temporary file, synchronized and atomically
renamed. Rename is the visibility commit point: pre-rename errors preserve the previous
file and clean up the temporary file; a directory-sync error after rename reports
uncertain durability and does not claim rollback. A configuration file that is a symlink
to a regular file is read normally, but is never replaced; writes fail with an actionable
error. Directories, FIFOs and other non-regular paths, and dangling or unresolvable
symlinks, are refused on read. Existing owned configuration directories are tightened to
`0700`; foreign-owned or non-directory paths are refused.

Target identifiers are deterministically derived from the logical base and path unless
an explicit identifier is supplied. Normalized or truncated collisions are errors. The
portable target conversion retains its identifier, source and logical root while
excluding modes and excludes.

This component does not capture files or GNOME settings, interpret excludes, enforce
consent modes, synchronize or restore data, load presets, remap devices, or support
profiles and config migration. Multi-process writes are not locked and currently use
last-writer-wins semantics. Locking must be implemented before consent modes are
actively enforced.
