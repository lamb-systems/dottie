# Linux integration

The platform package resolves `$HOME` and the XDG config, state, cache and data
locations. An unset, empty or relative XDG value uses its standard default under an
absolute `$HOME`; an absolute XDG value is used as configured. The application-local
locations are named `dottie` beneath their corresponding bases.

Filesystem resolution handles absent path tails by resolving the longest existing
ancestor, including symlinks, and then rejoining the remainder. Broken links,
non-directory ancestors and inaccessible ancestors fail closed rather than falling back
to lexical path cleaning. This resolution is used when comparing selected roots and
Dottie's own data locations.

Secret Service integration and private IPC locations are not implemented. A locked or
missing keyring must pause secure work; credentials must never be silently stored in a
selected directory.

`LockFile` opens a private lock file with `O_CLOEXEC` (Go's default) specified explicitly,
so exec'd helpers do not inherit the lock descriptor, and uses non-blocking exclusive
`flock`. Lock ownership is
per open file description and is released when the lock is closed or the process exits.
This is an advisory coordinator lock for local filesystems; NFS cross-host exclusion is
unsupported.

## Secret Service

`keyring_linux.go` talks to `org.freedesktop.secrets` over D-Bus. It resolves the **default**
collection only: custom collection aliases are not portable (gnome-keyring rejects them with
`Only the 'default' alias is supported`), so Dottie never creates, renames or relabels a
collection and instead scopes its items with `application=dottie` and `name=<item>` attributes.
A missing or locked collection yields a typed error and no plaintext fallback; the underlying
D-Bus failure is included in the message.
