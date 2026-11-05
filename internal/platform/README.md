# Linux integration

The platform package resolves `$HOME` and the XDG config, state, cache and data
locations. An unset, empty or relative XDG value falls back to its standard default under an
absolute `$HOME`; an absolute XDG value is used as configured. Application-local
locations use the name `dottie` beneath their corresponding bases.

Filesystem resolution handles absent path tails by resolving the longest existing
ancestor, including symlinks, and then rejoining the remainder. Broken links,
non-directory ancestors and inaccessible ancestors fail closed rather than falling back
to lexical path cleaning. Comparisons of selected roots and Dottie's own data
locations use this resolution.

Private IPC locations are not implemented. Secret Service keyring failures must pause
secure work; credentials and device keys are never silently stored in a selected directory.

`LockFile` opens a private lock file with `O_CLOEXEC` (Go's default) specified explicitly,
so exec'd helpers do not inherit the lock descriptor, and uses non-blocking exclusive
`flock`. Each open file description owns its lock; closing the lock or exiting the
process releases it.
This is an advisory coordinator lock for local filesystems; NFS cross-host exclusion is
unsupported.

OAuth session commands use `SessionLockPath` for one login-session lock namespace, independent of
`XDG_STATE_HOME`: an absolute existing `XDG_RUNTIME_DIR` is preferred, then an existing
`/run/user/<uid>`, then the OS temporary directory. The lock filename includes the effective uid.
`LockFile` opens it, rejects symlinks/non-regular files, enforces mode 0600 and takes
a non-blocking exclusive `flock`. A process deliberately using another runtime directory, a
non-cooperating process, or manual keyring changes are outside this advisory coordination guarantee.

## Secret Service

`keyring_linux.go` talks to `org.freedesktop.secrets` over D-Bus. It resolves the **default**
collection only: custom collection aliases are not portable (gnome-keyring rejects them with
`Only the 'default' alias is supported`), so Dottie never creates, renames or relabels a
collection and instead scopes its items with `application=dottie` and `name=<item>` attributes.
A missing or locked collection yields a typed error and no plaintext fallback. One item encodes
device signing and X25519 recipient private keys together, with attributes
`application=dottie` and `name=dottie:device:<vault-hex>:<device-id>`. Missing device items return
`ErrKeyringItemNotFound`; keyring service failures return `ErrKeyringUnavailable` (a locked
collection remains `ErrKeyringLocked`). There is no file fallback.

Secret Service is at-rest protection, not an authority boundary against a compromised session.
A process running in the unlocked user session can access secrets that the user can access; a
keyring does not make an already-compromised session trustworthy.
