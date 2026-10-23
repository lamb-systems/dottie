# Dottie

Directory-first preference synchronization for Linux and GNOME, using an existing
Atmosphere account and its PDS.

**Status: scaffold only.** The binary implements help and version output. Account
linking, capture, encryption, synchronization, restore, and the background service
are not implemented. Do not use this scaffold to back up real data.

## Target design

**Select directories. Reconcile files. Store encrypted snapshots.**

- One executable: CLI commands and a per-user background service.
- Two configuration sources: recursive files/directories and GNOME GSettings.
- Declarative application presets, starting with Neovim; no application parsers.
- Automatic inclusion of new files in approved roots and file-level conflicts.
- Per-target consent: automatic apply, download-and-review, or backup-only.
- Client-side encryption, independent recovery, and authenticated device roles.
- Atomic publication of snapshot references and the accepted remote head.

Applications keep their normal configuration locations. Machine-specific files can
remain local through explicit exclusions. Presets cannot execute hooks or expand
local permissions silently.

The initial scope is a Linux/GNOME CLI and background synchronizer. A GUI, package
installation, privileged system configuration, and other desktop platforms are
outside that scope.

## Develop

Requires Go 1.27+ and Git; Make is convenient. The scaffold uses only the standard
library. A `go.sum` will be generated when external dependencies are introduced.

```sh
make check
make test-race
make build
./bin/dottie help
./bin/dottie version
```

Unimplemented commands return a nonzero status. `make build` writes to ignored
`bin/`. Make defaults to `GOTOOLCHAIN=local`, avoiding implicit toolchain downloads.

## Layout

| Path | Responsibility |
| --- | --- |
| `cmd/dottie`, `internal/cli` | Executable entry point and commands |
| `internal/service`, `internal/syncengine` | Coordination, reconciliation and journaled apply |
| `internal/source` | Filesystem and GNOME integration |
| `internal/config`, `internal/model`, `internal/preset` | Targets, local policy and portable data |
| `internal/vault`, `internal/remote` | Encrypted snapshots and PDS transport |
| `internal/state`, `internal/platform` | Persistence and Linux integration |
| `lexicons`, `web` | Record definitions and static OAuth metadata |
| `packaging`, `tests` | Distribution and integration coverage |

Only the CLI entry point and its unit tests are executable today. Other component
directories document their responsibilities. Presets, OAuth metadata and the
systemd unit are draft examples, not functioning integrations or deployable configuration.

## Release prerequisites

A license, canonical repository/module path, owned Lexicon namespace, and OAuth
metadata host have not been selected. The local module name is currently `dottie`.
