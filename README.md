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

## Compatibility targets

Dottie aims to work across GNOME-based Linux distributions without distribution-
or CPU-specific synchronization logic. The initial validation target is openSUSE
Tumbleweed with GNOME 50 on x86_64 (`linux/amd64`). Other GNOME versions,
distributions and CPU architectures are not yet validated.

Native GSettings/keyring dependencies and packaging must be checked per platform.
Filesystem targets are not inherently GNOME-specific. The initial PDS validation
targets are independently hosted and Bluesky-hosted accounts; neither integration
is implemented or verified yet.

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

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

The canonical repository and Go module path is `github.com/dottorblaster/dottie`.
An owned Lexicon namespace and OAuth metadata host remain to be selected; the
example metadata is not production configuration.
