# Dottie

Directory-first preference synchronization for Linux and GNOME, using an existing
Atmosphere account and its PDS.

**Status: target selection and consent policy persist locally.** Capture, apply,
encryption, synchronization, restore, account linking and the background service
remain unimplemented. An opt-in internal GSettings feasibility boundary tests only
synthetic isolated memory/null backends; it is not CLI capture/apply or a production
desktop provider. Do not use this scaffold to back up real data.

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

The native GSettings feasibility boundary has a documentation-derived 2.40 GIO
API floor, set by the newest minimum version among the symbols used; runtime
observation is limited to GIO/GLib 2.88.4. This does not validate older libraries,
GNOME 50 or another architecture. Native dependencies and packaging must be checked
per platform. Filesystem targets are not inherently GNOME-specific. The initial PDS
validation targets are independently hosted and Bluesky-hosted accounts; neither
integration is implemented or verified yet.

## Develop

Requires Go 1.27+ and Git; Make is convenient. The default CLI build uses only the
standard library. Go dependencies are declared in `go.mod` and recorded in
`go.sum`; CI verifies that metadata.

```sh
make check
make test-race
make build
make verify
./bin/dottie help
./bin/dottie version
```

Unimplemented commands return a nonzero status. `make build` writes to ignored
`bin/`. Make defaults to `GOTOOLCHAIN=local`, avoiding implicit toolchain downloads.
The isolated native GSettings proof is separately opt-in with `make test-gnome` or
`make test-gnome-race` and requires Linux, cgo, a C compiler, GIO development files,
pkg-config and `glib-compile-schemas`; it does not make the CLI source provider
operational. `make verify` checks module integrity and tidiness. `make fuzz` runs each
fuzz target for 30 seconds by default; `FUZZ_TIME` overrides that bound. `make fuzz-smoke`
runs each target for five seconds and is reserved for non-required scheduled/manual
exploration. Fuzz seeds run as part of ordinary `go test` without time-bounded
exploration.

## Continuous integration

GitHub Actions runs required checks on pull requests and pushes to `main`. The default
job verifies Go module integrity and tidiness, formatting, vet, ordinary and race test
suites, the fuzz seed corpora, the CLI build, and cgo-disabled tests/builds. Its JSON
skip checks count only records with a non-empty test name and `Action == "skip"`; a
package-level `no test files` record is not treated as a skipped test. The job also
cross-builds for Linux amd64 and arm64 with cgo disabled and runs version/help smoke
checks on the amd64 binary only. A separate native GSettings job checks the isolated
boundary and race tests, with the same test-level skip detection.

A separate workflow, not a required check, runs bounded fuzz exploration on a schedule
or manual dispatch. It has no credentials or dependency cache. CI proves builds and
checks on its configured hosted runner, but this patch has no hosted-run evidence: an
owner-triggered run is still needed. The arm64 result is compile-only; arm64 runtime
behaviour is unproven. These checks do not exercise a real desktop session, real user
preferences or a PDS account. Preset and manifest validators are deferred to DOT-L03's
versioned preset-catalog task; the source-comment policy remains a review concern, not
an automated check. CI does not build release artifacts, sign or publish anything.

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

The default executable remains the CLI and its unit tests. Opt-in native tests
exercise an isolated GSettings boundary, but no source provider is wired into the
CLI. Other component directories document their responsibilities. Presets, OAuth
metadata and the systemd unit are draft examples, not functioning integrations or
deployable configuration.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

The canonical repository and Go module path is `github.com/dottorblaster/dottie`.
An owned Lexicon namespace and OAuth metadata host remain to be selected; the
example metadata is not production configuration.
