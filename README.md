# Dottie

Directory-first preference synchronization for Linux and GNOME, using an existing
Atmosphere account and its PDS.

**Status: synthetic publication privacy and transport-failure checks plus archive-to-plaintext recovery evidence are implemented; the live publication and archive gates remain opt-in. A prior owner-authorized publication attempt exposed the missing pristine-repository precondition; the corrected publication gate has not been rerun.**
Account authorization is available through `dottie account login`, `status` and `logout`;
OAuth sessions and device keys remain in the desktop Secret Service keyring. Config v2
persists GNOME category approval, resolved-key digest and matrix version; version-1 GNOME
targets upgrade to pending re-approval without inferred categories. The coordinator owns
verified reads, content-free preview, candidate-bound restore, recovery, local base recording,
push/sync, device administration, history summaries, export and archive validation. Manual
read/apply requires a local trust checkpoint and a signed-in account; GNOME apply requires a
build with the `gsettings` tag and an available settings backend. Bootstrap generates a new
recovery kit and vault every time and is not idempotent. Explicit multi-vault selection is
supported by these local commands, not promised as a complete multi-vault product feature.

`dottie history` reports local journal/applied-base summaries and checkpoint metadata without
content, settings values, absolute paths or secrets. Without `--did`/`--handle` it works
offline; with one account selector it attempts a verified read and reports `unavailable` or
`auth-expired` distinctly while retaining exit 0. `dottie export --out FILE --kit-file FILE
(--did DID | --handle HANDLE) [--vault HEX] [--anchor HEX] [--overwrite]` writes a complete
ciphertext-only archive through the coordinator's guarded atomic writer (0600). Existing
outputs are refused unless `--overwrite` is explicit. Export authenticates its checkpoint
with the supplied regular kit file, which must have no group/world access and decode to exactly
32 bytes; the kit is cleared and never stored or archived. Export is complete only for its
required authenticated closure and depends on the exporting machine having retained the
authenticated history needed to prove every required predecessor. An onboarding device that
has not observed prior publication heads can refuse export even when the current snapshot is
available. Version-1 count-only attestations with nonzero retained-point counts cannot be
enumerated and refuse export; no archive is written on refusal. Export and onboarding fetch required
snapshot bodies by CID through the verified remote reader; unavailable bodies refuse the workflow.
`dottie prune --plan` inspects retention candidates and separate recovery/confidentiality/unknown
holding floors; `dottie prune --apply --confirm` is the explicit foreground deletion path. Apply
without `--confirm` refuses without deletion. There is no scheduled or automatic garbage collection.
The retained-point cap limits selected epochs, not disk growth, and staged, orphaned or unknown-epoch
material may remain. `dottie import --archive FILE --kit-file FILE --anchor HEX --vault HEX`
requires independent expected vault and anchor inputs plus the kit; it validates the archive in V06
order and changes no state, configuration, target or preference. Validation does not decrypt the
snapshot or establish global freshness.

The command exit codes are 0 for success (including history with remote unavailable), 2 for
usage error, 3 for refusal/conflict/rejection, and 4 for queued, starved, fence-lost,
superseded, unavailable or another partial/indeterminate push/sync/device outcome. Export
succeeds with a complete required closure or refuses; it does not report a partial archive as
success. Push/sync never apply downloaded files or settings; restore remains explicit. Prune
returns 0 for a plan or successful apply, 2 for usage, 3 for refusal (including missing confirmation,
incomplete inventory or an invalid boundary/live-head check), and 4 for partial or indeterminate
apply. Recovery floor is the oldest complete inventory; confidentiality floor is the oldest surviving
known material. Unknown-epoch holdings make the confidentiality floor unknown. The cap bounds retained
epochs, not payload-directory growth. Signed retention attestations use schema version 2 to enumerate ordered recovery points while
preserving version-1 count-only decoding; the tagged two-machine gate exercises export/import
against a shared synthetic MemoryPDS. Offline publication, renderer and source-loss archive tests use
synthetic records, canaries and temporary homes. They do not establish live provider compatibility,
hosted-log visibility or production desktop behavior. The opt-in live publication and archive gates
require explicit disposable-account authorization. The publication gate requires a pristine disposable
repository; a used account, including one carrying ordinary `app.bsky.*` records, is an environment
limitation, not a privacy result. The corrected publication gate and the archive gate have not been run;
a skipped gate is not provider evidence. Real user data must not be used as a fixture.

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
per platform. Filesystem targets are not inherently GNOME-specific. OAuth account
linking uses the native client, but no live authorization or provider test was run.
Repository reads, writes and synchronization against independently hosted or
Bluesky-hosted PDS accounts remain unimplemented and unverified.

## Develop

Requires Go 1.27+ and Git; Make is convenient. The CLI uses Go dependencies declared
in `go.mod` and recorded in `go.sum`; CI verifies that metadata.

```sh
make check
make test-race
make build
make verify
./bin/dottie help
./bin/dottie version
```

Account authorization can be managed with `./bin/dottie account login --handle HANDLE`,
`./bin/dottie account status --did DID` (or `--handle HANDLE`), and
`./bin/dottie account logout --did DID`. Login prints the authorization URL; `--no-browser`
keeps browser opening manual and `--timeout` accepts 1s–15m (default 5m). Status is
offline with `--did`; `--refresh` is explicit. Local logout removes the local session;
`--remote` additionally requests refresh-token revocation and reports only that the
request was accepted. Account sessions require Secret Service and never fall back to
files. These commands do not touch target data.

Use `./bin/dottie push --did DID` to publish reconciled local changes or `./bin/dottie sync --did DID` to verify a pull and then push. Neither applies downloads; restore remains explicit. Use `./bin/dottie prune --plan --did DID` to inspect retention candidates, then `./bin/dottie prune --apply --confirm --did DID` to delete eligible payloads and aged backups. Pruning is manual and foreground-only; no automatic GC or scheduling is enabled. Push/sync/device command exit 0 is committed/no-op, 2 usage error, 3 refusal/conflict/rejection, and 4 queued or other partial/indeterminate non-success. `devices list`, root-only `devices enroll`/`revoke`, and newcomer `account import-bundle` transfer only public onboarding evidence. Recovery kit files must be regular files, decode to 32 bytes, and have group/world permissions removed (`chmod 600 FILE`); Dottie never stores the kit. See the CLI README for command flags and disclosures.

To remove a target whose ID begins with `-`, use `--` to end flag parsing, for example
`./bin/dottie targets remove -- -custom`. Other unimplemented commands return a nonzero status.
`make build` writes to ignored `bin/`. Make defaults to `GOTOOLCHAIN=local`, avoiding
implicit toolchain downloads.
The isolated native GSettings proof is separately opt-in with `make test-gnome` or
`make test-gnome-race` and requires Linux, cgo, a C compiler, GIO development files,
pkg-config and `glib-compile-schemas`; it does not make the CLI source provider
operational. `make verify` checks module integrity and tidiness. `make fuzz` runs each
fuzz target for 30 seconds by default; `FUZZ_TIME` overrides that bound. `make fuzz-smoke`
runs each target for five seconds and is reserved for non-required scheduled/manual
exploration. Fuzz seeds run as part of ordinary `go test` without time-bounded
exploration.

## Publication privacy and archive recovery gates

`go test -count=1 ./tests/integration` runs the offline publication audit against a synthetic
`MemoryPDS`: it scans repository and blob surfaces for plaintext/credential canaries, inventories
recursive record keys, checks typed blob references and models publication failure outcomes. The
source-loss archive test exports through the coordinator, removes the synthetic source records and
blobs, checks that online read/restore refuses without changing local application state, validates the
archive offline, and opens the archived current snapshot with a retained recipient key in a fresh
temporary home. `go test -count=1 ./internal/cli` exercises the package-internal renderer privacy
contract. These tests use synthetic data only.

The live publication gate skips by default. It requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1`, an
allowlisted disposable identity in `DOTTIE_HANDLE`, and explicit authorization; before writing the
manifest or records, it checks `com.atproto.repo.describeRepo` and skips repositories with any collections.
Genesis requires an empty repository. It writes synthetic canary records and cannot remove provider blobs.
The live archive gate also skips by default and requires `DOTTIE_LIVE_ARCHIVE=1`, an allowlisted `DOTTIE_HANDLE`, and
`DOTTIE_RECOVERY_KIT_FILE` naming a private regular file with no group/world permission bits that
decodes to a 32-byte kit, plus explicit disposable-account authorization. It uses the existing local vault selection/checkpoint and a temporary archive path;
export and archive validation are read-only and the gate rejects repository write endpoints. The archive
gate does not invoke genesis and does not depend on the publication gate's pristine-repository precondition.
A previous owner-authorized publication attempt stopped at genesis on a used repository; the corrected
publication gate and archive gate have not been run against a provider. A skipped gate is not provider
evidence. Hosted provider logs and server-side storage are not observable from a client.

## Local restore gate

[`tests/local/restore_gate_test.go`](tests/local/restore_gate_test.go) composes filesystem capture, reconciliation preview, journaled apply and rollback on a synthetic Neovim tree plus a custom WM root under temporary directories. It checks automatic module inclusion, combined file edits, rename planning, missing-root and unsafe-link refusals, local-only exclusions, convergence, repeatability, and preservation of a newer edit during rollback. Run it offline with `go test -v ./tests/local`. This is an internal integration proof, not a CLI workflow; it does not exercise GNOME, network services, remote publication or a real home directory.

## Combined GNOME/files restore gate

Run `make test-gnome` for the offline restore gate, or `make test-gnome-race` for
its race-enabled form. It runs one combined filesystem-and-settings restore scenario
against both the native GSettings keyfile backend and the native dconf backend. The
dconf run uses the real `dconf-service` activated on a temporary private D-Bus; both
runs use isolated temporary homes and XDG paths, compiled synthetic schemas with
canonical source defaults and different vendor destination defaults, and pre-created
selected directory skeletons with matching modes. The gate checks exact setting and
file values, reset behavior, convergence and no-op re-apply, unrelated cross-schema
sentinels, and journaled rollback while preserving newer file and setting edits. It
also checks missing keys and schemas, plus a 12-key synthetic per-key older-schema
subset (not older category compatibility).

**Real versus simulated boundary:** the gate exercises the real keyfile backend and
real dconf backend with a real dconf service on a temporary private bus, synthetic
schemas, isolated temporary homes, prepared directory selections, and simulated
locks. It does not use a production desktop session or profile, real user preferences,
system-db lockdown, a VM, or CLI wiring. The locked case decorates the real backend to
report one setting as non-writable; it does not validate real lockdown. Restore is
proved only into prepared directory selections: applying a file preview creates files
inside existing roots, not a missing selected root or directory hierarchy. The
unrelated-settings check is cross-schema preservation, not key-level isolation within
the schema being written. The 12-key older-surface case is a synthetic per-key subset,
not evidence of support for older GNOME categories or automatic degradation.

## Empty-remote two-machine gate

Run `go test -count=1 -tags gsettings ./tests/local` for the offline S2b2 scenario. Publisher A bootstraps and publishes through the real genesis, publication and transition compositions over one shared `atprototest.MemoryPDS`; newcomer B has an independent temporary HOME/XDG tree, state store, fake keyring and device keys. Both use the real `atproto.VaultReader`. A publishes a review-mode file target and approved GNOME appearance category, enrolls B as restore-only and exports the public onboarding bundle. B imports it with the independently supplied anchor, authenticates the successor using imported predecessor evidence, then previews and restores exact file bytes/mode and GNOME present/reset intent through the coordinator. The gate also checks no-op publication/restore, restore-only and revoked-device push refusals, wrong-kit and wrong-anchor controls, stale predecessor refusal, fingerprint-confirmed revocation and historical decryption as a positive control.

**Real versus simulated boundary:** repository signatures, CAR/revision reads, vault authentication/decryption, genesis/publication/transition compositions, MemoryPDS writes, coordinator policy and the native GNOME keyfile backend are real package code. MemoryPDS and all data are synthetic; homes, XDG paths, schemas, keys and settings are temporary. Keyfile operations run in short-lived helper processes so each machine gets an independently initialized process-global GSettings backend. No live PDS, CLI binary sequence, real account, real keyring, desktop session, dconf service or user preference is used. Full CLI-binary acceptance remains deferred to post-S3.

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
preferences or a PDS account. Preset and manifest validators are deferred to the versioned preset-catalog
work; the source-comment policy remains a review concern, not an automated check. CI does not build release artifacts, sign or publish anything.

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

The default executable remains the CLI and its unit tests. Manual push/sync and device administration use the coordinator; restore remains explicit and journaled. Account login/status/logout manage OAuth sessions, and no background synchronization service is wired.
Other component directories document their responsibilities. Presets, OAuth metadata
and the systemd unit are draft examples, not functioning synchronization integrations
or deployable configuration.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

The canonical repository and Go module path is `github.com/lamb-systems/dottie`.
An owned Lexicon namespace and OAuth metadata host remain to be selected; the
example metadata is not production configuration.
