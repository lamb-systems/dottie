# Dottie

Directory-first preference synchronization for Linux and GNOME, using an existing
Atmosphere account and its PDS.

**Status: publication privacy, transport-failure, checkpoint-backed archive-restore and two-home
restore evidence are implemented; the live publication, archive and two-home restore gates have run
against a disposable account and the owner accepted [`docs/acceptance.md`](docs/acceptance.md) on
2026-11-05. Real-data use is permitted under the residual limits recorded there: kit custody, no
global freshness, one published vault per account, and provider-held records and ciphertext that
cannot be deleted.**
Use `dottie account login`, `status` and `logout` for account authorization;
OAuth sessions and device keys remain in the desktop Secret Service keyring. Config v2
persists GNOME category approval, resolved-key digest and matrix version; version-1 GNOME
targets upgrade to pending re-approval without inferred categories. The coordinator owns
verified reads, content-free preview, candidate-bound remote and archive restore, recovery, local base recording,
push/sync, device administration, history summaries, export and archive validation. Manual
read/apply requires a local trust checkpoint and a signed-in account; GNOME apply requires a
build with the `gsettings` tag and an available settings backend. `account bootstrap` requires a
verified empty repository and a signed-in account. It checks repository emptiness before minting
keys or a kit, stores device keys in Secret Service, prints and flushes the recovery kit before
publication, then records trust atomically after verified publication. An account can hold only
one published Dottie vault because genesis requires an empty repository. Multi-vault selection
refers only to locally recorded vaults, not multiple published vaults on one account.

`dottie history` reports local journal/applied-base summaries and checkpoint metadata without
content, settings values, absolute paths or secrets. Without `--did`/`--handle` it runs
offline. With one account selector, it attempts a verified read, distinguishes `unavailable` from
`auth-expired`, and still exits 0. `dottie export --out FILE --kit-file FILE
(--did DID | --handle HANDLE) [--vault HEX] [--anchor HEX] [--overwrite]` writes a complete
ciphertext-only archive through the coordinator's guarded atomic writer (0600). Export refuses existing
outputs unless `--overwrite` is explicit. Export authenticates its checkpoint
with the supplied regular kit file, which must have no group/world access and decode to exactly
32 bytes; the kit is cleared and never stored or archived. Export is complete only for its
required authenticated closure. The exporting machine must have retained the
authenticated history needed to prove every required predecessor. An onboarding device that
has not observed prior publication heads can refuse export even when the current snapshot is
available. Version-1 count-only attestations with nonzero retained-point counts cannot be
enumerated and refuse export; no archive is written on refusal. Export and onboarding fetch required
snapshot bodies by CID through the verified remote reader; unavailable bodies refuse the workflow.
`dottie restore --archive FILE --kit-file FILE --anchor HEX --target ID [--vault HEX] [--device-id ID] [--confirm DIGEST]` restores only the kit-signed checkpoint position through the ordinary candidate-bound journaled apply path; it does not contact a provider and the archive may not be newest. The kit authorizes/checks the checkpoint but cannot decrypt. Decryption requires a compatible surviving device recipient private key. Losing all device keys without an independent complete export is data loss; an archive also needs a compatible retained recipient key. `dottie prune --plan` inspects retention candidates and separate recovery/confidentiality/unknown
holding floors; `dottie prune --apply --confirm` is the explicit foreground deletion path. Apply
without `--confirm` refuses without deletion. There is no scheduled or automatic garbage collection.
The retained-point cap limits selected epochs, not disk growth, and staged, orphaned or unknown-epoch
material may remain. `dottie import --archive FILE --kit-file FILE --anchor HEX --vault HEX`
requires independent expected vault and anchor inputs plus the kit. It validates the archive in the defined refusal order without changing any state, configuration, target or preference. Validation does not decrypt the snapshot or establish global freshness.

The command exit codes are 0 for success (including history with remote unavailable), 2 for
usage error, 3 for refusal/conflict/rejection, and 4 for queued, starved, fence-lost,
superseded, unavailable or another partial/indeterminate push/sync/device outcome. Export
succeeds with a complete required closure or refuses; it does not report a partial archive as
success. Push/sync never apply downloaded files or settings; restore remains explicit. Prune
returns 0 for a plan or successful apply, 2 for usage, 3 for refusal (including missing confirmation,
incomplete inventory or an invalid boundary/live-head check), and 4 for partial or indeterminate
apply. The recovery floor is the oldest complete inventory; the confidentiality floor is the oldest surviving
known material. Unknown-epoch holdings make the confidentiality floor unknown. The cap bounds retained
epochs, not payload-directory growth. Signed retention attestations use schema version 2 to enumerate ordered recovery points while
preserving version-1 count-only decoding. Offline publication, renderer, checkpoint-backed restore,
source-loss archive and rollback tests use synthetic records and temporary homes. They do not establish
provider compatibility, hosted-log visibility or production desktop behavior. The tagged keyfile twin is
`TestRestoreMilestoneGNOMEKeyfileTwoHome` and runs under `make test-gnome`. The live two-home restore
gate requires explicit disposable-account authorization and an already-existing readable Dottie vault; it
never invokes genesis, refuses nonempty application content, publishes only synthetic data and does not
delete records. The ephemeral test device's public enrollment remains, but its private
key is not retained. The separate live publication-privacy gate still requires a pristine disposable repository
because that gate tests genesis. A skipped gate is not provider evidence. No live restore result is claimed;
real user data is permitted only under the residual limits in `docs/acceptance.md`, which the owner accepted on 2026-11-05.

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

Dottie targets GNOME-based Linux distributions without distribution-
or CPU-specific synchronization logic. The initial validation target is openSUSE
Tumbleweed with GNOME 50 on x86_64 (`linux/amd64`). Other GNOME versions,
distributions and CPU architectures are not yet validated.

The native GSettings feasibility boundary has a documentation-derived 2.40 GIO
API floor: the highest minimum version among the symbols used. Runtime
observation is limited to GIO/GLib 2.88.4. This does not validate older libraries,
GNOME 50 or another architecture. Native dependencies and packaging must be checked
per platform. Filesystem targets are not inherently GNOME-specific. OAuth account
linking uses the native client, but no live authorization or provider test was run.
Repository reads, writes and synchronization against independently hosted or
Bluesky-hosted PDS accounts remain unimplemented and unverified.

## Develop

Development requires Go 1.27+ and Git; Make is convenient. The CLI uses Go dependencies declared
in `go.mod` and recorded in `go.sum`; CI verifies that metadata.

```sh
make check
make test-race
make build
make verify
./bin/dottie help
./bin/dottie version
```

Manage account authorization with `./bin/dottie account login --handle HANDLE`,
`./bin/dottie account status --did DID` (or `--handle HANDLE`), and
`./bin/dottie account logout --did DID`. Login prints the authorization URL; `--no-browser`
leaves browser opening to the user and `--timeout` accepts 1s–15m (default 5m). Status is
offline with `--did`; `--refresh` is explicit. Local logout removes the local session;
`--remote` also requests refresh-token revocation and reports only that the
request was accepted. Account sessions require Secret Service and never fall back to
files. These commands do not touch target data.

Use `./bin/dottie push --did DID` to publish reconciled local changes or `./bin/dottie sync --did DID` to verify a pull and then push. Neither applies downloads; restore remains explicit. Use `./bin/dottie prune --plan --did DID` to inspect retention candidates, then `./bin/dottie prune --apply --confirm --did DID` to delete eligible payloads and aged backups. Pruning is manual and foreground-only; no automatic GC or scheduling is enabled. Push/sync/device command exit 0 is committed/no-op, 2 usage error, 3 refusal/conflict/rejection, and 4 queued or other partial/indeterminate non-success. `devices list`, root-only `devices enroll`/`revoke`, and newcomer `account import-bundle` transfer only public onboarding evidence. Recovery kit files must be regular files, decode to 32 bytes, and have group/world permissions removed (`chmod 600 FILE`); Dottie never stores the kit. See the CLI README for command flags and disclosures.

To remove a target whose ID begins with `-`, use `--` to end flag parsing, for example
`./bin/dottie targets remove -- -custom`. Other unimplemented commands return a nonzero status.
`make build` writes to ignored `bin/`. Make defaults to `GOTOOLCHAIN=local` to avoid
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

The live publication-privacy gate skips by default. It requires `DOTTIE_LIVE_PUBLICATION_PRIVACY=1`, an
allowlisted disposable identity in `DOTTIE_HANDLE`, and explicit authorization; before writing the
manifest or records, it checks `com.atproto.repo.describeRepo` and skips repositories with any collections.
That gate tests genesis and therefore requires a pristine disposable repository. Production bootstrap checks
emptiness before minting and again immediately before publication; a race can leave an unreferenced staged
blob after a definite refusal. The gate writes synthetic canary records and cannot remove provider blobs.

The read-only live archive gate requires `DOTTIE_LIVE_ARCHIVE=1`, an allowlisted `DOTTIE_HANDLE`, and
`DOTTIE_RECOVERY_KIT_FILE` naming a private regular file with no group/world permission bits that decodes
to 32 kit bytes, plus explicit disposable-account authorization. It uses an existing local vault selection
and checkpoint, writes its archive only under a temporary path, and blocks repository write endpoints.

The live checkpoint-backed restore gate is `TestLiveRestoreMilestoneTwoHome`; it skips unless
`DOTTIE_LIVE_MILESTONE=1`, `DOTTIE_HANDLE` is allowlisted, and `DOTTIE_RECOVERY_KIT_FILE` is supplied,
with explicit disposable-account authorization. It requires existing local root trust and a readable Dottie
vault already present in the repository, refuses a missing/unreadable vault and any nonempty application
snapshot, and never invokes genesis. It publishes only synthetic file/settings content and one restore-only
enrollment to temporary homes, audits the fenced publication batches and current head/blob linkage, and never
deletes records or blobs. It writes its redacted artifact to `DOTTIE_LIVE_ARTIFACT_DIR` (or a temporary
artifact directory). All live gates are opt-in; a skipped gate is not provider evidence. Hosted provider
logs and server-side storage are not observable from a client. No live restore result is claimed here.

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
report one setting as non-writable; it does not validate real lockdown. The gate
proves restore only into prepared directory selections: applying a file preview creates files
inside existing roots, not a missing selected root or directory hierarchy. The
unrelated-settings check covers cross-schema preservation, not key-level isolation within
the schema being written. The 12-key older-surface case is a synthetic per-key subset,
not evidence of support for older GNOME categories or automatic degradation.

## Synthetic two-machine sync and administration gate

`go test -count=1 -tags gsettings ./tests/local` runs the offline two-machine gate. Publisher A bootstraps an empty synthetic `atprototest.MemoryPDS` fixture, publishes file/settings content, enrolls newcomer B as restore-only, and emits the public onboarding bundle. B imports it with the independently supplied anchor, authenticates the successor using imported predecessor evidence, then previews and restores exact file bytes/mode and GNOME present/reset intent through the coordinator. The gate also checks no-op publication/restore, restore-only and revoked-device push refusals, wrong-kit and wrong-anchor controls, stale predecessor refusal, fingerprint-confirmed revocation and historical decryption. This test-fixture genesis is not used by the separately authorized live restore gate.

**Real versus simulated boundary:** repository signatures, CAR/revision reads, vault authentication/decryption, genesis/publication/transition compositions, MemoryPDS writes, coordinator policy and the native GNOME keyfile backend are real package code. MemoryPDS and all data are synthetic; homes, XDG paths, schemas, keys and settings are temporary. Keyfile operations run in short-lived helper processes so each machine gets an independently initialized process-global GSettings backend. No live PDS, real account, real keyring, desktop session, dconf service or user preference is used.

## Checkpoint-backed GNOME restore milestone

`make test-gnome` also runs `TestRestoreMilestoneGNOMEKeyfileTwoHome`, a focused two-home flow that publishes synthetic file and settings values, enrolls a restore-only newcomer, imports/pulls the checkpoint-backed bundle, and verifies exact file bytes and exact setting values against the real native keyfile backend with compiled synthetic schemas. Both homes, schemas, settings and state are temporary; it does not use a desktop profile or a live provider.

## Continuous integration

GitHub Actions runs required checks on pull requests and pushes to `main`. The default
job verifies Go module integrity and tidiness, formatting, vet, ordinary and race test
suites, the fuzz seed corpora, the CLI build, and cgo-disabled tests/builds. Its JSON
skip checks count only records with a non-empty test name and `Action == "skip"`; the job does not count
a package-level `no test files` record as a skipped test. The job also
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
