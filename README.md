# Dottie

Directory-first preference synchronization for Linux and GNOME, using an existing
Atmosphere account and its PDS.

**Status: v2 publication is the product. `dottie push`, `dottie pull` and `dottie sync` publish,
inspect, apply and advance the accepted floor through the packed-plaintext v2 profile, with a durable
apply journal and recovery proven against real process death. `dottie pull --confirm` is the only
apply path. The v1 encrypted read-and-apply authority, the recovery-kit cross-machine workflow and
every command that served them were retired: `preview`, `restore`, `recover`, `export`, `import`,
`prune`, `history`, `devices *`, `account enroll`, `account import-bundle`, `account recovery`,
`account verify` and `account finalize` no longer exist. The signing material those commands consumed
is gone from the tree: `dottie account bootstrap` no longer mints a recovery kit, writes no kit to
state or the keyring and prints none, and `internal/vault` no longer creates, parses or validates kit
material, kit-signed checkpoints or export archives. Bootstrap also writes no repository record at
all: the v1 genesis record set is deleted and the first `push` publishes the vault. Cross-machine
recovery without a live PDS is not supported and is not planned; v2 publication replaces it.
Real-data use of this v2 tree awaits an explicit owner acceptance decision recording the v2 evidence
and residuals; [`docs/acceptance.md`](docs/acceptance.md) withholds that permission until it is
recorded. The 2026-11-05 acceptance covers only the retired v1 path, and the 2026-11-16 v2 live run
did not observe the confirmed first-use join end to end on a second machine; that gap remains visible
in the acceptance document. The open limits are no global freshness, one published vault per account,
provider-held records that cannot be deleted, and one disclosed plaintext residual: the packed
snapshot is uploaded before its record batch, so a rejected or ambiguous batch can leave an unattached
plaintext blob retrievable at the provider. Dottie never surfaces candidate bytes for a publication
that did not succeed.**
Use `dottie account login`, `status` and `logout` for account authorization;
OAuth sessions and device keys remain in the desktop Secret Service keyring. Config v2
persists GNOME category approval, resolved-key digest and matrix version; version-1 GNOME
targets upgrade to pending re-approval without inferred categories. The coordinator owns
verified reads, content-free publication planning, v2 pull apply, recovery, local base recording,
push/sync, device administration, history summaries, export and archive validation. GNOME settings
capture for publication requires a build with the `gsettings` tag and an available settings backend.
`account bootstrap` requires a
signed-in account and refuses an account that already holds a Dottie publication. It verifies that
before minting keys, stores root device keys in Secret Service, and records the local vault
selection. Records from other applications, ordinary `app.bsky.*` records included, do not block
bootstrap. Bootstrap writes no repository record and publishes no vault: v2 publication through
`push`, `pull` and `sync` is the only publication path, and the first push is what makes a
bootstrapped account's vault visible to another machine. An account can hold only one published
Dottie vault because bootstrap refuses an account that already holds one. Multi-vault selection
refers only to locally recorded vaults, not multiple published vaults on one account.

Authenticity is repo-scoped through AT Protocol account authority: the records live in the
account's own repository, signed by the account's repository key, and writing them requires an
authenticated session. Dottie adds no vault signature, no device-signed epoch authority and no
offline anchor; a reader can verify that a record set is authentic for the account, and cannot
verify that a position was ever authorized offline or that the provider withheld nothing. Vault
identity is derived from the vault name and the root device signing key, so no secret beyond the
device keys exists. The plaintext provider residual above is unchanged.

The retired commands are gone rather than deprecated: there is no kit generation to consume, no
ciphertext archive to export or validate, no retention sweep and no device administration surface.
`position status` is the one publication-position read, and `status` remains local-only. `status` prints the
locally recorded vault fingerprint and device id, so the recorded vault can be found without prior knowledge of it;
when no selection is recorded it says so instead of printing a zero value. `pull` and `sync` resolve the vault they
act on without being told it: `--vault` is an override, then the stored publication binding, then the vault named by
the account's published `vaultHeadV2` record at `self`, read through the same validated reader that reads the
position. An account that publishes nothing refuses with a typed `no-publication` reason. A vault the command
resolved rather than received is printed, so a fresh machine can join a published position without knowing its
fingerprint first. `position status` resolves the vault from `--vault` or the stored binding only, because a
provider read would give that local inspection an account session and a network dependency it does not have.

## Target design

**Select directories. Reconcile files. Publish packed snapshots under account authority.**

The publication model is plaintext-as-stored: a snapshot is a packed, content-addressed record set
published to the account's own repository under that account's authority. Snapshot confidentiality
is delegated to the existing account and provider relationship rather than to a separate
client-side envelope with kits, epochs and device certificates. This supersedes the scaffold-era
encrypted design, which is retired rather than retained as a parallel model.

- One executable: CLI commands and a per-user background service.
- Two configuration sources: recursive files/directories and GNOME GSettings.
- Declarative application presets, starting with Neovim; no application parsers.
- Automatic inclusion of new files in approved roots and file-level conflicts.
- Per-target consent: automatic apply, download-and-review, or backup-only.
- Exact local position and material ownership, with typed refusals and no silent adoption of
  foreign or legacy state.
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

Use `./bin/dottie push --did DID` to review one publication proposal, then `./bin/dottie push --did DID --confirm HEX` to publish exactly that proposal; a pre-submission failure abandons its own attempt without a flag. Push never applies downloads. `pull --did DID [--vault HEX]` compares the provider's validated position with the locally accepted floor, prints one finding and one apply plan, and changes nothing until it is repeated with the `--confirm` token it printed; a confirmed pull applies the plan, then advances the accepted floor. When the complete reconciliation has no file changes, a `first-use` or `diverges` finding instead offers a confirmed acceptance: the unconfirmed run prints that the verified position can be adopted without writing files and prints a token, and `--confirm` advances the floor without applying anything. Without `--vault` and without a stored binding, `pull` adopts the vault the account publishes at `self` and prints it, so a new machine joins a published position without being told the vault; a stored binding is used as recorded and the validated read refuses a provider head that names a different vault. The reconciled `sync --did DID` command does the same for its pull half, recomposes the push half from the post-pull state and requires it to match what was printed before publishing. A newcomer must complete a confirmed `pull` before `sync`: `sync` reconciles two directions and needs an accepted floor to reconcile against, so without one it refuses and names the confirmed pull followed by `sync`. Exit codes are 0 success or no-op, 2 usage error, 3 local refusal, and 4 indeterminate or partially completed remote work. See the CLI README for command flags and disclosures.

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

## Publication privacy gates

The v1 encrypted publication audit and the source-loss archive gate were retired with the commands they
served. Payload privacy on the v2 plaintext profile is tested offline by
[`tests/integration/publication_v2_privacy_test.go`](tests/integration/publication_v2_privacy_test.go):
it publishes through the real coordinator path to an in-memory provider, then scans every repository
record and its `listRecords` projection for per-run canaries (the published file's plaintext, a
credential-shaped string, an absolute local path, the account DID and the local review approval digest),
inventories the recursive record keys and the written collections, resolves every typed blob reference
against the blobs the publish actually uploaded, and models the upload, record-batch, post-processing and
lost-response failures through their typed outcomes.

The exact limit: repository records are asserted canary-free, the blob is not, because this profile
publishes packed plaintext. The packed snapshot is uploaded before its record batch, so a rejected or
ambiguous batch leaves an unattached plaintext blob retrievable at the provider; the gate asserts that
residual instead of denying it. There is still no live privacy gate: the rows in
[`docs/acceptance.md`](docs/acceptance.md) that name the retired gates are historical evidence for the
removed path, not coverage of this tree.

`go test -count=1 ./internal/cli` still exercises the package-internal renderer privacy contract against
synthetic data.

## Two-machine publication apply gate

[`tests/local/publication_two_machine_test.go`](tests/local/publication_two_machine_test.go) is the
offline replacement for the retired v1 two-machine gate. It runs two isolated temporary homes over
one synthetic in-memory provider: machine A publishes through `PreparePublicationPush` and
`ConfirmPublicationPush`, and machine B applies through `publicationstate.Inspect`,
`PlanPublicationApply`, `StagePublicationAccept`, `ApplyPublication` and `AcceptPublication`. It
checks exact applied bytes, both sentinel exclusions, terminal apply-journal rows, floor revision,
sequence and record CID, no-op re-application with inode and mtime identity, a reverse pull after B
publishes, a re-executed `SIGKILL` at the journaled stage followed by recovery, and a same-entry
conflict that refuses without changing either home, the provider revision or either accepted floor.
Run it with `go test -count=1 ./tests/local -run TestTwoMachine`. It uses synthetic homes, a fake
session, a fake provider transport and no network or PDS. The deleted gate also covered onboarding
import, device enrollment/revocation identity and GNOME present/reset application; those remain
single-machine coordinator and tagged GNOME-backend evidence, not two-machine command evidence.

## GNOME settings backend gate

Run `make test-gnome` or `make test-gnome-race` for the native GSettings backend gate. It uses
isolated temporary homes and XDG paths, compiled synthetic schemas with canonical source defaults
and different vendor destination defaults, and the real keyfile and dconf backends; the dconf run
uses a real `dconf-service` on a temporary private D-Bus. It checks observe/set/reset/read-back,
canonicalization, path identity, missing keys and schemas, and a 12-key synthetic per-key
older-schema subset. The combined files-and-settings apply and rollback scenario was retired with
the v1 apply engine. The gate does not use a production desktop session or profile, real user
preferences, system-db lockdown, a VM, or CLI wiring; it proves backend behavior, not v2 publication
apply of settings.

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
| `internal/service`, `internal/syncengine` | Coordination, v2 publication apply, reconciliation and the unreachable v1 journaled apply engine |
| `internal/source` | Filesystem and GNOME integration |
| `internal/config`, `internal/model`, `internal/preset` | Targets, local policy and portable data |
| `internal/vault`, `internal/remote` | Encrypted snapshots and PDS transport |
| `internal/state`, `internal/platform` | Persistence and Linux integration |
| `lexicons`, `web` | Record definitions and static OAuth metadata |
| `packaging`, `tests` | Distribution and integration coverage |

The default executable remains the CLI and its unit tests. Push, pull, sync and device administration use the coordinator; `pull --confirm` is the only apply path. Account login/status/logout manage OAuth sessions, and no background synchronization service is wired.
Other component directories document their responsibilities. Presets, OAuth metadata
and the systemd unit are draft examples, not functioning synchronization integrations
or deployable configuration.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

The canonical repository and Go module path is `github.com/lamb-systems/dottie`.
An owned Lexicon namespace and OAuth metadata host remain to be selected; the
example metadata is not production configuration.
