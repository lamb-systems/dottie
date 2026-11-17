# Dottie

Dottie keeps directories in sync between Linux machines through an existing AT Protocol
account. You choose a directory, it packs the files into a snapshot, publishes that snapshot to
your repository, and other machines pull it back. There is no Dottie server: your PDS holds the
data and your account authorises the writes.

It is early software. It works, it has been run against a real PDS from two independent
installs, but almost nobody has used it and the limits at the bottom of this file are real.

## What it does today

- `push` publishes a snapshot of the directories you selected.
- `pull` compares your local accepted position with the provider's, shows you a plan, and applies
  it only after you pass back the confirmation token it printed.
- `sync` does both, pull first, then push, under one confirmation.
- `status` shows your targets and which vault this install knows about, locally.
- `position status` reads the publication position without changing anything.

Files are synced as plaintext inside a packed archive. Snapshots are content addressed and
chained, so a reader can tell a snapshot belongs to the publication it claims to.

## Install

Requires Go 1.25 or newer on Linux. GNOME settings support needs a build with the `gsettings`
tag and the GIO development files.

```
make build          # writes ./bin/dottie
make check          # formatting, vet, tests
make lint           # golangci-lint, currently clean
```

CGO is optional. Without `gsettings` the files provider is all you get.

## Getting started

```
dottie account login --handle you.example.com
dottie targets add --id niri ~/.config/niri
dottie account bootstrap --vault-name main --device-id laptop
dottie push
dottie push --confirm <token from the previous output>
```

On a second machine, log in, add the same targets, and run `pull`. It resolves the vault from
your published position, so you do not need to copy a fingerprint around. If your local files
differ from the published ones and there is no history to compare, pull refuses and tells you
which files conflict. That is deliberate: it will not overwrite a file you edited, and it will
not merge.

`push` and `pull` take `--did` only when more than one account is authorised. `--vault` exists
for installs that know several vaults.

## How it works

A publication is two records in your repository. `vaultSnapshotV2` is an immutable link in a
chain: it names the packed payload as a blob, points at its predecessor, and carries a
publication id and sequence. `vaultHeadV2` is the single mutable pointer at `self` naming the
current snapshot record and payload. `pull` reads the head, walks back through the chain, then
fetches and verifies the payload against its CID and size.

Applying files is the part with the sharp edges, so it is journaled. Before touching a file,
Dottie records the intent and a copy of the previous contents in a separate journal database,
writes atomically, then confirms by observing the result. If the process dies mid-write, the
next run resolves the journal against what is actually on disk: matching postimage means it
applied, matching preimage means it did not, anything else stays indeterminate and blocks further
applies until you resolve it. This is tested by killing the process at five real points, but not
by pulling the power.

Authenticity is repo-scoped. A record set is authentic for the account that holds it, because
writing to that repository requires an authenticated session. Dottie adds no signature of its own
over a published position, which means it cannot prove anything against a provider that rewrites
or withholds history. It also means losing your machine's keys does not lose the data: your
account can read it back.

## Limits

- Plaintext. The packed payload is uploaded as a blob before any record references it, so a
  rejected or ambiguous batch can leave a retrievable blob at the provider. Dottie cannot delete
  provider blobs, and it never prints candidate bytes for a publication that failed.
- No offline verification. If you do not trust the provider to serve honest history, this is not
  the tool for that threat model.
- No recovery story of its own. A backup is `cp -r`. Earlier versions tried to build one from a
  recovery kit and it was not worth the complexity.
- Conflict resolution is manual by design. `pull` names the conflicting files and stops.
- Concurrent publication from two machines at once is refused rather than merged.
- No power-loss evidence. Process death, yes; sudden power loss, untested.

## Documentation

- `docs/security.md`: what the trust model actually guarantees, and what it does not.
- `docs/adr/`: design decisions, with their reasoning and the alternatives that lost.
- `docs/operations.md`: publishing the docs site, lexicons and release packaging.

## License

Apache 2.0. See `LICENSE`.
