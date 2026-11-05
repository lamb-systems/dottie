# 008 — Dependencies, and the two build boundaries

Status: accepted, 2026-10-31. Corrects a dependency claim in an earlier draft, which was wrong.

## Context

An earlier draft claimed indigo was used only for `atproto/atclient`, `api/atproto` and `atproto/syntax`.
That claim had two errors: `api/atproto` is not imported, and repository verification imports more than
the draft listed. We did not check the imports, so a reviewer found the errors first.

The same paragraph called the native settings boundary cgo-free. It is not. The default executable
builds with cgo disabled; the `gsettings` target is an opt-in Linux/cgo build.

## Decision

Go 1.27. Indigo stays pinned at `v0.0.0-20261027171756-51095abf6e95`.

Production code imports indigo's `atproto/atclient` for transport, and `atproto/atcrypto`,
`atproto/repo`, `atproto/repo/mst` and `atproto/syntax` for repository verification, alongside
`ipfs/go-cid` and `ipld/go-car`. Tests import `atproto/atdata` for fixtures. We retain our native OAuth
client. `atproto/auth/oauth` has no Secret Service and fails open when refresh persistence breaks, so
we do not use it.

The two build boundaries have separate requirements:

- The default `dottie` executable builds with `CGO_ENABLED=0`: SQLite through `modernc.org/sqlite`,
  D-Bus through `godbus`, no C toolchain.
- The `gsettings` target requires Linux, cgo, a C compiler, pkg-config, GIO development files and
  `glib-compile-schemas`. Its documentation-derived GIO floor is 2.40; only 2.88.4 has been observed at
  runtime.

The optional target exercises an isolated GIO proof against a memory and null backend. It does not
enable settings capture or apply in the CLI and is not a production desktop provider. Production
packaging remains unresolved. A packaged helper process is still an option; this record does not decide it.

This task changes nothing in `go.mod`.

## Consequences

The dependencies cost more than the earlier draft implied. The native target adds a C toolchain to
the build path, so packaging must account for that requirement.

A distribution without GIO development files can still build the CLI but not the native settings
target. Packaging documentation must make that distinction visible to packagers.

## Alternatives

Replacing indigo verification with our own was considered and rejected. Implementing MST and CAR
verification ourselves carries more risk than using a pinned verifier with documented costs.

Making GIO mandatory would force cgo on every build, which conflicts with the cgo-free default.
