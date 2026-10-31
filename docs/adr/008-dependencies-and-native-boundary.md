# 008 — Dependencies, and the two build boundaries

Status: accepted, 2026-10-31. Corrects a dependency claim in an earlier draft, which was wrong.

## Context

An earlier draft said indigo was used only for `atproto/atclient`, `api/atproto` and `atproto/syntax`.
Two things were wrong with that. `api/atproto` is not imported at all, and repository verification pulls
in more than the draft admitted. The claim was never checked against the imports, which is why a
reviewer found it rather than we did.

The same paragraph called the native settings boundary cgo-free. It is not. The default executable
builds with cgo disabled; the `gsettings` target is an opt-in Linux/cgo build.

## Decision

Go 1.27. Indigo stays pinned at `v0.0.0-20261027171756-51095abf6e95`.

Production imports of indigo: `atproto/atclient` for transport, and `atproto/atcrypto`,
`atproto/repo`, `atproto/repo/mst` and `atproto/syntax` for repository verification, alongside
`ipfs/go-cid` and `ipld/go-car`. Tests also import `atproto/atdata` for fixtures. The native
OAuth client remains ours; `atproto/auth/oauth` is not used, because it has no Secret Service and fails
open when refresh persistence breaks.

Two build boundaries, stated separately:

- The default `dottie` executable builds with `CGO_ENABLED=0`: SQLite through `modernc.org/sqlite`,
  D-Bus through `godbus`, no C toolchain.
- The `gsettings` target requires Linux, cgo, a C compiler, pkg-config, GIO development files and
  `glib-compile-schemas`. Its documentation-derived GIO floor is 2.40; only 2.88.4 has been observed at
  runtime.

The optional target exercises an isolated GIO proof against a memory and null backend. It does not enable
settings capture or apply in the CLI, and it is not a production desktop provider. Production packaging
for it is unresolved, and a packaged helper process remains an open option that is not decided here.

This task changes nothing in `go.mod`.

## Consequences

The dependency cost is larger than the earlier draft implied, and the native target puts a C toolchain on
the build path. That is packaging work with a toolchain requirement attached.

A distribution without GIO development files can still build the CLI, but it gets no native settings
target. The asymmetry belongs in packaging documentation, where a packager will read it.

## Alternatives

Replacing indigo verification with our own was considered and rejected: hand-rolling MST and CAR
verification is more risk than a pinned verifier whose cost is recorded.

Making GIO mandatory would force cgo on every build, which conflicts with the cgo-free default.
