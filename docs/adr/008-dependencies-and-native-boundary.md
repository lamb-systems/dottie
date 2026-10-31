# 008 — Dependencies, and the two build boundaries

Status: accepted, 2026-10-31. Corrects the dependency claim in an earlier draft of this decision, which
was factually wrong about what we import.

## Context

An earlier draft said indigo was used only for `atproto/atclient`, `api/atproto` and `atproto/syntax`.
That was wrong. Repository verification pulls more: `atproto/atcrypto`, `atproto/repo` and
`atproto/repo/mst`, alongside `ipfs/go-cid` and `ipld/go-car`. The claim was never checked against the
imports, which is why a reviewer found it rather than we did.

There was a second error in the same paragraph: the native settings boundary was described as cgo-free.
It is not. The default executable builds with cgo disabled, but the `gsettings` target is an opt-in
Linux/cgo build that needs a C compiler, pkg-config and GIO development files.

## Decision

Go 1.27. Indigo stays pinned at `v0.0.0-20261027171756-51095abf6e95` and is used for transport and for
repository verification, with that full import set recorded rather than trimmed to a slogan. The native
OAuth client remains ours; `atproto/auth/oauth` is still not used, because it has no Secret Service and
fails open when refresh persistence breaks.

Two build boundaries, stated separately:

- The default `dottie` executable builds with `CGO_ENABLED=0`: SQLite through `modernc.org/sqlite`,
  D-Bus through `godbus`, no C toolchain.
- The `gsettings` target requires Linux, cgo, a C compiler, pkg-config, GIO development files and
  header validation. Its documentation-derived GIO floor is 2.40; only 2.88.4 has been observed at
  runtime.

The production packaging choice for the native target is unresolved and is recorded as unresolved. A
packaged helper process remains an open option and is not decided here.

This task changes nothing in `go.mod`. Future dependency changes need their own ADR, including any
addition that exists only to satisfy a verifier.

## Consequences

The dependency cost is larger than the previous draft implied, and packaging for the native target is
real work with a C toolchain on the build path, not a configuration flag.

Because the native target is optional, distributions that cannot provide GIO development files can still
build the CLI, minus settings support. That asymmetry must be visible in packaging documentation rather
than discovered by a failing build.

## Alternatives

Replacing indigo verification with our own was considered and rejected: hand-rolling MST and CAR
verification is more risk than a pinned verifier with a recorded cost.

Making GIO mandatory would force cgo on every build, which conflicts with the cgo-free default.
