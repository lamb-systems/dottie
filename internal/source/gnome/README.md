# GNOME source — selected-key capture and settings apply boundary

The opt-in Linux/cgo `gsettings` build provides an internal capture library over
explicitly selected schema/key references and a library-only settings apply adapter.
Capture reads only each selected key's user value: a writable override becomes a typed
GVariant-present entry, and no user override becomes reset intent so destination
defaults are not pinned. Non-writable, missing-schema, missing-key and failed reads
are returned as `Unknown` with a reason. The caller supplies the target ID and owns
coverage outside the selected set; a key must appear in either `Entries` or `Unknown`,
and deselected keys remain caller-owned `Untracked` decisions. The library does not
enumerate schemas or infer coverage.

A versioned category matrix in `internal/source/gnome/matrix` publishes the local
selection units a GNOME preset may name. Matrix version 1 covers `appearance`,
`fonts` and `clock` with explicit schema, key and GVariant types. It was reviewed
against the gsettings-desktop-schemas 51.0 surface; `ReviewedMin` is GNOME 42 and
`ReviewedMax` is GNOME 51, while the product target remains GNOME 50. A key's `Since`
is 0 when upstream NEWS places it before GNOME 42, otherwise the first reviewed GNOME
major that introduced it. A category's version floor is the highest `Since` in that
category, so `appearance` requires GNOME 47 while `fonts` and `clock` require GNOME 42;
every floor is bounded by `ReviewedMax`. Runtime `missing-key` results come from the
installed schema surface, not from `Since`: `color-scheme` and `accent-color` are
reported that way when the schema lacks them and are never replaced with a substitute.
An unknown category, duplicate category or empty selection is rejected. The matrix
does not enumerate installed schemas, discover relocatable instances or copy dconf.

Synthetic fixtures under `tests/testdata/gsettings` mirror the published key surface.
`tests/testdata/gsettings-older` is a synthetic pre-42 surface containing exactly the
`Since == 0` keys and omitting every positive-`Since` key. Tests check key/type parity,
the older-fixture introduction bounds, category version floors, full category capture,
set-then-reset intent, and missing-key reporting for all categories. These are synthetic
fixtures, not evidence about a real desktop session.

The shipped categories exclude wallpaper, monitor, GPU, peripheral, input-source,
keybinding and media-key preferences. The last group includes command-bearing values
that could execute on the destination, so it is not shipped even when a schema is
available. `text-scaling-factor` ships as a text readability preference; monitor/DPI
scaling, cursor size and LCD subpixel ordering stay local. Theme, icon, cursor and font
names reference assets that must already be installed; Dottie never downloads, installs
or reloads them, and it makes no cross-desktop mapping claim.

The settings apply adapter observes only user overrides, validates the journaled
schema/path/key identity, and opens settings at the requested path. A fixed-path schema
accepts its resolved schema path and rejects a different supplied path; a relocatable
schema uses the explicit journaled path. The adapter verifies the opened path matches
the requested identity. Present values are parsed and range-checked against the schema
key and printed in canonical GVariant form before journaling. Set and reset synchronize
GSettings before returning, so callers can read back after backend completion. This
synchronization is not filesystem `fsync` and does not prove durability across a crash.
`g_settings_sync` blocks until the default backend reports completion; it has no deadline,
so a stalled backend can delay cancellation, close or recovery reporting.

The journal and rollback backup retain setting values in plaintext while retained;
they use the existing bounded rollback-material and backup-retention policy. The
adapter is library-only: it is not wired to the CLI or presets, grants no arbitrary
per-key selection or automatic-apply policy, and has no reliable change-watch service.
Real desktop validation belongs to G04; do not treat synthetic native tests as evidence
about actual desktop preferences.

The native default backend admits only the persistent `GKeyfileSettingsBackend` and
`DConfSettingsBackend` implementations; there is no memory/null fallback. Memory and
null backends are available through the internal test seam. Native memory/null and
isolated keyfile tests use synthetic schemas, temporary homes and isolated XDG paths;
they do not read real user preferences or copy dconf wholesale.

Run `make test-gnome` or `make test-gnome-race` for the opt-in native tests. They
require Linux, cgo, a C compiler, pkg-config, GIO development files and
`glib-compile-schemas`. The documentation-derived native GIO minimum is 2.40; Make
enforces this floor. Only GIO/GLib 2.88.4 was observed at runtime, so older releases,
the GNOME 50 target and other architectures have not been empirically tested.

The capture/`ReadUser` boundary bounds returned type and printed user-value sizes, but
GLib allocates a printed user value before the boundary can reject an oversized value.
The legacy `Read` API remains for tests and does not enforce that capture bound.
