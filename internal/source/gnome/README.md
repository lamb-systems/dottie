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
adapter is library-only: it is not wired to the CLI or presets, grants no schema/key
selection authority, and has no automatic-apply policy or reliable change-watch service.
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
