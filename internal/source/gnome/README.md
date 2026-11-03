# GNOME source — selected-key capture boundary

The opt-in Linux/cgo `gsettings` build provides an internal capture library over
explicitly selected schema/key references. It reads only each selected key's user
value: a writable override becomes a typed GVariant-present entry, and no user
override becomes reset intent so destination defaults are not pinned. Non-writable,
missing-schema, missing-key and failed reads are returned as `Unknown` with a reason.
The caller supplies the target ID and owns coverage outside the selected set; a key
must appear in either `Entries` or `Unknown`, and deselected keys remain caller-owned
`Untracked` decisions. The library does not enumerate schemas or infer coverage.

The native default backend admits only the persistent `GKeyfileSettingsBackend` and
`DConfSettingsBackend` implementations; there is no memory/null fallback. Memory and
null backends are available through the internal test seam. Native memory/null and
isolated keyfile tests use synthetic schemas, temporary homes and isolated XDG paths;
they do not read real user preferences or copy dconf wholesale. Real desktop
validation belongs to G04. This is not a production desktop provider: there is no CLI
or preset activation, apply path, schema/key selection authority, or reliable change
watch service.

Run `make test-gnome` or `make test-gnome-race` for the opt-in native tests. They
require Linux, cgo, a C compiler, pkg-config, GIO development files and
`glib-compile-schemas`. The documentation-derived native GIO minimum is 2.40; Make
enforces this floor. Only GIO/GLib 2.88.4 was observed at runtime, so older releases,
the GNOME 50 target and other architectures have not been empirically tested.

The capture/`ReadUser` boundary bounds returned type and printed user-value sizes, but
GLib allocates a printed user value before the boundary can reject an oversized value.
The legacy `Read` API remains for tests/apply and does not enforce that capture bound.
