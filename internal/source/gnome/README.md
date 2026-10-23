# GNOME source — isolated native feasibility boundary

The opt-in Linux/cgo `gsettings` build provides a narrow internal direct-GIO
boundary over explicitly constructed memory and read-only/null backends. It loads
only a caller-supplied compiled schema source with no parent and untrusted input
mode. Typed values pass as GVariant type plus text; reads preserve effective,
default and optional user values, and observed-key notifications are bounded hints
that callers must use to re-read state.

This is not a production desktop provider. The proof does not use the system or
default backend, session bus, installed schemas, dconf persistence, real
administrative locks or user preferences. The null backend demonstrates refusal
to write, not administrator policy. Notifications are not a production-reliable
watch service. Capture/apply, CLI integration and real GNOME desktop validation
remain unimplemented.

Run `make test-gnome` or `make test-gnome-race` for uncached isolated native tests.
They require Linux, cgo, a C compiler, pkg-config, GIO development files and
`glib-compile-schemas`. Native tests re-exec under a temporary HOME/XDG tree with
GLib warnings fatal. The documentation-derived native GIO minimum is 2.40,
set by APIs including user-value and schema-key lookups; Make enforces this floor.
Only GIO/GLib 2.88.4 was observed at runtime, so older releases and the GNOME 50
target have not been empirically tested.
