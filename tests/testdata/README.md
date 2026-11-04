# Synthetic fixtures

`gsettings/` contains isolated synthetic schemas and vendor overrides used by the
opt-in native GIO boundary tests. `gsettings-older/` is a synthetic pre-42 surface
containing the reviewed keys with `Since == 0` and omitting later introductions; it
does not claim fidelity to a named historical GNOME release. `gsettings-vendor/`
mirrors the canonical GNOME matrix's schema, key and type surface with intentionally
different defaults, includes the enum definitions and override required for strict
compilation, and carries the unrelated `org.dottie.Test` sentinel schema. The GNOME
restore gate compiles it with `glib-compile-schemas --strict`; a default-suite matrix
test checks surface and default drift. These fixtures are synthetic and are not
representations of installed distribution schemas.

Tests compile fixtures in temporary directories and never modify installed or user
schema locations. No real user preferences, application captures or credentials are
present.

No live application or PDS fixtures are present. Tests use temporary homes and
synthetic data rather than developer configuration or secrets.
