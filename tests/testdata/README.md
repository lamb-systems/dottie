# Synthetic fixtures

`gsettings/` contains isolated synthetic schemas and vendor overrides used by the
opt-in native GIO boundary tests. `gsettings-older/` is a synthetic pre-42 surface
containing the reviewed keys with `Since == 0` and omitting later introductions; it
does not claim fidelity to a named historical GNOME release. Tests compile fixtures in
temporary directories and never modify installed or user schema locations. No real user
preferences, application captures or credentials are present.

No live application or PDS fixtures are present. Tests use temporary homes and
synthetic data rather than developer configuration or secrets.
