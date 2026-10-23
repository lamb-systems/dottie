# Synthetic fixtures

`gsettings/` contains isolated synthetic schemas and vendor overrides used by the
opt-in native GIO boundary tests. Tests compile them in temporary directories and
never modify installed or user schema locations. No real user preferences,
application captures or credentials are present.

No live application or PDS fixtures are present. Tests use temporary homes and
synthetic data rather than developer configuration or secrets.
