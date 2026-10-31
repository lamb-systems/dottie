# Development guidance

- Start with README.md and the relevant component's README.
- This is a scaffold. Do not describe unimplemented features or placeholder
  component directories as working functionality.
- Keep repository documentation focused on product behavior, architecture and
  development commands.
- Scope: Linux/GNOME CLI and user-session background sync. Filesystem and
  GSettings providers; directory selection with file-level reconciliation.
- Presets are data, not hooks. Remote configuration cannot grant local path
  access, enable auto-apply or authorize external symlink traversal.
- Preserve key separation, exact policy/revision checks and atomic first blob
  reference plus head/control publication. Failed publication must not expose data.
- Recovery authenticates data, not global freshness. Risk acceptance cannot
  override invalid signatures, wrong keys or failed policy checks.
- Use synthetic fixtures and temporary homes, never real user dotfiles in tests.
  Live PDS tests require explicit disposable-account authorization.
- All test assertions use testify: require for conditions that stop the test,
  assert for ones that continue, with expected values first in Equal. Never call
  require inside a goroutine; use assert plus an explicit return there. A missing
  assertion means a bug, not a style choice, so `fmt.Errorf` is error
  construction and stays unchanged; never gate on a `t.Error` substring grep.
- Run make check, make test-race and make build for executable Go changes.
  Distinguish actual tests from unimplemented or skipped integration coverage.
- Do not add source comments unless absolutely necessary. Put explanations in
  the relevant component README.
- Leave staging and commits to the user. Do not commit or push.
- Do not change accounts, enable services or publish without explicit approval.
