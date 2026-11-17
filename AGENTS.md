# Development guidance

- Start with README.md, then docs/security.md for the trust model and docs/acceptance.md for what has
  actually been measured. Component directories carry no README of their own; put design notes in
  docs/, not beside the code.
- This is a scaffold. Do not describe unimplemented features or placeholder
  component directories as working functionality.
- Keep repository documentation focused on product behavior, architecture and
  development commands.
- Scope: Linux/GNOME CLI and user-session background sync. Filesystem and
  GSettings providers; directory selection with file-level reconciliation.
- Presets are data, not hooks. Remote configuration cannot grant local path
  access, enable auto-apply or authorize external symlink traversal.
- Preserve key separation, exact policy/revision checks and atomic first blob
  reference plus head/control publication. Failed publication must not expose data
  through Dottie itself: no Dottie command, log, error or archive may surface
  candidate bytes for a publication that did not succeed. The plaintext v2 profile
  uploads the packed payload before its record batch, so a rejected or ambiguous
  batch can leave an unattached, provider-held plaintext blob that cannot be
  deleted. That provider-side residual is accepted and recorded in
  docs/acceptance.md; it must be disclosed, never silently assumed away, and it
  does not license exposing candidate bytes locally.
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
  docs/, not in a component README that no longer exists.
- Leave staging and commits to the user. Do not commit or push.
- Do not change accounts, enable services or publish without explicit approval.
