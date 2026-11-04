# Declarative preset catalog

`data/` is an embedded, versioned TOML catalog. `Catalog` and `Lookup` validate the
closed schema, return presets sorted by id, and return deep copies. Unknown ids are
reported with the sorted known ids. Presets declare roots and exclusion suggestions;
they cannot contain commands, hooks, downloads, package requests, or consent overrides.

`BuildPreview` validates caller-supplied presets, resolves file roots against the
provided HOME and XDG paths, reports the destination's effective default mode, and
performs no filesystem mutation or config write. GNOME presets declare category IDs
from the published matrix in `internal/source/gnome/matrix`; preview resolves them to
the matrix's schema/key references and rejects unknown, duplicate or empty category
selections. The matrix, not the catalog, owns which keys a category contains. GNOME
selection therefore does not require a hand-built key list, and catalog data still
cannot name arbitrary keys.

`Materialize` returns a configuration proposal and never writes it. GNOME
materialization is permitted only when a stored, approved policy exactly matches the
catalog category IDs, current matrix version and digest of the resolved schema/path/key
set. Pending, absent or mismatched approval returns typed `ErrReapprovalRequired`; it
never replaces or widens the stored selection. Preview carries the resolved references,
matrix version and lowercase key-set digest so a later explicit local approval can bind
them. A changed matrix therefore requires re-approval.
Each new file target has an empty mode and inherits the destination default, which may
be `auto-apply`; presets cannot grant or widen consent. Proposed roots pass both `config.CheckAddition` and
`config.Config.Validate`. Existing identical logical roots are no-ops that preserve
their stored id, mode, and excludes. Different excludes for an existing root are
rejected rather than replacing local policy. IDs are derived only for new roots.

The Neovim preset selects exactly the `xdg-config/nvim` directory and excludes `.git`
and `.git/**`. Neovim configuration is synchronized as ordinary files and bytes: there
is no Lua awareness, plugin management, execution, or installation. Custom roots are
valid configuration selections and need no preset. Exclusions do not delete local
files, and external links are not authorized by preset data.
