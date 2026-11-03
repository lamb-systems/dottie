# Declarative preset catalog

`data/` is an embedded, versioned TOML catalog. `Catalog` and `Lookup` validate the
closed schema, return presets sorted by id, and return deep copies. Unknown ids are
reported with the sorted known ids. Presets declare roots and exclusion suggestions;
they cannot contain commands, hooks, downloads, package requests, or consent overrides.

`BuildPreview` validates caller-supplied presets, resolves file roots against the
provided HOME and XDG paths, reports the destination's effective default mode, and
performs no filesystem mutation or config write. The selected-key GNOME capture
library exists, but GNOME presets retain their catalog information and return a
structured `ErrSourceNotCapturable` reason until DOT-G03 defines supported preset key
selection. Catalog data cannot select capture keys or report whether anything is
captured locally; no CLI wiring is provided.

`Materialize` returns a configuration proposal and never writes it. GNOME materialization
remains unsupported because presets do not have key-selection authority. Each new target has
an empty mode and inherits the destination default, which may be `auto-apply`; presets
cannot grant or widen consent. Proposed roots pass both `config.CheckAddition` and
`config.Config.Validate`. Existing identical logical roots are no-ops that preserve
their stored id, mode, and excludes. Different excludes for an existing root are
rejected rather than replacing local policy. IDs are derived only for new roots.

The Neovim preset selects exactly the `xdg-config/nvim` directory and excludes `.git`
and `.git/**`. Neovim configuration is synchronized as ordinary files and bytes: there
is no Lua awareness, plugin management, execution, or installation. Custom roots are
valid configuration selections and need no preset. Exclusions do not delete local
files, and external links are not authorized by preset data.
