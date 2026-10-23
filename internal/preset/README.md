# Preset catalog — draft data only

No loader or runtime preset support exists yet. `data/` contains illustrative TOML
for selecting an existing source provider, logical roots or GNOME categories,
exclusion suggestions, risk labels and portability notes.

Presets cannot execute hooks, install applications or silently expand consent.
Accepted selections are materialized into local configuration. Updates must not
add roots, enable automatic apply or follow external links without approval.

The directory is the selection unit: ordinary new files inside an approved root
join synchronization automatically. Exclusion changes and untracking must not
delete local files. Explain why paths are excluded; do not blanket-exclude Lua,
hidden files or `plugin/` directories that can contain actual user configuration.

Neovim configuration is handled as ordinary bytes and paths, not evaluated code.
Custom roots need no catalog entry. Finalize a versioned, validated schema before
using these examples at runtime.
