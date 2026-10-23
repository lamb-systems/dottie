# GNOME source — not implemented

Use GIO/GSettings for selected typed user overrides and explicit resets. Validate
schemas, types, ranges and writability before applying changes, and verify results.
Preserve the distinction between a user override and the destination's default.

Do not copy binary dconf databases, use the read-only Settings portal as a setter,
or install schemas from synchronized data. Native dependencies remain to be selected.
