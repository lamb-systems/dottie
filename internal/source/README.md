# Source providers — not implemented

Only filesystem and GNOME GSettings providers initially. They capture portable
items and execute native validated mutations/read-back through the shared journaled
engine. Define the smallest common contract from the first vertical slice rather
than a speculative plugin API. Sources do not know account credentials or PDS URLs.
