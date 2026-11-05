# Source providers — not implemented

The initial providers are filesystem and GNOME GSettings only. They capture portable
items and execute native validated mutations/read-back through the shared journaled
engine. Define the smallest common contract from the first vertical slice rather
than a speculative plugin API. Sources have no knowledge of account credentials or PDS URLs.
