# Portable data model

`internal/model` defines versioned portable targets, desired file and GSettings
entries, local observations, structured entry identity and pure snapshot
validation. It neither captures nor applies local data. It is not an untrusted-input
codec or an authorization boundary.

Structural limits, in bytes, are: target IDs 128; filesystem and
GSettings paths 4,096; GSettings schema IDs and keys 255; GVariant type text 255;
GVariant value text 65,536; and relative symlink text 4,096. File content size and
snapshot entry-count limits belong to the later strict codec.
