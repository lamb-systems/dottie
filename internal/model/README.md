# Portable data model

`internal/model` defines versioned portable targets, desired file and GSettings
entries, local observations, structured entry identity and pure snapshot
validation. It does not capture or apply local data and is not an untrusted-input
codec or an authorization boundary.

The structural limits are measured in bytes: target IDs 128; filesystem and
GSettings paths 4,096; GSettings schema IDs and keys 255; GVariant type text 255;
GVariant value text 65,536; and relative symlink text 4,096. File content size and
snapshot entry-count limits belong to the later strict codec.
