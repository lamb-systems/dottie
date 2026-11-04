CREATE TABLE vault_selections (
    vault BLOB NOT NULL CHECK(length(vault) = 32),
    device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 255),
    recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0),
    PRIMARY KEY(vault, device_id)
) STRICT;
