CREATE TABLE vault_checkpoints (
    vault BLOB PRIMARY KEY CHECK (length(vault) = 32),
    anchor BLOB NOT NULL CHECK (length(anchor) = 32),
    control_cid BLOB NOT NULL,
    control_bytes BLOB NOT NULL,
    snapshot_cid BLOB NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    recorded_at INTEGER NOT NULL
);
