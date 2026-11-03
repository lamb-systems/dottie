CREATE TABLE retention_declarations (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    device_id TEXT NOT NULL CHECK (length(device_id) > 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    retention_floor INTEGER NOT NULL CHECK (retention_floor >= 0),
    declaration_digest BLOB NOT NULL CHECK (length(declaration_digest) = 32),
    declared_at INTEGER NOT NULL CHECK (declared_at >= 0),
    previous_declaration_digest BLOB NOT NULL CHECK (length(previous_declaration_digest) = 32),
    previous_declared_at INTEGER NOT NULL,
    PRIMARY KEY (vault, device_id)
) WITHOUT ROWID;
CREATE TABLE retention_recovery_points (
    vault BLOB NOT NULL,
    device_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    snapshot_cid BLOB NOT NULL CHECK (length(snapshot_cid) BETWEEN 1 AND 128),
    PRIMARY KEY (vault, device_id, ordinal),
    UNIQUE (vault, device_id, epoch, snapshot_cid),
    FOREIGN KEY (vault, device_id) REFERENCES retention_declarations(vault, device_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE retention_declaration_history (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    device_id TEXT NOT NULL CHECK (length(device_id) > 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    retention_floor INTEGER NOT NULL CHECK (retention_floor >= 0),
    declaration_digest BLOB NOT NULL CHECK (length(declaration_digest) = 32),
    declared_at INTEGER NOT NULL CHECK (declared_at >= 0),
    previous_declaration_digest BLOB NOT NULL CHECK (length(previous_declaration_digest) = 32),
    previous_declared_at INTEGER NOT NULL,
    PRIMARY KEY (vault, device_id, revision)
) WITHOUT ROWID;
CREATE TABLE retention_declaration_history_points (
    vault BLOB NOT NULL,
    device_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    snapshot_cid BLOB NOT NULL CHECK (length(snapshot_cid) BETWEEN 1 AND 128),
    PRIMARY KEY (vault, device_id, revision, ordinal),
    FOREIGN KEY (vault, device_id, revision) REFERENCES retention_declaration_history(vault, device_id, revision) ON DELETE CASCADE
) WITHOUT ROWID;
