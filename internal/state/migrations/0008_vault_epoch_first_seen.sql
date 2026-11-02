CREATE TABLE vault_epoch_first_seen (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    first_seen_at INTEGER NOT NULL CHECK (first_seen_at >= 0),
    PRIMARY KEY (vault, epoch)
) WITHOUT ROWID;
