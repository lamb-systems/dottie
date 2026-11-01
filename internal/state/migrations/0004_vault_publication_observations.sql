CREATE TABLE vault_publication_observations (
    vault BLOB PRIMARY KEY CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    publication_count INTEGER NOT NULL CHECK (publication_count >= 0),
    head_cid BLOB NOT NULL CHECK (length(head_cid) BETWEEN 1 AND 128)
);
