CREATE TABLE authenticated_position_evidence (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    policy_bytes BLOB NOT NULL CHECK (length(policy_bytes) BETWEEN 1 AND 65536),
    control_bytes BLOB NOT NULL CHECK (length(control_bytes) BETWEEN 1 AND 65536),
    head_bytes BLOB NOT NULL CHECK (length(head_bytes) BETWEEN 1 AND 65536),
    snapshot_bytes BLOB NOT NULL CHECK (length(snapshot_bytes) BETWEEN 1 AND 402653184),
    checkpoint_position BLOB CHECK (checkpoint_position IS NULL OR length(checkpoint_position) BETWEEN 1 AND 65536),
    PRIMARY KEY (vault, epoch, policy_digest)
) WITHOUT ROWID;

CREATE TABLE authenticated_position_certificates (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    certificate_index INTEGER NOT NULL CHECK (certificate_index >= 0 AND certificate_index < 64),
    certificate_bytes BLOB NOT NULL CHECK (length(certificate_bytes) BETWEEN 1 AND 65536),
    PRIMARY KEY (vault, epoch, policy_digest, certificate_index),
    UNIQUE (vault, epoch, policy_digest, certificate_bytes),
    FOREIGN KEY (vault, epoch, policy_digest)
        REFERENCES authenticated_position_evidence(vault, epoch, policy_digest)
        ON DELETE CASCADE
) WITHOUT ROWID;
