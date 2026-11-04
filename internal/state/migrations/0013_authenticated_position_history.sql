CREATE TABLE authenticated_position_history (
    vault BLOB NOT NULL CHECK(length(vault) = 32),
    epoch INTEGER NOT NULL CHECK(epoch >= 0),
    policy_digest BLOB NOT NULL CHECK(length(policy_digest) = 32),
    head_cid BLOB NOT NULL CHECK(length(head_cid) BETWEEN 1 AND 128),
    policy_bytes BLOB NOT NULL,
    control_bytes BLOB NOT NULL,
    head_bytes BLOB NOT NULL,
    snapshot_bytes BLOB NOT NULL,
    checkpoint_position BLOB,
    PRIMARY KEY(vault, epoch, policy_digest, head_cid)
);
CREATE TABLE authenticated_position_history_certificates (
    vault BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    policy_digest BLOB NOT NULL,
    head_cid BLOB NOT NULL,
    certificate_index INTEGER NOT NULL CHECK(certificate_index >= 0),
    certificate_bytes BLOB NOT NULL,
    PRIMARY KEY(vault, epoch, policy_digest, head_cid, certificate_index),
    FOREIGN KEY(vault, epoch, policy_digest, head_cid)
        REFERENCES authenticated_position_history(vault, epoch, policy_digest, head_cid) ON DELETE CASCADE
);
