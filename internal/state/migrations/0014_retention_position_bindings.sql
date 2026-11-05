CREATE TABLE authenticated_position_evidence_v14 (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    policy_bytes BLOB NOT NULL CHECK (length(policy_bytes) BETWEEN 1 AND 65536),
    control_bytes BLOB NOT NULL CHECK (length(control_bytes) BETWEEN 1 AND 65536),
    head_bytes BLOB NOT NULL CHECK (length(head_bytes) BETWEEN 1 AND 65536),
    checkpoint_position BLOB CHECK (checkpoint_position IS NULL OR length(checkpoint_position) BETWEEN 1 AND 65536),
    PRIMARY KEY (vault, epoch, policy_digest)
) WITHOUT ROWID;
INSERT INTO authenticated_position_evidence_v14(vault, epoch, policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position)
SELECT vault, epoch, policy_digest, policy_bytes, control_bytes, head_bytes, checkpoint_position FROM authenticated_position_evidence;
CREATE TABLE authenticated_position_certificates_v14 (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    certificate_index INTEGER NOT NULL CHECK (certificate_index >= 0 AND certificate_index < 64),
    certificate_bytes BLOB NOT NULL CHECK (length(certificate_bytes) BETWEEN 1 AND 65536),
    PRIMARY KEY (vault, epoch, policy_digest, certificate_index),
    UNIQUE (vault, epoch, policy_digest, certificate_bytes),
    FOREIGN KEY (vault, epoch, policy_digest)
        REFERENCES authenticated_position_evidence_v14(vault, epoch, policy_digest)
        ON DELETE CASCADE
) WITHOUT ROWID;
INSERT INTO authenticated_position_certificates_v14(vault, epoch, policy_digest, certificate_index, certificate_bytes)
SELECT vault, epoch, policy_digest, certificate_index, certificate_bytes FROM authenticated_position_certificates;
DROP TABLE authenticated_position_certificates;
DROP TABLE authenticated_position_evidence;
ALTER TABLE authenticated_position_evidence_v14 RENAME TO authenticated_position_evidence;
ALTER TABLE authenticated_position_certificates_v14 RENAME TO authenticated_position_certificates;
CREATE TABLE authenticated_position_history_v14 (
    vault BLOB NOT NULL CHECK(length(vault) = 32),
    epoch INTEGER NOT NULL CHECK(epoch >= 0),
    policy_digest BLOB NOT NULL CHECK(length(policy_digest) = 32),
    head_cid BLOB NOT NULL CHECK(length(head_cid) BETWEEN 1 AND 128),
    policy_bytes BLOB NOT NULL,
    control_bytes BLOB NOT NULL,
    head_bytes BLOB NOT NULL,
    checkpoint_position BLOB,
    PRIMARY KEY(vault, epoch, policy_digest, head_cid)
) WITHOUT ROWID;
INSERT INTO authenticated_position_history_v14(vault, epoch, policy_digest, head_cid, policy_bytes, control_bytes, head_bytes, checkpoint_position)
SELECT vault, epoch, policy_digest, head_cid, policy_bytes, control_bytes, head_bytes, checkpoint_position FROM authenticated_position_history;
CREATE TABLE authenticated_position_history_certificates_v14 (
    vault BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    policy_digest BLOB NOT NULL,
    head_cid BLOB NOT NULL,
    certificate_index INTEGER NOT NULL CHECK(certificate_index >= 0),
    certificate_bytes BLOB NOT NULL,
    PRIMARY KEY(vault, epoch, policy_digest, head_cid, certificate_index),
    FOREIGN KEY(vault, epoch, policy_digest, head_cid)
        REFERENCES authenticated_position_history_v14(vault, epoch, policy_digest, head_cid) ON DELETE CASCADE
) WITHOUT ROWID;
INSERT INTO authenticated_position_history_certificates_v14(vault, epoch, policy_digest, head_cid, certificate_index, certificate_bytes)
SELECT vault, epoch, policy_digest, head_cid, certificate_index, certificate_bytes FROM authenticated_position_history_certificates;
DROP TABLE authenticated_position_history_certificates;
DROP TABLE authenticated_position_history;
ALTER TABLE authenticated_position_history_v14 RENAME TO authenticated_position_history;
ALTER TABLE authenticated_position_history_certificates_v14 RENAME TO authenticated_position_history_certificates;
ALTER TABLE retention_declarations ADD COLUMN digest_version INTEGER NOT NULL DEFAULT 1 CHECK (digest_version IN (1, 2));
ALTER TABLE retention_declaration_history ADD COLUMN digest_version INTEGER NOT NULL DEFAULT 1 CHECK (digest_version IN (1, 2));
ALTER TABLE retention_recovery_points ADD COLUMN policy_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK (length(policy_digest) = 32);
ALTER TABLE retention_recovery_points ADD COLUMN control_cid BLOB NOT NULL DEFAULT X'' CHECK (length(control_cid) <= 128);
UPDATE retention_recovery_points SET policy_digest = (SELECT policy_digest FROM retention_declarations WHERE retention_declarations.vault = retention_recovery_points.vault AND retention_declarations.device_id = retention_recovery_points.device_id);
ALTER TABLE retention_declaration_history_points ADD COLUMN policy_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK (length(policy_digest) = 32);
ALTER TABLE retention_declaration_history_points ADD COLUMN control_cid BLOB NOT NULL DEFAULT X'' CHECK (length(control_cid) <= 128);
UPDATE retention_declaration_history_points SET policy_digest = (SELECT policy_digest FROM retention_declaration_history WHERE retention_declaration_history.vault = retention_declaration_history_points.vault AND retention_declaration_history.device_id = retention_declaration_history_points.device_id AND retention_declaration_history.revision = retention_declaration_history_points.revision);
UPDATE retention_recovery_material SET inventory_complete = 0
WHERE payload_ref = '' AND backup_ref = '' AND EXISTS (
    SELECT 1 FROM retention_recovery_points AS point
    WHERE point.vault = retention_recovery_material.vault AND point.device_id = retention_recovery_material.device_id
      AND point.epoch = retention_recovery_material.epoch AND point.snapshot_cid = retention_recovery_material.snapshot_cid
);
