ALTER TABLE vault_publication_observations
ADD COLUMN control_cid BLOB NOT NULL DEFAULT X'' CHECK (length(control_cid) BETWEEN 0 AND 128);
