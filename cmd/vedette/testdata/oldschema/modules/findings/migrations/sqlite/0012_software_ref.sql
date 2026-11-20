-- +goose Up
-- The software row a finding rests on (the matcher's Match.SoftwareID, set when it opens, touches or closes the finding) and, for a
-- finding Vedette closed by proof, the version or package release it compared (what a person's entry has to equal to be the reason).
-- Nullable: a row stays empty until the next match or reconcile reaches it. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE fnd_finding ADD COLUMN software_id TEXT CHECK (software_id IS NULL OR length(software_id) BETWEEN 1 AND 200);
ALTER TABLE fnd_finding ADD COLUMN proved_version TEXT CHECK (proved_version IS NULL OR length(proved_version) BETWEEN 1 AND 200);
