-- +goose Up
-- #825 (INV-23): Home's 30-day trend reads the findings closed inside the window. With the status index alone SQLite visits every
-- closed finding ever and filters resolved_at row by row; (status, resolved_at) makes it a range per closed status. Only an index:
-- no row changes. Forward-only (DATA_MODEL 6, rule 1).
CREATE INDEX fnd_finding_status_resolved_idx ON fnd_finding (status, resolved_at);
