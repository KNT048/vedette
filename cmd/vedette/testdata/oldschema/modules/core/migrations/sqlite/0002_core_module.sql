-- +goose Up
-- Module on/off state (docs/DATA_MODEL.md 5.6) and the scheduler's run history (WP-04a).
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

-- One row per toggleable module. tier, depends and the rest come from MANIFEST.yaml in the code, not from here.
-- Rows are inserted at start-up from each manifest's default (ON CONFLICT DO NOTHING), never dropped:
-- turning a module off keeps its data and its row (INV-4).
CREATE TABLE core_module (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (id GLOB '[a-z]*' AND length(id) BETWEEN 1 AND 32),
    enabled     BOOLEAN NOT NULL CHECK (enabled IN (0, 1)),
    enabled_at  TEXT    CHECK (enabled_at IS NULL OR enabled_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    disabled_at TEXT    CHECK (disabled_at IS NULL OR disabled_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    version     TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64)
);

-- One row per finished run of a scheduled job; the scheduler keeps the last 200 per (module, job).
-- A run is written when it ends, so there is no "running" status.
CREATE TABLE core_job_run (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    module      TEXT NOT NULL CHECK (length(module) BETWEEN 1 AND 32),
    job         TEXT NOT NULL CHECK (length(job) BETWEEN 1 AND 64),
    started_at  TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT NOT NULL CHECK (finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT NOT NULL CHECK (status IN ('ok', 'error', 'cancelled')),
    error       TEXT CHECK (error IS NULL OR length(error) <= 1000)
);

CREATE INDEX core_job_run_job_idx ON core_job_run (module, job, started_at);
