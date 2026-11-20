-- +goose Up
-- Certificates core issued to its own sensors (D-110; DATA_MODEL core_sensor_cert). One row per leaf: the serial is what the
-- sensor link checks on every request (sensor-protocol section 4), so only the current serial of a role and the one before it
-- (retired_at IS NULL) are accepted. Rows are never deleted: the history shows which serials were live and when they ended.
-- The CA key is not here: it is a core_secret row of purpose core_sensor_ca.
-- Order of issue is the rowid (rows are only inserted), so there is no issued_at column to disagree with it.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

CREATE TABLE core_sensor_cert (
    serial     TEXT NOT NULL PRIMARY KEY CHECK (length(serial) BETWEEN 1 AND 64 AND serial NOT GLOB '*[^0-9a-f]*'), -- hex of the x509 serial
    role       TEXT NOT NULL CHECK (role IN ('passive', 'active')),
    not_after  TEXT NOT NULL CHECK (not_after GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    retired_at TEXT CHECK (retired_at IS NULL OR retired_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX core_sensor_cert_live ON core_sensor_cert (role) WHERE retired_at IS NULL;
