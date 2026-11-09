-- +goose Up
-- Passive sensor tables (docs/DATA_MODEL.md 4.2). Forward-only (DATA_MODEL 6, rule 1): no Down section.
-- Only sensorpassive.Service writes these tables. Observations never land here: they go to the inventory
-- through core/observe (INV-5, FORBID-3), and no packet content is stored (INV-3).

-- The sensor of this box (one row, D-24). interface and span are what the admin chose; the interface list
-- and online/offline are computed on read.
CREATE TABLE sp_sensor (
    id            TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    interface     TEXT    CHECK (interface IS NULL OR length(interface) BETWEEN 1 AND 15),
    span          INTEGER NOT NULL DEFAULT 0 CHECK (span IN (0, 1)),
    version       TEXT    CHECK (version IS NULL OR length(version) <= 64),
    last_seen     TEXT    CHECK (last_seen IS NULL OR last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    devices_seen  INTEGER NOT NULL DEFAULT 0 CHECK (devices_seen >= 0)
) STRICT;

-- The last SPAN measurement of each sensor (POST-4): measured, never inferred. At most one row per sensor.
CREATE TABLE sp_span_stat (
    sensor_id       TEXT    NOT NULL PRIMARY KEY REFERENCES sp_sensor (id) ON DELETE CASCADE,
    packets_per_s   INTEGER NOT NULL CHECK (packets_per_s >= 0),
    other_macs      INTEGER NOT NULL CHECK (other_macs >= 0),
    last_packet_at  TEXT    CHECK (last_packet_at IS NULL OR last_packet_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    measured_at     TEXT    NOT NULL CHECK (measured_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

-- The highest batch sequence number accepted per (sensor, epoch) (PRE-3, POST-3): a batch with a seq at or
-- below it was already applied and is acknowledged without being applied again. The epoch is "local" while
-- the sensor runs inside the core process; the remote sensor protocol (docs/specs/sensor-protocol.md 5.2)
-- opens a new epoch when a sensor loses its local store.
CREATE TABLE sp_seq (
    sensor_id  TEXT    NOT NULL REFERENCES sp_sensor (id) ON DELETE CASCADE,
    epoch      TEXT    NOT NULL DEFAULT 'local' CHECK (length(epoch) BETWEEN 1 AND 64),
    last_seq   INTEGER NOT NULL CHECK (last_seq >= 0),
    PRIMARY KEY (sensor_id, epoch)
) STRICT;
