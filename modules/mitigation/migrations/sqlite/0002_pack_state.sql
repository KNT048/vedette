-- +goose Up
-- The version of the update the loaded packs came from (one row), so an older or repeated update
-- cannot be installed again (replay protection of Loader.Install).
CREATE TABLE mit_pack_state (
    id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    version      TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    installed_at TEXT    NOT NULL CHECK (installed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
