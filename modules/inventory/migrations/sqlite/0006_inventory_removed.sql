-- +goose Up
-- A device a person removed: its row goes with everything known about it, and what identified it stays here, so discovery and agents
-- do not make it again (removed.go). One row per removal. It stays until a person forgets it (Devices, To review, Removed) or adds a
-- device by hand at its address: removing is a person's decision, so it does not expire.
-- Forward-only: there is no Down section.
CREATE TABLE inv_removed (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    -- the device as Devices named it and its main address when it was removed, for the Removed list (the address is an identifier
    -- only through an inv_removed_id row)
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    ip         TEXT CHECK (ip IS NULL OR length(ip) BETWEEN 7 AND 15),
    -- what happened to its agent: none (it had none), stopped (the person chose to stop it: its node went, and its token when it
    -- was made for this device alone)
    agent      TEXT NOT NULL CHECK (agent IN ('none', 'stopped')),
    removed_by TEXT NOT NULL CHECK (length(removed_by) BETWEEN 1 AND 256),
    removed_at TEXT NOT NULL CHECK (removed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- The identifiers of a removed device. mac: a MAC a maker burned in or a stable virtual one (a private Wi-Fi address rotates, so it
-- would block nothing); ip: an address, kept only for a device known by no such MAC, and it stops only a sighting with no MAC (DHCP
-- gives the address to another machine, which is a new device); agent: an agent's enrolment on a token other machines share
-- ("osquery-host:<token>/<host identifier>"), so that machine cannot enrol again with it.
CREATE TABLE inv_removed_id (
    removed_id TEXT NOT NULL REFERENCES inv_removed (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('mac', 'ip', 'agent')),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 1200),
    PRIMARY KEY (kind, value)
);

CREATE INDEX inv_removed_id_removed ON inv_removed_id (removed_id);
