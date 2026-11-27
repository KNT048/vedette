-- +goose Up
-- The deep-scan settings of a target: what a person turned off for it. They only narrow what the testing terms and the scan's
-- own rules allow (a scheduled scan, a typed IP, an address that is not the box's own, carrier-grade NAT); they never turn a group
-- on. No row means the defaults: the denial-of-service checks off, everything else on, normal speed, nothing skipped. One row per
-- target, removed with it. skip_ports are TCP port numbers every engine leaves out; skip_paths are URL path prefixes the web
-- scans leave out (two separate lists: one is never turned into the other). Forward-only: there is no Down section.
CREATE TABLE exp_deep_setting (
    target_id   TEXT    NOT NULL PRIMARY KEY REFERENCES exp_target (id) ON DELETE CASCADE,
    dos         INTEGER NOT NULL DEFAULT 0 CHECK (dos IN (0, 1)),
    logins      INTEGER NOT NULL DEFAULT 1 CHECK (logins IN (0, 1)),
    web_active  INTEGER NOT NULL DEFAULT 1 CHECK (web_active IN (0, 1)),
    data_change INTEGER NOT NULL DEFAULT 1 CHECK (data_change IN (0, 1)),
    openvas     INTEGER NOT NULL DEFAULT 1 CHECK (openvas IN (0, 1)),
    speed       TEXT    NOT NULL DEFAULT 'normal' CHECK (speed IN ('normal', 'gentle')),
    skip_ports  TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(skip_ports) AND json_type(skip_ports) = 'array'),
    skip_paths  TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(skip_paths) AND json_type(skip_paths) = 'array'),
    updated_at  TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by  TEXT    NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 320)
) WITHOUT ROWID;
