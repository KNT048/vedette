-- +goose Up
-- D-603: the Windows releases Microsoft's release information pages list (feed windows-releases), handed to core/winrel, which answers
-- from its own table first. Replaced whole by each good pull; a failed pull or a feed turned off keeps the last good list. Server or
-- client by build, the NVD name Vedette gives it, the first build of its line (the release whose monthly update it shares), the day
-- of general availability and the revision of its first public build (0: not known). Forward-only.
CREATE TABLE feeds_winrel (
    build   INTEGER NOT NULL CHECK (build BETWEEN 10240 AND 99999),
    server  INTEGER NOT NULL CHECK (server IN (0, 1)),
    product TEXT    NOT NULL UNIQUE CHECK (length(product) BETWEEN 1 AND 60 AND product GLOB 'windows_*'),
    display TEXT    NOT NULL CHECK (length(display) BETWEEN 1 AND 60),
    line    INTEGER NOT NULL CHECK (line BETWEEN 10240 AND 99999),
    ga      TEXT    NOT NULL CHECK (ga GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    ga_rev  INTEGER NOT NULL CHECK (ga_rev BETWEEN 0 AND 999999),
    PRIMARY KEY (build, server)
) WITHOUT ROWID;
