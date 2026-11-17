-- +goose Up
-- The monthly security updates ("YYYY-MM B") Microsoft's Windows release information pages list (feed windows-releases), one row per
-- release (build, server or client) and revision, handed to core/winrel.LearnUpdates: findings names the newest one as the target of a
-- Windows release's cumulative update when it is newer than every fixed build NVD lists (NVD analyses a month's CVEs later). A good
-- pull replaces the rows of every release it read; a page that failed keeps its releases' rows. Forward-only.
CREATE TABLE feeds_winrel_update (
    build  INTEGER NOT NULL CHECK (build BETWEEN 10240 AND 99999),
    server INTEGER NOT NULL CHECK (server IN (0, 1)),
    rev    INTEGER NOT NULL CHECK (rev BETWEEN 1 AND 999999),
    kb     TEXT    NOT NULL CHECK (kb = '' OR (kb GLOB 'KB[0-9]*' AND kb NOT GLOB 'KB*[^0-9]*' AND length(kb) BETWEEN 8 AND 10)),
    day    TEXT    NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    PRIMARY KEY (build, server, rev)
) WITHOUT ROWID;
