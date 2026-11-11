-- +goose Up
-- Signature counters (WP-24 L3): what the digest reads instead of scanning lines. Add-only (D-151): an older binary ignores them.
-- A signature is the short normalised text that stands for a kind of line (modules/logs/signature). Nothing here holds a raw line
-- but one clipped sample per row, written when the row is created.

-- One row per UTC day, source and signature. count is the number of lines; first_seen is the receive time of the first line of the
-- row; sample is that line, clipped (what the digest shows as an example); dest is the destination of the latest line, for display
-- only (it is not part of the key, so a scan of many addresses is one row). mined is 1 when the signature came from the generic
-- template miner and 0 when a device profile made it: the two have separate caps, so a flood of mined lines can never push a profile
-- signature out. Caps per source and day: 1,000 mined and 2,000 profile rows; the rest of the lines of that day are counted under the
-- signature "(other)" (a device is untrusted: a different line every time must not grow the table). The primary key starts with the
-- day (the digest reads the last 10 days as a range, the purge deletes by day); the index serves the reads of one signature of one source (the example and the destination of a digest item).
CREATE TABLE logs_signature_daily (
    day        TEXT    NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    source_id  TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    signature  TEXT    NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    dest       TEXT    NOT NULL CHECK (length(dest) <= 64),
    count      INTEGER NOT NULL CHECK (count > 0),
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    sample     TEXT    NOT NULL CHECK (length(sample) <= 512),
    mined      INTEGER NOT NULL CHECK (mined IN (0, 1)),
    PRIMARY KEY (day, source_id, signature)
) WITHOUT ROWID;
CREATE INDEX logs_signature_daily_source ON logs_signature_daily (source_id, signature, day);

-- The same count per 5 minutes, kept 48 hours: the read port of response's log_threshold ("10 failed logins in 5 minutes"), which a
-- daily row cannot answer. Caps per source and bucket: 500 mined and 500 profile rows, the rest under "(other)".
CREATE TABLE logs_signature_buckets (
    source_id TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    signature TEXT    NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    count     INTEGER NOT NULL CHECK (count > 0),
    mined     INTEGER NOT NULL CHECK (mined IN (0, 1)),
    PRIMARY KEY (bucket, source_id, signature) -- starts with the bucket: the purge is a range delete, and Counts reads the few buckets of its window
) WITHOUT ROWID;

-- What logs.anomaly.detected has already announced, so that a restart does not announce again and so that "at most 20 an hour per
-- source" can be counted: one row per signature announced (ref is the first time for "new", the UTC day for "spike"), and the
-- events sent in the last hour are the distinct (target, sent_at) of a source. Kept 3 days.
CREATE TABLE logs_anomaly_sent (
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    kind      TEXT NOT NULL CHECK (kind IN ('new', 'spike')),
    signature TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    ref       TEXT NOT NULL,
    target    TEXT NOT NULL,
    sent_at   TEXT NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (source_id, kind, signature, ref)
) WITHOUT ROWID;
