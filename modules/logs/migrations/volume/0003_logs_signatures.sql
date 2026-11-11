-- +goose Up
-- Signature counters (WP-24 L3): what the digest reads instead of scanning lines. Add-only (D-151): an older binary ignores them.
-- A signature is the short normalised text that stands for a kind of line (modules/logs/signature). Nothing here holds a raw line
-- but one clipped sample per row, written when the row is created.

-- One row per UTC day, source, signature and destination. count is the number of lines; first_seen is the receive time of the first
-- line of the row; sample is that line, clipped (what the digest shows as an example). The primary key starts with the day:
-- the digest reads the last 9 days as a range, the purge deletes by day. At most 2,000 rows per source and day, the rest of the lines
-- of that day are counted under the signature "(other)" (the device is untrusted: a different line every time must not grow the table).
CREATE TABLE logs_signature_daily (
    day        TEXT    NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    source_id  TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    signature  TEXT    NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    dest       TEXT    NOT NULL CHECK (length(dest) <= 64),
    count      INTEGER NOT NULL CHECK (count > 0),
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    sample     TEXT    NOT NULL CHECK (length(sample) <= 512),
    PRIMARY KEY (day, source_id, signature, dest)
) WITHOUT ROWID;

-- The same count per 5 minutes without the destination, kept 48 hours: the read port of response's log_threshold ("10 failed
-- logins in 5 minutes"), which a daily row cannot answer. At most 500 rows per source and bucket, the rest under "(other)".
CREATE TABLE logs_signature_buckets (
    source_id TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    signature TEXT    NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    count     INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (source_id, bucket, signature)
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
