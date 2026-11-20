-- +goose Up
-- The whole schema of the logs module in its own database, logs.db. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- Received lines. ts is the receive time (device clocks drift, RFC 3164 has no year); "newest first" walks the ts index backwards. A
-- purge of the oldest is a range delete by ts, and ids (handed out in receive order) bound the number of rows kept.
CREATE TABLE logs_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT, -- never reused: the API id le-N names one line for ever
    ts        TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    line      TEXT NOT NULL CHECK (length(line) <= 8192)
);

-- Lines per source per 5 minutes: feeds lines_per_hour and lines_24h without counting events.
CREATE TABLE logs_source_buckets (
    source_id TEXT    NOT NULL,
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    lines     INTEGER NOT NULL CHECK (lines >= 0),
    PRIMARY KEY (source_id, bucket)
) WITHOUT ROWID;

-- The last time a line arrived from a source.
CREATE TABLE logs_source_seen (
    source_id     TEXT NOT NULL PRIMARY KEY,
    last_received TEXT NOT NULL CHECK (last_received GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) WITHOUT ROWID;

-- How many bytes of line text logs_events holds: the byte bound of the purge (M2) is checked by Ingest on every batch, and a
-- sum over millions of rows is not something a batch can afford. Ingest adds to it in the batch's own transaction, the purge
-- subtracts in the transaction that deletes. One row. Add-only: an older binary ignores the table.
CREATE TABLE logs_volume (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    line_bytes INTEGER NOT NULL CHECK (line_bytes >= 0)
);

-- One row per UTC day, source and signature. count is the number of lines; first_seen is the receive time of the first line of the
-- row; sample is that line, clipped (what the digest shows as an example); dest is the destination of the latest line, for display
-- only (it is not part of the key, so a scan of many addresses is one row). mined is 1 when the signature came from the generic
-- template miner or from a profile whose text is free (1), 0 when the signature comes from a vocabulary that shipped data bounds (a known
-- log id, a known event id): the two have separate caps, so a flood of mined lines can never push a bounded signature out. Caps per source
-- and day: 1,000 mined and 2,000 bounded rows; the rest of the lines of that day are counted under the
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

-- The same count per 5 minutes, kept 24 hours and one bucket (Counts is the only reader, with a window of 24 hours at most): the read port of
-- response's log_threshold ("10 failed logins in 5 minutes"), which a daily row cannot answer. The signature is a 64-bit hash (the first 64 bits of the SHA-256) and
-- not the text: a row is small, and Counts is given the same text and hashes it. Caps per source and bucket: 200 mined and 600 bounded
-- rows (600 is at least the largest bounded vocabulary, the 540 signatures of FortiGate), the rest under the hash of "(other)". The primary key starts with the bucket (the purge is a range delete); the index serves Counts
-- (one source, one signature, a range of buckets), which must not read the other sources.
CREATE TABLE logs_signature_buckets (
    source_id TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    sig_hash  INTEGER NOT NULL,
    count     INTEGER NOT NULL CHECK (count > 0),
    mined     INTEGER NOT NULL CHECK (mined IN (0, 1)),
    PRIMARY KEY (bucket, source_id, sig_hash)
) WITHOUT ROWID;

-- What logs.anomaly.detected has already announced, so that a restart does not announce again and so that "at most 20 an hour per
-- source" can be counted: one row per signature announced (ref is the first time for "new", the UTC day for "spike"), and the
-- events sent in the last hour are the distinct (target, sent_at) of a source. Kept 3 days. Kind 'summary' is the one summary of an
-- hour (a flood of mined kinds, or the backlog of bounded events), and 'covered' marks an item that a summary has named (it is not
-- announced one by one yet, and the next summary leaves it out).
CREATE TABLE logs_anomaly_sent (
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    kind      TEXT NOT NULL CHECK (kind IN ('new', 'spike', 'summary', 'covered')),
    signature TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 256),
    ref       TEXT NOT NULL,
    target    TEXT NOT NULL,
    bounded   INTEGER NOT NULL CHECK (bounded IN (0, 1)), -- the room of the hour that the event used: bounded signatures have their own
    sent_at   TEXT NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (source_id, kind, signature, ref)
) WITHOUT ROWID;

-- Remote addresses per signature: the read port TopAddresses of response's log_threshold ("10 failed VPN logins from one
-- address"). One row per 5-minute bucket, source, signature (the same 64-bit hash as logs_signature_buckets) and address: the address
-- is the remote peer the line is about (modules/logs/signature, never the device that sent the log), as bytes. Bounded
-- per source and bucket (a device is untrusted, and so is the address it names): at most 50 addresses per signature and 500 rows
-- in all; a new address beyond a quota replaces the least counted row only if it has more lines than that row (a spoofed flood of
-- one-line addresses cannot push out an address that sent ten), and is otherwise not stored (its lines are in logs_signature_buckets
-- as before). Kept 24 hours and one bucket like them. The primary key starts with the bucket (the purge is a range delete, and the
-- caps read one bucket and source); the index serves TopAddresses (one source, one signature, a range of buckets).
CREATE TABLE logs_signature_addrs (
    source_id TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    sig_hash  INTEGER NOT NULL,
    addr      BLOB    NOT NULL CHECK (length(addr) IN (4, 16)), -- the 4 or 16 bytes of the address (an IPv4-mapped one is stored as IPv4)
    count     INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (bucket, source_id, sig_hash, addr)
) WITHOUT ROWID;

CREATE TABLE logs_ioc_hits (
    id         TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    ts         TEXT    NOT NULL,
    src_ip     TEXT    NOT NULL CHECK (length(src_ip) BETWEEN 7 AND 15),
    dest       TEXT    NOT NULL CHECK (length(dest) BETWEEN 1 AND 253),
    dest_kind  TEXT    NOT NULL CHECK (dest_kind IN ('ip', 'domain')),
    seen_via   TEXT    NOT NULL CHECK (length(seen_via) BETWEEN 1 AND 128),
    feeds      TEXT    NOT NULL CHECK (json_valid(feeds)),
    confidence REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    source_id  TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64)
, blocked INTEGER NOT NULL DEFAULT 0, listed_as TEXT NOT NULL DEFAULT '');

CREATE INDEX logs_events_ts ON logs_events (ts);

CREATE INDEX logs_events_source_ts ON logs_events (source_id, ts);

CREATE INDEX logs_signature_daily_source ON logs_signature_daily (source_id, signature, day);

CREATE INDEX logs_signature_buckets_source ON logs_signature_buckets (source_id, sig_hash, bucket);

CREATE INDEX logs_signature_addrs_source ON logs_signature_addrs (source_id, sig_hash, bucket);

CREATE INDEX logs_ioc_hits_ts ON logs_ioc_hits (ts);

CREATE INDEX logs_ioc_hits_pair ON logs_ioc_hits (src_ip, dest, ts);

CREATE INDEX logs_ioc_hits_listed ON logs_ioc_hits (src_ip, listed_as, ts);

INSERT INTO logs_volume (id, line_bytes) VALUES (1, 0);
