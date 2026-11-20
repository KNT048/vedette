-- +goose Up
-- Remote addresses per signature (D-210, #338): the read port TopAddresses of response's log_threshold ("10 failed VPN logins from one
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
CREATE INDEX logs_signature_addrs_source ON logs_signature_addrs (source_id, sig_hash, bucket);
