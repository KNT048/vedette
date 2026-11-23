-- +goose Up
-- What a device brought to a person's merge, kept on the device it joined, so that splitting off its interface again gives back the
-- device it was: its id, its name in Vedette and what was known of it only (maker, model, host name, type, OS), not a new
-- "Unknown" row. One row per device a merge took; it goes when that interface is split off, or with the kept device.
-- Forward-only: there is no Down section.
CREATE TABLE inv_merged_from (
    asset_id  TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    -- the id the merged device had; it is free again once that device was deleted by the merge
    from_id   TEXT NOT NULL CHECK (length(from_id) BETWEEN 1 AND 96),
    -- the main interface the merged device had (one of the kept device's addresses after the merge)
    ip        TEXT CHECK (ip IS NULL OR length(ip) BETWEEN 7 AND 15),
    mac       TEXT CHECK (mac IS NULL OR length(mac) = 17),
    user_name TEXT CHECK (user_name IS NULL OR length(user_name) BETWEEN 1 AND 64),
    -- the observations only the merged device held (the kept one had none of that field, source and value): a JSON array of
    -- {field, value, source, confidence, seen_at}
    facts     TEXT NOT NULL CHECK (json_valid(facts) AND length(facts) <= 65536),
    merged_at TEXT NOT NULL CHECK (merged_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, from_id),
    CHECK (ip IS NOT NULL OR mac IS NOT NULL)
);
