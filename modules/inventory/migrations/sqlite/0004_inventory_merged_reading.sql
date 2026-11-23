-- +goose Up
-- The software readings a device brought to a person's merge (one inv_merged_from row), so that splitting it off again gives its
-- software back: the line it had (its id, kept by the line that moved whole; a line the kept device had too took the reading in) and
-- each reading of it, by source and instance. shared: the kept device read the same before the merge, so a copy goes back and its
-- own stays. The rows follow their inv_merged_from row (a later merge of the kept device) and go with it.
-- Forward-only: there is no Down section.
CREATE TABLE inv_merged_reading (
    asset_id    TEXT    NOT NULL,
    from_id     TEXT    NOT NULL,
    software_id TEXT    NOT NULL CHECK (length(software_id) BETWEEN 1 AND 96),
    product_key TEXT    NOT NULL CHECK (length(product_key) BETWEEN 1 AND 400),
    line        TEXT    NOT NULL CHECK (length(line) <= 20),
    source      TEXT    NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    instance    TEXT    NOT NULL CHECK (length(instance) <= 120),
    shared      INTEGER NOT NULL CHECK (shared IN (0, 1)),
    PRIMARY KEY (asset_id, from_id, software_id, source, instance),
    FOREIGN KEY (asset_id, from_id) REFERENCES inv_merged_from (asset_id, from_id) ON DELETE CASCADE ON UPDATE CASCADE
) WITHOUT ROWID;
