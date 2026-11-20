-- +goose Up
-- INV-47: a person looked at a detected value that differs from what they entered and chose to keep their own. One row per device,
-- field and detected value: the notice stays hidden while the sources keep reading that value, and shows again when they read
-- another. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE inv_detected_keep (
    asset_id TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    field    TEXT NOT NULL CHECK (field IN ('hostname', 'vendor', 'model', 'os', 'kind')),
    detected TEXT NOT NULL CHECK (length(detected) BETWEEN 1 AND 253),
    kept_at  TEXT NOT NULL,
    kept_by  TEXT,
    PRIMARY KEY (asset_id, field, detected)
) WITHOUT ROWID;
