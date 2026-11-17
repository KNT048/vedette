-- +goose Up
-- G2 (kien, J2): the name a person gives a device in Vedette, apart from the host name the network reports (hostname, a fold of the
-- observations that only RecomputeAsset writes). NULL = no name given: every page names the device by the naming rule (D-471);
-- set, it wins on every page and in every module (inventory.DisplayName). At most 64 characters, no < or >, trimmed (Go checks the
-- characters, PATCH /inventory/devices/{id} name). Forward-only (DATA_MODEL 6).
ALTER TABLE inv_asset ADD COLUMN user_name TEXT CHECK (user_name IS NULL OR length(user_name) BETWEEN 1 AND 64);
