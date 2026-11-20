-- +goose Up
-- #829 (J2): the address is an attribute of a device, never its identity. ip_confirmed_at is when a sighting last tied the device to
-- its address (a sensor saw its MAC there, its bound agent reported from there, a person declared it, or, for a device known by its
-- address only, anything was seen there). A hint with only an address goes to the address's device only while this is recent (ipTrust,
-- 3 days): DHCP may have given the address to another machine that no sensor has seen yet. Rows that have an address start from their
-- last sighting, so no live device loses its facts at the upgrade. Forward-only (DATA_MODEL 6).
ALTER TABLE inv_asset ADD COLUMN ip_confirmed_at TEXT;
UPDATE inv_asset SET ip_confirmed_at = last_seen WHERE ip IS NOT NULL;
