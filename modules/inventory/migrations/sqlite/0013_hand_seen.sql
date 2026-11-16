-- +goose Up
-- #829 (J2, N100 n71): a device added by hand with its address only binds the MAC a sensor sees at that address only when that MAC is
-- the first and only one seen there since the person added it. Each MAC seen at the address of such a device (no MAC, no agent) is
-- kept here, by any source: a second MAC means the address is not the person's machine alone (DHCP gave it to another one), so a later
-- machine there is a new, announced device, offered as "possibly the same device" (D-599) instead of silently inheriting the row.
-- Deleting the device drops its rows. Forward-only (DATA_MODEL 6).
CREATE TABLE inv_hand_seen (
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    mac        TEXT NOT NULL CHECK (length(mac) = 17),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, mac)
);
CREATE INDEX inv_hand_seen_mac_ix ON inv_hand_seen (mac);
