-- +goose Up
-- D-598 (4), n69: a sighting whose MAC is no device's MAC now looks for the device a sensor saw with it before (pastOwner), and every
-- device a batch touched looks for another row seen with one of its MACs (sameMAC). Both read mac observations by value across devices;
-- inv_observation_uq starts with asset_id, so without this index each lookup reads the whole table. Forward-only (DATA_MODEL 6).
CREATE INDEX inv_observation_mac_ix ON inv_observation (value) WHERE field = 'mac';
