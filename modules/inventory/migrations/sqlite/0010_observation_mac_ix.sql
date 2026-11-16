-- +goose Up
-- D-598 (4), n69: every device a batch touched looks for the one other row a sensor saw last with the same private MAC (sameMAC,
-- macHolders). That reads mac observations by value across devices; inv_observation_uq starts with asset_id, so without this index each
-- lookup reads the whole table. Forward-only (DATA_MODEL 6).
CREATE INDEX inv_observation_mac_ix ON inv_observation (value) WHERE field = 'mac';
