-- +goose Up
-- #849 (review #855 r1 L3): the Devices page reads which sources reported each device (DISTINCT asset_id, source of inv_software,
-- with inv_observation and inv_service). This index lets that pass read the index instead of every software row (an osquery or
-- Wazuh host carries about 1,500). inv_observation is covered by inv_observation_uq; inv_service is small. Forward-only (DATA_MODEL 6).
CREATE INDEX inv_software_asset_source_ix ON inv_software (asset_id, source);
