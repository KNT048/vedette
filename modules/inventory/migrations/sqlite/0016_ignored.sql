-- +goose Up
-- D-628 (kien, J2): a person ignores a device that needs no watching (a staff phone). ignored_at is when; NULL = watched. An ignored
-- device stays known (its row, MAC and agent key keep it across sightings) but leaves To review, the device counts, the new-device
-- alert, the scans and SNMP reads (its scan_source and snmp_source are set off with it) and the vulnerability matching; trap hits
-- and intrusion-detection incidents from it still alert. Forward-only (DATA_MODEL 6).
ALTER TABLE inv_asset ADD COLUMN ignored_at TEXT;
