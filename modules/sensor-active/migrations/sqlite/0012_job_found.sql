-- +goose Up
-- What a device check found, kept with its job so Settings › Scanning › History and the device page's Last checks can say it in
-- words ("3 open ports: 22 ssh, 80 http, 443 https; OS guess …; nothing changed since the last check") instead of pointing at the
-- device page. asset_id: the device a device check was for (NULL for sweeps, SNMP reads, external runs and device checks stored
-- before this migration). found: a JSON object of nmap's result for that device (open ports with nmap's service names, the OS
-- guess, what changed since the previous check of the same reach); NULL until the check records something. Forward-only
-- (DATA_MODEL 6, rule 1).
ALTER TABLE sa_job ADD COLUMN asset_id TEXT CHECK (asset_id IS NULL OR length(asset_id) BETWEEN 1 AND 96);
ALTER TABLE sa_job ADD COLUMN found TEXT CHECK (found IS NULL OR (json_valid(found) AND json_type(found) = 'object' AND length(found) <= 8000));
CREATE INDEX sa_job_asset_ix ON sa_job (asset_id, started_at) WHERE asset_id IS NOT NULL;
