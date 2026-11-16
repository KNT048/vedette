-- +goose Up
-- D-598: the agent bound to a device ("osquery:<node id>"), the identity the box gave the agent. A report of that
-- agent finds this device first, before its address, so a machine whose address changed is not counted twice. At most one device
-- per agent; NULL for every device no agent has reported on yet.
ALTER TABLE inv_asset ADD COLUMN agent_key TEXT CHECK (agent_key IS NULL OR length(agent_key) BETWEEN 3 AND 81);
CREATE UNIQUE INDEX inv_asset_agent_key ON inv_asset (agent_key) WHERE agent_key IS NOT NULL;
-- The address the bound agent last reported from: when a sensor then sees the device's burned-in MAC at another address, the binding
-- is a spoof's and is dropped (D-598, review #831 N2).
ALTER TABLE inv_asset ADD COLUMN agent_ip TEXT CHECK (agent_ip IS NULL OR length(agent_ip) BETWEEN 7 AND 15);
