-- +goose Up
-- agent-intake, the first report and the enrolment's approval (S-INV-4, D-503). Only package modules/agent-intake writes these columns.
-- Forward-only (DATA_MODEL 6): no Down section.

-- created_by: who made the token (the audit user of inventory.agent_token_create). The device a node of the token reports on is approved
-- in that person's name (D-503). NULL for a token made before this column: the approval's audit line then says so.
ALTER TABLE intake_agent_tokens ADD COLUMN created_by TEXT CHECK (created_by IS NULL OR length(created_by) BETWEEN 1 AND 256);

-- reported: which answers of the first report the inventory has taken from this node, comma-separated from the fixed set
-- os_version, system_info, interfaces, packages. Within the first hour after enrolment the config asks every minute for each one not here
-- yet (schedule.go), so a new machine shows its OS and packages within minutes, not at the next hourly run.
ALTER TABLE intake_osquery_nodes ADD COLUMN reported TEXT NOT NULL DEFAULT '' CHECK (length(reported) <= 64);

-- approved_at: when the enrolment approved the device this node reports on (or found it marked suspicious by a person and left it):
-- done once per node, so a later change by a person is never undone by the next report.
ALTER TABLE intake_osquery_nodes ADD COLUMN approved_at TEXT;
