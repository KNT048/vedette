-- +goose Up
-- "I updated it" for software an osquery agent reads (S-MIT-1, kien G12 follow-up): when a person last asked this node to send its
-- software now (report_asked_at), and when the inventory last took a software list from it (software_taken_at). While the ask is
-- newer than the last list taken and younger than reportWindow, config hands the software queries the first-report interval
-- (schedule.go nodeSchedule). NULL = never. Forward-only (DATA_MODEL 6).
ALTER TABLE intake_osquery_nodes ADD COLUMN report_asked_at TEXT;
ALTER TABLE intake_osquery_nodes ADD COLUMN software_taken_at TEXT;
