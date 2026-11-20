-- +goose Up
-- Review r1 M1 of #953: an ask of "I updated it" closes only once the node's software list was taken AFTER its own operating-system
-- answer (kernel_info on Linux, os_revision on Windows) came since the ask, so a list taken with the old kernel or update revision
-- does not end it. os_taken_at is when that answer last came while an ask was open; NULL = never. Forward-only (DATA_MODEL 6).
ALTER TABLE intake_osquery_nodes ADD COLUMN os_taken_at TEXT;
