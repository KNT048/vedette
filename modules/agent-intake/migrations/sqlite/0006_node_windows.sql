-- +goose Up
-- D-524: the Windows release and monthly update revision a node last reported (osquery os_version.revision, its own Windows-only
-- query os_revision): the name ("Microsoft Windows 11 Pro"), the full version with the revision ("10.0.22631.4460") and the NVD
-- target_hw of its architecture. The package list may come in another request, and it carries the operating system's own software
-- row from these. '' until the node reports them (Linux nodes never do). Forward-only (DATA_MODEL 6).
ALTER TABLE intake_osquery_nodes ADD COLUMN win_name TEXT NOT NULL DEFAULT '' CHECK (length(win_name) <= 200);
ALTER TABLE intake_osquery_nodes ADD COLUMN win_version TEXT NOT NULL DEFAULT '' CHECK (length(win_version) <= 40);
ALTER TABLE intake_osquery_nodes ADD COLUMN win_target TEXT NOT NULL DEFAULT '' CHECK (win_target IN ('', 'x64', 'x86', 'arm64'));
