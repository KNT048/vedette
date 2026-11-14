-- +goose Up
-- D-516 (review round 2 of #732): the running kernel release a node last reported ("7.0.0-43-generic", osquery kernel_info.version,
-- its own one-row query), so the package list, which may come in another request, maps the Kernel row to the running kernel's
-- image. '' until the node reports it (the Kernel row then takes the lowest installed image). Forward-only (DATA_MODEL 6).
ALTER TABLE intake_osquery_nodes ADD COLUMN kernel TEXT NOT NULL DEFAULT '' CHECK (length(kernel) <= 100);
