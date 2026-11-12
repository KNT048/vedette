-- +goose Up
-- The name a feed lists when dest is one of its subdomains (D-228, D-425): '' for a destination listed under its own name. The page shows
-- "listed as <name>" and Look up goes to it; dedupe is on (src_ip, listed name), so the random subdomains of one listed name that a
-- device asks for are one hit in 24 hours. Add-only (D-151): an older binary does not name the column and its rows are '', which is
-- what it showed before. No CHECK (an older binary's writes must not fail); the value is a parent of dest, so at most 253 bytes.
ALTER TABLE logs_ioc_hits ADD COLUMN listed_as TEXT NOT NULL DEFAULT '';
