-- +goose Up
-- Whether the device that logged a hit stopped the connection (D-384): 1 for a line its profile marks as blocked (a FortiGate deny, a
-- blocked web-filter request), 0 for one that went through or does not say. The page and the incident say "tried to reach" for 1 and
-- "connected to" for 0. Add-only (D-151): an older binary does not name the column and its rows are 0, which is what it said before.
ALTER TABLE logs_ioc_hits ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;
