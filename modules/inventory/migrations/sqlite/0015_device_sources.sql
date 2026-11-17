-- +goose Up
-- D-601 (kien, FortiGate added by hand): a person turns each active source on or off per device. scan_source is the network scan
-- (discovery's nmap and the vulnerability scans), snmp_source the SNMP reads. NULL is the default: on for a device a sensor found
-- (the box's own settings decide, as before), off for a device added by hand (INV-5: it stays silent until a person turns a source
-- on). 'off' stops that traffic for any device; 'on' lifts the hand-added default for that source only, every other safety rule
-- holds. Forward-only (DATA_MODEL 6).
ALTER TABLE inv_asset ADD COLUMN scan_source TEXT CHECK (scan_source IN ('on', 'off'));
ALTER TABLE inv_asset ADD COLUMN snmp_source TEXT CHECK (snmp_source IN ('on', 'off'));
