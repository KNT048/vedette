-- +goose Up
-- kien 2026-11-17: the UDP port an SNMP credential is sent to. NULL is the SNMP port, 161 (every credential saved before this one);
-- a device that serves SNMP on another port gets a credential of its own whose scope holds it, with that port (PRTG keeps the port
-- with the SNMP credentials). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE sa_snmp ADD COLUMN port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535);
