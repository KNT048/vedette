-- +goose Up
-- n82 (BN340): what the device said, kept with its newest answer, so a sysDescr or sysObjectID that no layout reads yet can be read on
-- the box (sqlite3 … 'SELECT ip, sys_descr, sys_object_id FROM sa_snmp_answer') and become the next layout. The device's own text,
-- untrusted: cleaned by sensor-active first (valid UTF-8, no control or format character, spaces collapsed, at most 200 characters),
-- never shown as HTML, never parsed but through the fixed layouts. NULL for answers stored before this migration until the next one.
-- Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE sa_snmp_answer ADD COLUMN sys_descr TEXT CHECK (sys_descr IS NULL OR length(sys_descr) BETWEEN 1 AND 200);
ALTER TABLE sa_snmp_answer ADD COLUMN sys_object_id TEXT CHECK (sys_object_id IS NULL OR length(sys_object_id) BETWEEN 1 AND 200);
