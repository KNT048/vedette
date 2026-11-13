-- +goose Up
-- D-474 (MK-1, B9a): when each source first reported to this box, so inventory.asset.discovered can say a device was found while the
-- source that found it was still learning the network (its first 36 hours). One row per source (agent, snmp, nmap, passive, scan;
-- never manual), written once by the first observation, software or service list of that source and never moved. The box's own data
-- (EnsureBox, its dpkg list) is no source's contact.
CREATE TABLE inv_source (
    source     TEXT NOT NULL PRIMARY KEY CHECK (source IN ('agent', 'snmp', 'nmap', 'passive', 'scan')),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
-- A box that ran before this migration: a source that already reported gets the first_seen of the earliest device (not the box) it
-- has rows on. seen_at moves forward on every repeat, so it cannot say when a source began; a device's first_seen does not move. It
-- may be earlier than the source's real first contact (passive found the device, nmap came later): the error is "not learning",
-- which is how every device was announced before D-474.
INSERT INTO inv_source (source, first_seen)
SELECT r.source, min(a.first_seen) FROM (
    SELECT asset_id, source FROM inv_observation
    UNION SELECT asset_id, source FROM inv_service
    UNION SELECT asset_id, source FROM inv_software
) r JOIN inv_asset a ON a.id = r.asset_id
WHERE a.is_box = 0 AND r.source <> 'manual'
GROUP BY r.source;

-- D-474 (MK-2): an agent row read from the operating system's package database (osquery deb_packages/rpm_packages, Wazuh deb/rpm, the
-- box's dpkg list). Rows from before say 0 until the agent's next report (hourly) rewrites them.
ALTER TABLE inv_software ADD COLUMN packaged BOOLEAN NOT NULL DEFAULT 0 CHECK (packaged IN (0, 1));
