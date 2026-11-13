-- +goose Up
-- D-466: a Trap IP is a profile (name, address, preset, vendor, its own services). One table replaces the secondary IP (hp_config key
-- "config"), the five box-wide trap switches (hp_trap) and the decoy personalities (hp_decoys). Forward-only: no Down section.
-- No address answers a port after this migration that it did not answer before: the secondary IP keeps the traps that were on; a decoy
-- keeps the services of its preset that were on (a decoy used to answer every trap that was on, which D-466 ends); a profile left with
-- nothing that was on keeps its preset's services and is switched off. Vendor is NULL, so every address keeps the MAC it has. Hits stay.
CREATE TABLE hp_trap_ips (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 15),
    ip         TEXT    NOT NULL UNIQUE CHECK (length(ip) BETWEEN 7 AND 15),
    preset     TEXT    NOT NULL CHECK (preset IN ('file_server', 'nas', 'printer', 'camera', 'linux', 'database', 'custom')),
    vendor     TEXT    CHECK (vendor IS NULL OR length(vendor) BETWEEN 1 AND 32),
    services   TEXT    NOT NULL CHECK (json_valid(services) AND json_type(services) = 'array'),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

-- The secondary IP becomes the first profile: created a second before anything else, so it stays first (the first profile with SMB
-- names the share, D-466 (4)).
INSERT INTO hp_trap_ips (id, name, ip, preset, vendor, services, enabled, created_at)
SELECT 'tip-secondary',
       CASE WHEN length(trim(coalesce(json_extract(c.value, '$.hostname'), ''))) BETWEEN 1 AND 15 THEN trim(json_extract(c.value, '$.hostname')) ELSE 'TRAP-1' END,
       json_extract(c.value, '$.secondary_ip'),
       CASE WHEN EXISTS (SELECT 1 FROM hp_trap WHERE enabled = 1) THEN 'custom' ELSE 'file_server' END,
       NULL,
       CASE WHEN EXISTS (SELECT 1 FROM hp_trap WHERE enabled = 1)
            THEN (SELECT json_group_array(service) FROM (SELECT service FROM hp_trap WHERE enabled = 1
                  ORDER BY CASE service WHEN 'smb' THEN 1 WHEN 'rdp' THEN 2 WHEN 'ssh' THEN 3 WHEN 'mssql' THEN 4 ELSE 5 END))
            ELSE '["smb","rdp"]' END,
       EXISTS (SELECT 1 FROM hp_trap WHERE enabled = 1),
       strftime('%Y-%m-%dT%H:%M:%fZ', min(c.updated_at, coalesce((SELECT min(created_at) FROM hp_decoys), c.updated_at)), '-1 second')
FROM hp_config c
WHERE c.key = 'config' AND coalesce(json_extract(c.value, '$.secondary_ip'), '') != '';

-- Each decoy becomes a profile of its personality's preset, with the services of that preset that were switched on. A decoy only ever
-- listened while the secondary IP was set and a trap was on.
WITH pre (personality, preset, service, ord) AS (VALUES
    ('windows_fs', 'file_server', 'smb', 1), ('windows_fs', 'file_server', 'rdp', 2),
    ('nas', 'nas', 'http', 1), ('nas', 'nas', 'smb', 2),
    ('printer', 'printer', 'http', 1),
    ('camera', 'camera', 'http', 1),
    ('linux', 'linux', 'ssh', 1))
INSERT INTO hp_trap_ips (id, name, ip, preset, vendor, services, enabled, created_at)
SELECT d.id, d.name, d.ip,
       (SELECT p.preset FROM pre p WHERE p.personality = d.personality LIMIT 1),
       NULL,
       CASE WHEN EXISTS (SELECT 1 FROM pre p JOIN hp_trap t ON t.service = p.service AND t.enabled = 1 WHERE p.personality = d.personality)
            THEN (SELECT json_group_array(service) FROM (SELECT p.service FROM pre p JOIN hp_trap t ON t.service = p.service AND t.enabled = 1
                  WHERE p.personality = d.personality ORDER BY p.ord))
            ELSE (SELECT json_group_array(service) FROM (SELECT p.service FROM pre p WHERE p.personality = d.personality ORDER BY p.ord)) END,
       d.enabled = 1
           AND EXISTS (SELECT 1 FROM hp_trap_ips WHERE id = 'tip-secondary')
           AND EXISTS (SELECT 1 FROM pre p JOIN hp_trap t ON t.service = p.service AND t.enabled = 1 WHERE p.personality = d.personality),
       d.created_at
FROM hp_decoys d;

DROP TABLE hp_decoys;
DROP TABLE hp_trap;
DELETE FROM hp_config WHERE key = 'config';
