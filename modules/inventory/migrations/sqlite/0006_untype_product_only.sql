-- +goose Up
-- D-515 (4), W9-1: before #722 a product declared with neither IP nor name ("Microsoft Office (no device)") was stored with the type
-- its catalog entry or feeds' "I have this" suggested (pc, server or web; the catalog suggests no other computer type), written by
-- createManual as a manual kind observation in the same write as the row, its vendor observation and its software. #722 stops that
-- for new rows; this one-time clean-up untypes the rows already on a box. A row matches only as that write left it: declared by hand,
-- no IP, MAC or host name, not the box, its current type the manual observation stamped with the row's first_seen and no other type
-- observation, and the manual vendor observation of the same write (the software row of that write moves its seen_at when a person
-- edits the version, "I updated it", so the vendor observation is the stamp that stays). A type a person set later on the device page
-- has a later seen_at (re-picking the same type moves the observation's seen_at) and stays; an appliance type (firewall, router…)
-- stays. What RecomputeAsset would now store follows: kind unknown, no kind observation, fragile from fragile_kinds unless a person
-- set it. No audit row and no event, as no inventory migration writes them; the device page reads the row. Forward-only
-- (DATA_MODEL 6, rule 1).
CREATE TEMP TABLE inv_untype AS
SELECT a.id AS asset_id, o.id AS obs_id
FROM inv_asset a JOIN inv_observation o ON o.id = a.kind_obs_id AND o.asset_id = a.id
WHERE a.origin = 'manual' AND a.ip IS NULL AND a.mac IS NULL AND a.hostname IS NULL AND a.is_box = 0
  AND a.kind IN ('pc', 'server', 'web')
  AND o.field = 'kind' AND o.value = a.kind AND o.source = 'manual' AND o.seen_at = a.first_seen
  AND NOT EXISTS (SELECT 1 FROM inv_observation k WHERE k.asset_id = a.id AND k.field = 'kind' AND k.id <> o.id)
  AND EXISTS (SELECT 1 FROM inv_observation v WHERE v.asset_id = a.id AND v.field = 'vendor' AND v.source = 'manual' AND v.seen_at = a.first_seen)
  AND EXISTS (SELECT 1 FROM inv_software s WHERE s.asset_id = a.id AND s.source = 'manual');

UPDATE inv_asset SET kind = 'unknown', kind_obs_id = NULL,
    fragile = CASE WHEN fragile_manual = 1 THEN fragile
        ELSE EXISTS (SELECT 1 FROM inv_setting st, json_each(st.value) j WHERE st.key = 'fragile_kinds' AND j.value = 'unknown') END
WHERE id IN (SELECT asset_id FROM inv_untype);

DELETE FROM inv_observation WHERE id IN (SELECT obs_id FROM inv_untype);

DROP TABLE inv_untype;
