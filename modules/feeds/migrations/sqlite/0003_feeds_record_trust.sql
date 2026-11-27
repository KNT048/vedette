-- +goose Up
-- A CVE record's defaultStatus "unaffected" says something about the versions an entry does not list only when the assigner is the
-- product's own vendor (feeds ownCNA, record reader "ranges-6"). The rows an older reader stored do not say who assigned the record,
-- so every CNA and ADP row the generic comparison reads that keeps "unaffected" is read as unknown until the whole list is read again
-- with the current reader (the reader revision change starts that read; it writes the vendor's own lists back as they are). Until then
-- such a list only ever says "affected": no third party's list decides "not affected" on rows stored before the upgrade. The rows kept
-- in a vendor's notation ('vendor:%', read by a product's version scheme) keep their word, as the current reader keeps it.
-- Forward-only.
UPDATE feeds_cve_range SET default_status = 'unknown'
WHERE origin <> 'nvd' AND default_status = 'unaffected' AND version_type NOT LIKE 'vendor:%';
