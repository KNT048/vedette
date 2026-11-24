-- +goose Up
-- A network scan names a software line by its banner, product and version together ("OpenSSH 9.6"), while the version is a column
-- of its own: the pages and the questions showed it twice ("OpenSSH 9.6 9.6"). New readings keep the product name alone (bannerName);
-- this drops the repeated version from the scan readings and lines already stored. Only data changes, no column: a rollback keeps
-- working on these rows. Forward-only: there is no Down section.
UPDATE inv_software_reading SET display = rtrim(substr(display, 1, length(display) - length(version) - 1))
WHERE source IN ('nmap', 'scan') AND version IS NOT NULL AND length(display) > length(version) + 1
  AND substr(display, length(display) - length(version)) = ' ' || version
  AND trim(substr(display, 1, length(display) - length(version) - 1)) <> '';

UPDATE inv_software SET display = rtrim(substr(display, 1, length(display) - length(version) - 1))
WHERE source IN ('nmap', 'scan') AND version IS NOT NULL AND length(display) > length(version) + 1
  AND substr(display, length(display) - length(version)) = ' ' || version
  AND trim(substr(display, 1, length(display) - length(version) - 1)) <> '';
