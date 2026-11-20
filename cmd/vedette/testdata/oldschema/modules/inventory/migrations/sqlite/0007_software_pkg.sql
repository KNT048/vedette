-- +goose Up
-- D-516: the full Debian version ("1:9.6p1-3ubuntu13.14", epoch and revision kept) and the source package ("openssh") of a
-- packaged agent row (osquery deb_packages, Wazuh deb packages, the box's dpkg list), so findings can compare the device's
-- package with the version Ubuntu or Debian fixed a CVE in. version keeps the upstream number the matcher compares with NVD.
-- NULL for every other row, and for rows stored before this migration until the next report rewrites them (within the hour).
ALTER TABLE inv_software ADD COLUMN pkg_version TEXT CHECK (pkg_version IS NULL OR length(pkg_version) BETWEEN 1 AND 100);
ALTER TABLE inv_software ADD COLUMN pkg_source TEXT CHECK (pkg_source IS NULL OR length(pkg_source) BETWEEN 1 AND 100);
