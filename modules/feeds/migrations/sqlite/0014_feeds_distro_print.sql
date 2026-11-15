-- +goose Up
-- D-622: ubuntu-osv and debian-tracker also keep the fixed rows of the tier CVEs (nvd-recent's last 12 months) for the source
-- packages the devices run, for findings' "Updates to plan". distro_print is the SHA-256 of the sorted package names a
-- distribution feed's stored rows were kept for (NULL = none, or stored before this column): when the devices run a package it
-- does not cover, the feed is pulled at the next check without its validators. A box upgraded with Ubuntu or Debian devices
-- therefore pulls those feeds once at the first check. Forward-only.
ALTER TABLE feeds_source ADD COLUMN distro_print TEXT CHECK (distro_print IS NULL OR (length(distro_print) = 64 AND distro_print NOT GLOB '*[^0-9a-f]*'));
