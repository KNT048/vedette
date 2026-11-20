-- +goose Up
-- D-622: ubuntu-osv and debian-tracker also keep the fixed rows of the tier CVEs (nvd-recent's last 12 months) for the source
-- packages the devices run, for findings' "Updates to plan". distro_packages is the sorted JSON array of the package names a
-- distribution feed's stored rows were kept for (NULL = no pull with tier rows yet, or stored before this column): when the
-- devices run a name it lacks, the feed is pulled at the next check at least 6 hours after its last good pull, without its
-- validators; a release counts as compared only once such a pull stored rows for it. A box upgraded with Ubuntu or Debian devices
-- therefore pulls those feeds once at the first check. Forward-only.
ALTER TABLE feeds_source ADD COLUMN distro_packages TEXT CHECK (distro_packages IS NULL OR (json_valid(distro_packages) AND json_type(distro_packages) = 'array'));
