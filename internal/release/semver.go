package release

import (
	"regexp"

	"golang.org/x/mod/semver"
)

// Versions are SemVer 2.0 "MAJOR.MINOR.PATCH[-prerelease]" with no leading "v" and no build
// metadata (update-manifest.md §14). A prerelease sorts below its release (1.0.0-beta.1 < 1.0.0).
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*)?$`)

func validVersion(v string) bool { return len(v) <= 64 && versionRE.MatchString(v) }

// compareVersions orders two versions already checked by validVersion: -1, 0 or +1.
func compareVersions(a, b string) int { return semver.Compare("v"+a, "v"+b) }

// CompareVersions orders two release versions; it errors when either is not valid.
func CompareVersions(a, b string) (int, error) {
	if !validVersion(a) || !validVersion(b) {
		return 0, wrap(ErrMalformed, "version %q or %q", clip(a), clip(b))
	}
	return compareVersions(a, b), nil
}

// CheckUpgrade applies the start rules of D-104 (4) for moving a service from running to m's
// release: a lower version is ErrDowngrade (going back is container.rollback), and a running
// version below min_upgrade_from is ErrUpgradePath. The same version is allowed (idempotent start).
// An empty running means nothing is installed yet.
func CheckUpgrade(m *Manifest, running string) error {
	if running == "" {
		return nil
	}
	c, err := CompareVersions(m.Version, running)
	if err != nil {
		return err
	}
	if c < 0 {
		return wrap(ErrDowngrade, "%s < %s", m.Version, running)
	}
	if m.MinUpgradeFrom != "" && compareVersions(running, m.MinUpgradeFrom) < 0 {
		return wrap(ErrUpgradePath, "running %s, need at least %s", running, m.MinUpgradeFrom)
	}
	return nil
}

// CheckRollback applies D-104 (5): running is the manifest of the release that is running, previous
// the version to go back to; previous below running.rollback.min_version is refused.
func CheckRollback(running *Manifest, previous string) error {
	if !validVersion(previous) {
		return wrap(ErrMalformed, "version %q", clip(previous))
	}
	if running.Rollback.MinVersion != "" && compareVersions(previous, running.Rollback.MinVersion) < 0 {
		return wrap(ErrRollbackNotAllowed, "%s < %s", previous, running.Rollback.MinVersion)
	}
	return nil
}
