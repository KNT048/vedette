package ops

import "io"

// Pure functions that the contract tests (modules/host) and the fuzz targets exercise from
// outside the package. They have no side effects and take no paths.

// ReadArchive walks a backup archive and hands each accepted member to sink (see readArchive for
// what is accepted). It never writes anywhere.
func ReadArchive(r io.Reader, sink func(name string, data []byte) error) error {
	return readArchive(r, func(name string, mr io.Reader, size int64) error {
		b, err := io.ReadAll(io.LimitReader(mr, size))
		if err != nil {
			return err
		}
		return sink(name, b)
	})
}

// ParseManifest validates the text of a backup manifest.
func ParseManifest(b []byte) (Manifest, error) { return parseManifest(b) }

// ValidateApt is the validator of the apt-get binary: the only argv shapes it may ever be given.
func ValidateApt(args []string) error { return validateApt(args) }

// ValidateSystemctl returns the validator of the systemctl binary for a given core unit.
func ValidateSystemctl(coreUnit string) func([]string) error { return validateSystemctl(coreUnit) }

// ValidateJournal is the validator of the journalctl binary.
func ValidateJournal(args []string) error { return validateJournal(args) }
