package worker

// VersionOf exposes versionOf to the tests of this package.
func VersionOf(out []byte) string { return versionOf(out) }
