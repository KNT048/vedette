//go:build releasetestkeys

package release

// Test-only keys, compiled in only with `-tags releasetestkeys`. They are the public halves of the
// throwaway keys under testdata/ (see testdata/README.md; their private halves are not kept).
// A production build never passes this tag, and a test proves it embeds no key.
const (
	testMinisignActive = "RWQKlA4ScH3YgTPtNRI2lXvp+qqxNB4JMtwen+fPXZX2SwayKdy3b0VF"
	testMinisignBackup = "RWSv8NWZsQoH50es1abOBWl5Q1vU5Xi99s5m4ZXDkaUu5z+ibvrErpZn"
	testCosign         = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi+p8NnqO/1b1gKrYq1TWg7LHYdAG
kvmL+BY3itWt2Gx0VQcUOWpD2mVTFguZy3U4Ssn+rk86m0CwM1/TLVA0LA==
-----END PUBLIC KEY-----
`
)

func embeddedKeys() (active, backup, cosign string, testOnly bool) {
	return testMinisignActive, testMinisignBackup, testCosign, true
}
