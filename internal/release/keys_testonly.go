//go:build releasetestkeys

package release

// Test-only keys, compiled in only with `-tags releasetestkeys`. They are the public halves of the
// throwaway keys under testdata/ (see testdata/README.md; their private halves are not kept).
// A production build never passes this tag, and a test proves it embeds no key.
const (
	testMinisignActive = "RWQoMGCadH/y2zDMUp9yWF1XArDH1RqkXCsqQeHwyhnXOCyKlJ3c5uD3"
	testMinisignBackup = "RWSLahs6lf1b8KCTWyGzo96ecNkY9ukL2lvoSK2VcAAJK5R3q8g1Yafu"
	testCosign         = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdGQd2grAcfphVcDEkmEskS/5cKsE
4Kd5B6gch15BR5xCEV84CnZFnt1YshNz+AlSvezJo6TJdpMKazGBvkVoTg==
-----END PUBLIC KEY-----
`
)

func embeddedKeys() (active, backup, cosign string, testOnly bool) {
	return testMinisignActive, testMinisignBackup, testCosign, true
}
