//go:build !releasetestkeys

package release

// embeddedKeys: a production build has only the constants of keys.go.
func embeddedKeys() (active, backup, cosign string, testOnly bool) {
	return prodMinisignActive, prodMinisignBackup, prodCosign, false
}
