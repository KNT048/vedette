package main

import (
	"os"
	"os/exec" //nolint:depguard // test of a release shell script, fixed argv
	"strings"
	"testing"
)

// keygen.sh's check that a Keychain item trusts no application (D-259). testdata/keychain-dump.txt is the real output of
// `security dump-keychain -a` for a throwaway keychain with three items: vt-none (-T ""), vt-default (no -T: security trusts
// itself) and vt-app (-T /usr/bin/true).
func TestKeychainACLCheck(t *testing.T) {
	dump, err := os.ReadFile("testdata/keychain-dump.txt")
	must(t, err)
	check := func(svc, acct, in string) error {
		cmd := exec.CommandContext(t.Context(), "bash", "keychain-acl.sh", svc, acct)
		cmd.Stdin = strings.NewReader(in)
		return cmd.Run()
	}
	for _, c := range []struct {
		svc, acct, in string
		ok            bool
	}{
		{"vt-none", "me", string(dump), true},
		{"vt-default", "me", string(dump), false},
		{"vt-app", "me", string(dump), false},
		{"vt-missing", "me", string(dump), false},
		{"vt-none", "other", string(dump), false},
		{"vt-none", "me", strings.ReplaceAll(string(dump), "applications (0):", "applications: <null>"), false}, // every application
		{"vt-none", "me", strings.ReplaceAll(string(dump), "decrypt derive export_clear", "derive"), false},     // no reader entry found
		{"vt-none", "me", string(dump) + string(dump), false},                                                   // two items
		{"vt-none", "me", "", false},
	} {
		if err := check(c.svc, c.acct, c.in); (err == nil) != c.ok {
			t.Errorf("%s/%s: err=%v, want ok=%t", c.svc, c.acct, err, c.ok)
		}
	}
}
