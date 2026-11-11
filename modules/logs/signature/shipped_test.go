package signature

import (
	"os"
	"testing"
)

// shipped loads the profiles that ship in modules/logs/data/profiles (the module embeds the same directory).
func shipped(t testing.TB) *Set {
	t.Helper()
	set, err := Load(os.DirFS("../data"), "profiles")
	if err != nil {
		t.Fatalf("the shipped profiles: %v", err)
	}
	return set
}
