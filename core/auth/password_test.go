package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func TestHashFormat(t *testing.T) {
	t.Parallel()
	h, err := auth.HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		t.Fatalf("hash = %q", h)
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) != 16 || len(key) != 32 {
		t.Fatalf("salt %d bytes (%v), key %d bytes (%v)", len(salt), err1, len(key), err2)
	}
	// The key is argon2id of the password with that salt: the format is the standard one, not private.
	if want := argon2.IDKey([]byte("a long enough password"), salt, 3, 65536, 2, 32); string(want) != string(key) {
		t.Fatal("key does not match argon2.IDKey of the password")
	}
	ok, rehash, err := auth.VerifyPassword(h, "a long enough password")
	if err != nil || !ok || rehash {
		t.Fatalf("verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := auth.VerifyPassword(h, "a long enough passworD"); ok {
		t.Fatal("wrong password verified")
	}
	h2, _ := auth.HashPassword("a long enough password")
	if h == h2 {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
}

func TestVerifyReportsOutdatedParameters(t *testing.T) {
	t.Parallel()
	old := auth.Params{Memory: 64, Time: 1, Threads: 1}
	h, err := old.Hash("some password value")
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := authtest.Cheap.Verify(h, "some password value")
	if err != nil || !ok || rehash {
		t.Fatalf("same params: %v %v %v", ok, rehash, err)
	}
	stronger := auth.Params{Memory: 128, Time: 1, Threads: 1}
	ok, rehash, err = stronger.Verify(h, "some password value")
	if err != nil || !ok || !rehash {
		t.Fatalf("stronger params: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, rehash, _ := stronger.Verify(h, "wrong"); ok || rehash {
		t.Fatalf("wrong password must not ask for a rehash: %v %v", ok, rehash)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	t.Parallel()
	good, _ := authtest.Cheap.Hash("x")
	parts := strings.Split(good, "$")
	with := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	tests := map[string]string{
		"empty":             "",
		"not phc":           "plaintext",
		"argon2i":           with(1, "argon2i"),
		"old version":       with(2, "v=16"),
		"unknown parameter": with(3, "m=64,t=1,x=1"),
		"missing parameter": with(3, "m=64,t=1"),
		"memory bomb":       with(3, "m=4194304,t=1,p=1"),
		"time bomb":         with(3, "m=64,t=1000000,p=1"),
		"threads bomb":      with(3, "m=64,t=1,p=255"),
		"zero threads":      with(3, "m=64,t=1,p=0"),
		"memory too small":  with(3, "m=4,t=1,p=1"),
		"bad salt":          with(4, "!!!"),
		"tiny salt":         with(4, "AAAA"),
		"bad key":           with(5, "!!!"),
		"extra field":       good + "$x",
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := authtest.Cheap.Verify(h, "x"); err == nil {
				t.Fatalf("accepted %q", h)
			}
		})
	}
}

func TestHashRefusesUnsafeParams(t *testing.T) {
	t.Parallel()
	for _, p := range []auth.Params{{}, {Memory: 64, Time: 0, Threads: 1}, {Memory: 4, Time: 1, Threads: 1}, {Memory: 1 << 30, Time: 1, Threads: 1}} {
		if _, err := p.Hash("x"); err == nil {
			t.Errorf("Hash accepted %+v", p)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, password, email string
		ok                    bool
	}{
		{"twelve characters", "lamp river42", "u@acme.example", true},
		{"eleven characters", "lamp river4", "u@acme.example", false},
		{"empty", "", "u@acme.example", false},
		{"counts characters not bytes", strings.Repeat("ấbcd", 3), "u@acme.example", true},
		{"eleven multi-byte characters", string([]rune(strings.Repeat("ấbcd", 3))[:11]), "u@acme.example", false},
		{"256 characters", strings.Repeat("abcd", 64), "u@acme.example", true},
		{"257 characters", strings.Repeat("abcd", 64) + "e", "u@acme.example", false},
		// D-389: long enough but among the first guesses (NIST SP 800-63B 5.1.1.2).
		{"common stem with digits", "password1234", "u@acme.example", false},
		{"common stem with symbols and case", "Qwerty123456!", "u@acme.example", false},
		{"common stem in look-alikes", "P@$$word2024", "u@acme.example", false},
		{"common stem repeated", "adminadmin12", "u@acme.example", false},
		{"product name", "Vedette2026!!", "u@acme.example", false},
		{"one character", "aaaaaaaaaaaa", "u@acme.example", false},
		{"two characters", "121212121212", "u@acme.example", false},
		{"digit run", "123456789012", "u@acme.example", false},
		{"keyboard run backwards", "lkjhgfdsapoiu", "u@acme.example", false},
		{"name of the email", "Someone2026!!", "someone@acme.example", false},
		{"a sentence", "correct horse battery staple", "u@acme.example", true},
		{"common word inside a sentence", "my password is long now", "u@acme.example", true},
		{"is the email", "someone@acme.example", "someone@acme.example", false},
		{"is the email in other case", "Someone@Acme.example", "someone@acme.example", false},
		{"contains the email", "someone@acme.example!", "someone@acme.example", true},
		{"invalid UTF-8", "abcdefghij\xff\xfe", "u@acme.example", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := auth.ValidatePassword(tc.password, tc.email)
			if (e == nil) != tc.ok {
				t.Fatalf("ValidatePassword = %v, want ok=%v", e, tc.ok)
			}
			if e != nil && (e.Status != 400 || e.Code != "weak_password") {
				t.Fatalf("error = %+v", e)
			}
		})
	}
}

func TestTempPassword(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 50 {
		p, err := auth.NewTempPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 20 || strings.ContainsAny(p, "0O1lI") || seen[p] {
			t.Fatalf("temp password %q", p)
		}
		if e := auth.ValidatePassword(p, ""); e != nil {
			t.Fatalf("temp password fails the policy: %v", e)
		}
		seen[p] = true
	}
}
