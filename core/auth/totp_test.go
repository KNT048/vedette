package auth_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
)

// RFC 6238 appendix B, SHA-1, secret "12345678901234567890". The RFC lists 8-digit codes; the 6-digit
// code is their last six digits (the same truncated value modulo 10^6).
var rfc6238 = []struct {
	unix int64
	code string
}{
	{59, "287082"},
	{1111111109, "081804"},
	{1111111111, "050471"},
	{1234567890, "005924"},
	{2000000000, "279037"},
	{20000000000, "353130"},
}

func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	for _, v := range rfc6238 {
		if got := auth.TOTPCode(secret, auth.TOTPStep(time.Unix(v.unix, 0))); got != v.code {
			t.Errorf("T=%d: code %s, want %s", v.unix, got, v.code)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0) // inside step 37037036
	cur := auth.TOTPStep(now)
	at := func(step int64) string { return auth.TOTPCode(secret, step) }

	tests := []struct {
		name     string
		code     string
		lastStep int64
		wantStep int64
		ok       bool
	}{
		{"current step", at(cur), auth.NoStep, cur, true},
		{"previous step", at(cur - 1), auth.NoStep, cur - 1, true},
		{"next step", at(cur + 1), auth.NoStep, cur + 1, true},
		{"two steps back", at(cur - 2), auth.NoStep, 0, false},
		{"two steps ahead", at(cur + 2), auth.NoStep, 0, false},
		{"replay of the accepted step", at(cur), cur, 0, false},
		{"older than the accepted step", at(cur - 1), cur, 0, false},
		{"newer than the accepted step", at(cur + 1), cur, cur + 1, true},
		{"wrong code", "000000", auth.NoStep, 0, false},
		{"too short", at(cur)[:5], auth.NoStep, 0, false},
		{"too long", at(cur) + "0", auth.NoStep, 0, false},
		{"not digits", "abcdef", auth.NoStep, 0, false},
		{"empty", "", auth.NoStep, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step, ok := auth.VerifyTOTP(secret, tc.code, now, tc.lastStep)
			if ok != tc.ok || (ok && step != tc.wantStep) {
				t.Fatalf("VerifyTOTP = %d, %v; want %d, %v", step, ok, tc.wantStep, tc.ok)
			}
		})
	}
	if _, ok := auth.VerifyTOTP(secret, "287082", time.Unix(100000, 0), auth.NoStep); ok {
		t.Error("a code from far away verified")
	}
}

func TestOTPAuthURI(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	if got := auth.SecretBase32(secret); got != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("base32 = %s", got) // the RFC 6238 secret in base32
	}
	raw := auth.OTPAuthURI("a+b@acme.example", secret)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Vedette:a+b@acme.example" ||
		q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "Vedette" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("uri = %s (%+v)", raw, q)
	}
	if strings.Contains(raw, " ") {
		t.Fatal("uri contains a space")
	}
	s1, _ := auth.NewTOTPSecret()
	s2, _ := auth.NewTOTPSecret()
	if len(s1) != 20 || string(s1) == string(s2) {
		t.Fatal("secrets are not 20 random bytes")
	}
}
