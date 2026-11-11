package authtest

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
)

func TestWrongCodeIsNeverAnAcceptedCode(t *testing.T) {
	if got := WrongCode("000000", "111111"); got != "222222" {
		t.Fatalf("WrongCode = %q", got)
	}
	if got := WrongCode("123456"); got != "000000" {
		t.Fatalf("WrongCode = %q", got)
	}
	secret := []byte("12345678901234567890")
	start := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	for i := range 2000 {
		now := start.Add(time.Duration(i) * 30 * time.Second)
		if _, ok := auth.VerifyTOTP(secret, WrongTOTP(secret, now), now, auth.NoStep); ok {
			t.Fatalf("WrongTOTP at %v is accepted", now)
		}
	}
}
