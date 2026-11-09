package notify

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var key = bytes.Repeat([]byte{0x42}, 32)

func binding(now time.Time) Binding {
	return Binding{RequestID: "ar-2026-1109-001", UserID: "u-admin", Channel: "email", ExpiresAt: now.Add(ApprovalTTL)}
}

// memNonce is the in-memory consumed-token store used as the test fake.
type memNonce struct {
	mu   sync.Mutex
	used map[TokenID]bool
}

func (m *memNonce) Consume(_ context.Context, id TokenID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used == nil {
		m.used = map[TokenID]bool{}
	}
	if m.used[id] {
		return false, nil
	}
	m.used[id] = true
	return true, nil
}

type failingNonce struct{}

func (failingNonce) Consume(context.Context, TokenID) (bool, error) {
	return false, errors.New("db down")
}

func TestContract_INV7_TokenFormatAndRoundTrip(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	tok, id, err := MintApprovalToken(key, b, RiskMedium, now)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22}$`).MatchString(tok) || len(tok) != 48 {
		t.Fatalf("token format: %q (%d)", tok, len(tok))
	}
	pid, err := ParseApprovalToken(tok)
	if err != nil || pid != id || len(id.String()) != 32 {
		t.Fatalf("parse: %v %v", pid, err)
	}
	got, err := VerifyApprovalToken(key, tok, b, now.Add(ApprovalTTL-time.Second))
	if err != nil || got != id {
		t.Fatalf("verify: %v", err)
	}
	// Verify (the GET) changes nothing: it can run any number of times.
	for range 3 {
		if _, err := VerifyApprovalToken(key, tok, b, now); err != nil {
			t.Fatal(err)
		}
	}
	// Two mints for the same binding differ (random token_id): one token per approver and attempt.
	tok2, id2, _ := MintApprovalToken(key, b, RiskMedium, now)
	if tok2 == tok || id2 == id {
		t.Error("two tokens for one binding are identical")
	}
}

func TestContract_INV7_TokenBoundToRequestAndRecipient(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	tok, _, _ := MintApprovalToken(key, b, RiskLow, now)
	for name, mod := range map[string]func(*Binding){
		"other request": func(x *Binding) { x.RequestID = "ar-2026-1109-002" },
		"other user":    func(x *Binding) { x.UserID = "u-op" },
		"other channel": func(x *Binding) { x.Channel = "zalo" },
		"later expiry":  func(x *Binding) { x.ExpiresAt = x.ExpiresAt.Add(time.Second) },
		"earlier":       func(x *Binding) { x.ExpiresAt = x.ExpiresAt.Add(-time.Second) },
		"id with lf":    func(x *Binding) { x.RequestID = b.RequestID + "\nu-op" },
		"empty user":    func(x *Binding) { x.UserID = "" },
	} {
		x := b
		mod(&x)
		if _, err := VerifyApprovalToken(key, tok, x, now); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%s: err = %v, want ErrTokenInvalid", name, err)
		}
	}
	other := bytes.Repeat([]byte{0x43}, 32)
	if _, err := VerifyApprovalToken(other, tok, b, now); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("other key: %v", err)
	}
	if _, err := VerifyApprovalToken(key[:31], tok, b, now); !errors.Is(err, ErrKeyTooShort) {
		t.Errorf("short key: %v", err)
	}
}

func TestContract_INV7_MalformedTokens(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	tok, _, _ := MintApprovalToken(key, b, RiskLow, now)
	flip := func(i int) string {
		c := []byte(tok)
		if c[i] == 'A' {
			c[i] = 'B'
		} else {
			c[i] = 'A'
		}
		return string(c)
	}
	last := tok[len(tok)-1]
	// The last base64 character carries unused bits; a non-canonical spelling of the same bytes must be refused.
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alt := tok[:len(tok)-1] + string(alpha[strings.IndexByte(alpha, last)^1])
	for name, in := range map[string]string{
		"empty": "", "prefix only": "v1.", "v2": "v2" + tok[2:], "no dots": strings.ReplaceAll(tok, ".", "-"),
		"truncated": tok[:len(tok)-1], "extended": tok + "A", "flip id": flip(5), "flip mac": flip(30),
		"padding": tok + "==", "space": " " + tok, "newline": tok + "\n", "unicode": tok[:10] + "é" + tok[11:],
		"swapped": "v1." + tok[26:] + "." + tok[3:25], "slash": strings.Replace(tok, tok[10:11], "/", 1),
	} {
		if _, err := VerifyApprovalToken(key, in, b, now); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if alt != tok {
		if _, err := VerifyApprovalToken(key, alt, b, now); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("non-canonical spelling accepted: %v", err)
		}
	}
}

func TestContract_INV7_Expiry(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	tok, _, _ := MintApprovalToken(key, b, RiskLow, now)
	if _, err := VerifyApprovalToken(key, tok, b, b.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Errorf("just before expiry: %v", err)
	}
	for _, when := range []time.Time{b.ExpiresAt, b.ExpiresAt.Add(time.Hour)} {
		if _, err := VerifyApprovalToken(key, tok, b, when); !errors.Is(err, ErrTokenExpired) {
			t.Errorf("at %v: %v", when, err)
		}
	}
	// Minting: never beyond 30 minutes, never in the past, never for the unknown.
	for name, e := range map[string]time.Time{"31 min": now.Add(31 * time.Minute), "past": now.Add(-time.Minute), "now": now, "zero": {}} {
		x := b
		x.ExpiresAt = e
		if _, _, err := MintApprovalToken(key, x, RiskLow, now); !errors.Is(err, ErrBadBinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Spec §3.2: min(now + 30 min, request expiry).
	if got := ApprovalExpiry(now, now.Add(15*time.Minute)); !got.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("request expires first: %v", got)
	}
	if got := ApprovalExpiry(now, now.Add(2*time.Hour)); !got.Equal(now.Add(ApprovalTTL)) {
		t.Errorf("30 minutes first: %v", got)
	}
	x := b
	x.ExpiresAt = ApprovalExpiry(now, now.Add(15*time.Minute))
	if _, _, err := MintApprovalToken(key, x, RiskLow, now); err != nil {
		t.Errorf("mint with ApprovalExpiry: %v", err)
	}
}

func TestContract_INV7_SingleUse(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	store := &memNonce{}
	tok, id, _ := MintApprovalToken(key, b, RiskLow, now)
	other, _, _ := MintApprovalToken(key, Binding{RequestID: b.RequestID, UserID: "u-op", Channel: "email", ExpiresAt: b.ExpiresAt}, RiskLow, now)

	if got, err := ConsumeApprovalToken(context.Background(), store, key, tok, b, now); err != nil || got != id {
		t.Fatalf("first use: %v", err)
	}
	if _, err := ConsumeApprovalToken(context.Background(), store, key, tok, b, now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second use: %v", err)
	}
	// Another approver's token for the same request is independent.
	if _, err := ConsumeApprovalToken(context.Background(), store, key, other, Binding{RequestID: b.RequestID, UserID: "u-op", Channel: "email", ExpiresAt: b.ExpiresAt}, now); err != nil {
		t.Fatalf("other approver: %v", err)
	}
	// A bad or expired token never reaches the store, so it cannot burn anyone's token.
	fresh, freshID, _ := MintApprovalToken(key, b, RiskLow, now)
	if _, err := ConsumeApprovalToken(context.Background(), store, key, fresh, b, b.ExpiresAt); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	if store.used[freshID] {
		t.Error("an expired token was burned")
	}
	if _, err := ConsumeApprovalToken(context.Background(), failingNonce{}, key, fresh, b, now); err == nil || errors.Is(err, ErrTokenUsed) {
		t.Errorf("store failure: %v", err)
	}
}

// Atomicity of "first use wins" belongs to the NonceStore (the database does it
// with a conditional UPDATE). This test pins the contract the store must meet
// and checks that ConsumeApprovalToken maps it to exactly one success and
// ErrTokenUsed for every other concurrent POST; memNonce is the in-memory model.
func TestContract_INV7_NonceStoreContractGivesOneWinner(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	store := &memNonce{}
	tok, _, _ := MintApprovalToken(key, b, RiskLow, now)
	var wins, used atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ConsumeApprovalToken(context.Background(), store, key, tok, b, now)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrTokenUsed):
				used.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || used.Load() != 19 {
		t.Errorf("wins=%d used=%d", wins.Load(), used.Load())
	}
}

func TestContract_FORBID3_HighRiskNeverByEmail(t *testing.T) {
	t.Parallel()
	now := at(10, 0)
	b := binding(now)
	for _, r := range []Risk{RiskHigh, "", "critical", "HIGH"} {
		if _, _, err := MintApprovalToken(key, b, r, now); !errors.Is(err, ErrHighRiskViaEmail) {
			t.Errorf("risk %q minted an email token: %v", r, err)
		}
		if ApprovalViaChannelAllowed("email", r) == nil {
			t.Errorf("risk %q allowed by email", r)
		}
	}
	for _, r := range []Risk{RiskLow, RiskMedium} {
		if _, _, err := MintApprovalToken(key, b, r, now); err != nil {
			t.Errorf("risk %q: %v", r, err)
		}
	}
	for _, ch := range []string{"slack", "telegram", "zalo-personal"} {
		if ApprovalViaChannelAllowed(ch, RiskHigh) != nil {
			t.Errorf("%s must not be blocked by the email rule", ch)
		}
	}
	zalo := b
	zalo.Channel = "zalo"
	if _, _, err := MintApprovalToken(key, zalo, RiskMedium, now); err != nil {
		t.Errorf("zalo link token: %v", err)
	}
	// A Zalo OA link is a bearer credential like an email link: high and unknown risk are refused too.
	for _, r := range []Risk{RiskHigh, "", "critical"} {
		if _, _, err := MintApprovalToken(key, zalo, r, now); !errors.Is(err, ErrHighRiskViaEmail) {
			t.Errorf("zalo token minted for risk %q: %v", r, err)
		}
		if ApprovalViaChannelAllowed("zalo", r) == nil {
			t.Errorf("risk %q allowed by zalo", r)
		}
	}
	bad := b
	bad.Channel = "slack" // chat channels use buttons, not link tokens
	if _, _, err := MintApprovalToken(key, bad, RiskLow, now); !errors.Is(err, ErrBadBinding) {
		t.Errorf("slack token: %v", err)
	}
	if _, _, err := MintApprovalToken(key[:16], b, RiskLow, now); !errors.Is(err, ErrKeyTooShort) {
		t.Errorf("short key: %v", err)
	}
}

func FuzzParseApprovalToken(f *testing.F) {
	tok, _, _ := MintApprovalToken(key, binding(at(10, 0)), RiskLow, at(10, 0))
	f.Add(tok)
	f.Add("v1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("v1..")
	f.Add(strings.Repeat("A", 48))
	f.Fuzz(func(t *testing.T, s string) {
		id, m, err := parse(s)
		if err != nil {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if encode(id, m) != s { // one token, one spelling
			t.Fatalf("non-canonical token accepted: %q", s)
		}
	})
}

func FuzzVerifyApprovalToken(f *testing.F) {
	now := at(10, 0)
	b := binding(now)
	good := encode(TokenID{1, 2, 3}, mac(key, TokenID{1, 2, 3}, b)) // fixed id: the fuzz coordinator and its workers must agree
	f.Add(good)
	f.Add(good[:47])
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := VerifyApprovalToken(key, s, b, now)
		if err == nil && s != good {
			t.Fatalf("a different string verified: %q", s)
		}
	})
}

func FuzzMintBinding(f *testing.F) {
	f.Add("ar-1", "u-admin", "email")
	f.Add("ar-1\nu-admin", "u", "email")
	f.Add("", "\x00", "zalo")
	f.Fuzz(func(t *testing.T, req, user, ch string) {
		now := at(10, 0)
		b := Binding{RequestID: req, UserID: user, Channel: ch, ExpiresAt: now.Add(10 * time.Minute)}
		tok, _, err := MintApprovalToken(key, b, RiskLow, now)
		if err != nil {
			return
		}
		if strings.ContainsAny(req+user, "\n\r\x00 ") {
			t.Fatalf("minted a token for ids %q %q", req, user)
		}
		if _, err := VerifyApprovalToken(key, tok, b, now); err != nil {
			t.Fatalf("minted token does not verify: %v", err)
		}
	})
}
