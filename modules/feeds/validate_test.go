package feeds

import (
	"errors"
	"strings"
	"testing"
)

func TestContract_INV2_URLRule(t *testing.T) {
	t.Parallel()
	ok := []string{
		"https://www.cisa.gov/feed.json",
		"HTTPS://Example.COM/a?b=c",
		"  https://example.com/x  ",
		"http://localhost:8080/feed",
		"http://127.0.0.1/feed",
		"http://127.9.9.9/feed",
		"http://10.1.2.3/feed",
		"http://172.16.0.1/feed",
		"http://172.31.255.255/feed",
		"http://192.168.1.10/feed",
		"http://feeds.lan/x",
		"http://intel.internal/x",
		"http://box.local/x",
		"http://a.localhost/x",
		"http://[::1]:9000/x",
	}
	for _, u := range ok {
		if err := CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", u, err)
		}
	}
	httpsOnly := []string{
		"http://example.com/feed",
		"http://172.32.0.1/feed",
		"http://172.15.0.1/feed",
		"http://192.169.0.1/feed",
		"http://11.0.0.1/feed",
		"http://10.0.0.1.evil.com/feed",
		"http://localhost.evil.com/feed",
		"http://evil.com/.local",
		"http://[2001:db8::1]/x",
	}
	for _, u := range httpsOnly {
		err := CheckURL(u)
		if !errors.Is(err, ErrHTTPSRequired) || !errors.Is(err, ErrInvalidURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrHTTPSRequired (is ErrInvalidURL)", u, err)
		}
	}
	bad := []string{
		"", "   ", "example.com/feed", "ftp://example.com/f", "file:///etc/passwd", "javascript:alert(1)",
		"https://", "https:///path", "https://user:pw@example.com/f", "https://exa mple.com/",
		"https://example.com/\x00", "https://example.com/\r\nHost: x", "mailto:a@b.c", "//example.com/feed",
		"https://example.com/" + strings.Repeat("a", MaxURLLen),
	}
	for _, u := range bad {
		if err := CheckURL(u); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrInvalidURL", u, err)
		}
	}
}

func TestContract_INV5_Interval(t *testing.T) {
	t.Parallel()
	for _, h := range []int{1, 6, 24, 168} {
		if err := CheckInterval(h); err != nil {
			t.Errorf("CheckInterval(%d) = %v", h, err)
		}
	}
	for _, h := range []int{-1, 0, 169, 1000} {
		if err := CheckInterval(h); !errors.Is(err, ErrInvalidInterval) {
			t.Errorf("CheckInterval(%d) = %v, want ErrInvalidInterval", h, err)
		}
	}
}

func TestContract_INV5_KindFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		k  Kind
		f  Format
		ok bool
	}{
		{KindVulnerabilities, FormatJSON, true}, {KindVulnerabilities, FormatCSV, true}, {KindVulnerabilities, FormatRSS, true},
		{KindVulnerabilities, FormatSTIX, false}, {KindVulnerabilities, FormatLines, false},
		{KindIOC, FormatJSON, true}, {KindIOC, FormatCSV, true}, {KindIOC, FormatRSS, true},
		{KindIOC, FormatSTIX, true}, {KindIOC, FormatLines, true},
		{KindIOC, "xml", false}, {"other", FormatJSON, false},
	}
	for _, c := range cases {
		err := CheckKindFormat(c.k, c.f)
		if (err == nil) != c.ok {
			t.Errorf("CheckKindFormat(%s,%s) = %v, want ok=%v", c.k, c.f, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidFormat) {
			t.Errorf("CheckKindFormat(%s,%s) error %v is not ErrInvalidFormat", c.k, c.f, err)
		}
	}
}

func TestContract_INV5_NameUniqueCaseInsensitive(t *testing.T) {
	t.Parallel()
	others := []string{"Partner list", "Second feed"}
	if err := CheckName("Third feed", others); err != nil {
		t.Fatalf("fresh name rejected: %v", err)
	}
	for _, n := range []string{"partner LIST", "  Partner list ", "SECOND FEED", "cisa kev", "Ipsum", "ABUSE.CH SSLBL"} {
		if err := CheckName(n, others); !errors.Is(err, ErrDuplicateName) {
			t.Errorf("CheckName(%q) = %v, want ErrDuplicateName", n, err)
		}
	}
	for _, n := range []string{"", "   ", strings.Repeat("x", MaxNameLen+1), "bad\x00name", "line\nbreak"} {
		if err := CheckName(n, others); !errors.Is(err, ErrInvalidName) {
			t.Errorf("CheckName(%q) = %v, want ErrInvalidName", n, err)
		}
	}
	if err := CheckName(strings.Repeat("é", MaxNameLen), nil); err != nil {
		t.Errorf("60 multibyte characters should be accepted: %v", err)
	}
}

func TestContract_INV6_SecretRules(t *testing.T) {
	t.Parallel()
	good := []string{"12345678", "s3cr3t-token-value", strings.Repeat("a", 500)}
	for _, s := range good {
		if err := CheckSecret(s); err != nil {
			t.Errorf("CheckSecret(%d chars) = %v", len(s), err)
		}
	}
	bad := []string{"", "1234567", "has space1", "tab\tchar12", "new\nline12", "nul\x00byte1", "nbsp here1", strings.Repeat("a", 501), "bad\xffutf8xx"}
	for _, s := range bad {
		if err := CheckSecret(s); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("CheckSecret(%q) = %v, want ErrInvalidSecret", s, err)
		}
	}
}

func TestContract_INV6_AuthKeepsStoredSecret(t *testing.T) {
	t.Parallel()
	str := func(s string) *string { return &s }
	cases := []struct {
		name     string
		t        AuthType
		header   string
		user     string
		secret   *string
		stored   bool
		wantFail bool
	}{
		{"none ignores everything", AuthNone, "!!", "", nil, false, false},
		{"bearer with new secret", AuthBearer, "", "", str("abcdefgh"), false, false},
		{"bearer without secret and none stored", AuthBearer, "", "", nil, false, true},
		{"bearer edit keeps stored secret", AuthBearer, "", "", nil, true, false},
		{"bearer weak secret", AuthBearer, "", "", str("short"), true, true},
		{"header ok", AuthHeader, "X-Api-Key", "", str("abcdefgh"), false, false},
		{"header bad name", AuthHeader, "X Api", "", str("abcdefgh"), false, true},
		{"header injection", AuthHeader, "X-A\r\nHost", "", str("abcdefgh"), false, true},
		{"header reserved host", AuthHeader, "Host", "", str("abcdefgh"), false, true},
		{"header reserved user-agent", AuthHeader, "user-agent", "", str("abcdefgh"), false, true},
		{"basic ok", AuthBasic, "", "bob", str("abcdefgh"), false, false},
		{"basic needs user", AuthBasic, "", "  ", str("abcdefgh"), false, true},
		{"basic colon in user", AuthBasic, "", "a:b", str("abcdefgh"), false, true},
		{"unknown type", "digest", "", "", str("abcdefgh"), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckAuth(c.t, c.header, c.user, c.secret, c.stored)
			if (err != nil) != c.wantFail {
				t.Fatalf("err = %v, wantFail %v", err, c.wantFail)
			}
			if err != nil && !errors.Is(err, ErrInvalidAuth) && !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf("unexpected error kind: %v", err)
			}
		})
	}
}

func TestErrorDetailIsUserSentence(t *testing.T) {
	t.Parallel()
	err := CheckURL("http://example.com")
	var fe *Error
	if !errors.As(err, &fe) || !strings.HasPrefix(fe.Detail, "Use an https://") {
		t.Fatalf("detail not exposed: %v", err)
	}
}
