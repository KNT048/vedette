package transport

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// M2: one redaction for the Test, the writer and the reader.
func TestRedactCoversEveryFormOfASecret(t *testing.T) {
	t.Parallel()
	const secret = "s3cr/et&with+odd=chars%1 x\"y" //nolint:gosec // a fixture
	j, _ := json.Marshal(secret)
	forms := map[string]string{
		"clear":        secret,
		"json":         string(j[1 : len(j)-1]),
		"json slashes": strings.ReplaceAll(string(j[1:len(j)-1]), "/", `\/`),
		"query":        url.QueryEscape(secret),
		"path":         url.PathEscape(secret),
		"base64":       base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64url":    base64.URLEncoding.EncodeToString([]byte(secret)),
		"base64 raw":   base64.RawStdEncoding.EncodeToString([]byte(secret)),
	}
	for name, f := range forms {
		if got := Redact("before "+f+" after", secret); strings.Contains(got, f) || !strings.Contains(got, "***") {
			t.Errorf("%s: %q", name, got)
		}
	}
	// base64 of a longer text that holds the secret, at each of the three alignments.
	for k := range 3 {
		whole := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", k) + secret + "tail"))
		got := Redact(whole, secret)
		enc := base64.RawStdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(got, enc[4:len(enc)-4]) {
			t.Errorf("alignment %d: %q", k, got)
		}
	}
}

func TestRedactBasicValueAndPasswordWithUserName(t *testing.T) {
	t.Parallel()
	const user, pw = "svc", "svc:pw-9876543" //nolint:gosec // a fixture: a password that holds the user name and a colon
	basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + pw))
	got := Redact("Authorization: Basic "+basic+" and "+pw, Secrets("basic", user, pw)...)
	if strings.Contains(got, "pw-9876543") || strings.Contains(got, basic) || strings.Contains(got, basic[:8]) {
		t.Errorf("%q", got)
	}
	// The user name is not a secret: it stays.
	if got := Redact("user svc signed in", Secrets("basic", user, pw)...); got != "user svc signed in" {
		t.Errorf("the user name was redacted: %q", got)
	}
	if len(Secrets("token", "u", "")) != 0 || len(Forms("abc")) != 0 {
		t.Error("a short or empty secret has forms")
	}
}

func TestRedactReplacesTheLongestFirst(t *testing.T) {
	t.Parallel()
	// The password is the tail of the Basic value in base64 when the user name is a multiple of 3 bytes: the whole goes first.
	user, pw := "abc", "pw-1234567"
	basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + pw))
	got := Redact("v "+basic, Secrets("basic", user, pw)...)
	if got != "v ***" {
		t.Errorf("%q", got)
	}
}

func TestCleanTextCutsAfterRedactionAndDropsAPartialSecret(t *testing.T) {
	t.Parallel()
	const secret = "tok-0123456789-abcdef"
	// A secret straddling the cut: nothing of it, not even its first characters, is the end of the text.
	in := strings.Repeat("x", 10) + secret + strings.Repeat("y", 50)
	out, cut := CleanText(in, 14, secret)
	if !cut || strings.Contains(out, "tok") || strings.Contains(out, "***tok") {
		t.Errorf("%q cut=%v", out, cut)
	}
	// A multibyte character at the limit is not split.
	out, cut = CleanText(strings.Repeat("é", 10), 5)
	if !cut || out != "éé" {
		t.Errorf("%q cut=%v", out, cut)
	}
	// Newline and tab stay; the rest of the controls, ANSI, separators and invisible characters go.
	in = "a\nb\tc\x1b[31mred\x1b[0m\x00\u2028\u2029\u200b\ufe0f\u202e\r!\x1b[3"
	if out, cut = CleanText(in, 100); out != "a\nb\tcred!" || cut {
		t.Errorf("%q cut=%v", out, cut)
	}
}

func TestCleanLineKeepsOneLineWithoutInvisibles(t *testing.T) {
	t.Parallel()
	if got := CleanLine("a\u2028b\u2029c\ufe0fd\u200be\nf"); got != "a b cde f" {
		t.Errorf("%q", got)
	}
	long := strings.Repeat("a", 190) + "tok-0123456789" + strings.Repeat("b", 50)
	if got := CleanLine(long, "tok-0123456789"); strings.Contains(got, "tok-") || len([]rune(got)) > MaxLine {
		t.Errorf("%q", got)
	}
}

func TestKeepSchema(t *testing.T) {
	t.Parallel()
	if got := keepSchema([]byte(`{ "type" : "object" }`)); string(got) != `{"type":"object"}` {
		t.Errorf("compact: %q", got)
	}
	over := []byte(`{"x":"` + strings.Repeat("a", MaxSchema) + `"}`)
	if keepSchema(over) != nil {
		t.Error("a schema over 8 KiB was kept")
	}
	for _, bad := range []string{``, `[1,2]`, `"text"`, `null`, `5`, `{`, `{"a":}`} {
		if keepSchema([]byte(bad)) != nil {
			t.Errorf("%q was kept", bad)
		}
	}
}
