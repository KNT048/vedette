package channel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
)

func TestContract_INV1_SecretNeverPrints(t *testing.T) {
	t.Parallel()
	const v = "super-secret-value-123"
	type holder struct {
		Token Secret
		Name  string
	}
	h := holder{Token: NewSecret(v), Name: "x"}
	for _, got := range []string{
		fmt.Sprint(h.Token), fmt.Sprintf("%v %+v %#v %s %q %x %d", h.Token, h.Token, h.Token, h.Token, h.Token, h.Token, h.Token),
		fmt.Sprintf("%v %+v %#v", h, h, h), fmt.Sprintf("%v", &h), fmt.Sprintf("%v", []Secret{h.Token}),
		fmt.Sprintf("%v", map[string]Secret{"k": h.Token}),
	} {
		mustNot(t, got, v, "secret-value")
	}
	if h.Token.Reveal() != v || h.Token.IsZero() || !NewSecret("").IsZero() {
		t.Fatal("Reveal/IsZero broken")
	}

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("config", "token", h.Token, slog.Any("holder", h), slog.Group("g", slog.Any("t", h.Token)))
	mustNot(t, buf.String(), v)
	if !bytes.Contains(buf.Bytes(), []byte("[redacted]")) {
		t.Errorf("slog output has no placeholder: %s", buf.String())
	}

	j, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	mustNot(t, string(j), v)
}

func TestScrubKeepsShortValues(t *testing.T) {
	t.Parallel()
	if got := scrub("abc abcdef", NewSecret("abc"), NewSecret("abcdef")); got != "abc [redacted]" {
		t.Errorf("scrub = %q", got)
	}
}
