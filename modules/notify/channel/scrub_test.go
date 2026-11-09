package channel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

func TestContract_INV1_ChannelSecretsNeverPrint(t *testing.T) {
	t.Parallel()
	const v = "super-secret-value-123"
	type holder struct {
		Token secrets.Value
		Name  string
	}
	h := holder{Token: secrets.NewValue(v), Name: "x"}
	for _, got := range []string{
		fmt.Sprint(h.Token), fmt.Sprintf("%v %+v %#v %s %q %x %d", h.Token, h.Token, h.Token, h.Token, h.Token, h.Token, h.Token),
		fmt.Sprintf("%v %+v %#v", h, h, h), fmt.Sprintf("%v", &h), fmt.Sprintf("%v", []secrets.Value{h.Token}),
		fmt.Sprintf("%v", map[string]secrets.Value{"k": h.Token}),
	} {
		mustNot(t, got, v, "secret-value")
	}
	if h.Token.Reveal() != v || !isSet(h.Token) || isSet(secrets.NewValue("")) {
		t.Fatal("Reveal/isSet broken")
	}

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("config", slog.Any("token", h.Token), slog.Any("holder", h), slog.Group("g", slog.Any("t", h.Token)))
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
	if got := scrub("abc abcdef", secrets.NewValue("abc"), secrets.NewValue("abcdef")); got != "abc [redacted]" {
		t.Errorf("scrub = %q", got)
	}
}
