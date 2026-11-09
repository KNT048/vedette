package feeds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const secretValue = "hunter2-hunter2"

type holder struct {
	Public Secret
	hidden Secret
}

func TestSecretNeverLeaks(t *testing.T) {
	t.Parallel()
	s, err := NewSecret(secretValue)
	if err != nil {
		t.Fatal(err)
	}
	h := holder{Public: s, hidden: s}
	outputs := map[string]string{
		"%v":        fmt.Sprintf("%v", s),
		"%+v":       fmt.Sprintf("%+v", s),
		"%#v":       fmt.Sprintf("%#v", s),
		"%s":        fmt.Sprintf("[%s]", s),
		"%q":        fmt.Sprintf("%q", s),
		"Sprint":    fmt.Sprint(s),
		"ptr":       fmt.Sprintf("%v", &s),
		"holder %v": fmt.Sprintf("%v", h),
		"holder +v": fmt.Sprintf("%+v", h),
		"holder #v": fmt.Sprintf("%#v", h),
		"Auth %+v":  fmt.Sprintf("%+v", Auth{Type: AuthBearer, Secret: s}),
	}
	mj, _ := json.Marshal(s)
	outputs["json"] = string(mj)
	hj, _ := json.Marshal(Auth{Type: AuthBearer, Secret: s})
	outputs["json auth"] = string(hj)

	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("x", slog.Any("secret", s), slog.Any("auth", Auth{Type: AuthBasic, Username: "u", Secret: s}), slog.Any("h", h))
	slog.New(slog.NewJSONHandler(&js, nil)).Info("x", slog.Any("secret", s), slog.Any("auth", Auth{Type: AuthBasic, Username: "u", Secret: s}))
	outputs["slog text"] = text.String()
	outputs["slog json"] = js.String()

	for name, out := range outputs {
		if strings.Contains(out, secretValue) || strings.Contains(out, "hunter2") {
			t.Errorf("%s leaks the secret: %s", name, out)
		}
	}
	if !strings.Contains(outputs["%v"], "redacted") || !strings.Contains(outputs["slog text"], "redacted") {
		t.Errorf("expected [redacted] marker: %q / %q", outputs["%v"], outputs["slog text"])
	}
}

func TestSecretAccessors(t *testing.T) {
	t.Parallel()
	s, _ := NewSecret(secretValue)
	if s.Reveal() != secretValue || s.Last4() != "ter2" {
		t.Fatalf("Reveal/Last4 wrong: %q %q", s.Reveal(), s.Last4())
	}
	if (Secret{}).IsSet() || (Secret{}).Reveal() != "" || (Secret{}).Last4() != "" {
		t.Fatal("zero Secret must be empty")
	}
	if _, err := NewSecret("short"); err == nil {
		t.Fatal("short secret accepted")
	}
}
