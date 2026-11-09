package secrets_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

const plain = "hunter2-very-secret"

func TestValueRedaction(t *testing.T) {
	t.Parallel()
	v := secrets.NewValue(plain)
	type holder struct {
		Exported secrets.Value
		hidden   secrets.Value
	}
	h := holder{Exported: v, hidden: v}

	outputs := map[string]string{
		"String":          v.String(),
		"GoString":        v.GoString(),
		"Sprint":          fmt.Sprint(v),
		"Sprintf %v":      fmt.Sprintf("%v", v),
		"Sprintf %+v":     fmt.Sprintf("%+v", v),
		"Sprintf %#v":     fmt.Sprintf("%#v", v),
		"Sprintf %s":      fmt.Sprintf("%s", v),
		"Sprintf %q":      fmt.Sprintf("%q", v),
		"Sprintf %x":      fmt.Sprintf("%x", v),
		"Sprintf %d":      fmt.Sprintf("%d", v),
		"Sprintf pointer": fmt.Sprintf("%v", &v),
		"struct %v":       fmt.Sprintf("%v", h),
		"struct %+v":      fmt.Sprintf("%+v", h),
		"struct %#v":      fmt.Sprintf("%#v", h),
		"slice":           fmt.Sprint([]secrets.Value{v}),
		"map":             fmt.Sprint(map[string]secrets.Value{"k": v}),
		"error wrap":      fmt.Errorf("failed with %v: %w", v, fmt.Errorf("x")).Error(),
	}
	for name, got := range outputs {
		if strings.Contains(got, plain) || strings.Contains(strings.ToLower(got), "hunter") {
			t.Errorf("%s leaked: %q", name, got)
		}
	}
	for _, name := range []string{"String", "GoString", "Sprint", "Sprintf %v", "Sprintf %#v", "Sprintf %s", "Sprintf %q", "Sprintf %d", "Sprintf %x"} {
		if outputs[name] != "[redacted]" {
			t.Errorf("%s = %q, want [redacted]", name, outputs[name])
		}
	}
	if v.Reveal() != plain {
		t.Errorf("Reveal = %q", v.Reveal())
	}
	if (secrets.Value{}).Reveal() != "" {
		t.Error("zero Value reveals something")
	}
}

func TestValueEncoding(t *testing.T) {
	t.Parallel()
	v := secrets.NewValue(plain)
	cases := map[string]any{
		"value":   v,
		"pointer": &v,
		"struct":  struct{ Key secrets.Value }{v},
		"map":     map[string]secrets.Value{"k": v},
		"slice":   []secrets.Value{v},
	}
	for name, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(b, []byte("hunter")) || !bytes.Contains(b, []byte("[redacted]")) {
			t.Errorf("%s: JSON = %s", name, b)
		}
	}
	// A map key goes through MarshalText.
	b, err := json.Marshal(map[secrets.Value]int{v: 1})
	if err != nil || bytes.Contains(b, []byte("hunter")) {
		t.Errorf("text key: %s, %v", b, err)
	}
	txt, err := encoding.TextMarshaler(v).MarshalText()
	if err != nil || string(txt) != "[redacted]" {
		t.Errorf("MarshalText = %q, %v", txt, err)
	}
}

func TestValueSlog(t *testing.T) {
	t.Parallel()
	v := secrets.NewValue(plain)
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		log := slog.New(mk(&buf))
		log.Info("with secret", "api_key", v, slog.Group("g", slog.Any("inner", v)))
		out := buf.String()
		if strings.Contains(out, "hunter") || !strings.Contains(out, "[redacted]") {
			t.Errorf("%s handler output: %s", name, out)
		}
	}
}
