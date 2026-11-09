package ops_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// byteArray renders s the way journalctl -o json prints a field value that holds a control
// character: an array of byte values.
func byteArray(s string) string {
	parts := make([]string, len(s))
	for i := range len(s) {
		parts[i] = fmt.Sprint(s[i])
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// journalctl prints a field that occurs more than once as an array of values, each a string or a
// byte array ("FOO":["text",[1,2,3]]). A secret in any of them must be redacted, wherever the array
// sits in the line.
func TestRedactLineCatchesAByteArrayNestedInARepeatedField(t *testing.T) {
	t.Parallel()
	secret := "password=hunter2\t" // the TAB makes journalctl print it as bytes
	for name, line := range map[string]string{
		"whole value":            `{"MESSAGE":` + byteArray(secret) + `}`,
		"text then bytes":        `{"MESSAGE":["started",` + byteArray(secret) + `]}`,
		"bytes then bytes":       `{"MESSAGE":[` + byteArray(secret) + `,` + byteArray("x\t") + `]}`,
		"bytes then text":        `{"MESSAGE":[` + byteArray(secret) + `,"done"]}`,
		"after another field":    `{"A":"1","MESSAGE":["a",` + byteArray(secret) + `]}`,
		"space before the array": `{"MESSAGE":[ ` + byteArray(secret) + `]}`,
	} {
		got := ops.RedactLine([]byte(line))
		if bytes.Equal(got, []byte(line)) || !json.Valid(got) {
			t.Errorf("%s: secret passes the export filter or the line broke: %s", name, got)
		}
		var v map[string]any
		_ = json.Unmarshal(got, &v)
		if strings.Contains(fmt.Sprint(v), "104 117 110 116 101 114 50") { // "hunter2" as bytes
			t.Errorf("%s: the secret bytes are still there: %s", name, got)
		}
	}
	clean := `{"MESSAGE":["a",[104,105]],"PRIORITY":"6"}`
	if got := ops.RedactLine([]byte(clean)); !bytes.Equal(got, []byte(clean)) {
		t.Errorf("a clean repeated field must stay as it is: %s", got)
	}
}

// systemd-coredump fields hold a crash's stack and environment; the export leaves them out.
func TestRedactLineDropsCoredumpFields(t *testing.T) {
	t.Parallel()
	line := `{"MESSAGE":"Process 1 dumped core","COREDUMP_ENVIRON":"TOKEN=x","_COREDUMP_UNIT":"u","COREDUMP_PID":"1","PRIORITY":"2"}`
	got := string(ops.RedactLine([]byte(line)))
	if strings.Contains(got, "COREDUMP") || !strings.Contains(got, `"PRIORITY":"2"`) || !strings.Contains(got, "dumped core") {
		t.Errorf("coredump fields should go and the rest stay: %s", got)
	}
}

func FuzzRedactLine(f *testing.F) {
	f.Add(`{"MESSAGE":["a",[112,97,115,115,119,111,114,100,61,120,9]]}`)
	f.Add(`{"MESSAGE":[[1],[2]],"COREDUMP_X":"y"}`)
	f.Add(`{"MESSAGE":[ 1 , 2 ]}`)
	f.Fuzz(func(t *testing.T, line string) {
		out := ops.RedactLine([]byte(line))
		if json.Valid([]byte(line)) && !json.Valid(out) {
			t.Fatalf("redaction turned valid JSON into invalid JSON:\n in: %q\nout: %q", line, out)
		}
		if again := ops.RedactLine(out); !bytes.Equal(again, out) {
			t.Fatalf("redaction is not idempotent:\n once: %q\ntwice: %q", out, again)
		}
	})
}
