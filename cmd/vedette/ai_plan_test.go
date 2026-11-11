package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/knt048/vedette/modules/ai"
)

func TestPlanSchemaIsJSON(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(planSchema), &v); err != nil {
		t.Fatal(err)
	}
}

func TestParsePlan(t *testing.T) {
	good := `{"steps":[{"kind":"contain","title":"Block","detail":"d","action_id":"blocklist_add","params":[{"name":"ip","value":"203.0.113.50"}]},{"kind":"check","title":"c","detail":"d","action_id":"","params":[]}]}`
	d, err := parsePlan(good)
	if err != nil || len(d.Steps) != 2 || d.Steps[0].ActionID != "blocklist_add" || d.Steps[0].Params[0].Value != "203.0.113.50" {
		t.Fatalf("%+v %v", d, err)
	}
	for name, bad := range map[string]string{
		"not json":      `ok`,
		"no steps":      `{"steps":[]}`,
		"extra field":   `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"command":"reboot"}]}`,
		"extra object":  good + `{"steps":[]}`,
		"top-level add": `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[]}],"run":"x"}`,
	} {
		if _, err := parsePlan(bad); !errors.Is(err, ai.ErrBadOutput) {
			t.Fatalf("%s: err = %v, want ErrBadOutput", name, err)
		}
	}
}
