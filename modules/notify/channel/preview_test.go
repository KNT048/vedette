package channel

import (
	"errors"
	"strings"
	"testing"
)

func TestPreviewRendersLikeTheAdapters(t *testing.T) {
	m := Message{ID: "in-1", Kind: "incident", Severity: "high", Title: "PC-01 <!channel> touched the trap", Device: "PC-01", What: "w", Action: "a", Link: "https://box.example/incidents/in-1"}
	subj, text, err := Preview(Email, m)
	if err != nil || !strings.HasPrefix(subj, "[Vedette] High: ") || !strings.Contains(text, "Hello,") || !strings.Contains(text, "Details: https://box.example/incidents/in-1") {
		t.Fatalf("email = %q %q %v", subj, text, err)
	}
	if _, text, _ = Preview(Slack, m); !strings.Contains(text, "&lt;!channel&gt;") || !strings.Contains(text, "<https://box.example/incidents/in-1|Open in Vedette>") {
		t.Fatalf("slack = %q", text)
	}
	if subj, text, _ = Preview(Webhook, m); subj != "" || !strings.Contains(text, `"event": "incident.created"`) || !strings.Contains(text, `"devices": []`) {
		t.Fatalf("webhook = %q %q", subj, text)
	}
	for _, ty := range []Type{Telegram, Zalo, ZaloPersonal} {
		if subj, text, err = Preview(ty, m); err != nil || subj != "" || !strings.HasPrefix(text, "High: ") {
			t.Fatalf("%s = %q %q %v", ty, subj, text, err)
		}
	}
	bad := m
	bad.Link = "javascript:alert(1)"
	if _, _, err = Preview(Slack, bad); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err = Preview("fax", m); err == nil {
		t.Fatal("unknown type accepted")
	}
}

func TestPreviewWithoutLinkSaysToOpenVedette(t *testing.T) {
	t.Parallel()
	m := Message{ID: "in-1", Kind: "incident", IncidentKind: "trap", Severity: "high", Title: "t", Device: "PC-01", Devices: []DeviceRef{{ID: "a1", Name: "PC-01"}}, What: "w", Action: "a"}
	for _, ty := range []Type{Slack, Telegram, Zalo, Email} {
		_, text, err := Preview(ty, m)
		if err != nil || !strings.Contains(text, "Open Vedette to see details.") || strings.Contains(text, "Details:") || strings.Contains(text, "http") {
			t.Errorf("%s = %q %v", ty, text, err)
		}
	}
	_, text, err := Preview(Webhook, m)
	if err != nil || !strings.Contains(text, `"kind": "trap"`) || !strings.Contains(text, `"id": "a1"`) || strings.Contains(text, `"url"`) {
		t.Errorf("webhook = %q %v", text, err)
	}
}
