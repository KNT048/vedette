package channel

import (
	"strings"
	"testing"
)

const goodPress = `{"type":"interactive","envelope_id":"e-1","payload":{"type":"block_actions","team":{"id":"T0EXAMPLE1"},"user":{"id":"U04ABCD1234"},` +
	`"channel":{"id":"C04ABCDEF12"},"container":{"type":"message","message_ts":"1731326400.000100","channel_id":"C04ABCDEF12"},` +
	`"response_url":"https://hooks.slack.com/actions/T0EXAMPLE1/1/abc","actions":[{"action_id":"vedette_a","value":"a:act-1"}]}}`

func TestParseSlackEnvelope_GoodPress(t *testing.T) {
	e := ParseSlackEnvelope([]byte(goodPress))
	want := SlackPress{TeamID: "T0EXAMPLE1", UserID: "U04ABCD1234", ChannelID: "C04ABCDEF12", TS: "1731326400.000100",
		ResponseURL: "https://hooks.slack.com/actions/T0EXAMPLE1/1/abc", RequestID: "act-1", Approve: true}
	if e.Kind != SlackPressKind || e.EnvelopeID != "e-1" || e.Press != want {
		t.Fatalf("%+v", e)
	}
}

func TestParseSlackEnvelope_OutOfFormIsInvalidNeverAPress(t *testing.T) {
	for name, edit := range map[string][2]string{
		"two actions":       {`"actions":[{"action_id":"vedette_a","value":"a:act-1"}]`, `"actions":[{"action_id":"vedette_a","value":"a:act-1"},{"action_id":"vedette_r","value":"r:act-1"}]`},
		"no action":         {`"actions":[{"action_id":"vedette_a","value":"a:act-1"}]`, `"actions":[]`},
		"other action":      {`"vedette_a"`, `"vedette_x"`},
		"value vs action":   {`"value":"a:act-1"`, `"value":"r:act-1"`},
		"value junk":        {`"value":"a:act-1"`, `"value":"a:act 1"`},
		"value too long":    {`"value":"a:act-1"`, `"value":"a:` + strings.Repeat("x", 200) + `"`},
		"bad user":          {`"U04ABCD1234"`, `"u04"`},
		"bad team":          {`"T0EXAMPLE1"`, `"team"`},
		"bad ts":            {`"1731326400.000100"`, `"1731326400"`},
		"channel mismatch":  {`"container":{"type":"message","message_ts":"1731326400.000100","channel_id":"C04ABCDEF12"}`, `"container":{"type":"message","message_ts":"1731326400.000100","channel_id":"C0OTHER0001"}`},
		"no container":      {`"container":{"type":"message","message_ts":"1731326400.000100","channel_id":"C04ABCDEF12"},`, ``},
		"not block_actions": {`"type":"block_actions"`, `"type":"view_submission"`},
	} {
		e := ParseSlackEnvelope([]byte(strings.Replace(goodPress, edit[0], edit[1], 1)))
		if e.Kind != SlackPressKind || !e.Press.Invalid || e.Press.RequestID != "" || e.Press.UserID != "" || e.EnvelopeID != "e-1" {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

func TestParseSlackEnvelope_ResponseURLMustBeHooksSlackCom(t *testing.T) {
	for _, bad := range []string{"https://hooks.slack.com.evil.example/actions/a", "http://hooks.slack.com/actions/a", "https://hooks.slack.com:444/actions/a",
		"https://x@hooks.slack.com/actions/a", "https://hooks.slack.com/actions/a?q=1", "https://hooks.slack.com/actions/a#f", "https://hooks.slack.com/actions/../x",
		"https://hooks.slack.com/services/a", "https://hooks.slack.com./actions/a", "https://HOOKS.slack.com/actions/a", ""} {
		e := ParseSlackEnvelope([]byte(strings.Replace(goodPress, "https://hooks.slack.com/actions/T0EXAMPLE1/1/abc", bad, 1)))
		if e.Press.ResponseURL != "" || e.Press.Invalid {
			t.Errorf("%q: %+v (the press is valid, its reply address is not)", bad, e.Press)
		}
	}
}

func TestParseSlackEnvelope_OtherKinds(t *testing.T) {
	for in, kind := range map[string]string{`{"type":"hello"}`: SlackHello, `{"type":"disconnect","reason":"x"}`: SlackDisconnect,
		`{"type":"events_api","envelope_id":"e-2"}`: SlackOther, `{"type":"interactive"}`: SlackOther, `not json`: SlackOther, `{"type":"interactive","envelope_id":"bad id!"}`: SlackOther} {
		if e := ParseSlackEnvelope([]byte(in)); e.Kind != kind {
			t.Errorf("%s: %+v", in, e)
		}
	}
	if e := ParseSlackEnvelope([]byte(`{"type":"events_api","envelope_id":"e-2"}`)); e.EnvelopeID != "e-2" {
		t.Error("an envelope of another kind is still acknowledged")
	}
	if e := ParseSlackEnvelope([]byte(strings.Repeat(" ", maxSlackEnvelope) + goodPress)); e.Kind != SlackOther {
		t.Error("an oversize frame was read")
	}
}

func TestCheckSocketURL(t *testing.T) {
	for _, ok := range []string{"wss://wss-primary.slack.com/link/?ticket=a", "wss://wss-backup.slack.com:443/link?ticket=a", "wss://WSS-PRIMARY.slack.com/link/"} {
		if checkSocketURL(ok) != nil {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "ws://wss-primary.slack.com/link/", "wss://wss-primary.slack.com.evil.test/link/", "wss://evil-wss-primary.slack.com/link/",
		"wss://wss-primary.slack.com:80/link/", "wss://a@wss-primary.slack.com/link/", "wss://wss-primary.slack.com/x", "wss://wss-primary.slack.com/link/../x",
		"wss://wss-primary.slack.com./link/", "wss://wss-primary.slack.com/link/#f", "wss://slack.com/link/", "wss://wss-other.slack.com/link/"} {
		if err := checkSocketURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		} else if strings.Contains(err.Error(), bad) && bad != "" {
			t.Errorf("the error repeats the address: %v", err)
		}
	}
}

func FuzzParseSlackEnvelope(f *testing.F) {
	f.Add([]byte(goodPress))
	f.Add([]byte(`{"type":"hello"}`))
	f.Add([]byte(`{"type":"interactive","envelope_id":"x","payload":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		e := ParseSlackEnvelope(b)
		if e.Kind == SlackPressKind && !e.Press.Invalid {
			p := e.Press
			if !slackTeamRE.MatchString(p.TeamID) || !slackUserRE.MatchString(p.UserID) || !slackChannelRE.MatchString(p.ChannelID) ||
				!slackTSRE.MatchString(p.TS) || p.RequestID == "" || (p.ResponseURL != "" && checkResponseURL(p.ResponseURL) != nil) || e.EnvelopeID == "" {
				t.Fatalf("a press came through with a field out of form: %+v", e)
			}
		}
		if e.EnvelopeID != "" && !slackEnvelopeRE.MatchString(e.EnvelopeID) {
			t.Fatalf("envelope id %q", e.EnvelopeID)
		}
	})
}
