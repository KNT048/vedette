package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/secrets"
)

// SlackConfig configures an Incoming Webhook channel (D-38).
type SlackConfig struct {
	Webhook secrets.Value // https://hooks.slack.com/services/T…/B…/… ; the path is the credential
	Label   string        // optional display label such as "#it-alerts" (not a secret)
	Client  *http.Client  // nil = NewHTTPClient()
}

var slackPathRE = regexp.MustCompile(`^/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$`)

const slackLabelMax = 80

type slackSender struct {
	noPrint
	hook   secrets.Value
	label  string
	client *http.Client
}

// NewSlack validates cfg (INV-8: the webhook must be https://hooks.slack.com/services/…) and returns the adapter.
func NewSlack(cfg SlackConfig) (Sender, error) {
	raw := strings.TrimSpace(cfg.Webhook.Reveal())
	if raw == "" {
		return nil, cfgErr("secret_required", "Enter the Incoming Webhook URL.")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != "hooks.slack.com" || (u.Port() != "" && u.Port() != "443") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || !slackPathRE.MatchString(u.Path) {
		return nil, cfgErr("bad_webhook", "A Slack Incoming Webhook URL starts with https://hooks.slack.com/services/. Copy it again from your Slack app.")
	}
	label := strings.TrimSpace(clean(cfg.Label, false))
	if utf8.RuneCountInString(label) > slackLabelMax {
		return nil, cfgErr("bad_label", "The channel label can be at most 80 characters.")
	}
	return &slackSender{hook: secrets.NewValue(u.String()), label: label, client: clientOrDefault(cfg.Client)}, nil
}

func (*slackSender) Type() Type { return Slack }

// slackEscape escapes the three characters Slack treats as control characters in
// mrkdwn (& < >), which also stops <!channel>, <@U123> and <http://…|text> injection.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackText renders m as Slack mrkdwn: a bold head, plain lines, a link. Every
// untrusted string is escaped; the link was validated to hold no < > |.
func slackText(m Message, link string) string {
	more := m.moreLine()
	m.More = 0 // the link line is Slack's own below; the "and N more" line goes before it
	l := m.mapText(slackFormat).lines(link)
	out := []string{"*" + slackEscape(l[0]) + "*"}
	for _, x := range l[1 : len(l)-1] {
		out = append(out, slackEscape(x))
	}
	if more != "" {
		out = append(out, "- "+more)
	}
	if link == "" {
		return strings.Join(append(out, openVedetteLine), "\n")
	}
	return strings.Join(append(out, "<"+slackEscape(link)+"|Open in Vedette>"), "\n")
}

func (s *slackSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	body, err := json.Marshal(map[string]any{"text": slackText(m.norm(), link), "mrkdwn": true})
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: slack: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.hook.Reveal(), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: slack: build request: %s", transportReason(err, []secrets.Value{s.hook}))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	code, ans, err := do(s.client, Slack, req, s.hook)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Slack, code, ans, s.hook)
	}
	to, detail := s.label, "Slack accepted the message."
	if to == "" {
		to = "Slack webhook"
	} else {
		detail = fmt.Sprintf("Slack accepted the message (%s).", to)
	}
	return Receipt{To: to, Detail: detail}, nil
}

func (s *slackSender) Dest() string {
	if s.label == "" {
		return "Slack webhook"
	}
	return s.label
}
