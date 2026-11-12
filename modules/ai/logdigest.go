package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The AI log digest (S-AI-4, INV-6, D-221): the `log-digest` job reads the digest the logs module already computed (kinds of line,
// counts, spikes, bad connections) and says what to look at first. It never reads a log line: the port carries signatures and counts
// (INV-11 of logs), the adapter in cmd/vedette copies only the fields named below, and the text of a line (`sample`) is not among them.

// LogDigestData is what the log-digest job reads. Its JSON names are those of GET /logs/digest, so the adapter can copy the answer of
// logs through JSON and a field this type does not name (the sample line of an item) is dropped on the way.
type LogDigestData struct {
	Lines24h       int                `json:"lines_24h"`
	BaselineDays   int                `json:"baseline_days"`
	New            []LogDigestNew     `json:"new"`
	Spikes         []LogDigestSpike   `json:"spikes"`
	BadConnections []LogDigestBadConn `json:"bad_connections"`
}

// LogDigestNew is a kind of line a source had not sent before.
type LogDigestNew struct {
	Signature  string `json:"signature"`
	SourceName string `json:"source_name"`
	Count      int    `json:"count"`
	FirstSeen  string `json:"first_seen"`
}

// LogDigestSpike is a kind of line a source sent far more often than usual.
type LogDigestSpike struct {
	Signature      string  `json:"signature"`
	SourceName     string  `json:"source_name"`
	Count          int     `json:"count"`
	BaselinePerDay float64 `json:"baseline_per_day"`
}

// LogDigestBadConn is a connection to an address a threat feed lists.
type LogDigestBadConn struct {
	TS         string   `json:"ts"`
	AssetName  *string  `json:"asset_name"`
	SrcIP      string   `json:"src_ip"`
	Dest       string   `json:"dest"`
	DestKind   string   `json:"dest_kind"`
	SeenVia    string   `json:"seen_via"`
	Feeds      []string `json:"feeds"`
	Confidence float64  `json:"confidence"`
}

func (d LogDigestData) empty() bool {
	return d.Lines24h == 0 && len(d.New) == 0 && len(d.Spikes) == 0 && len(d.BadConnections) == 0
}

// LogDigestItem is one point of the digest.
type LogDigestItem struct {
	Severity       string   `json:"severity"` // high, medium or info
	Title          string   `json:"title"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

// LogDigestResult is the answer of GET and POST /ai/logs/digest (LogDigest of contract.ts).
type LogDigestResult struct {
	Tier        Tier            `json:"tier"`
	GeneratedAt string          `json:"generated_at"`
	Cadence     string          `json:"cadence"`
	Summary     string          `json:"summary"`
	Items       []LogDigestItem `json:"items"`
	ToolCalls   []struct{}      `json:"tool_calls"` // log-investigate (tools over the logs) is not built: always empty
	Model       string          `json:"model"`
	Profile     string          `json:"profile"`
	Tokens      struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
	Empty bool `json:"empty"` // no log events yet: the AI was not asked and no tokens were spent
}

// logDigestBody is what is stored in ai_result.payload for kind log_digest (key = the level the digest was made at).
type logDigestBody struct {
	Summary string          `json:"summary"`
	Items   []LogDigestItem `json:"items"`
}

const (
	digestMaxItems    = 8
	digestMaxEvidence = 4
	digestMaxSummary  = 600
	digestMaxTitle    = 200
	digestMaxEvLine   = 300
	digestMaxRec      = 400
	digestKeep        = 10 // results kept per level

	// What goes to the provider: at most this many of each list, each text cut to its own length. The level min sends the short lists.
	digestListMax    = 20
	digestListMaxMin = 5
	digestSigChars   = 200
	digestNameChars  = 80
	digestFeedsMax   = 5
)

const digestNone = "There are no log events to summarise yet. Add a log source on the Logs page; once events arrive, the summary appears here."

const digestSchema = `{"type":"object","properties":{"summary":{"type":"string"},"items":{"type":"array","items":{"type":"object","properties":{"severity":{"type":"string","enum":["high","medium","info"]},"title":{"type":"string"},"evidence":{"type":"array","items":{"type":"string"}},"recommendation":{"type":"string"}},"required":["severity","title","evidence","recommendation"],"additionalProperties":false}}},"required":["summary","items"],"additionalProperties":false}`

const digestTask = `Summarise the last 24 hours of logs of a small company's network for an IT person, in plain English, from the one data block: the kinds of log line (signatures) with their counts, new kinds, kinds far above their usual rate, and connections to addresses on threat feeds. You are not given log lines, only their kinds and counts. In "summary" write at most three sentences saying what to look at first, or that nothing stands out. In "items" list at most eight points, the most important first. Each has a "severity" (high: a connection to a listed address or a very large spike of failed logons or errors; medium: a spike or a new kind that deserves a look; info: the rest), a short "title", "evidence" (at most four short lines quoting the counts and kinds from the data), and a "recommendation" (one or two sentences of what to do). Use only the data block; do not invent devices, addresses, counts or causes, and say "not known" when the data does not say. Reply with one JSON object only.`

func digestCadence(t Tier) string {
	switch t {
	case TierMin:
		return "A short summary of the most serious points, made when you ask"
	case TierMed:
		return "A full summary of new kinds of line, spikes and bad connections, made when you ask"
	}
	return "Same as the medium level; investigating with read-only tools is not built yet"
}

// digestBlock is the data block of the call: signatures, counts and connections, capped. Every text came from a device or a feed, so
// each goes through clip (control characters removed, cut to length) and then the before-AI hooks, like any data block.
func digestBlock(d LogDigestData, tier Tier) DataBlock {
	n := digestListMax
	if tier == TierMin {
		n = digestListMaxMin
	}
	var b strings.Builder
	// counts carry thousands separators: a 9- or 12-digit count must not read as an identity number to the hooks
	fmt.Fprintf(&b, "Window: the last 24 hours. Lines received: %s. Baseline: %d days.\n", number(d.Lines24h), d.BaselineDays)
	b.WriteString("New kinds of line (not seen from this source in the baseline):\n")
	for i, x := range d.New {
		if i == n {
			break
		}
		fmt.Fprintf(&b, "- source %q: %s (%s lines, first seen %s)\n", clip(x.SourceName, digestNameChars), clip(x.Signature, digestSigChars), number(x.Count), clip(x.FirstSeen, 32))
	}
	b.WriteString("Kinds of line far above their usual rate:\n")
	for i, x := range d.Spikes {
		if i == n {
			break
		}
		fmt.Fprintf(&b, "- source %q: %s (%s lines in 24 hours, usually about %s a day)\n", clip(x.SourceName, digestNameChars), clip(x.Signature, digestSigChars), number(x.Count), number(int(math.Round(x.BaselinePerDay))))
	}
	b.WriteString("Connections to addresses on threat feeds:\n")
	for i, x := range d.BadConnections {
		if i == n {
			break
		}
		who := "a device that is not in the inventory"
		if x.AssetName != nil && *x.AssetName != "" {
			who = clip(*x.AssetName, digestNameChars)
		}
		feeds := make([]string, 0, digestFeedsMax)
		for _, f := range x.Feeds {
			if len(feeds) < digestFeedsMax {
				feeds = append(feeds, clip(f, digestNameChars))
			}
		}
		fmt.Fprintf(&b, "- %s, IP %s, to %s (%s), seen via %s, listed by %s, confidence %.2f, at %s\n", who, clip(x.SrcIP, 45), clip(x.Dest, 253), clip(x.DestKind, 8), clip(x.SeenVia, 60), strings.Join(feeds, ", "), x.Confidence, clip(x.TS, 32))
	}
	return DataBlock{Kind: DataLog, Source: "summary of the logs of the last 24 hours: kinds of line and counts, no log lines", Text: b.String()}
}

type digestAnswer struct {
	Summary string `json:"summary"`
	Items   []struct {
		Severity       string   `json:"severity"`
		Title          string   `json:"title"`
		Evidence       []string `json:"evidence"`
		Recommendation string   `json:"recommendation"`
	} `json:"items"`
}

// parseDigest reads the model's answer strictly: the schema's fields and nothing else, a known severity, text cleaned and cut.
func parseDigest(text string) (logDigestBody, error) {
	var a digestAnswer
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || dec.More() || !hasKeys(text, "summary", "items") {
		return logDigestBody{}, ErrBadOutput
	}
	out := logDigestBody{Summary: cleanLine(a.Summary, digestMaxSummary), Items: []LogDigestItem{}}
	if out.Summary == "" {
		return logDigestBody{}, ErrBadOutput
	}
	for _, it := range a.Items {
		if it.Severity != "high" && it.Severity != "medium" && it.Severity != "info" {
			return logDigestBody{}, ErrBadOutput
		}
		title := cleanLine(it.Title, digestMaxTitle)
		if title == "" {
			return logDigestBody{}, ErrBadOutput
		}
		if len(out.Items) == digestMaxItems {
			break
		}
		ev := []string{}
		for _, e := range it.Evidence {
			if e = cleanLine(e, digestMaxEvLine); e != "" && len(ev) < digestMaxEvidence {
				ev = append(ev, e)
			}
		}
		out.Items = append(out.Items, LogDigestItem{Severity: it.Severity, Title: title, Evidence: ev, Recommendation: cleanLine(it.Recommendation, digestMaxRec)})
	}
	return out, nil
}

func (s *Service) digestView(tier Tier, body logDigestBody, model, profile string, tin, tout int, at time.Time) LogDigestResult {
	v := LogDigestResult{Tier: tier, GeneratedAt: FormatTS(at), Cadence: digestCadence(tier), Summary: body.Summary, Items: body.Items, ToolCalls: []struct{}{}, Model: model, Profile: profile}
	v.Tokens.Input, v.Tokens.Output = tin, tout
	if v.Items == nil {
		v.Items = []LogDigestItem{}
	}
	return v
}

func (s *Service) digestEmpty(tier Tier, at time.Time) LogDigestResult {
	v := s.digestView(tier, logDigestBody{Summary: digestNone}, "", "", 0, 0, at)
	v.Empty = true
	return v
}

// loadDigest reads the newest stored digest of a level; with hash set, only one made from exactly those inputs.
func (s *Service) loadDigest(ctx context.Context, tier Tier, hash string) (LogDigestResult, bool, error) {
	q := `SELECT payload, model, profile, tokens_in, tokens_out, created_at FROM ai_result WHERE kind = 'log_digest' AND key = ?`
	args := []any{string(tier)}
	if hash != "" {
		q += ` AND inputs_hash = ?`
		args = append(args, hash)
	}
	var payload, created, model, profile string
	var tin, tout int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, q+` ORDER BY created_at DESC, rowid DESC LIMIT 1`, args...).Scan(&payload, &model, &profile, &tin, &tout, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return LogDigestResult{}, false, nil
	}
	if err != nil {
		return LogDigestResult{}, false, fmt.Errorf("ai: read log digest: %w", err)
	}
	var body logDigestBody
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return LogDigestResult{}, false, fmt.Errorf("ai: stored log digest is not readable: %w", err)
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", created)
	if err != nil {
		return LogDigestResult{}, false, fmt.Errorf("ai: stored log digest time: %w", err)
	}
	return s.digestView(tier, body, model, profile, tin, tout, t), true, nil
}

func (s *Service) readLogDigest(ctx context.Context) (LogDigestData, error) {
	if s.cfg.LogDigest == nil {
		return LogDigestData{}, apiUnavailable("The box has no logs to summarise. Turn on the logs module in Settings, Modules.")
	}
	d, on, err := s.cfg.LogDigest(ctx)
	if err != nil {
		return LogDigestData{}, fmt.Errorf("ai: read log digest: %w", err)
	}
	if !on {
		return LogDigestData{}, apiUnavailable("The logs module is off, so there is no log summary to read. Turn it on in Settings, Modules.")
	}
	return d, nil
}

// CachedLogDigest is GET /ai/logs/digest: the newest digest made at the level in force, with no AI call (INV-6). nil when none was
// made yet. When the logs hold no events there is nothing to summarise: the answer says so (empty), which needs no AI either. With the
// logs module off it is 409 like POST, also when a digest was stored before: a stale digest is not served for logs that are off.
func (s *Service) CachedLogDigest(ctx context.Context) (*LogDigestResult, error) {
	d, err := s.readLogDigest(ctx)
	if err != nil {
		return nil, err
	}
	tier := s.meter.Tier()
	if v, ok, err := s.loadDigest(ctx, tier, ""); err != nil || ok {
		if err != nil {
			return nil, err
		}
		return &v, nil
	}
	if d.empty() {
		v := s.digestEmpty(tier, s.cfg.Clock())
		return &v, nil
	}
	return nil, nil
}

// LogDigest is POST /ai/logs/digest: the AI summarises the digest of the logs now. The same inputs (the digest, the level, the
// company rules and memory) answer from the stored result without tokens. A digest of a box with no log events is the "empty"
// answer: the AI is not asked.
func (s *Service) LogDigest(ctx context.Context, actor string) (LogDigestResult, error) {
	if err := s.Ready(JobLogDigest); err != nil {
		return LogDigestResult{}, err
	}
	d, err := s.readLogDigest(ctx)
	if err != nil {
		return LogDigestResult{}, err
	}
	tier := s.meter.Tier()
	if d.empty() {
		return s.digestEmpty(tier, s.cfg.Clock()), nil
	}
	block := digestBlock(d, tier)
	har := s.harness.Load()
	mem, err := s.memoryForCall(ctx, har.runner, JobLogDigest)
	if err != nil {
		return LogDigestResult{}, err
	}
	var rules []string
	for _, r := range har.rules {
		if r.Enabled && r.appliesTo(JobLogDigest) {
			rules = append(rules, r.Text)
		}
	}
	var body logDigestBody
	now := s.cfg.Clock()
	maxTokens := 2500
	if tier == TierMin {
		maxTokens = 1200
	}
	var hash string
	spec := JobSpec{
		Job: JobLogDigest, Actor: actor, Task: digestTask,
		Question:  "What in the logs of the last 24 hours should be looked at first?",
		Data:      []DataBlock{block},
		Schema:    &provider.Schema{Name: "log_digest", JSON: json.RawMessage(digestSchema)},
		MaxTokens: maxTokens,
		Summary:   fmt.Sprintf("Summarised the log digest: %d new kinds of line, %d spikes, %d bad connections", len(d.New), len(d.Spikes), len(d.BadConnections)),
		Check: func(text string) error {
			var perr error
			body, perr = parseDigest(text)
			return perr
		},
		Store: func(ctx context.Context, tx *sql.Tx, r JobResult) error {
			payload, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("ai: encode log digest: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ai_result (id, kind, key, inputs_hash, payload, model, profile, tokens_in, tokens_out, asked_by, activity_id, created_at)
				VALUES (?, 'log_digest', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, store.NewID("res"), string(tier), hash, string(payload), r.Model, r.Profile, r.TokensIn, r.TokensOut, actor, r.ActivityID, FormatTS(now)); err != nil {
				return fmt.Errorf("ai: store log digest: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM ai_result WHERE kind = 'log_digest' AND key = ? AND id NOT IN
				(SELECT id FROM ai_result WHERE kind = 'log_digest' AND key = ? ORDER BY created_at DESC, rowid DESC LIMIT ?)`, string(tier), string(tier), digestKeep); err != nil {
				return fmt.Errorf("ai: prune log digests: %w", err)
			}
			return nil
		},
	}
	// The pieces of the knowledge base the call would carry are part of the inputs, like in explain: a changed document is a cache miss.
	// Retrieved once here and handed to RunJob (one retrieval, one hook pass).
	know, err := s.knowledgeForCall(ctx, har.runner, JobLogDigest, knowledgeQuery(spec))
	if err != nil {
		return LogDigestResult{}, err
	}
	spec.knowledge = &know
	hash = HashContent("log-digest-v1\n" + string(tier) + "\n" + block.Text + "\nmemory:" + mem.block.Text + knowledgeKey(know) + "\nrules:" + strings.Join(rules, "\n"))
	if v, ok, err := s.loadDigest(ctx, tier, hash); err != nil || ok {
		return v, err
	}
	res, err := s.RunJob(ctx, spec)
	if err != nil {
		return LogDigestResult{}, err
	}
	return s.digestView(tier, body, res.Model, res.Profile, res.TokensIn, res.TokensOut, now), nil
}
