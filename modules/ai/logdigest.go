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
	"unicode/utf8"

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
	ToolCalls   []AskToolCall   `json:"tool_calls"` // the read-only tools the AI used at the maximum level (log-investigate, D-223)
	Model       string          `json:"model"`
	Profile     string          `json:"profile"`
	Tokens      struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
	Empty bool `json:"empty"` // no log events yet: the AI was not asked and no tokens were spent
	// MemoriesSuggested is how many memories the AI suggested while making this digest (INV-8, D-223); 0 when it is read back.
	MemoriesSuggested int `json:"memories_suggested"`
}

// logDigestBody is what is stored in ai_result.payload for kind log_digest (key = the level the digest was made at).
type logDigestBody struct {
	Summary      string          `json:"summary"`
	Items        []LogDigestItem `json:"items"`
	Investigated bool            `json:"investigated,omitempty"` // made by log-investigate, with tools
	ToolCalls    []AskToolCall   `json:"tool_calls,omitempty"`
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

// digestRemember is the field of the answer that suggests memories (INV-8, D-223): only in the schema while suggestions are allowed.
const (
	digestRemember     = `"remember":{"type":"array","items":{"type":"string"}},`
	digestRememberMax  = 2
	digestRememberTask = ` In "remember" give at most two lasting facts about this network that the data shows and that would help later summaries (for example which device makes a nightly backup), one short sentence each, or an empty list. Never put a person's name, a password, a key or an address of a threat feed there. An administrator reviews each one before it is kept.`
	digestToolsTask    = ` You may check a point with the read-only tools before you write it: events_around for what the logs counted about one IP address around a time, lookup_ioc, search_assets and lookup_cve. Call a tool only when a point needs it; then reply with the JSON object only, with no markdown around it.`
)

const digestSchema = `{"type":"object","properties":{"summary":{"type":"string"},"items":{"type":"array","items":{"type":"object","properties":{"severity":{"type":"string","enum":["high","medium","info"]},"title":{"type":"string"},"evidence":{"type":"array","items":{"type":"string"}},"recommendation":{"type":"string"}},"required":["severity","title","evidence","recommendation"],"additionalProperties":false}}},"required":["summary","items"],"additionalProperties":false}`

const digestTask = `Summarise the last 24 hours of logs of a small company's network for an IT person, in plain English, from the one data block: the kinds of log line (signatures) with their counts, new kinds, kinds far above their usual rate, and connections to addresses on threat feeds. You are not given log lines, only their kinds and counts. In "summary" write at most three sentences saying what to look at first, or that nothing stands out. In "items" list at most eight points, the most important first. Each has a "severity" (high: a connection to a listed address or a very large spike of failed logons or errors; medium: a spike or a new kind that deserves a look; info: the rest), a short "title", "evidence" (at most four short lines quoting the counts and kinds from the data), and a "recommendation" (one or two sentences of what to do). Use only the data block; do not invent devices, addresses, counts or causes, and say "not known" when the data does not say. Reply with one JSON object only.`

// digestSchemaFor is the schema of the answer; with remember the field that suggests memories is in it (and required, as strict
// structured output wants every property listed).
func digestSchemaFor(remember bool) string {
	if !remember {
		return digestSchema
	}
	out := strings.Replace(digestSchema, `"properties":{"summary"`, `"properties":{`+digestRemember+`"summary"`, 1)
	return strings.Replace(out, `"required":["summary","items"],"additionalProperties":false}`, `"required":["summary","items","remember"],"additionalProperties":false}`, 1)
}

func digestCadence(t Tier, investigated bool) string {
	switch {
	case t == TierMin:
		return "A short summary of the most serious points, made when you ask"
	case t == TierMed:
		return "A full summary of new kinds of line, spikes and bad connections, made when you ask"
	case investigated:
		return "A full summary made when you ask, with the AI checking points through read-only tools (what the logs counted for an address, devices, threat feeds, the exploited list)"
	}
	return "Same as the medium level: no read-only tools were used, because Log investigation has no AI profile that can take it or its skill is off (Settings, AI assistant)"
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
	Summary  string   `json:"summary"`
	Remember []string `json:"remember"`
	Items    []struct {
		Severity       string   `json:"severity"`
		Title          string   `json:"title"`
		Evidence       []string `json:"evidence"`
		Recommendation string   `json:"recommendation"`
	} `json:"items"`
}

// unfence takes the JSON out of a markdown code block: an answer given without structured output (the tool loop) may come in one.
func unfence(text string) string {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "```") {
		return t
	}
	if i := strings.IndexByte(t, '\n'); i >= 0 {
		t = t[i+1:]
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(t), "```"))
}

// parseDigest reads the model's answer strictly: the schema's fields and nothing else, a known severity, text cleaned and cut. With
// remember the answer may have the remember field (at most digestRememberMax suggestions are kept); without, that field is refused.
func parseDigest(text string, remember bool) (logDigestBody, []string, error) {
	var a digestAnswer
	text = unfence(text)
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	// remember may be missing when suggestions are on: the tool loop has no schema to make the model write an empty list
	if err := dec.Decode(&a); err != nil || dec.More() || !hasKeys(text, "summary", "items") || (!remember && a.Remember != nil) {
		return logDigestBody{}, nil, ErrBadOutput
	}
	out := logDigestBody{Summary: cleanLine(a.Summary, digestMaxSummary), Items: []LogDigestItem{}}
	if out.Summary == "" {
		return logDigestBody{}, nil, ErrBadOutput
	}
	for _, it := range a.Items {
		if it.Severity != "high" && it.Severity != "medium" && it.Severity != "info" {
			return logDigestBody{}, nil, ErrBadOutput
		}
		title := cleanLine(it.Title, digestMaxTitle)
		if title == "" {
			return logDigestBody{}, nil, ErrBadOutput
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
	var mem []string
	for _, r := range a.Remember {
		if r = cleanLine(r, memoryMax); utf8.RuneCountInString(r) >= memoryMin && len(mem) < digestRememberMax {
			mem = append(mem, r)
		}
	}
	return out, mem, nil
}

func (s *Service) digestView(tier Tier, body logDigestBody, model, profile string, tin, tout int, at time.Time) LogDigestResult {
	v := LogDigestResult{Tier: tier, GeneratedAt: FormatTS(at), Cadence: digestCadence(tier, body.Investigated), Summary: body.Summary, Items: body.Items, ToolCalls: nonNilCalls(body.ToolCalls), Model: model, Profile: profile}
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
// answer: the AI is not asked. At the maximum level the job is log-investigate, whose model may check points with read-only tools
// (D-223), when that job can run; otherwise it is the plain log-digest. While suggestions are allowed, the answer may carry up to two
// memories the AI suggests (INV-8): they wait for an administrator.
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
	job, task, version := JobLogDigest, digestTask, "log-digest-v1"
	var ts *toolSession
	if tier == TierMax && s.Ready(JobLogInvestigate) == nil {
		job, task, version = JobLogInvestigate, digestTask+digestToolsTask, "log-investigate-v1"
		ts = s.newToolSession(ctx, job)
	}
	suggest, err := suggestOn(ctx, s.cfg.DB.Reader())
	if err != nil {
		return LogDigestResult{}, err
	}
	if suggest {
		task += digestRememberTask
	}
	block := digestBlock(d, tier)
	har := s.harness.Load()
	mem, err := s.memoryForCall(ctx, har.runner, job)
	if err != nil {
		return LogDigestResult{}, err
	}
	var rules []string
	for _, r := range har.rules {
		if r.Enabled && r.appliesTo(job) {
			rules = append(rules, r.Text)
		}
	}
	var body logDigestBody
	var remember []string
	now := s.cfg.Clock()
	maxTokens := 2500
	if tier == TierMin {
		maxTokens = 1200
	}
	var hash string
	summary := fmt.Sprintf("Summarised the log digest: %d new kinds of line, %d spikes, %d bad connections", len(d.New), len(d.Spikes), len(d.BadConnections))
	if ts != nil {
		summary = fmt.Sprintf("Investigated the log digest: %d new kinds of line, %d spikes, %d bad connections", len(d.New), len(d.Spikes), len(d.BadConnections))
	}
	spec := JobSpec{
		Job: job, Actor: actor, Task: task, tools: ts,
		Question:  "What in the logs of the last 24 hours should be looked at first?",
		Data:      []DataBlock{block},
		Schema:    &provider.Schema{Name: "log_digest", JSON: json.RawMessage(digestSchemaFor(suggest))},
		MaxTokens: maxTokens,
		Summary:   summary,
		Check: func(text string) error {
			var perr error
			body, remember, perr = parseDigest(text, suggest)
			return perr
		},
		Store: func(ctx context.Context, tx *sql.Tx, r JobResult) error {
			if ts != nil {
				body.Investigated, body.ToolCalls = true, nonNilCalls(ts.calls)
			}
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
	know, err := s.knowledgeForCall(ctx, har.runner, job, knowledgeQuery(spec))
	if err != nil {
		return LogDigestResult{}, err
	}
	spec.knowledge = &know
	hash = HashContent(version + "\n" + string(tier) + "\n" + block.Text + "\nmemory:" + mem.block.Text + knowledgeKey(know) + "\nrules:" + strings.Join(rules, "\n") + fmt.Sprintf("\nsuggest:%t", suggest))
	if v, ok, err := s.loadDigest(ctx, tier, hash); err != nil || ok {
		return v, err
	}
	res, err := s.RunJob(ctx, spec)
	if err != nil {
		return LogDigestResult{}, err
	}
	sctx, cancel := detached(ctx) // the tokens are spent: the suggestions are kept even if the person has gone
	defer cancel()
	v := s.digestView(tier, body, res.Model, res.Profile, res.TokensIn, res.TokensOut, now)
	v.MemoriesSuggested = s.suggestFromDigest(sctx, remember, now)
	return v, nil
}

// suggestFromDigest hands the memories the AI suggested to SuggestMemory, which keeps them for an administrator (INV-8), and says how
// many were kept. A suggestion that is not kept (suggestions just turned off, too many waiting, a text the hooks stop, one already
// remembered or waiting) is not an error of the digest.
func (s *Service) suggestFromDigest(ctx context.Context, remember []string, at time.Time) int {
	kept := 0
	for _, text := range remember {
		stored, err := s.suggestMemory(ctx, text, "log summary of "+at.UTC().Format("2 Jan 2006"))
		if stored {
			kept++
		}
		if err != nil && !errors.Is(err, ErrSuggestionsOff) && !errors.Is(err, ErrTooManySuggestions) && !errors.Is(err, ErrInvalidPromptInput) {
			s.cfg.Log.WarnContext(ctx, "ai: could not keep a memory suggested by the log digest", "error", err)
		}
	}
	return kept
}
