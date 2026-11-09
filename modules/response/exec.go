package response

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// What is sent to a device (INV-22, D-94, D-95). buildExec renders the four steps of an action once, when the request is made, from
// the stored templates and the checked values; the item keeps them (itemRec.Exec) and the executor gets exactly them. Nothing is
// rendered again at run time, so an edit of the catalog after the approval cannot change what is sent (it also fails the
// fingerprint, INV-9), and a value that came from a client never reaches a device in any other way than through Fill.

// execStep is one rendered step. A step has the form of its connection kind: command lines (SSH), a method, an address, a body and
// headers (API kinds), or a tool with typed arguments (MCP).
type execStep struct {
	Lines   []string          `json:"lines,omitempty"`
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Tool    string            `json:"tool,omitempty"`
	Args    json.RawMessage   `json:"args,omitempty"`
}

// execRec is the four steps of an item and the texts the outputs of the read steps are compared with.
type execRec struct {
	Precheck *execStep `json:"precheck,omitempty"`
	Run      *execStep `json:"run,omitempty"`
	Rollback *execStep `json:"rollback,omitempty"`
	Verify   *execStep `json:"verify,omitempty"`

	Refuse         []string `json:"refuse,omitempty"`          // the check before refuses when its output holds one of these (precheck_refuse)
	PrecheckExpect string   `json:"precheck_expect,omitempty"` // ... or when it lacks this
	Expect         string   `json:"expect,omitempty"`          // the read-back must hold this after the change and must not after the undo, placeholders filled
}

// runtimeShown matches the display form of a value that only the device can give while an action runs.
var runtimeShown = regexp.MustCompile(`<(seq|previous_vlan|found_id|expiry_s|timeout|rules_before)>`)

// usesRuntime reports whether a template names the runtime value.
func (c catRow) usesRuntime(name string) bool {
	for _, t := range []Tpl{c.Run, c.Rollback, c.Verify, c.Precheck} {
		for _, x := range []string{t.CLI, t.Path, t.Body, t.Headers, t.Expect} {
			if strings.Contains(x, "{"+name+"}") {
				return true
			}
		}
	}
	return false
}

// expanded makes the filled text final: {expiry_s} becomes the time to live in seconds (D-94 (4)); any other runtime value that is still
// there is an error, because nothing here can know it.
func expanded(text string, ttlMin *int) (string, error) {
	if ttlMin != nil {
		text = strings.ReplaceAll(text, "<expiry_s>", strconv.Itoa(*ttlMin*60))
	}
	if runtimeShown.MatchString(text) {
		return "", errors.New("response: a value that is read from the device is still in the step")
	}
	return text, nil
}

func (s *Service) fillExec(text string, vals Values, t Transport, ttlMin *int) (string, error) {
	out, err := Fill(text, vals, t)
	if err != nil {
		return "", err
	}
	return expanded(out, ttlMin)
}

// stepOf renders one template for a connection. An empty template has no step.
func (s *Service) stepOf(t Tpl, conn *ConnectionInfo, tool string, vals Values, ttlMin *int) (*execStep, error) {
	if t.Empty() || conn == nil {
		return nil, nil
	}
	switch {
	case isMCP(conn.Kind):
		body := "{}"
		if t.Body != "" {
			b, err := s.fillExec(t.Body, vals, TJSON, ttlMin)
			if err != nil {
				return nil, err
			}
			body = b
		}
		var obj map[string]any
		dec := json.NewDecoder(bytes.NewReader([]byte(body)))
		dec.UseNumber()
		if err := dec.Decode(&obj); err != nil || obj == nil || dec.More() {
			return nil, errors.New("response: the arguments of the tool are not a JSON object")
		}
		return &execStep{Tool: tool, Args: json.RawMessage(body)}, nil
	case conn.Kind == "ssh":
		text, err := s.fillExec(t.CLI, vals, TCLI, ttlMin)
		if err != nil {
			return nil, err
		}
		var lines []string
		for l := range strings.SplitSeq(text, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		if len(lines) == 0 {
			return nil, errors.New("response: the command has no line")
		}
		return &execStep{Lines: lines}, nil
	case isHTTPKind(conn.Kind) && t.Method != "" && t.Path != "":
		path, err := s.fillExec(t.Path, vals, TURL, ttlMin)
		if err != nil {
			return nil, err
		}
		st := &execStep{Method: t.Method, URL: conn.Target + path}
		if t.Body != "" {
			b, err := s.fillExec(t.Body, vals, TJSON, ttlMin)
			if err != nil {
				return nil, err
			}
			if !json.Valid([]byte(b)) {
				return nil, errors.New("response: the filled body is not JSON")
			}
			st.Body = b
		}
		for line := range strings.SplitSeq(t.Headers, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				return nil, errors.New("response: a header has no name")
			}
			v, err := s.fillExec(strings.TrimSpace(v), vals, THeader, ttlMin)
			if err != nil {
				return nil, err
			}
			if st.Headers == nil {
				st.Headers = map[string]string{}
			}
			st.Headers[strings.TrimSpace(k)] = v
		}
		return st, nil
	}
	return nil, errors.New("response: the step does not fit the connection")
}

// buildExec renders the four steps of an action for the connection it runs on. ttlMin is the undo time of the item: {expiry_s} is
// its seconds.
func (s *Service) buildExec(c catRow, vals Values, conn *ConnectionInfo, ttlMin *int) (*execRec, error) {
	ex := &execRec{Refuse: nonNilStrings(c.PrecheckRefuse), PrecheckExpect: c.PrecheckExpect}
	if len(ex.Refuse) == 0 {
		ex.Refuse = nil
	}
	var err error
	if ex.Run, err = s.stepOf(c.Run, conn, c.Tool, vals, ttlMin); err != nil {
		return nil, err
	}
	if ex.Run == nil {
		return nil, errors.New("response: the action has no step to run")
	}
	if c.reversible() {
		if ex.Rollback, err = s.stepOf(c.Rollback, conn, c.RollbackTool, vals, ttlMin); err != nil {
			return nil, err
		}
	}
	if ex.Verify, err = s.stepOf(c.Verify, conn, "", vals, ttlMin); err != nil {
		return nil, err
	}
	if ex.Precheck, err = s.stepOf(c.Precheck, conn, "", vals, ttlMin); err != nil {
		return nil, err
	}
	if c.Verify.Expect != "" {
		if ex.Expect, err = s.fillExec(c.Verify.Expect, vals, TCLI, ttlMin); err != nil {
			return nil, err
		}
	}
	return ex, nil
}

// deviceStep is the step as the executor gets it.
func deviceStep(reqID string, it itemRec, conn ConnectionInfo, phase string, st *execStep) DeviceStep {
	return DeviceStep{ConnectionID: conn.ID, ConnFP: it.ConnFP, Phase: phase, Tool: st.Tool, Lines: st.Lines, Method: st.Method, URL: st.URL, Body: st.Body,
		Headers: st.Headers, Args: st.Args, RequestID: reqID, ItemID: it.ID}
}

// readOnlyProblem is the refused-command check, made again right before a check or a read-back goes out: its command lines may
// hold no change command (data/cli-ban.json) and its API call is a GET without a body. "" when it may go.
func readOnlyProblem(st *execStep) string {
	if st == nil {
		return ""
	}
	if st.Method != "" && (st.Method != "GET" || st.Body != "") {
		return "an API call that reads can only be a GET without a body"
	}
	if st.Tool != "" {
		return "a check or a read-back cannot call a tool"
	}
	ban, err := banData()
	if err != nil {
		return "the list of refused commands could not be read"
	}
	lines := make([]string, 0, len(st.Lines))
	for _, l := range st.Lines {
		lines = append(lines, strings.Join(strings.Fields(strings.ToLower(l)), " "))
	}
	if l := banHit(lines, ban.everywhere); l != "" {
		return `the command "` + oneLine(l, 60) + `" is not allowed`
	}
	if l := banHit(lines, ban.readOnly); l != "" {
		return `the command "` + oneLine(l, 60) + `" can change the device`
	}
	return ""
}
