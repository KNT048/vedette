// Package client is how core talks to vedette-host over its unix socket (docs/specs/host-api.md).
// An absent socket is ErrUnreachable: "not an appliance, or the host is not running"; core shows
// the matching "unsupported / cannot reach vedette-host" state and never pretends success
// (modules/host/CONTRACT.md, "Khi vắng mặt").
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
)

// ErrUnreachable is wrapped by every failure to reach the socket (missing, refused, not allowed).
var ErrUnreachable = errors.New("host: vedette-host is unreachable (not an appliance, or the host is not running)")

// ErrStreamLost is returned by Stream.Next when the connection was lost and could not be resumed.
// It is not io.EOF: a lost stream says nothing about whether the run finished (ask GetRun).
var ErrStreamLost = errors.New("host: event stream lost")

// Error is a non-2xx answer of the host, with the codes of spec section 11.
type Error struct {
	Status      int
	Code        string
	Message     string
	Details     []api.Detail
	RunID       string // busy: the run in progress
	RetryAfterS int    // rate_limited
}

func (e *Error) Error() string { return fmt.Sprintf("host: %s (%d): %s", e.Code, e.Status, e.Message) }

// IsCode reports whether err is a host Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Client calls the host. It is safe for concurrent use.
type Client struct {
	socket string
	http   *http.Client
	// stream has no overall timeout: SSE connections live as long as the run.
	stream *http.Client
}

// New returns a Client for the socket path.
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
			}
			return c, nil
		},
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: time.Second,
	}
	return &Client{socket: socket, http: &http.Client{Transport: tr, Timeout: 60 * time.Second}, stream: &http.Client{Transport: tr}}
}

// Close drops idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://host"+path, body)
	if err != nil {
		return nil, fmt.Errorf("host: build request: %w", err)
	}
	req.Header.Set(api.HeaderProto, strconv.Itoa(api.Proto))
	return req, nil
}

func (c *Client) do(hc *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := hc.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.Is(err, ErrUnreachable) || (errors.As(err, &ne) && ne.Op == "dial") {
			return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
		}
		return nil, fmt.Errorf("host: %w", err)
	}
	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }()
		return nil, decodeError(resp)
	}
	return resp, nil
}

func decodeError(resp *http.Response) error {
	var eb api.ErrorBody
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(data, &eb); err != nil || eb.Error.Code == "" {
		return &Error{Status: resp.StatusCode, Code: "unexpected_response", Message: "The host answered with an unexpected response."}
	}
	e := eb.Error
	return &Error{Status: resp.StatusCode, Code: e.Code, Message: e.Message, Details: e.Details, RunID: e.RunID, RetryAfterS: e.RetryAfterS}
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(c.http, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeBody(resp.Body, out)
}

func decodeBody(r io.Reader, out any) error {
	if err := json.NewDecoder(io.LimitReader(r, 32<<20)).Decode(out); err != nil {
		return fmt.Errorf("host: decode response: %w", err)
	}
	return nil
}

// Info returns GET /v1/info.
func (c *Client) Info(ctx context.Context) (api.Info, error) {
	var out api.Info
	err := c.getJSON(ctx, "/v1/info", &out)
	return out, err
}

// Run sends POST /v1/commands/{command} with args (any JSON-encodable value, nil for none).
// requestID must be a UUID v4: it is the idempotency key, so retrying with the same id after a
// lost connection returns the same run instead of running twice. A replay returns the existing run.
func (c *Client) Run(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error) {
	if command == "" || strings.ContainsAny(command, "/?#% \t\r\n") {
		return api.Run{}, fmt.Errorf("host: bad command name %q", command)
	}
	raw := json.RawMessage("{}")
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return api.Run{}, fmt.Errorf("host: encode args: %w", err)
		}
		raw = b
	}
	body, err := json.Marshal(api.CommandRequest{Args: raw})
	if err != nil {
		return api.Run{}, fmt.Errorf("host: encode request: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/v1/commands/"+url.PathEscape(command), bytes.NewReader(body))
	if err != nil {
		return api.Run{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.HeaderRequestID, requestID)
	req.Header.Set(api.HeaderActor, actor)
	resp, err := c.do(c.http, req)
	if err != nil {
		return api.Run{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var run api.Run
	return run, decodeBody(resp.Body, &run)
}

// GetRun returns GET /v1/runs/{id}.
func (c *Client) GetRun(ctx context.Context, runID string) (api.Run, error) {
	var out api.Run
	err := c.getJSON(ctx, "/v1/runs/"+url.PathEscape(runID), &out)
	return out, err
}

// ListRuns returns the newest runs, newest first.
func (c *Client) ListRuns(ctx context.Context, limit int) ([]api.Run, error) {
	var out api.RunList
	err := c.getJSON(ctx, "/v1/runs?limit="+strconv.Itoa(limit), &out)
	return out.Runs, err
}

// Audit returns one page of the host audit log with seq greater than since.
func (c *Client) Audit(ctx context.Context, since int64, limit int) (api.AuditPage, error) {
	var out api.AuditPage
	err := c.getJSON(ctx, "/v1/audit?since="+strconv.FormatInt(since, 10)+"&limit="+strconv.Itoa(limit), &out)
	return out, err
}

// Stream reads the SSE events of one run. After a dropped connection it reconnects with
// Last-Event-ID, so no event is delivered twice and none is skipped (except those the host dropped:
// then events carry Truncated).
type Stream struct {
	c       *Client
	ctx     context.Context //nolint:containedctx // a Stream is a long-lived reader bound to the caller's context
	runID   string
	last    uint64
	body    io.ReadCloser
	rd      *bufio.Reader
	ended   bool
	retries int
	linked  bool // a connection worked once, so a failed reconnect is retried
}

const (
	maxReconnects = 5
	maxSSELine    = 16 << 10
)

// Events starts reading the events of runID after event number after (0 for all).
func (c *Client) Events(ctx context.Context, runID string, after uint64) *Stream {
	return &Stream{c: c, ctx: ctx, runID: runID, last: after}
}

// Close releases the connection.
func (s *Stream) Close() {
	if s.body != nil {
		_ = s.body.Close()
		s.body = nil
	}
}

// Next returns the next event, io.EOF after the run's final state event, or an error.
func (s *Stream) Next() (api.Event, error) {
	for {
		if s.ended {
			return api.Event{}, io.EOF
		}
		var ev api.Event
		err := error(nil)
		if s.body == nil {
			err = s.connect()
			if err != nil && (!s.linked || !errors.Is(err, ErrUnreachable)) {
				return api.Event{}, err
			}
		}
		if err == nil {
			ev, err = s.read()
		}
		if err == nil {
			if ev.Seq <= s.last {
				continue // a resumed stream never repeats, but do not trust that
			}
			s.last, s.retries = ev.Seq, 0
			if ev.Kind == api.KindState && ev.Status.Terminal() {
				s.ended = true
				s.Close()
			}
			return ev, nil
		}
		s.Close()
		if s.ctx.Err() != nil {
			return api.Event{}, fmt.Errorf("host: events: %w", s.ctx.Err())
		}
		// The host closed the stream or the connection dropped before the final event: resume.
		if s.retries++; s.retries > maxReconnects {
			return api.Event{}, fmt.Errorf("%w: %s", ErrStreamLost, err.Error())
		}
		t := time.NewTimer(time.Duration(s.retries) * 100 * time.Millisecond)
		select {
		case <-t.C:
		case <-s.ctx.Done():
			t.Stop()
			return api.Event{}, fmt.Errorf("host: events: %w", s.ctx.Err())
		}
	}
}

func (s *Stream) connect() error {
	req, err := s.c.newRequest(s.ctx, http.MethodGet, "/v1/runs/"+url.PathEscape(s.runID)+"/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if s.last > 0 {
		req.Header.Set("Last-Event-ID", strconv.FormatUint(s.last, 10))
	}
	resp, err := s.c.do(s.c.stream, req) //nolint:bodyclose // the body is kept in s.body and closed by Stream.Close
	if err != nil {
		return err
	}
	s.linked = true
	s.body, s.rd = resp.Body, bufio.NewReaderSize(resp.Body, 4<<10)
	return nil
}

// read parses one SSE event ("id:" and "data:" lines, blank line ends it; comments are ignored).
func (s *Stream) read() (api.Event, error) {
	var data []byte
	for {
		line, err := readSSELine(s.rd)
		if err != nil {
			return api.Event{}, err
		}
		switch {
		case line == "":
			if len(data) == 0 {
				continue
			}
			var ev api.Event
			if err := json.Unmarshal(data, &ev); err != nil {
				return api.Event{}, fmt.Errorf("host: bad event: %w", err)
			}
			return ev, nil
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")...)
		}
	}
}

func readSSELine(rd *bufio.Reader) (string, error) {
	var buf []byte
	for {
		part, err := rd.ReadSlice('\n')
		buf = append(buf, part...)
		if len(buf) > maxSSELine {
			return "", errors.New("host: event line is too long")
		}
		if err == nil {
			return strings.TrimRight(string(buf), "\r\n"), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
}
