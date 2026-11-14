package agentintake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
)

// The Wazuh server API client (D-169 (12), D-306). Read-only by construction (FORBID-4): the one POST is the login, every other call is a
// GET on an allow-listed path, checked here before anything is sent, whatever the role of the account allows. Shapes are those of the
// official OpenAPI spec of Wazuh v4.9.2 (api/api/spec/spec.yaml): the login answers the plain JWT with ?raw=true, GET / needs no RBAC
// action, GET /agents and /syscollector/{agent_id}/* page with limit/offset (limit up to 100,000; 500 recommended; we ask 250).

const (
	wazuhPage     = 250                    // rows asked per page (plan 3.2)
	wazuhPace     = 250 * time.Millisecond // at most 4 calls a second: under the manager's default of 300 requests a minute (api.yaml)
	wazuhMaxWait  = 60 * time.Second       // the longest Retry-After honoured after a 429
	wazuhRetries  = 2                      // 429 answers retried per call
	maxWazuhAgent = MaxNodes               // agents read in one pull at most, like the osquery cap
	maxJWT        = 8 << 10
)

var (
	agentIDRE     = regexp.MustCompile(`^[0-9]{3,10}$`) // the AgentID format of the spec ("numbers", 3 or more)
	jwtRE         = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	apiVersionRE  = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.]{1,16})?$`)
	syscollPathRE = regexp.MustCompile(`^/syscollector/[0-9]{3,10}/(netaddr|netiface|packages)$`)
)

// allowedCall is the allow-list of FORBID-4: the login (POST) and the documented read-only GETs, and nothing else.
func allowedCall(method, path string) bool {
	switch method {
	case http.MethodPost:
		return path == "/security/user/authenticate"
	case http.MethodGet:
		return path == "/" || path == "/agents" || syscollPathRE.MatchString(path)
	}
	return false
}

// wazuhErr is a failure with the code and the words the administrator sees (API_CONVENTIONS). fatal stops a pull; a non-fatal one
// (forbidden or not understood for one agent) skips that agent.
type wazuhErr struct {
	status int
	code   string
	msg    string
}

func (e *wazuhErr) Error() string { return e.code + ": " + e.msg }

func (e *wazuhErr) fatal() bool { return e.code != "wazuh_forbidden" && e.code != "wazuh_bad_reply" }

func errUnreachable(origin string) *wazuhErr {
	return &wazuhErr{502, "wazuh_unreachable", fmt.Sprintf("Could not reach %s. Check the address and port (55000 by default) and that this box may connect to the Wazuh server.", origin)}
}

func errAuth() *wazuhErr {
	return &wazuhErr{422, "wazuh_auth", "Wazuh refused the user name or password. Check the read-only API user you created."}
}

func errForbidden() *wazuhErr {
	return &wazuhErr{422, "wazuh_forbidden", "Wazuh signed the user in, but it may not read the agents or their inventory. Give its role the agent:read and syscollector:read actions on agent:id:* (the steps above)."}
}

func errBadReply(what string) *wazuhErr {
	return &wazuhErr{502, "wazuh_bad_reply", fmt.Sprintf("The Wazuh server answered in a way Vedette does not understand (%s). Check that the address is the Wazuh server API, port 55000 by default.", what)}
}

func errTLSChanged() *wazuhErr {
	return &wazuhErr{502, "wazuh_tls", "The Wazuh certificate changed since it was saved, so the saved password was not sent. Open Edit and press Save to trust the new one, or check what answers at that address."}
}

func errRefused(why string) *wazuhErr {
	return &wazuhErr{400, "bad_url", "Vedette never connects to " + why + ". Enter the address of the Wazuh server itself."}
}

// wazuhClient makes the calls of one test or one pull, with one trust decision (one conn.HTTPSClient) and one login.
type wazuhClient struct {
	http   *conn.HTTPSClient
	origin string // https://host:port, no path
	user   string
	pass   secrets.Value
	jwt    secrets.Value
	sleep  func(ctx context.Context, d time.Duration) error
	pace   time.Duration
	last   time.Time
	calls  int // calls sent, for the log line of a pull
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// classify turns a transport error into the administrator's words. Every error of conn.HTTPSClient is already cleaned and never
// holds the password or the token.
func (c *wazuhClient) classify(err error) *wazuhErr {
	var re *conn.RefusedError
	var de *conn.DeviceError
	switch {
	case errors.Is(err, conn.ErrPinMismatch), errors.Is(err, conn.ErrUnverified):
		return errTLSChanged()
	case errors.As(err, &re):
		return errRefused(re.Why)
	case errors.As(err, &de):
		return errBadReply(de.Msg) // the transport's own cleaned words (an answer over 1 MiB, say), never the server's text
	}
	return errUnreachable(c.origin)
}

// send is one allow-listed call, paced, with the 429 answers of the manager waited out.
func (c *wazuhClient) send(ctx context.Context, method, path string, q url.Values, basic bool) (*conn.HTTPSResponse, error) {
	if !allowedCall(method, path) {
		return nil, fmt.Errorf("agentintake: %s %s is not an allowed Wazuh call", method, path) // a programming error: FORBID-4
	}
	u := c.origin + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	for attempt := 0; ; attempt++ {
		if wait := c.pace - time.Since(c.last); wait > 0 {
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		req := conn.HTTPSRequest{Method: method, URL: u}
		if basic { // the login answers text/plain with ?raw=true: no Accept that could ask for something else
			req.BasicUser, req.Secret = c.user, c.pass
		} else {
			req.Header, req.Bearer, req.Secret = http.Header{"Accept": {"application/json"}}, true, c.jwt
		}
		c.last = time.Now()
		c.calls++
		resp, err := c.http.Do(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, c.classify(err)
		}
		if resp.Status != http.StatusTooManyRequests || attempt >= wazuhRetries {
			return resp, nil
		}
		wait := wazuhMaxWait
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 1 && time.Duration(s)*time.Second < wait {
			wait = time.Duration(s) * time.Second
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// login gets the JWT (POST /security/user/authenticate?raw=true, Basic). The token lasts auth_token_exp_timeout (default 900 s).
func (c *wazuhClient) login(ctx context.Context) error {
	resp, err := c.send(ctx, http.MethodPost, "/security/user/authenticate", url.Values{"raw": {"true"}}, true)
	if err != nil {
		return err
	}
	switch resp.Status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return errAuth()
	case http.StatusTooManyRequests:
		return errUnreachable(c.origin) // still refused after the retries; the next pull tries again
	default:
		return errBadReply("HTTP " + strconv.Itoa(resp.Status) + " to the login")
	}
	tok := strings.TrimSpace(string(resp.Body))
	var wrapped struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if strings.HasPrefix(tok, "{") && json.Unmarshal(resp.Body, &wrapped) == nil { // a server that ignores raw=true answers the JSON form
		tok = wrapped.Data.Token
	}
	if len(tok) > maxJWT || !jwtRE.MatchString(tok) {
		return errBadReply("the login answer is not a token")
	}
	c.jwt = secrets.NewValue(tok)
	return nil
}

// get is a GET with the token; a 401 (the token expired, or was revoked) signs in again once.
func (c *wazuhClient) get(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.send(ctx, http.MethodGet, path, q, false)
	if err != nil {
		return err
	}
	if resp.Status == http.StatusUnauthorized {
		if err := c.login(ctx); err != nil {
			return err
		}
		if resp, err = c.send(ctx, http.MethodGet, path, q, false); err != nil {
			return err
		}
	}
	switch resp.Status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errAuth()
	case http.StatusForbidden:
		return errForbidden()
	case http.StatusTooManyRequests:
		return errUnreachable(c.origin)
	default:
		return errBadReply("HTTP " + strconv.Itoa(resp.Status))
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return errBadReply("not the documented JSON")
	}
	return nil
}

// ---- the shapes read (allow-listed fields only; Wazuh adds fields between versions and they are ignored) ----

type wzItems[T any] struct {
	Data *struct {
		Items []T  `json:"affected_items"`
		Total *int `json:"total_affected_items"`
	} `json:"data"`
}

func (w wzItems[T]) ok() bool { return w.Data != nil && w.Data.Total != nil && *w.Data.Total >= 0 }

type wzAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	LastKeepAlive string `json:"lastKeepAlive"`
	OS            struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`  // "x86_64", "i686", "aarch64": the target_hw of a Windows agent's row (D-546)
		Uname    string `json:"uname"` // "Linux |host |7.0.0-43-generic |#43-Ubuntu SMP … |x86_64": the third field is the running kernel (D-516)
	} `json:"os"`
}

type wzAddr struct {
	Iface   string `json:"iface"`
	Address string `json:"address"`
	Proto   string `json:"proto"`
}

type wzIface struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

type wzPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
	Format  string `json:"format"`
	Source  string `json:"source"`
}

// version is the API version (GET /, no RBAC action needed), "unknown" when it does not look like one.
func (c *wazuhClient) version(ctx context.Context) (string, error) {
	var info struct {
		Data *struct {
			APIVersion string `json:"api_version"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/", nil, &info); err != nil {
		var we *wazuhErr
		if errors.As(err, &we) && !we.fatal() {
			return "unknown", nil
		}
		return "", err
	}
	if info.Data == nil || !apiVersionRE.MatchString(info.Data.APIVersion) {
		return "unknown", nil
	}
	return info.Data.APIVersion, nil
}

// agentCount is the number of agents the account may read (the Test result), with one row asked.
func (c *wazuhClient) agentCount(ctx context.Context) (int, error) {
	var page wzItems[wzAgent]
	if err := c.get(ctx, "/agents", url.Values{"select": {"id"}, "limit": {"1"}}, &page); err != nil {
		return 0, err
	}
	if !page.ok() {
		return 0, errBadReply("no agent count")
	}
	return *page.Data.Total, nil
}

// agents reads the active and disconnected agents (pending and never-connected ones have no inventory), at most maxWazuhAgent.
func (c *wazuhClient) agents(ctx context.Context) ([]wzAgent, error) {
	var out []wzAgent
	seen := map[string]bool{}
	for offset := 0; len(out) < maxWazuhAgent; {
		var page wzItems[wzAgent]
		q := url.Values{"select": {"id,name,ip,status,lastKeepAlive,os.name,os.version,os.platform,os.arch,os.uname"}, "status": {"active,disconnected"},
			"limit": {strconv.Itoa(wazuhPage)}, "offset": {strconv.Itoa(offset)}}
		if err := c.get(ctx, "/agents", q, &page); err != nil {
			return nil, err
		}
		if !page.ok() {
			return nil, errBadReply("no agent list")
		}
		fresh := 0
		for _, a := range page.Data.Items {
			if !seen[a.ID] {
				seen[a.ID] = true
				out = append(out, a)
				fresh++
			}
		}
		offset += len(page.Data.Items)
		if fresh == 0 || offset >= *page.Data.Total { // a server that ignores offset repeats a page: stop, do not loop to the cap
			break
		}
	}
	if len(out) > maxWazuhAgent {
		out = out[:maxWazuhAgent]
	}
	return out, nil
}

// one page of an agent's syscollector table (netaddr, netiface: one page of 250 rows is plenty for the interfaces of a server).
func syscollPage[T any](ctx context.Context, c *wazuhClient, id, table, fields string, offset int) ([]T, int, error) {
	var page wzItems[T]
	q := url.Values{"select": {fields}, "limit": {strconv.Itoa(wazuhPage)}, "offset": {strconv.Itoa(offset)}}
	if err := c.get(ctx, "/syscollector/"+id+"/"+table, q, &page); err != nil {
		return nil, 0, err
	}
	if !page.ok() {
		return nil, 0, errBadReply("no " + table + " list")
	}
	return page.Data.Items, *page.Data.Total, nil
}

// packages reads an agent's packages, at most maxRows (the inventory's limit per device).
func (c *wazuhClient) packages(ctx context.Context, id string) ([]wzPackage, error) {
	var out []wzPackage
	for offset := 0; len(out) < maxRows; {
		items, total, err := syscollPage[wzPackage](ctx, c, id, "packages", "name,version,vendor,format,source", offset)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		offset += len(items)
		if len(items) == 0 || offset >= total {
			break
		}
	}
	return out, nil
}
