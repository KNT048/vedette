package sensorlink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
)

var (
	// ErrDropped says a batch was given up on: the server refused it in a way a retry cannot fix (D-112 (4)). It is counted in
	// Stats and wraps the *Error when there was one.
	ErrDropped = errors.New("sensorlink: batch dropped")
	// ErrModuleOff says the module of this role is off (409 module_off): stop at once and drop the queue, no last batch
	// (SYS-5, D-80 (4)).
	ErrModuleOff = errors.New("sensorlink: module off")
	errReply     = errors.New("sensorlink: unusable reply")
)

// reloadRetry is how long a client waits before reading a credentials file again after it read one it could not use.
const reloadRetry = 5 * time.Second

// ClientOptions configures a Client.
type ClientOptions struct {
	// BaseURL is core's sensor listener, https://127.0.0.1:8444 (or https://core:8444 in compose).
	BaseURL string
	// CredsPath is <creds>/<role>/sensor.pem. The client reads it, never writes it.
	CredsPath string
	// Now is the clock of the TLS checks. nil means time.Now.
	Now func() time.Time
	// Sleep waits for d or until ctx ends. nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Rand returns a number in [0,1) for the jitter. nil uses math/rand/v2.
	Rand func() float64
}

// ClientStats counts what the client did that a person looking at a heartbeat would want to know.
type ClientStats struct {
	Dropped uint64 // batches given up on
	Retries uint64 // sends repeated after a failure
	Reloads uint64 // times a new credentials bundle was read
}

// Client is the sensor side of the protocol.
type Client struct {
	base  *url.URL
	path  string
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
	rnd   func() float64

	mu      sync.Mutex
	st      *clientState
	nextTry time.Time

	dropped, retries, reloads atomic.Uint64
}

type clientState struct {
	bundle *Bundle
	fi     os.FileInfo
	tr     *http.Transport
	hc     *http.Client
}

// NewClient reads the credentials once (an unusable bundle at start is an error) and builds the client.
func NewClient(o ClientOptions) (*Client, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("sensorlink: base URL must be https://host:port")
	}
	c := &Client{base: u, path: o.CredsPath, now: o.Now, sleep: o.Sleep, rnd: o.Rand}
	if c.now == nil {
		c.now = time.Now
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	if c.rnd == nil {
		c.rnd = rand.Float64
	}
	b, fi, err := readBundleFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("sensorlink: credentials: %w", err)
	}
	bundle, err := ParseBundle(b)
	if err != nil {
		return nil, err
	}
	c.st = c.newState(bundle, fi, nil)
	return c, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Stats returns the counters.
func (c *Client) Stats() ClientStats {
	return ClientStats{Dropped: c.dropped.Load(), Retries: c.retries.Load(), Reloads: c.reloads.Load()}
}

// newState builds the state for a bundle with a transport of its own. Every reload gets a new transport, not only a new CA: an
// old one may still be about to put a connection that carries the old certificate back in its idle pool (net/http does that
// after the body is read, asynchronously), and a connection of the old certificate must never serve a request again. The old
// transport is told to close what it has idle; a connection that was in use then ends by IdleConnTimeout.
func (c *Client) newState(b *Bundle, fi os.FileInfo, old *clientState) *clientState {
	if old != nil {
		old.tr.CloseIdleConnections()
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              b.Pool, // the CA in the bundle: the server must chain to it with EKU serverAuth
			GetClientCertificate: c.clientCert,
			Time:                 c.now,
		},
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &clientState{bundle: b, fi: fi, tr: tr, hc: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// clientCert is tls.Config.GetClientCertificate: it picks up a rotated bundle before every handshake (D-110 (4)).
func (c *Client) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	st := c.refresh(false)
	return &st.bundle.Cert, nil
}

// refresh reads the credentials file again when it changed (mtime, size or the file itself: a rename gives a new inode).
// A file that cannot be used (half written, wrong key, not a regular file) leaves the bundle in memory as it was and is tried
// again after reloadRetry. force skips that wait (a 403 cert_retired says the bundle in memory is stale).
func (c *Client) refresh(force bool) *clientState {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Lstat(c.path)
	if err == nil && sameFile(fi, c.st.fi) {
		return c.st
	}
	if !force && c.now().Before(c.nextTry) {
		return c.st
	}
	b, fi, err := readBundleFile(c.path)
	if err == nil {
		var bundle *Bundle
		if bundle, err = ParseBundle(b); err == nil {
			c.st = c.newState(bundle, fi, c.st)
			c.reloads.Add(1)
			return c.st
		}
	}
	c.nextTry = c.now().Add(reloadRetry)
	return c.st
}

func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// Backoff is the wait of a sensor that is retrying: 1 s, doubling to 60 s, each wait cut by a random share of its upper half
// so that sensors do not retry in step (D-112 (4)).
type Backoff struct {
	cur time.Duration
	rnd func() float64
}

// NewBackoff returns a Backoff. rnd returns a number in [0,1); nil uses math/rand/v2.
func NewBackoff(rnd func() float64) *Backoff {
	if rnd == nil {
		rnd = rand.Float64
	}
	return &Backoff{rnd: rnd}
}

// Next returns the next wait and raises the following one.
func (b *Backoff) Next() time.Duration {
	if b.cur == 0 {
		b.cur = BackoffStart
	}
	d := b.cur/2 + time.Duration(b.rnd()*float64(b.cur/2))
	b.cur = min(b.cur*2, BackoffCap)
	return d
}

// Reset starts again at one second, after a success.
func (b *Backoff) Reset() { b.cur = 0 }

type reply struct {
	status int
	etag   string
}

// do sends one request and decodes a 200 into out. A non-2xx answer is an *Error; no answer at all is the transport's error.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, header http.Header, in, out any, maxReply int, timeout time.Duration) (reply, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return reply{}, err
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path, u.RawQuery = path, q.Encode()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return reply{}, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set(ProtoHeader, ProtoVersion)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	st := c.refresh(false)
	resp, err := st.hc.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		return reply{}, c.errorOf(resp)
	}
	r := reply{status: resp.StatusCode, etag: resp.Header.Get("ETag")}
	if out == nil || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return r, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxReply)+1))
	if err != nil {
		return reply{}, err
	}
	if len(raw) > maxReply {
		return reply{}, fmt.Errorf("%w: over %d bytes", errReply, maxReply)
	}
	if err := jsonstrict.Decode(raw, out); err != nil {
		return reply{}, fmt.Errorf("%w: %w", errReply, err)
	}
	return r, nil
}

func (c *Client) errorOf(resp *http.Response) error {
	e := &Error{Status: resp.StatusCode}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		e.RetryAfter = time.Duration(min(s, int(BackoffCap/time.Second))) * time.Second
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxOtherReply))
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if jsonstrict.Decode(raw, &env) == nil {
		if _, ok := codes[env.Error.Code]; ok {
			e.Code = env.Error.Code
		}
	}
	if e.Code == CodeCertRetired {
		c.refresh(true) // the bundle in memory is stale: look at the file now
	}
	return e
}

// Config is one long poll of GET /config (passive). etag is the ETag of the configuration in use, "" the first time. It ends
// when the answer comes, at wait plus a margin, or when ctx is cancelled, whichever is first: cancel ctx to stop a poll.
func (c *Client) Config(ctx context.Context, etag string, wait time.Duration) (ConfigReply, error) {
	q, h := url.Values{"wait": {strconv.Itoa(int(min(wait, MaxWait) / time.Second))}}, http.Header{}
	if etag != "" {
		h.Set("If-None-Match", etag)
	}
	var cfg Config
	r, err := c.do(ctx, http.MethodGet, PathPrefix+"/config", q, h, nil, &cfg, MaxConfigReply, min(wait, MaxWait)+10*time.Second)
	if err != nil {
		return ConfigReply{}, err
	}
	if r.status == http.StatusNotModified {
		return ConfigReply{NotModified: true, ETag: etag}, nil
	}
	return ConfigReply{ETag: r.etag, Config: cfg}, nil
}

// Jobs is one long poll of GET /jobs (active); running is the id of the job the worker runs, "" when idle. Cancel ctx to stop.
func (c *Client) Jobs(ctx context.Context, running string, wait time.Duration) (JobsReply, error) {
	q := url.Values{"wait": {strconv.Itoa(int(min(wait, MaxWait) / time.Second))}}
	if running != "" {
		q.Set("running", running)
	}
	var rep JobsReply
	if _, err := c.do(ctx, http.MethodGet, PathPrefix+"/jobs", q, nil, nil, &rep, MaxJobsReply, min(wait, MaxWait)+10*time.Second); err != nil {
		return JobsReply{}, err
	}
	return rep, nil
}

// PassiveHeartbeat sends one heartbeat of the passive role and returns the instance nonce of core.
func (c *Client) PassiveHeartbeat(ctx context.Context, hb *PassiveHeartbeat) (string, error) {
	return c.heartbeat(ctx, hb)
}

// ActiveHeartbeat sends one heartbeat of the active role and returns the instance nonce of core.
func (c *Client) ActiveHeartbeat(ctx context.Context, hb *ActiveHeartbeat) (string, error) {
	return c.heartbeat(ctx, hb)
}

func (c *Client) heartbeat(ctx context.Context, hb any) (string, error) {
	var rep instanceReply
	if _, err := c.do(ctx, http.MethodPost, PathPrefix+"/heartbeat", nil, nil, hb, &rep, MaxOtherReply, 30*time.Second); err != nil {
		return "", err
	}
	if !epochRE.MatchString(rep.Instance) {
		return "", fmt.Errorf("%w: instance", errReply)
	}
	return rep.Instance, nil
}

// PostResult sends the result of a job. It does not retry: a 413 or 404 means core has already given up on the job.
func (c *Client) PostResult(ctx context.Context, id string, res *JobResult) error {
	_, err := c.do(ctx, http.MethodPost, PathPrefix+"/jobs/"+id+"/result", nil, nil, res, nil, MaxOtherReply, 60*time.Second)
	return err
}

// SendObservations delivers one batch the way D-112 (4) says, and returns when it was delivered (the 200, with the items it
// rejected, which are never sent again), given up on (ErrDropped), or ctx ended.
//   - no answer (connection error, core restarting): the same batch again after a backoff;
//   - 429 and 503: the same batch after the longer of Retry-After and the backoff;
//   - 426: the same batch after the backoff, however long it takes: the queue is kept while core is being updated;
//   - 403 cert_retired: the credentials file is read again, then the same batch after the backoff;
//   - 409 module_off: ErrModuleOff at once;
//   - 413: onTooLarge gets the batch and returns the half to send now (it keeps the other half for later); nil, or a batch
//     of one item, drops it;
//   - any other status: dropped, counted.
func (c *Client) SendObservations(ctx context.Context, req *ObservationsRequest, onTooLarge func(*ObservationsRequest) *ObservationsRequest) (ObservationsReply, error) {
	bo := NewBackoff(c.rnd)
	for {
		var rep ObservationsReply
		_, err := c.do(ctx, http.MethodPost, PathPrefix+"/observations", nil, nil, req, &rep, MaxOtherReply, 60*time.Second)
		if err == nil {
			return rep, nil
		}
		if ctx.Err() != nil {
			return ObservationsReply{}, ctx.Err()
		}
		wait := bo.Next()
		var e *Error
		switch {
		case !errors.As(err, &e): // no answer, or one we cannot read: try the same batch again
		case e.Code == CodeModuleOff:
			return ObservationsReply{}, ErrModuleOff
		case e.Status == http.StatusRequestEntityTooLarge:
			if onTooLarge == nil || len(req.Items) <= 1 {
				return ObservationsReply{}, c.drop(err)
			}
			smaller := onTooLarge(req)
			if smaller == nil || len(smaller.Items) == 0 || len(smaller.Items) >= len(req.Items) {
				return ObservationsReply{}, c.drop(err)
			}
			req = smaller
			continue
		case e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable:
			wait = max(wait, e.RetryAfter)
		case e.Status == http.StatusUpgradeRequired || e.Code == CodeCertRetired:
		default:
			return ObservationsReply{}, c.drop(err)
		}
		c.retries.Add(1)
		if err := c.sleep(ctx, min(wait, BackoffCap)); err != nil {
			return ObservationsReply{}, err
		}
	}
}

func (c *Client) drop(err error) error {
	c.dropped.Add(1)
	return fmt.Errorf("%w: %w", ErrDropped, err)
}
