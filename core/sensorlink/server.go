package sensorlink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Identity is what the server needs from the CA (core/pki.Authority implements it). It is an interface so this package never
// imports the database or the secrets store, which the sensor binary must not link.
type Identity interface {
	// ClientCAs is the pool a sensor certificate must chain to: only the sensor CA (D-110 (1)).
	ClientCAs() *x509.CertPool
	// ServerCertificate is the current server leaf (EKU serverAuth only), for tls.Config.GetCertificate.
	ServerCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// SerialValid reports whether serial is the current or the previous serial of role (D-110 (5)).
	SerialValid(role Role, serial *big.Int) bool
}

// Backend is what core's modules implement: sensor-passive for the passive role, sensor-active for the active one. The server
// has already authenticated the role, checked the route, the module switch, the rate and the size, and decoded the body.
// A Backend returns *Error for a refusal with a code of the table; any other error becomes 500 internal and is logged here,
// never sent.
type Backend interface {
	// Config holds the request open up to wait (long poll) until the ETag differs from ifNoneMatch ("" the first time).
	Config(ctx context.Context, wait time.Duration, ifNoneMatch string) (ConfigReply, error)
	Observations(ctx context.Context, req *ObservationsRequest) (ObservationsReply, error)
	// PassiveHeartbeat and ActiveHeartbeat return the instance nonce of this core process (32 hex).
	PassiveHeartbeat(ctx context.Context, hb *PassiveHeartbeat) (instance string, err error)
	ActiveHeartbeat(ctx context.Context, hb *ActiveHeartbeat) (instance string, err error)
	// Jobs holds the request open up to wait until there is a job or a cancel; running is the job the worker says it runs.
	Jobs(ctx context.Context, wait time.Duration, running string) (JobsReply, error)
	// JobRunning says whether id is the job this core handed to the active role and has not finished. It is asked before the
	// body of a result is read, so a result for any other job costs nothing (404 unknown_job without reading).
	JobRunning(id string) bool
	// JobResult returns CodeUnknownJob for a job that is not running or was not handed out.
	JobResult(ctx context.Context, id string, res *JobResult) error
}

// Options configures a Server.
type Options struct {
	Identity Identity
	Backend  Backend
	// ModuleOn says whether the module of a role is on; off answers 409 module_off on every route of that role (D-111 (4)).
	// nil means on.
	ModuleOn func(Role) bool
	// Now is the clock for the TLS checks, the certificate expiry and the rate limit. nil means time.Now.
	Now func() time.Time
	// Log receives what a 500 hides. nil discards.
	Log *slog.Logger
	// BodyTimeout overrides BodyTimeout (tests).
	BodyTimeout time.Duration
}

// Server serves the sensor protocol.
type Server struct {
	id          Identity
	be          Backend
	moduleOn    func(Role) bool
	now         func() time.Time
	log         *slog.Logger
	bodyTimeout time.Duration
	buckets     map[Role]*bucket
	polls       map[Role]*gate
	bodies      map[Role]chan struct{} // in-flight request bodies per role: MaxBodiesPerRole slots
	results     chan struct{}          // in-flight result bodies (the large ones): MaxResultBodies slots
}

// NewServer builds a Server.
func NewServer(o Options) (*Server, error) {
	if o.Identity == nil || o.Backend == nil {
		return nil, errors.New("sensorlink: server needs an Identity and a Backend")
	}
	s := &Server{
		id: o.Identity, be: o.Backend, moduleOn: o.ModuleOn, now: o.Now, log: o.Log, bodyTimeout: o.BodyTimeout,
		buckets: map[Role]*bucket{}, polls: map[Role]*gate{}, bodies: map[Role]chan struct{}{}, results: make(chan struct{}, MaxResultBodies),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.bodyTimeout <= 0 {
		s.bodyTimeout = BodyTimeout
	}
	for _, r := range Roles {
		s.buckets[r] = &bucket{}
		s.polls[r] = &gate{}
		s.bodies[r] = make(chan struct{}, MaxBodiesPerRole)
	}
	return s, nil
}

// TLSConfig is the listener's configuration: TLS 1.3 at least, a client certificate required and verified against the sensor
// CA only, and VerifyConnection checking the EKU, the role URI and the serial on every handshake, resumed ones included
// (VerifyPeerCertificate does not run on a resumed session; D-109 (2)).
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        s.id.ClientCAs(),
		GetCertificate:   s.id.ServerCertificate,
		Time:             s.now,
		VerifyConnection: s.verifyConnection,
		NextProtos:       []string{"h2", "http/1.1"},
	}
}

func (s *Server) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return ErrIdentity
	}
	leaf := cs.PeerCertificates[0]
	role, err := ClientRole(leaf)
	if err != nil {
		return err
	}
	if !s.id.SerialValid(role, leaf.SerialNumber) {
		return fmt.Errorf("%w: serial is not current", ErrIdentity)
	}
	return nil
}

// HTTPServer returns the http.Server for addr with the timeouts of the protocol: serve it with ServeTLS(listener, "", "").
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr, Handler: s.Handler(), TLSConfig: s.TLSConfig(),
		ReadHeaderTimeout: ReadHeaderTimeout, WriteTimeout: WriteTimeout, IdleTimeout: IdleTimeout, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn), // like the 8443 server: handshake refusals go to the log, not stderr
	}
}

// Serve serves the protocol on l until it is closed: at most MaxConns connections at once (a connection that is refused its
// slot waits in the kernel's accept queue; nothing is read from it), then the TLS and HTTP of HTTPServer.
func (s *Server) Serve(l net.Listener) error {
	return s.HTTPServer("").ServeTLS(LimitListener(l, MaxConns), "", "")
}

// takeBody takes the slot a request needs before its body is read: one of MaxBodiesPerRole for the role, and for a result also
// the single result slot. ok is false when there is none; release gives the slots back.
func (s *Server) takeBody(role Role, id routeID) (release func(), ok bool) {
	select {
	case s.bodies[role] <- struct{}{}:
	default:
		return nil, false
	}
	if id == rResult {
		select {
		case s.results <- struct{}{}:
		default:
			<-s.bodies[role]
			return nil, false
		}
	}
	return func() {
		if id == rResult {
			<-s.results
		}
		<-s.bodies[role]
	}, true
}

// Handler is the protocol, without TLS: it reads the role from the verified client certificate of each request.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

type routeID int

const (
	rConfig routeID = iota + 1
	rObservations
	rHeartbeat
	rJobs
	rResult
)

type route struct {
	id   routeID
	long bool
	max  int64
}

// lookup finds the route of (method, path) for role. Anything else, including a route of the other role, is not found.
func lookup(role Role, method, p string) (rt route, jobID string, ok bool) {
	switch {
	case p == PathPrefix+"/config" && method == http.MethodGet && role == Passive:
		return route{rConfig, true, 0}, "", true
	case p == PathPrefix+"/observations" && method == http.MethodPost && role == Passive:
		return route{rObservations, false, MaxObservationsBody}, "", true
	case p == PathPrefix+"/heartbeat" && method == http.MethodPost:
		return route{rHeartbeat, false, MaxHeartbeatBody}, "", true
	case p == PathPrefix+"/jobs" && method == http.MethodGet && role == Active:
		return route{rJobs, true, 0}, "", true
	case method == http.MethodPost && role == Active && strings.HasPrefix(p, PathPrefix+"/jobs/") && strings.HasSuffix(p, "/result"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, PathPrefix+"/jobs/"), "/result")
		if id != "" && !strings.Contains(id, "/") {
			return route{rResult, false, MaxResultBody}, id, true
		}
	}
	return route{}, "", false
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// 1. who: the certificate of the connection, checked again for every request. A keep-alive connection outlives the
	// retirement of its serial and the expiry of its certificate; neither is a handshake event (D-110 (5)).
	role, err := s.callerRole(r)
	if err != nil {
		w.Header().Set("Connection", "close") // a connection whose identity is no longer good is not reused (HTTP/1.1)
		s.writeError(w, NewError(CodeCertRetired))
		return
	}
	// 2. protocol version
	if r.Header.Get(ProtoHeader) != ProtoVersion {
		s.writeError(w, NewError(CodeProtoUnsupported))
		return
	}
	// 3. route of the role, before any body is read
	rt, jobID, ok := lookup(role, r.Method, r.URL.Path)
	if !ok {
		s.writeError(w, NewError(CodeForbiddenRoute))
		return
	}
	// 4. module switch
	if s.moduleOn != nil && !s.moduleOn(role) {
		s.writeError(w, NewError(CodeModuleOff))
		return
	}
	// 5. rate
	if ok, retry := s.buckets[role].take(s.now()); !ok {
		e := NewError(CodeRateLimited)
		e.RetryAfter = retry
		s.writeError(w, e)
		return
	}
	// 6. one long poll per role
	if rt.long {
		g := s.polls[role]
		if !g.enter() {
			s.writeError(w, NewError(CodePollInProgress))
			return
		}
		defer g.leave()
	}
	ctx, cancel := context.WithTimeout(r.Context(), WriteTimeout-time.Second)
	defer cancel()
	// 7 to 9. size, strict decoding, handler
	s.dispatch(ctx, w, r, role, rt, jobID)
}

// callerRole returns the role of the certificate that carried this request, or an error when it is not current.
func (s *Server) callerRole(r *http.Request) (Role, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrIdentity
	}
	leaf := r.TLS.PeerCertificates[0]
	role, err := ClientRole(leaf)
	if err != nil {
		return "", err
	}
	if t := s.now(); t.Before(leaf.NotBefore) || t.After(leaf.NotAfter) {
		return "", fmt.Errorf("%w: outside its validity", ErrIdentity)
	}
	if !s.id.SerialValid(role, leaf.SerialNumber) {
		return "", fmt.Errorf("%w: serial is not current", ErrIdentity)
	}
	return role, nil
}

func (s *Server) dispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, role Role, rt route, jobID string) {
	q, err := queryOf(r, rt.id)
	if err != nil {
		s.writeError(w, NewError(CodeInvalidRequest))
		return
	}
	var raw []byte
	if rt.max > 0 {
		// What costs nothing is decided before any memory is spent on a body, and every refusal here closes the connection: its
		// body is not read, so the connection cannot be reused.
		if rt.id == rResult {
			if !jobIDRE.MatchString(jobID) {
				w.Header().Set("Connection", "close")
				s.writeError(w, NewError(CodeInvalidRequest))
				return
			}
			if !s.be.JobRunning(jobID) {
				w.Header().Set("Connection", "close")
				s.writeError(w, NewError(CodeUnknownJob))
				return
			}
		}
		release, ok := s.takeBody(role, rt.id)
		if !ok {
			w.Header().Set("Connection", "close")
			s.writeError(w, StoreBusy(time.Second))
			return
		}
		defer release()
		if raw, err = s.readBody(w, r, rt.max); err != nil {
			s.fail(ctx, w, err)
			return
		}
	}
	switch rt.id {
	case rConfig:
		rep, err := s.be.Config(ctx, q.wait, q.etag)
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		if rep.ETag != "" {
			w.Header().Set("ETag", rep.ETag)
		}
		if rep.NotModified {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if rep.Config.Filters == nil {
			rep.Config.Filters = []Filter{}
		}
		s.writeJSON(ctx, w, rep.Config, MaxConfigReply)
	case rObservations:
		req, err := decodeObservations(raw)
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		rep, err := s.be.Observations(ctx, req)
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		if rep.Rejected == nil {
			rep.Rejected = []Rejected{}
		}
		s.writeJSON(ctx, w, rep, MaxOtherReply)
	case rHeartbeat:
		var inst string
		if role == Passive {
			var hb *PassiveHeartbeat
			if hb, err = decodePassiveHeartbeat(raw); err == nil {
				inst, err = s.be.PassiveHeartbeat(ctx, hb)
			}
		} else {
			var hb *ActiveHeartbeat
			if hb, err = decodeActiveHeartbeat(raw); err == nil {
				inst, err = s.be.ActiveHeartbeat(ctx, hb)
			}
		}
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		s.writeJSON(ctx, w, instanceReply{Instance: inst}, MaxOtherReply)
	case rJobs:
		rep, err := s.be.Jobs(ctx, q.wait, q.running)
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		if rep.Jobs == nil {
			rep.Jobs = []Job{}
		}
		if rep.Cancel == nil {
			rep.Cancel = []string{}
		}
		s.writeJSON(ctx, w, rep, MaxJobsReply)
	case rResult:
		res, err := decodeJobResult(raw)
		if err == nil {
			err = s.be.JobResult(ctx, jobID, res)
		}
		if err != nil {
			s.fail(ctx, w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type query struct {
	wait    time.Duration
	running string
	etag    string
}

// queryOf validates the query string and the conditional header of a route. Any parameter the route does not take is an error.
func queryOf(r *http.Request, id routeID) (query, error) {
	q := query{wait: DefaultWait}
	vals, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, err
	}
	allowed := map[routeID][]string{rConfig: {"wait"}, rJobs: {"wait", "running"}}[id]
	for k, v := range vals {
		if len(v) != 1 || !slices.Contains(allowed, k) {
			return q, errInvalid
		}
	}
	if w := vals.Get("wait"); w != "" {
		n, err := strconv.Atoi(w)
		if err != nil || len(w) > 2 || n < 0 || n > int(MaxWait/time.Second) {
			return q, errInvalid
		}
		q.wait = time.Duration(n) * time.Second
	}
	if run := vals.Get("running"); run != "" {
		if !jobIDRE.MatchString(run) {
			return q, errInvalid
		}
		q.running = run
	}
	if id == rConfig {
		if v := r.Header.Get("If-None-Match"); v != "" {
			if !etagRE.MatchString(v) {
				return q, errInvalid
			}
			q.etag = v
		}
	}
	return q, nil
}

// readBody reads one request body: JSON only, never compressed, at most max bytes, in at most bodyTimeout.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.Header.Get("Content-Encoding") != "" {
		return nil, errInvalid
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, errInvalid
	}
	if r.ContentLength > limit {
		return nil, errTooLarge
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(s.bodyTimeout)) // wall clock: a socket deadline, not the clock seam; not every ResponseWriter can set one, the size cap still holds
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		// The deadline stays where it is: the connection cannot be reused after a body that failed half way, and net/http would
		// otherwise wait for the rest of it with no limit once the answer is written.
		w.Header().Set("Connection", "close")
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errTooLarge
		}
		return nil, errInvalid
	}
	_ = rc.SetReadDeadline(time.Time{}) // the long reads of the next request on this connection are not on this clock
	return b, nil
}

// fail answers a decoder error or a Backend error. Nothing but a code of the table leaves this function.
func (s *Server) fail(ctx context.Context, w http.ResponseWriter, err error) {
	var e *Error
	switch {
	case errors.Is(err, errTooLarge):
		e = NewError(CodePayloadTooLarge)
	case errors.Is(err, errInvalid):
		e = NewError(CodeInvalidRequest)
	case errors.As(err, &e):
		if c, ok := codes[e.Code]; !ok || c.status != e.Status {
			s.log.ErrorContext(ctx, "sensor_link_backend_error_outside_table", "code", e.Code, "status", e.Status)
			e = NewError(CodeInternal)
		}
	default:
		s.log.ErrorContext(ctx, "sensor_link_backend_error", "error", err)
		e = NewError(CodeInternal)
	}
	s.writeError(w, e)
}

func (s *Server) writeError(w http.ResponseWriter, e *Error) {
	if e.RetryAfter > 0 || e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds(e.RetryAfter)))
	}
	body := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	body.Error.Code = e.Code
	body.Error.Message = codes[e.Code].message
	b, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(e.Status)
	_, _ = w.Write(b)
}

func (s *Server) writeJSON(ctx context.Context, w http.ResponseWriter, v any, limit int) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > limit {
		s.log.ErrorContext(ctx, "sensor_link_reply_unusable", "size", len(b), "cap", limit)
		s.writeError(w, NewError(CodeInternal))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
