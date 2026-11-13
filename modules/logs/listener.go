package logs

import (
	"context"
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/knt048/vedette/modules/logs/listen"
)

// SyslogConfig is where the syslog listener binds. Ports are tried in order for the first socket that opens and the one that
// works is kept; a port is skipped only when the process may not bind it (514 needs a right that the core container may not have).
type SyslogConfig struct {
	Host   string // "" = every IPv4 address
	Ports  []int  // nil = 514, then 5514
	Limits listen.Limits
	// TLS is the certificate side of syslog over TLS (RFC 5425), the box's HTTPS configuration cloned by cmd/vedette (D-214): the same
	// GetCertificate, so a renewal is served by the next handshake; TLS 1.2 minimum; a client certificate is requested only from a sender whose source pins one (D-435), else the sender's IP is its identity.
	// Nil (a loopback or dev box serves no TLS): sources with proto tls are refused (400 tls_unavailable) and nothing listens for TLS.
	// The TLS port follows the plain one: 6514 for 514, p+1 for any other (5515 for the core container's 5514).
	TLS *tls.Config
	// RetryEvery is how often the job retries a socket that could not be opened, or a read of the sources that failed
	// (0 = SyslogRetry).
	RetryEvery time.Duration
}

// DefaultSyslogPorts is the port devices are told to use and the one used when that is not allowed.
var DefaultSyslogPorts = []int{514, 5514}

// SyslogRetry is how long the listener waits before it retries a socket it could not open (inside the job; the job does not end).
const SyslogRetry = 30 * time.Second

// sourcesChanged wakes the listener: a source was added, edited or deleted. Non-blocking, one pending wake-up is enough.
func (s *Service) sourcesChanged() {
	s.dropSnapshot() // the digest names the sources: a change makes the stored reading stale
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// listenSources is the declared senders the listener serves, by sender address. A tls row is counted as well: the listener serves it only
// while the box has a TLS configuration, and the count is what the warning for a left-over row (declared before this box had one) is about.
func (s *Service) listenSources(ctx context.Context) (m map[netip.Addr]listen.Source, tlsRows int, err error) {
	load := s.loadSources
	if s.loadForListener != nil { // a test makes the read fail
		load = s.loadForListener
	}
	rows, err := load(ctx)
	if err != nil {
		return nil, 0, err
	}
	m = make(map[netip.Addr]listen.Source, len(rows))
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.SenderIP)
		if err != nil {
			continue // validated on the way in; a row that is not an address is not served
		}
		switch r.Proto {
		case "udp", "tcp":
			m[ip] = listen.Source{ID: r.ID, Proto: r.Proto}
		default:
			tlsRows++
			m[ip] = listen.Source{ID: r.ID, Proto: r.Proto, ClientCertSHA256: r.ClientCert} // the server serves it only when it has a TLS configuration
		}
	}
	return m, tlsRows, nil
}

// sink hands a batch to Ingest. The listener never stores anything itself.
func (s *Service) sink(ctx context.Context, lines []listen.Line) error {
	batch := make([]Line, len(lines))
	for i, l := range lines {
		batch[i] = Line{SourceID: l.SourceID, At: l.At, Text: l.Text}
	}
	_, err := s.Ingest(ctx, batch)
	return err
}

// runSyslog is the listener job (SYS-5: a core/jobs job, not Housekeeping, so it runs only while the module is on and its
// context is cancelled the moment the module is turned off, which closes every socket). It ends only when ctx does. A socket that
// cannot be opened, or a read of the sources that fails, does not end it and does not touch the sockets that are open: it is
// retried every RetryEvery, and the status (ListenStatus) says what is down and why. The sockets are open while the job runs, with or
// without sources (D-443), so a sender that is not declared yet is counted for the Sources page instead of meeting a closed port.
func (s *Service) runSyslog(ctx context.Context) error {
	ports := s.cfg.Syslog.Ports
	if len(ports) == 0 {
		ports = DefaultSyslogPorts
	}
	lim := s.cfg.Syslog.Limits
	if lim.BatchLines <= 0 || lim.BatchLines > MaxBatch {
		lim.BatchLines = MaxBatch // Ingest takes MaxBatch lines at most: a larger batch would be refused whole
	}
	retry := s.cfg.Syslog.RetryEvery
	if retry <= 0 {
		retry = SyslogRetry
	}
	srv, err := listen.New(listen.Config{Host: s.cfg.Syslog.Host, Ports: ports, Sink: s.sink, Log: s.cfg.Log, Now: s.now, Limits: lim, TLS: s.cfg.Syslog.TLS})
	if err != nil {
		return err
	}
	select { // a change before this run is covered by the load below
	case <-s.changed:
	default:
	}
	// What was last warned about, so that a retry every few seconds does not repeat it (the way noteBind does for the sockets).
	var warnedTLS int
	var warnedRead string
	// apply reloads the sources into the server; it reports whether it has to be tried again.
	apply := func() (again bool) {
		m, tlsRows, err := s.listenSources(ctx)
		if err != nil {
			if ctx.Err() == nil && warnedRead != err.Error() {
				warnedRead = err.Error()
				s.cfg.Log.WarnContext(ctx, "logs: could not read the sources for the syslog listener; the sockets stay as they are and it is retried", "err", err)
			}
			return true
		}
		warnedRead = ""
		if s.cfg.Syslog.TLS != nil { // sources over TLS are served
			tlsRows = 0
		}
		if tlsRows != warnedTLS {
			warnedTLS = tlsRows
			if tlsRows > 0 {
				s.cfg.Log.WarnContext(ctx, "logs: sources declared with TLS are not served: this box has no TLS configuration (it serves plain HTTP)", "sources", tlsRows)
			}
		}
		err = srv.SetSources(m) // the server logs the reason and keeps the sockets that opened
		st := srv.Status()
		return err != nil || st.UDPErr != "" || st.TCPErr != "" || st.TLSErr != ""
	}
	apply() // the sources are in the server before it runs; Run opens the sockets
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx) }()
	s.listening.Store(srv)
	defer s.listening.Store(nil)
	again := true // Run may not have opened the sockets yet: look once after the retry time whether it could
	var tick <-chan time.Time
	arm := func() {
		tick = nil
		if again {
			tick = time.After(retry)
		}
	}
	arm()
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case <-s.changed:
			again = apply()
			arm()
		case <-tick:
			again = apply()
			arm()
		case <-ctx.Done():
			stop()
			<-done //nolint:errcheck // the error of a cancelled run is not news; the sockets are closed and the last batch stored before the job ends
			return ctx.Err()
		}
	}
}

// ListenStatus says whether and where the box listens for syslog.
type ListenStatus struct {
	Listening bool // the listener job is running
	listen.Status
	Stats listen.Stats
}

// UnknownShown is how many dropped senders GET /logs/unknown-senders returns, the most recent first.
const UnknownShown = 10

// UnknownSenders is the senders whose syslog the listener dropped because no source declares them, or declares them with another protocol
// (FORBID-5; a UDP source takes TCP too, D-444): the S-LOG-1 hint "lines arrive from an address that is not a source". The addresses come from the socket (listen.UnknownSender),
// never from the text of a line. A sender that a source now declares with the protocol it last used is left out, so adding the source clears
// the hint at once. In memory only (the listener's 256-sender table, the 10 most recent returned; no line text is kept): empty while the listener is not running, and counted again from zero when it restarts.
func (s *Service) UnknownSenders(ctx context.Context) (UnknownSendersView, error) {
	out := UnknownSendersView{Items: []UnknownSender{}}
	srv := s.listening.Load()
	if srv == nil {
		return out, nil
	}
	declared, _, err := s.listenSources(ctx)
	if err != nil {
		return UnknownSendersView{}, err
	}
	for _, u := range srv.Stats().UnknownSender {
		if src, ok := declared[u.IP]; ok && listen.Accepts(src.Proto, u.Proto) {
			continue
		}
		out.Items = append(out.Items, UnknownSender{IP: u.IP.String(), Proto: u.Proto, Count: u.Count, LastSeen: u.Last})
		if len(out.Items) == UnknownShown {
			break
		}
	}
	return out, nil
}

// ListenStatus reports the listener, for the box block of the sources page (not shown yet, see the deferred line of L2).
func (s *Service) ListenStatus() ListenStatus {
	srv := s.listening.Load()
	if srv == nil {
		return ListenStatus{}
	}
	return ListenStatus{Listening: true, Status: srv.Status(), Stats: srv.Stats()}
}
