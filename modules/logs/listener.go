package logs

import (
	"context"
	"fmt"
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
}

// DefaultSyslogPorts is the port devices are told to use and the one used when that is not allowed.
var DefaultSyslogPorts = []int{514, 5514}

// SyslogRetry is how long after the listener job ended (a socket that could not be opened) core/jobs starts it again.
const SyslogRetry = 30 * time.Second

// sourcesChanged wakes the listener: a source was added, edited or deleted. Non-blocking, one pending wake-up is enough.
func (s *Service) sourcesChanged() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// listenSources is the declared senders the listener serves: udp and tcp sources by sender address. A tls source is not served
// by this listener (see ListenStatus.TLSSources).
func (s *Service) listenSources(ctx context.Context) (m map[netip.Addr]listen.Source, tls int, err error) {
	rows, err := s.loadSources(ctx)
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
			tls++
		}
	}
	return m, tls, nil
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
// context is cancelled the moment the module is turned off, which closes every socket). It returns when ctx ends, or at once
// with the error of a socket that could not be opened (core/jobs starts it again after SyslogRetry). No source, no socket.
func (s *Service) runSyslog(ctx context.Context) error {
	ports := s.cfg.Syslog.Ports
	if len(ports) == 0 {
		ports = DefaultSyslogPorts
	}
	srv, err := listen.New(listen.Config{Host: s.cfg.Syslog.Host, Ports: ports, Sink: s.sink, Log: s.cfg.Log, Now: s.now, Limits: s.cfg.Syslog.Limits})
	if err != nil {
		return err
	}
	select { // a change before this run is covered by the load below
	case <-s.changed:
	default:
	}
	apply := func() error {
		m, tls, err := s.listenSources(ctx)
		if err != nil {
			return err
		}
		if tls > 0 {
			s.cfg.Log.WarnContext(ctx, "logs: sources declared with TLS are not served yet: the TLS listener (port 6514) is not built", "sources", tls)
		}
		return srv.SetSources(m)
	}
	if err := apply(); err != nil {
		return err
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx) }()
	s.listening.Store(srv)
	defer s.listening.Store(nil)
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case <-s.changed:
			if err := apply(); err != nil {
				stop()
				<-done
				return fmt.Errorf("logs: updating the syslog listener: %w", err)
			}
		case <-ctx.Done():
			stop()
			<-done // the sockets are closed and the last batch is stored before the job ends
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

// ListenStatus reports the listener, for the box block of the sources page (not shown yet, see the deferred line of L2).
func (s *Service) ListenStatus() ListenStatus {
	srv := s.listening.Load()
	if srv == nil {
		return ListenStatus{}
	}
	return ListenStatus{Listening: true, Status: srv.Status(), Stats: srv.Stats()}
}
