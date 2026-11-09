package honeypot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/knt048/vedette/core/events"
)

// hostCache is what the last Apply learned: Apply is the only writer, Overview reads it (INV-7: a trap listens only
// when the container is up with a configuration that has it).
type hostCache struct {
	available bool
	running   bool
	reason    string
	services  map[ServiceName]bool // the services of the configuration the container was started with
}

func (s *Service) listening(svc ServiceName) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.available && s.host.running && s.host.services[svc]
}

// HostStatus says whether the traps can listen and, when they cannot, why. The API has no field for it: a trap that is
// on but cannot listen shows state "off" and the reason is here and in the log.
func (s *Service) HostStatus() (listening bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.available && s.host.running, s.host.reason
}

// desired is what the host should look like, from the database and the inventory (D-55: configuration comes from the
// database, never edited by hand). A secondary IP or decoy IP that a device now has is left out (INV-6, FORBID-1).
func (w *world) desired() (ips []netip.Addr, services []ServiceName) {
	if w.secIP.IsValid() && w.deviceAt(w.secIP) == nil {
		for _, svc := range Services {
			if w.traps[svc].enabled {
				services = append(services, svc)
			}
		}
		if len(services) > 0 {
			ips = append(ips, w.secIP)
		}
	}
	if len(services) > 0 {
		for _, d := range w.decoys {
			if d.Enabled && d.ip.IsValid() && w.deviceAt(d.ip) == nil && d.ip != w.box.IP && !slices.Contains(ips, d.ip) {
				ips = append(ips, d.ip)
			}
		}
	}
	return ips, services
}

// Apply makes the host match the database: writes opencanary.conf and honeytokens.json (atomically, only when they
// changed), then, if the host is an appliance, hands it the decoy IPs and starts or stops the container. It is
// idempotent and safe to call at any time.
func (s *Service) Apply(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	w, err := s.load(ctx)
	if err != nil {
		return err
	}
	ips, services := w.desired()
	if s.cfg.ConfigDir != "" {
		var files []string
		toks, err := s.loadTokens(ctx, s.db.Reader())
		if err != nil {
			return err
		}
		for _, t := range toks {
			if t.Type == TokenFile {
				files = append(files, t.Value)
			}
		}
		nas := false
		for _, d := range w.decoys {
			nas = nas || d.Enabled && d.Personality == NAS
		}
		conf, err := RenderConfig(ConfigInput{Enabled: services, LogPath: s.cfg.LogPath, NASDecoy: nas})
		if err != nil {
			return err
		}
		tok, err := RenderTokens(files)
		if err != nil {
			return err
		}
		for _, f := range []struct {
			name string
			data []byte
		}{{ConfFile, conf}, {TokensFile, tok}} {
			if _, err := writeAtomic(s.cfg.ConfigDir, f.name, f.data); err != nil {
				return err
			}
		}
	}
	st, err := s.cfg.Host.Status(ctx)
	if err != nil {
		s.setHost(hostCache{reason: "the host does not answer"})
		return fmt.Errorf("honeypot: host status: %w", err)
	}
	if s.cfg.ConfigDir == "" {
		st = HostStatus{Reason: "the honeypot volume is not configured"}
	}
	if !st.Available {
		reason := st.Reason
		if reason == "" {
			reason = "this machine is not an appliance"
		}
		s.setHost(hostCache{reason: reason})
		s.cfg.Log.InfoContext(ctx, "honeypot: traps cannot listen", "reason", reason)
		return nil
	}
	if err := s.syncIPs(ctx, ips); err != nil {
		s.setHost(hostCache{available: true, reason: "the decoy IPs could not be set"})
		return err
	}
	if len(services) == 0 || len(ips) == 0 {
		if err := s.cfg.Host.StopContainer(ctx); err != nil {
			return fmt.Errorf("honeypot: stop container: %w", err)
		}
		s.setHost(hostCache{available: true, reason: "no trap is on"})
		return nil
	}
	if err := s.cfg.Host.StartContainer(ctx); err != nil {
		s.setHost(hostCache{available: true, reason: "the honeypot container did not start"})
		return fmt.Errorf("honeypot: start container: %w", err)
	}
	m := map[ServiceName]bool{}
	for _, svc := range services {
		m[svc] = true
	}
	s.setHost(hostCache{available: true, running: true, services: m})
	return nil
}

func (s *Service) setHost(h hostCache) {
	s.mu.Lock()
	s.host = h
	s.mu.Unlock()
}

// syncIPs adds the wanted decoy IPs, removes the ones handed over earlier that are no longer wanted, and remembers the
// set (hp_config "applied") so a restart can still remove a stale one.
func (s *Service) syncIPs(ctx context.Context, want []netip.Addr) error {
	var prev []string
	if err := loadJSON(ctx, s.db.Reader(), "applied", &prev); err != nil {
		return err
	}
	have := map[netip.Addr]bool{}
	var errs []error
	for _, p := range prev {
		if a, err := netip.ParseAddr(p); err == nil {
			have[a] = true
		}
	}
	for _, ip := range want {
		if err := s.cfg.Host.AddDecoyIP(ctx, ip); err != nil {
			errs = append(errs, fmt.Errorf("honeypot: add decoy IP %s: %w", ip, err))
			continue
		}
		have[ip] = true
	}
	for ip := range have {
		if !slices.Contains(want, ip) {
			if err := s.cfg.Host.RemoveDecoyIP(ctx, ip); err != nil {
				errs = append(errs, fmt.Errorf("honeypot: remove decoy IP %s: %w", ip, err))
				continue
			}
			delete(have, ip)
		}
	}
	now := make([]string, 0, len(have))
	for ip := range have {
		now = append(now, ip.String())
	}
	sort.Strings(now)
	if !slices.Equal(prev, now) {
		err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.saveJSON(ctx, tx, "applied", now, "system") })
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Disable is what the module does when it is switched off (SYS-5): the container stops, the decoy IPs go, nothing
// listens. The data stays.
func (s *Service) Disable(ctx context.Context) error {
	st, err := s.cfg.Host.Status(ctx)
	if err != nil || !st.Available || s.cfg.ConfigDir == "" {
		s.setHost(hostCache{reason: "the module is off"})
		return err
	}
	var errs []error
	if err := s.cfg.Host.StopContainer(ctx); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, s.syncIPs(ctx, nil))
	s.setHost(hostCache{available: true, reason: "the module is off"})
	return errors.Join(errs...)
}

// Bus is the part of core/events the module subscribes through.
type Bus interface {
	Subscribe(name string, fn events.Handler) (unsubscribe func())
}

// Subscribe registers the reactions: a device that appears or changes may now sit on a secondary or decoy IP, so the
// state is applied again (INV-6: the trap becomes conflict and stops listening). Events are hints; the run loop also
// applies every minute.
func (s *Service) Subscribe(bus Bus) (unsubscribe func()) {
	var undo []func()
	for _, name := range []string{"inventory.asset.discovered", "inventory.asset.updated"} {
		undo = append(undo, bus.Subscribe(name, func(context.Context, events.Event) error {
			if s.on() {
				s.Kick()
			}
			return nil
		}))
	}
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

// applyEvery is how often the state is applied again whatever happened.
const applyEvery = time.Minute

// Run is the job of the module: it applies the state, then tails the OpenCanary log until ctx ends (the scheduler
// cancels it when the module is switched off, SYS-5). It returns nil on cancellation.
func (s *Service) Run(ctx context.Context) error {
	defer func() {
		if s.on() { // the process is stopping or the loop failed: the module is still on, the traps stay as they are
			return
		}
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.Disable(dctx); err != nil {
			s.cfg.Log.WarnContext(dctx, "honeypot: switching off", "error", err)
		}
	}()
	if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
		s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
	}
	if err := s.restoreTail(ctx); err != nil {
		return err
	}
	poll := time.NewTicker(s.cfg.PollEvery)
	defer poll.Stop()
	again := time.NewTicker(applyEvery)
	defer again.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.kick:
			if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
				s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
			}
		case <-again.C:
			if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
				s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
			}
		case <-poll.C:
			if err := s.Poll(ctx); err != nil && ctx.Err() == nil {
				s.cfg.Log.WarnContext(ctx, "honeypot: read the trap log", "error", err)
			}
		}
	}
}
