package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/pki"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

// sensorBackend is the one sensorlink.Backend of core (D-141): the passive half (Config, Observations, PassiveHeartbeat) from
// sensor-passive and the active half (Jobs, JobRunning, JobResult, ActiveHeartbeat) from the Dispatcher. Both are embedded, so every
// method of either is promoted as it is: the Server finds sensorlink.ResultRejector (the Dispatcher's JobResultRejected) by type
// assertion on this value, and a wrapper that restated the seven methods would hide it. A method added to both types at once makes
// the name ambiguous and the compile fails, instead of one half winning quietly.
type sensorBackend struct {
	*sensorpassive.Service
	*sensoractive.Dispatcher
}

var (
	_ sensorlink.Backend        = sensorBackend{}
	_ sensorlink.ResultRejector = sensorBackend{}
)

// sensorModule is the module a role talks to: the switch behind module_off (D-111 (4)).
func sensorModule(r sensorlink.Role) string {
	if r == sensorlink.Active {
		return "sensor-active"
	}
	return "sensor-passive"
}

// sensorLink is core's second listener, for the two sensor containers (D-109): mutual TLS, TLS 1.3, its own CA.
type sensorLink struct {
	srv *http.Server
	ln  net.Listener
}

// openSensorLink opens the PKI once, issues the server leaf and the two bundles into creds, and only then listens on addr (D-110 (4)):
// a sensor that finds its bundle never meets a closed port, and a core that cannot write the bundles does not listen at all. It sets
// d.Authority and d.SensorCreds, which the daily renew job (coreJobs) reads, so call it before the jobs are added.
func openSensorLink(ctx context.Context, d *deps, addr, creds string) (*sensorLink, error) {
	if d.SensorPassive == nil || d.SensorDispatcher == nil {
		return nil, errors.New("sensor link: the sensor services are not built")
	}
	auth, err := pki.Open(ctx, pki.Options{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Now: d.Clock, Log: d.Log})
	if err != nil {
		return nil, fmt.Errorf("sensor link: %w", err)
	}
	if err := auth.Start(ctx, creds); err != nil {
		d.Log.ErrorContext(ctx, "sensor link: the credentials folder could not be written; check the volume and its owner", "dir", creds, "error", err)
		return nil, fmt.Errorf("sensor link: credentials for the sensors: %w", err)
	}
	d.Authority, d.SensorCreds = auth, creds
	o := sensorlink.Options{Identity: auth, Backend: sensorBackend{d.SensorPassive, d.SensorDispatcher}, Now: d.Clock, Log: d.Log}
	if d.Reg != nil {
		o.ModuleOn = func(r sensorlink.Role) bool { return d.Reg.Enabled(sensorModule(r)) }
	}
	srv, err := sensorlink.NewServer(o)
	if err != nil {
		return nil, fmt.Errorf("sensor link: %w", err)
	}
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sensor link: listen: %w", err)
	}
	hs := srv.HTTPServer(addr)
	hs.Handler = limitWrites(hs.Handler, store.RequestWriteWait)
	return &sensorLink{srv: hs, ln: ln}, nil
}

// limitWrites gives every request the database writer wait limit d (D-246): past it a write answers store.ErrBusy, which the
// sensor backends answer with 503 store_busy, instead of holding the sensor's request for its whole deadline. It sits here
// because core/sensorlink imports nothing of core.
func limitWrites(next http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(store.LimitWriteWait(r.Context(), d)))
	})
}

// Addr is the address the listener is bound to.
func (l *sensorLink) Addr() string { return l.ln.Addr().String() }

// serve serves until Close. The server takes its certificate from the Authority at every handshake (GetCertificate), so the daily
// renewal needs no restart.
func (l *sensorLink) serve() error {
	return l.srv.ServeTLS(sensorlink.PendingListener(l.ln), "", "")
}

// close cuts the connections at once: a long poll would otherwise hold the shutdown for its whole wait, and a sensor retries by design.
func (l *sensorLink) close() error { return l.srv.Close() }

// renewEvery is how often the certificates are looked at: Renew replaces only what has a third of its life or less left (D-110 (3)).
const renewEvery = 24 * time.Hour

// coreJobs is the Jobs func of the core entry in wiredModules: the daily renewal of the sensor certificates, when the link exists.
func coreJobs(d deps) []jobs.Job {
	if d.Authority == nil {
		return nil
	}
	return []jobs.Job{{Module: "core", Name: "sensor-cert-renew", Every: renewEvery, Run: func(ctx context.Context) error {
		return d.Authority.Renew(ctx, d.SensorCreds)
	}}}
}
