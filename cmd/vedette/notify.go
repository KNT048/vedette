package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
)

var (
	notifyMu       sync.Mutex
	notifyServices = map[*store.DB]*notify.Service{}
)

// notifyUsers implements notify.Users over core/auth: approvers are named by user id, and the email-code count
// is the number of active accounts whose two-step method is "email" (INV-9). auth is read through deps at call
// time because notify is built before auth (auth takes notify's code mailer, see buildServices).
type notifyUsers struct{ d *deps }

func (u notifyUsers) Lookup(ctx context.Context, id string) (notify.User, bool, error) {
	got, err := u.d.Auth.GetUser(ctx, id)
	var ae *apierr.Error
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return notify.User{}, false, nil
	}
	if err != nil {
		return notify.User{}, false, err
	}
	return notify.User{ID: got.ID, Email: got.Email, Role: string(got.Role), Active: !got.Disabled}, true, nil
}

func (u notifyUsers) EmailCodeUsers(ctx context.Context) (int, error) {
	all, err := u.d.Auth.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range all {
		if !x.Disabled && x.TwofaMethod == "email" {
			n++
		}
	}
	return n, nil
}

// notifyDevices implements notify.DeviceDirectory over the inventory: the name a person gave the device
// (hostname, else the IP, else the kind of device), so a notice says "FortiGate" and not an asset id.
type notifyDevices struct{ inv *inventory.Service }

func (a notifyDevices) DeviceName(ctx context.Context, assetID string) (string, bool, error) {
	refs, err := a.inv.DeviceRefs(ctx, []string{assetID})
	if err != nil {
		return "", false, err
	}
	r, ok := refs[assetID]
	if !ok {
		return "", false, nil
	}
	if r.Hostname != nil && *r.Hostname != "" {
		return *r.Hostname, true, nil
	}
	if _, err := netip.ParseAddr(r.IP); err == nil { // the inventory shows an em dash when the IP is unknown
		return r.IP, true, nil
	}
	return r.Display, true, nil
}

// orgZone is notify's Zone: the organization time zone of core's general settings, read at every use so a change
// applies at once. A failed read answers "" and notify uses its default zone for that call.
func orgZone(d *deps) func(context.Context) string {
	return func(ctx context.Context) string {
		z, err := d.Core.OrgTimeZone(ctx)
		if err != nil {
			d.Log.WarnContext(ctx, "notify: reading the organization time zone failed; using the default", "error", err)
			return ""
		}
		return z
	}
}

// baseURL is the address people open Vedette at: https://<first -hosts name, else the first certificate name>,
// with the listen port when it is not 443. hosts is what transport returned (-hosts, else the certificate's
// names). Wildcards and loopback names cannot be reached from another machine and are skipped. Empty when the
// box listens on loopback only (dev) or has no usable name: notify then sends no links and refuses approval
// requests (a link that approves an action must point at the real box).
func baseURL(hosts []string, listen string) string {
	if loop, err := isLoopback(listen); err != nil || loop {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") || strings.EqualFold(h, "localhost") {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil && a.Unmap().IsLoopback() {
			continue
		}
		if port == "443" {
			return "https://" + hostForURL(h)
		}
		return "https://" + net.JoinHostPort(h, port)
	}
	return ""
}

// hostForURL brackets an IPv6 literal.
func hostForURL(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

// newNotify builds the notify service once per database, so the handlers, the deliver job, the event
// subscriptions and the code mailer share it (the Zalo personal adapter keeps its signed-in session and its
// sign-in pause in memory). Events go to and come from deps.Bus. buildServices calls it first with the real
// *deps: Users, Zone and Devices read d.Auth, d.Core and d.Inventory when asked, so notify can exist before
// auth, which takes notify's code mailer.
// ponytail: no finding directory (Emily's, Config.Findings) and no token recorder (response module, WP-13), no BoxAddrs (WP-08): the
// service degrades without them.
func newNotify(d *deps) *notify.Service {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	if s := notifyServices[d.DB]; s != nil {
		return s
	}
	c := notify.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: notifyUsers{d}, Log: d.Log, Modules: d.Reg, Clock: d.Clock,
		Zone: orgZone(d), BaseURL: d.BaseURL}
	if d.Inventory != nil {
		c.Devices = notifyDevices{d.Inventory}
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		c.Bus = d.Bus
	}
	svc, err := notify.New(c)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus) // handlers ignore events while the module is off; the box lives as long as the process
	}
	notifyServices[d.DB] = svc
	return svc
}

// notifyJobs is the Jobs func of the notify entry in wiredModules: the "deliver" job.
func notifyJobs(d deps) []jobs.Job { return newNotify(&d).Jobs() }
