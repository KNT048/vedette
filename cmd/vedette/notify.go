package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
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

// deviceVendorMax caps the vendor in a device label: notify refuses an incident title over 200 characters.
const deviceVendorMax = 48

// DeviceLabel names a newly discovered device for its unknown_device incident (walk 4: "A new unknown device appeared:
// switch"): the hostname, else the IP or else the MAC followed by the vendor when one is known ("192.168.18.254 (Sichuan
// AI-Link)"); the kind only when nothing else is known. The values come from the network: plainText cleans them.
func (a notifyDevices) DeviceLabel(ctx context.Context, assetID string) (string, bool, error) {
	refs, err := a.inv.DeviceRefs(ctx, []string{assetID})
	if err != nil {
		return "", false, err
	}
	r, ok := refs[assetID]
	if !ok {
		return "", false, nil
	}
	if r.Hostname != nil {
		if h := plainText(*r.Hostname, 160); h != "" {
			return h, true, nil
		}
	}
	id := r.MAC
	if _, err := netip.ParseAddr(r.IP); err == nil { // the inventory shows an em dash when the IP is unknown
		id = r.IP
	}
	if id == "" {
		return r.Display, true, nil
	}
	if v := plainText(r.Vendor, deviceVendorMax); v != "" {
		id += " (" + v + ")"
	}
	return id, true, nil
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

// testBaseURL is the test seam of D-173 (WP-30 slice 9b): the end-to-end box listens on loopback, where baseURL answers "" and notify refuses
// every approval request, so the box of `make e2e-real` answers http://127.0.0.1:<port> for its own listen address. Unexported, no flag, nil in the
// shipped binary: only a _test.go file sets it, so the production derivation above is the only one a real box ever runs.
var testBaseURL func(listen string) string

// boxBaseURL is baseURL, unless a test box has said otherwise for this listen address.
func boxBaseURL(hosts []string, listen string) string {
	if testBaseURL != nil {
		if u := testBaseURL(listen); u != "" {
			return u
		}
	}
	return baseURL(hosts, listen)
}

// hostForURL brackets an IPv6 literal.
func hostForURL(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

// notifyApproverLinks is notify's Config.ApproverLinks (D-191, notify INV-13): whether the person proved this address in My account, as the
// response module keeps it. d.Response is read when asked (response is built after notify); a response that does not exist yet is an error, so
// notify skips the approver (fail closed). The error never holds the address.
type notifyApproverLinks struct{ d *deps }

func (l notifyApproverLinks) Linked(ctx context.Context, userID string, ch channel.Type, address string) (bool, error) {
	if l.d.Response == nil {
		return false, errResponseNotReady
	}
	return l.d.Response.Linked(ctx, userID, string(ch), address)
}

// ChatLinkToken is notify's Config.LinkCodes (D-447): response makes the token of the confirm link sent to a Zalo personal approver.
func (l notifyApproverLinks) ChatLinkToken(ctx context.Context, userID string, ch channel.Type, address string) (token, name string, err error) {
	if l.d.Response == nil {
		return "", "", errResponseNotReady
	}
	return l.d.Response.ChatLinkToken(ctx, userID, string(ch), address)
}

// DropChatLink is the other half of notify's Config.LinkCodes (D-447): an approver removed or given another Zalo loses the old proof.
func (l notifyApproverLinks) DropChatLink(ctx context.Context, actor, userID string, ch channel.Type, address string) error {
	if l.d.Response == nil {
		return errResponseNotReady
	}
	return l.d.Response.DropChatLink(ctx, actor, userID, string(ch), address)
}

// newNotify builds the notify service once per database, so the handlers, the deliver job, the event
// subscriptions and the code mailer share it (the Zalo personal adapter keeps its signed-in session and its
// sign-in pause in memory). Events go to and come from deps.Bus. buildServices calls it first with the real
// *deps: Users, Zone and Devices read d.Auth, d.Core and d.Inventory when asked, so notify can exist before
// auth, which takes notify's code mailer.
// BoxAddrs is the box-address provider (d.HostNet): the appliance's own addresses, which core's container cannot see, so no webhook can
// point at the box (issue #62). The token recorder is the response module (notifyTokens, read lazily
// because response is built after notify).
// notifySMTPLoopback is set by the tests of this package only (notify_wiring_test.go): their fake SMTP servers, and the e2e box's,
// listen on 127.0.0.1, which notify refuses as an SMTP server (in a container loopback is core itself).
var notifySMTPLoopback bool

func newNotify(d *deps) *notify.Service {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	if s := notifyServices[d.DB]; s != nil {
		return s
	}
	c := notify.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: notifyUsers{d}, Log: d.Log, Clock: d.Clock,
		Zone: orgZone(d), BaseURL: d.BaseURL, Tokens: notifyTokens{d}, Decisions: responseDecisions{d}, BoxAddrs: machineAddrs(d), SelfAddrs: vedetteSelf(d),
		ApproverLinks: notifyApproverLinks{d}, LinkCodes: notifyApproverLinks{d}, SMTPLoopback: notifySMTPLoopback} // unknown only while a configured vedette-host has never answered (#157)
	if d.Inventory != nil {
		c.Devices = notifyDevices{d.Inventory}
	}
	c.Findings = notifyFindings{d} // d.Findings and the feeds store are built after notify: read when asked
	if d.Reg != nil {              // a nil *modreg.Registry inside the interface would not compare equal to nil, and OnChange would panic
		c.Modules = d.Reg
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

// firstAnswerWait is how long a caller of notifyBoxAddrs waits for vedette-host's first answer since core started (D-408). The host
// answers state/net in milliseconds; one that does not answer within it leaves the set unknown.
const firstAnswerWait = 2 * time.Second

// notifyBoxAddrs is notify's Config.BoxAddrs over the shared cache of what vedette-host reports (feeds and logs use it too). Once the
// host has answered it reads the last known set and never waits for the host (notify asks at every webhook connection and save); a
// stale set is refreshed in the background, and a host that does not answer leaves the previous set in place. Before a configured
// host's first answer it waits up to firstAnswerWait for that answer (D-408: else the first webhook save after a start is a 503 only
// because nothing had asked the host yet); still unknown (known=false), notify refuses every webhook save and connection until it is
// known (fail closed, #157). Without a host (nil cache) the set is empty and known: the container's own interfaces, which notify
// reads itself, are all the box has.
func notifyBoxAddrs(c *hostNetCache) func() ([]netip.Addr, bool) {
	return func() ([]netip.Addr, bool) {
		ps, known := c.SnapshotKnownWithin(firstAnswerWait)
		var out []netip.Addr
		for _, p := range ps {
			out = append(out, p.Addr())
		}
		return out, known
	}
}

// notifyJobs is the Jobs func of the notify entry in wiredModules: the "deliver" job.
func notifyJobs(d deps) []jobs.Job { return newNotify(&d).Jobs() }
