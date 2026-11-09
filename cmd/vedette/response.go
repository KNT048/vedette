package main

import (
	"context"
	"errors"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/response"
)

// Adapters between the response module's ports and the modules that provide them. They live here because only the binary
// knows both sides (modules/response imports no other module, rules/modules.md).

// ---- core/auth -> response.Users ----

type responseUsers struct{ d *deps }

func (u responseUsers) Lookup(ctx context.Context, id string) (response.User, bool, error) {
	got, err := u.d.Auth.GetUser(ctx, id)
	if e, ok := apierr.As(err); ok && e.Status == 404 {
		return response.User{}, false, nil
	}
	if err != nil {
		return response.User{}, false, err
	}
	return response.User{ID: got.ID, Name: got.Name, Email: got.Email, Role: string(got.Role), TwoStep: got.TwofaMethod != "", Disabled: got.Disabled}, true, nil
}

// ---- notify -> response.Notifier and response.Webhooks ----

type responseNotifier struct {
	n   *notify.Service
	now func() time.Time
}

var channelNames = map[string]string{"slack": "Slack", "telegram": "Telegram", "zalo": "Zalo OA", "zalo-personal": "Zalo (personal)", "email": "Email", "webhook": "Webhook"}

func (r responseNotifier) Channels(ctx context.Context) ([]response.NotifyChannel, error) {
	v, err := r.n.Channels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.NotifyChannel, 0, len(v.Channels))
	for _, c := range v.Channels {
		label := channelNames[string(c.Type)]
		if c.Type == "slack" && c.Fields["label"] != "" {
			label = "Slack " + c.Fields["label"]
		}
		out = append(out, response.NotifyChannel{Type: string(c.Type), Label: label, Configured: c.Configured, Enabled: c.Enabled, Approvals: c.Approvals, Approvers: len(c.Approvers)})
	}
	return out, nil
}

// Message queues a short text as an incident notice: every enabled channel whose minimum severity it meets gets it.
func (r responseNotifier) Message(ctx context.Context, id, title, text string) error {
	return r.n.Publish(ctx, notify.Notice{ID: id, Kind: notify.KindIncident, Severity: notify.Medium, Title: title, What: text, At: r.now()})
}

type responseWebhooks struct{ n *notify.Service }

func (w responseWebhooks) Target(ctx context.Context) (response.WebhookTarget, bool, error) {
	u, key, ok, err := w.n.WebhookTarget(ctx)
	return response.WebhookTarget{URL: u, SigningKey: key}, ok, err
}

// ---- inventory and findings -> response.Directory ----

type responseDirectory struct {
	inv *inventory.Service
	fnd *findings.Service
}

func (r responseDirectory) Device(ctx context.Context, id string) (response.DeviceInfo, bool, error) {
	d, err := r.inv.Device(ctx, id)
	if errors.Is(err, inventory.ErrNotFound) {
		return response.DeviceInfo{}, false, nil
	}
	if err != nil {
		return response.DeviceInfo{}, false, err
	}
	return deviceInfo(d), true, nil
}

// DevicesOfKind lists every inventory device of the kinds (the gateways: router, firewall), uncapped (inventory.DevicesOfKind, not
// Devices: that one stops at 2000 rows, newest first, and would drop the oldest device, the gateway). An unreadable inventory is an
// error: response refuses the action rather than go on without them.
func (r responseDirectory) DevicesOfKind(ctx context.Context, kinds ...string) ([]response.DeviceInfo, error) {
	l, err := r.inv.DevicesOfKind(ctx, kinds)
	if err != nil {
		return nil, err
	}
	out := make([]response.DeviceInfo, 0, len(l))
	for _, d := range l {
		i := response.DeviceInfo{ID: d.ID, IP: d.IP, Kind: d.Kind}
		if d.IP == "—" { // unknown address
			i.IP = ""
		}
		if i.Name = i.IP; d.Hostname != nil && *d.Hostname != "" {
			i.Name = *d.Hostname
		}
		if d.MAC != nil {
			i.MAC = *d.MAC
		}
		out = append(out, i)
	}
	return out, nil
}

func deviceInfo(d inventory.Device) response.DeviceInfo {
	out := response.DeviceInfo{ID: d.ID, IP: d.IP, Kind: d.Kind, Approved: d.Approved}
	if d.IP == "—" { // unknown address
		out.IP = ""
	}
	out.Name = out.IP
	if d.Hostname != nil && *d.Hostname != "" {
		out.Name = *d.Hostname
	}
	if d.MAC != nil {
		out.MAC = *d.MAC
	}
	if d.Vendor != nil {
		out.Vendor = d.Vendor.Value
	}
	out.Seen, _ = time.Parse(time.RFC3339, d.FirstSeen)
	return out
}

// Finding answers the fields a trigger needs. Every finding the box holds comes from the exploited-vulnerability list
// (findings matches the CISA KEV list only), so kev is true; the firewall virtual IP of the trigger is not known without a
// firewall read (part 13b) and stays empty.
func (r responseDirectory) Finding(ctx context.Context, id string) (response.FindingInfo, bool, error) {
	rec, err := r.fnd.Get(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return response.FindingInfo{}, false, nil
	}
	if err != nil {
		return response.FindingInfo{}, false, err
	}
	return response.FindingInfo{ID: rec.ID, AssetID: rec.AssetID, CVE: rec.CVE, Severity: string(rec.Severity), Status: string(rec.Status), KEV: true}, true, nil
}

// ---- core/conn/write -> response.Executor ----

// responseExecutor is the only holder of the writer (FORBID-1): it turns a step of an approved item into core/conn/write's Step and
// the writer's answer into response's. Nothing else in the binary names the writer package.
type responseExecutor struct{ w *write.Writer }

func (e responseExecutor) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	r := e.w.Do(ctx, write.Step{ConnectionID: s.ConnectionID, ConnFP: s.ConnFP, ByIdentity: s.ByIdentity, ConnIdentity: s.ConnIdentity, Phase: s.Phase, Tool: s.Tool, Lines: s.Lines, Method: s.Method, URL: s.URL,
		Body: s.Body, Headers: s.Headers, Args: s.Args})
	return response.DeviceResult{Status: response.StepStatus(r.Status), Detail: r.Detail, Output: r.Output}, nil
}

// newResponse builds the response service. serve calls it once, in buildServices, after the services it reads (core/auth, notify,
// inventory, findings, core/conn). Device actions run through core/conn/write: an approved item reaches its device over the
// connection, with a check before and a read-back (D-94, D-95).
func newResponse(d *deps) (*response.Service, error) {
	cfg, err := responseConfig(d)
	if err != nil {
		return nil, err
	}
	svc, err := response.New(cfg)
	if err != nil {
		return nil, err
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus) // handlers ignore events while the module is off
	}
	return svc, nil
}

// responseConfig is the configuration of the response service: every port wired to the module that provides it.
func responseConfig(d *deps) (response.Config, error) {
	n := newNotify(d)
	cfg := response.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: responseUsers{d}, Log: d.Log, Clock: d.Clock,
		Notifier: responseNotifier{n: n, now: d.Clock}, Webhooks: responseWebhooks{n}, Directory: responseDirectory{inv: d.Inventory, fnd: d.Findings}}
	if d.Conn != nil { // a nil *conn.Service inside the interface would not compare equal to nil
		cfg.Connections = responseConnections{d.Conn}
		w, err := write.New(write.Config{Conns: d.Conn})
		if err != nil {
			return cfg, err
		}
		cfg.Executor = responseExecutor{w}
	}
	if d.Reg != nil {
		cfg.Modules = d.Reg
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Bus = d.Bus
	}
	return cfg, nil
}

// responseJobs is the Jobs func of the response entry in wiredModules: the "evaluate" and "sweep" jobs.
func responseJobs(d deps) []jobs.Job { return d.Response.Jobs() }
