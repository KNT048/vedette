package main

import (
	"context"
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify"
)

var (
	notifyMu       sync.Mutex
	notifyServices = map[*store.DB]*notify.Service{}
)

// unwiredUsers stands in for the user directory until core/auth provides notify.Users: nobody can be
// named as an approver (fail closed) and no one is counted as an email-code user.
// ponytail: replace with an adapter over core/auth (Users.Lookup, EmailCodeUsers).
type unwiredUsers struct{}

func (unwiredUsers) Lookup(context.Context, string) (notify.User, bool, error) {
	return notify.User{}, false, nil
}

func (unwiredUsers) EmailCodeUsers(context.Context) (int, error) { return 0, nil }

// newNotify builds the notify service once per database, so the handlers, the deliver job, the event
// subscriptions and the code mailer share it (the Zalo personal adapter keeps its signed-in session and its
// sign-in pause in memory). Events go to and come from deps.Bus.
// ponytail: no Users adapter over core/auth yet, no BaseURL (links use the default host name), no finding or
// device directory, no token recorder (response module): the service degrades without them.
// auth.Config.Mailer = newNotify(d).CodeMailer() waits for core/auth wiring.
func newNotify(d deps) *notify.Service {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	if s := notifyServices[d.DB]; s != nil {
		return s
	}
	c := notify.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: unwiredUsers{}, Log: d.Log, Modules: d.Reg, Clock: d.Clock}
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
func notifyJobs(d deps) []jobs.Job { return newNotify(d).Jobs() }
