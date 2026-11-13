package main

import (
	"testing"

	"github.com/knt048/vedette/modules/notify"
)

// The titles are the ones modules/logs/authfail.go writes; the report tells the two log anomalies of the failed-login rule by them.
func TestIncidentTitles(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		kind  notify.IncidentKind
		title string
		want  string
	}{
		{notify.IncidentLogAnomaly, "5 failed logins from 45.155.205.233 on web-1 in 10 minutes", "failed_logins"},
		{notify.IncidentLogAnomaly, "A login from 45.155.205.233 was ACCEPTED after failed attempts on web-1", "login_accepted"},
		{notify.IncidentLogAnomaly, "web-1 sent 900 events of a kind it rarely sends", "anomaly"},
		{notify.IncidentTrap, "Someone touched the SSH trap", "trap"},
		{notify.IncidentBadAddress, "pc-1 reached a known-bad address", "bad_connection"},
		{notify.IncidentUnknownDevice, "A new unknown device appeared: cam-3", ""},
	} {
		if got := incidentKind(c.kind, c.title); got != c.want {
			t.Errorf("%s %q = %q, want %q", c.kind, c.title, got, c.want)
		}
	}
}
