package write_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/conn/cliban"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/write"
)

// D-358: after a refused SSH line, the line that leaves configuration mode without saving goes out once, then the session closes.

func refuseBad(line string) string {
	if strings.HasPrefix(line, "bad") {
		return "% Invalid input detected at '^' marker."
	}
	return ""
}

// The leave lines load, are plain lines a template could hold, and none of them saves: an abort form where a vendor has one.
func TestLeaveRulesLoad(t *testing.T) {
	t.Parallel()
	lines, err := write.LeaveRulesForTest()
	if err != nil || len(lines) == 0 {
		t.Fatalf("leave.json: %v %v", lines, err)
	}
	rules, err := cliban.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if hit := cliban.Hit(cliban.Lines(l), rules.Everywhere); hit != "" {
			t.Errorf("leave line %q is a refused command", l)
		}
		for _, saves := range []string{"next", "commit", "write", "copy", "save", "exit", "quit", "yes"} {
			if strings.HasPrefix(strings.ToLower(l), saves) {
				t.Errorf("leave line %q may save or answer a question", l)
			}
		}
	}
}

// The nearest line that entered configuration mode picks the leave line; no such line, nothing.
func TestLeaveLineFollowsTheNearestEnterLine(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		sent []string
		want string
	}{
		{[]string{"terminal length 0", "configure terminal", "interface Gi1/0/5"}, "end"},
		{[]string{"no page", "Conf  T", "interface 1/1/5"}, "end"},
		{[]string{"config firewall vip", `edit "web"`}, "abort"},
		{[]string{"config firewall address", "edit x", "next", "end", "config firewall addrgrp", "edit g"}, "abort"},
		{[]string{"terminal length 0"}, ""},
		{[]string{"configure"}, ""}, // ArubaOS-Switch and Junos: no rule, nothing is typed (D-358)
		{[]string{"configuration"}, ""},
		{nil, ""},
	} {
		if got := write.LeaveLineForTest(c.sent); got != c.want {
			t.Errorf("%q: leave %q, want %q", c.sent, got, c.want)
		}
	}
}

// IOS-like: a refused line inside configuration mode is followed by end, and nothing else; the outcome stays unknown.
func TestWriterLeavesConfigurationModeAfterARefusedLine(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: refuseBad})
	c := r.sw(f)
	res := r.do(sshStep(c, write.PhaseRun, "terminal length 0", "configure terminal", "interface Gi1/0/5", "bad shutdown", "end"))
	wantStatus(t, res, write.StatusUnknown)
	if got := strings.Join(f.Lines(), "|"); got != "terminal length 0|configure terminal|interface Gi1/0/5|bad shutdown|end" {
		t.Fatalf("lines %s", got)
	}
	if !strings.Contains(res.Detail, "Invalid input") {
		t.Errorf("detail %q", res.Detail)
	}

	// FortiOS-like: abort, never next or end, which would save the half-typed entry. The rollback is a write too.
	g := conntest.NewSSH(t, conntest.SSHOpts{Prompt: "FGT", Respond: refuseBad})
	r2 := newRig(t)
	fc := r2.sw(g)
	res = r2.do(sshStep(fc, write.PhaseRollback, "config firewall vip", `edit "web"`, "bad status enable", "next", "end"))
	wantStatus(t, res, write.StatusUnknown)
	if got := strings.Join(g.Lines(), "|"); got != `config firewall vip|edit "web"|bad status enable|abort` {
		t.Fatalf("lines %s", got)
	}
}

// Nothing is typed after a refused line 0 (nothing was entered yet), after a refused enter line, without a line that entered
// configuration mode, or in a read.
func TestWriterSendsNoLeaveLineWhenNothingWasEntered(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "configure terminal" {
			return refuseBad("bad")
		}
		return refuseBad(line)
	}})
	c := r.sw(f)
	for _, x := range []struct {
		lines []string
		want  string
	}{
		{[]string{"bad configure terminal", "interface Gi1/0/5", "end"}, "bad configure terminal"},
		{[]string{"terminal length 0", "configure terminal", "interface Gi1/0/5", "end"}, "terminal length 0|configure terminal"},
		{[]string{"terminal length 0", "bad interface", "end"}, "terminal length 0|bad interface"},
	} {
		n := len(f.Lines())
		wantStatus(t, r.do(sshStep(c, write.PhaseRun, x.lines...)), write.StatusUnknown)
		if got := strings.Join(f.Lines()[n:], "|"); got != x.want {
			t.Fatalf("%q: the device received %s, want %s", x.lines, got, x.want)
		}
	}
	n := len(f.Lines())
	wantStatus(t, r.do(sshStep(c, write.PhaseVerify, "show running-config", "bad show")), write.StatusFailed)
	if got := strings.Join(f.Lines()[n:], "|"); got != "show running-config|bad show" {
		t.Fatalf("read: %s", got)
	}
}

// A device that never answers the leave line does not hold the step past the leave budget.
func TestWriterLeaveLineHasItsOwnDeadline(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "end" {
			<-release // no prompt comes back
		}
		return refuseBad(line)
	}})
	c := r.sw(f)
	r.w.SetLeaveBudgetForTest(300 * time.Millisecond)
	start := time.Now()
	res := r.do(sshStep(c, write.PhaseRun, "configure terminal", "interface Gi1/0/5", "bad shutdown", "end"))
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the step took %s", d)
	}
	wantStatus(t, res, write.StatusUnknown)
	if got := strings.Join(f.Lines(), "|"); got != "configure terminal|interface Gi1/0/5|bad shutdown|end" {
		t.Fatalf("lines %s", got)
	}
}

func TestWriterLeaveBudget(t *testing.T) {
	t.Parallel()
	if write.LeaveBudget != 5*time.Second {
		t.Fatalf("LeaveBudget = %s", write.LeaveBudget)
	}
}
