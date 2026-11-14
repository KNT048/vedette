package exposure

import "testing"

// INV-22 (D-560): a port the previous scan saw and this one did not is "not seen", and still counts as open; the second scan that
// misses it makes it closed; a scan that sees it again leaves a normal row and no "opened" noise.
func TestNotSeen_OneMissIsNotClosed_TwoMissesAre(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := scanReady(t, e)
	full, gone := sampleContent(), sampleContent()
	gone.Ports = gone.Ports[:2] // the smtp port on ipB is missed
	run := &fakeRunner{}
	e.svc.SetRunner(run)
	scan := func(c Content) Snapshot {
		t.Helper()
		e.advance(day)
		run.content = c
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", v.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.svc.SnapshotOf(e.ctx(), v.ID, s.Date)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	notSeen := func(s Snapshot) int {
		n := 0
		for _, p := range s.Ports {
			if p.LastSeen != "" {
				n++
			}
		}
		return n
	}

	d1 := scan(full)
	d2 := scan(gone)
	if notSeen(d1) != 0 || notSeen(d2) != 1 || len(d2.Ports) != 3 || d2.Counts.Ports != 3 {
		t.Fatalf("after one miss: %+v counts %+v", d2.Ports, d2.Counts)
	}
	if last := d2.Ports[2]; last.Port != 25 || last.LastSeen != d1.Date {
		t.Fatalf("the carried port = %+v, want port 25 last seen %s", last, d1.Date)
	}
	df, err := e.svc.Diff(e.ctx(), v.ID, d1.Date, d2.Date)
	if err != nil || len(df.Removed) != 0 || len(df.Changed) != 1 || df.Changed[0].To != PortNotSeen {
		t.Fatalf("diff after one miss: %+v %v", df, err)
	}

	d3 := scan(gone)
	if notSeen(d3) != 0 || len(d3.Ports) != 2 || d3.Counts.Ports != 2 {
		t.Fatalf("after two misses: %+v", d3.Ports)
	}
	df, err = e.svc.Diff(e.ctx(), v.ID, d2.Date, d3.Date)
	if err != nil || len(df.Removed) != 1 || df.Removed[0].Label != ipB+":25" || len(df.Added) != 0 {
		t.Fatalf("diff after two misses: %+v %v", df, err)
	}
}

func TestNotSeen_SeenAgainIsNormalAndNotNew(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := scanReady(t, e)
	full, gone := sampleContent(), sampleContent()
	gone.Ports = gone.Ports[:2]
	run := &fakeRunner{}
	e.svc.SetRunner(run)
	var dates []string
	for _, c := range []Content{full, gone, full} {
		e.advance(day)
		run.content = c
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", v.ID)
		if err != nil {
			t.Fatal(err)
		}
		dates = append(dates, s.Date)
	}
	last, err := e.svc.SnapshotOf(e.ctx(), v.ID, dates[2])
	if err != nil || len(last.Ports) != 3 || last.Ports[2].LastSeen != "" {
		t.Fatalf("seen again: %+v %v", last.Ports, err)
	}
	df, err := e.svc.Diff(e.ctx(), v.ID, dates[1], dates[2])
	if err != nil || len(df.Added)+len(df.Removed)+len(df.Changed) != 0 {
		t.Fatalf("diff when seen again: %+v %v", df, err)
	}
}
