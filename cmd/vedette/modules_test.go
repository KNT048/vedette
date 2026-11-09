package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules"
)

// Migrations run in wiredModules order, so a module whose tables reference another module's must
// come after it. The order is checked against the manifests' depends lists.
func TestWiredModulesFollowDependencies(t *testing.T) {
	t.Parallel()
	manifests, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]modreg.Manifest{}
	for _, m := range manifests {
		byID[m.ID] = m
	}
	wired := wiredModules()
	if len(wired) == 0 || wired[0].ID != "core" {
		t.Fatalf("wiredModules must start with core, got %v", ids(wired))
	}
	pos := map[string]int{}
	for i, w := range wired {
		m, ok := byID[w.ID]
		if !ok {
			t.Fatalf("wired module %q has no modules/%s/MANIFEST.yaml", w.ID, w.ID)
		}
		if m.Component {
			t.Fatalf("wired module %q is a component, not a module", w.ID)
		}
		if _, dup := pos[w.ID]; dup {
			t.Fatalf("module %q is wired twice", w.ID)
		}
		for _, dep := range m.Depends {
			if _, ok := pos[dep]; !ok {
				t.Errorf("module %q depends on %q, which is not wired before it (order %v)", w.ID, dep, ids(wired))
			}
		}
		pos[w.ID] = i
	}
}

func TestAddJobs(t *testing.T) {
	t.Parallel()
	run := func(context.Context) error { return nil }
	tests := []struct {
		name    string
		jobs    []jobs.Job
		wantErr string
	}{
		{name: "own module", jobs: []jobs.Job{{Module: "feeds", Name: "pull-kev", Every: time.Hour, Run: run}}},
		{name: "other module", jobs: []jobs.Job{{Module: "core", Name: "pull-kev", Every: time.Hour, Run: run}}, wantErr: `module feeds registers job "pull-kev" for module "core"`},
		{name: "invalid job", jobs: []jobs.Job{{Module: "feeds", Name: "pull-kev", Run: run}}, wantErr: "jobs of feeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sched := jobs.New(slog.New(slog.DiscardHandler), allOn{}, nil)
			var got deps
			wired := []moduleWiring{
				{ID: "core"},
				{ID: "feeds", Jobs: func(d deps) []jobs.Job { got = d; return tt.jobs }},
			}
			d := deps{Clock: time.Now}
			err := addJobs(sched, d, wired)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("addJobs: %v", err)
				}
				if got.Clock == nil {
					t.Fatal("Jobs func did not receive deps")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("addJobs error = %v, want containing %q", err, tt.wantErr)
			}
			if tt.name == "invalid job" && !errors.Is(err, jobs.ErrInvalid) {
				t.Fatalf("addJobs error = %v, want wrapping jobs.ErrInvalid", err)
			}
		})
	}
}

func ids(w []moduleWiring) []string {
	out := make([]string, len(w))
	for i, x := range w {
		out[i] = x.ID
	}
	return out
}
