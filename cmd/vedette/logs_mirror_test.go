package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/logs"
)

// Mirror-port metadata on the real wiring, with no log source declared: what the sensor posts (POST /metadata, here the Backend
// call the sensor link makes after it checked the body) reaches the logs module's bad-address matching through sensor-passive. A
// DNS query for a name a feed lists is a hit seen on the mirror port and opens a bad-address incident; a clean name and a flow to a
// documentation address make nothing, and nothing but the hit is stored. With the logs module off the same batch makes nothing.
func TestWiringMirrorMetadataRaisesABadAddressIncidentWithoutASyslogSource(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	ctx := t.Context()
	s.setModule("feeds", true)
	s.setModule("logs", true)
	s.setModule("sensor-passive", true)
	var feedID string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id FROM feeds_source ORDER BY id LIMIT 1`).Scan(&feedID); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES ('ioc-m1', 'domain', 'bad-site.net', ?1, ?1)`, stamp); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES ('ioc-m1', ?1, ?2, 0.9)`, feedID, stamp)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var got []logs.BadAddressEvent
	s.d.Bus.Subscribe(logs.EventBadAddress, func(_ context.Context, e events.Event) error {
		got = append(got, e.Data.(logs.BadAddressEvent))
		return nil
	})
	svc := logsService(*s.d)
	if v, err := svc.Sources(ctx); err != nil || len(v.Sources) != 0 {
		t.Fatalf("sources %+v %v: the test needs none", v.Sources, err)
	}
	be := sensorBackend{s.d.SensorPassive, s.d.SensorDispatcher}
	now := time.Now().UTC()
	req := &sensorlink.MetadataRequest{Items: []sensorlink.MetadataItem{
		{Kind: sensorlink.MetaDNS, At: now, Src: "10.0.0.5", Dest: "bad-site.net"},
		{Kind: sensorlink.MetaDNS, At: now, Src: "10.0.0.5", Dest: "www.example.com"},
		{Kind: sensorlink.MetaFlow, At: now, Src: "10.0.0.5", Dest: "198.51.100.7"},
	}}
	if err := be.Metadata(ctx, req); err != nil {
		t.Fatal(err)
	}
	hits, err := svc.IocHits(ctx, now.Add(-time.Hour), 0)
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits %+v %v, want 1", hits, err)
	}
	if h := hits[0]; h.SrcIP != "10.0.0.5" || h.Dest != "bad-site.net" || h.SeenVia != "span_dns" {
		t.Fatalf("hit %+v", h)
	}
	if len(got) != 1 || !strings.Contains(got[0].What, "Seen on the mirror port") {
		t.Fatalf("bad-address events %+v", got)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'bad_address' AND status <> 'resolved'`); n != 1 {
		t.Fatalf("%d open bad-address incidents, want 1", n)
	}

	s.setModule("logs", false)
	req.Items[0].Src = "10.0.0.6"
	if err := be.Metadata(ctx, req); err != nil {
		t.Fatal(err)
	}
	if hits, err := svc.IocHits(ctx, now.Add(-time.Hour), 0); err != nil || len(hits) != 1 {
		t.Fatalf("with logs off: %+v %v", hits, err)
	}
}
