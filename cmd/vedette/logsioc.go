package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/response"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

// logsFeeds is logs' Feeds port: the listing of an address or a domain in the indicators of the feeds module, read in the box
// (nothing leaves it). The feeds module off answers logs.ErrFeedsOff, so no hit is made while it is off (PRE-3, SYS-5). A value that is
// not a public address or a name that can be listed (feeds.IOCKey) is not listed. The service is looked up on each call because it is
// built after logs (feeds needs the inventory).
type logsFeeds struct{ d *deps }

func (f logsFeeds) Lookup(ctx context.Context, kind, value string) (logs.Listing, bool, error) {
	if f.d.Reg != nil && !f.d.Reg.Enabled("feeds") {
		return logs.Listing{}, false, logs.ErrFeedsOff
	}
	key, ok := feeds.IOCKey(kind, value)
	if !ok {
		return logs.Listing{}, false, nil
	}
	svc, err := feedsService(*f.d)
	if err != nil {
		return logs.Listing{}, false, err
	}
	rec, found, err := svc.Store().IOCLookup(ctx, kind, key)
	if err != nil || !found {
		return logs.Listing{}, false, err
	}
	l := listingOf(rec, kind)
	return l, len(l.Feeds) > 0, nil // an indicator that no enabled feed lists is not a hit
}

// listingOf is what the switched-on feeds say about an indicator: their plain names (stored on the hit; logs adds a list's credit where
// it shows the hit, Credits), and how sure they are together (feeds.IOCConfidence:
// each feed's rating, rising with independent feeds) with whether one lists it as a command-and-control server. The same for the
// feeds that list a domain with all of its subdomains (hagezi TIF). A feed that was switched off is not pulled and not pruned: its
// listings are stale and not counted.
func listingOf(rec feeds.IOCRecord, kind string) logs.Listing {
	var l logs.Listing
	var on, sub []feeds.IOCSighting
	for _, s := range rec.Sightings {
		if !s.Enabled {
			continue
		}
		on = append(on, s)
		l.Feeds = append(l.Feeds, s.SourceName)
		if s.Subdomains && kind == "domain" {
			sub = append(sub, s)
			l.SubFeeds = append(l.SubFeeds, s.SourceName)
		}
	}
	l.Confidence, l.C2 = feeds.IOCConfidence(on)
	l.SubConfidence, l.SubC2 = feeds.IOCConfidence(sub)
	return l
}

func (f logsFeeds) On() bool { return f.d.Reg == nil || f.d.Reg.Enabled("feeds") }

func (f logsFeeds) Listed(ctx context.Context) (bool, error) {
	svc, err := feedsService(*f.d)
	if err != nil {
		return false, err
	}
	return svc.Store().IOCListed(ctx)
}

// Credits is the name each feed whose terms ask for credit with a time is shown by (feeds.Store.IOCCredits: Spamhaus DROP with its last
// good pull); none while the feeds module is off.
func (f logsFeeds) Credits(ctx context.Context) (map[string]string, error) {
	if !f.On() {
		return nil, nil
	}
	svc, err := feedsService(*f.d)
	if err != nil {
		return nil, err
	}
	return svc.Store().IOCCredits(ctx)
}

// Subdomains says whether a switched-on feed lists names with all of their subdomains; logs skips the parent walk without one.
func (f logsFeeds) Subdomains(ctx context.Context) (bool, error) {
	if !f.On() {
		return false, nil
	}
	svc, err := feedsService(*f.d)
	if err != nil {
		return false, err
	}
	return svc.Store().IOCSubdomainsOn(ctx)
}

// logsIocEvidence is the adapter for response's Evidence.IocHit (EvidencePorts): the hit with this id, as the digest shows it, in the shape
// response wants. Logs off answers "not found" (the evidence does not exist while the module is off). Wired as cfg.Evidence.IocHit in
// response.go; Connection stays empty (a set one would make the hit read as a connection read).
func logsIocEvidence(svc *logs.Service, on func() bool) func(ctx context.Context, id string) (response.EvidenceRef, bool, error) {
	return func(ctx context.Context, id string) (response.EvidenceRef, bool, error) {
		if svc == nil || !on() {
			return response.EvidenceRef{}, false, nil
		}
		h, found, err := svc.IocHit(ctx, id)
		if err != nil || !found {
			return response.EvidenceRef{}, false, err
		}
		name := h.SrcIP
		if h.AssetName != nil && *h.AssetName != "" {
			name = *h.AssetName + " (" + h.SrcIP + ")"
		}
		return response.EvidenceRef{ID: h.ID, Summary: name + " connected to " + h.Dest + ", listed by " + strings.Join(slices.Clone(h.Feeds), ", "), Relates: []string{h.SrcIP, h.Dest}}, true, nil
	}
}

// logsMirror is sensor-passive's MirrorMatcher: the metadata a sensor read on a mirror port goes to the logs module's bad-address
// matching (logs.MatchMirror), which stores only the matches. With the logs module off nothing is matched and nothing is stored
// (SYS-5); with the feeds module off logs makes no lookup (PRE-3). The logs service is looked up on each call: it is built
// once per database, and the sensor link only opens after every service exists.
func logsMirror(d deps) sensorpassive.MirrorMatcher {
	return func(ctx context.Context, items []sensorlink.MetadataItem) error {
		if d.Reg != nil && !d.Reg.Enabled("logs") {
			return nil
		}
		svc := logsService(d)
		if svc == nil {
			return nil
		}
		in := make([]logs.MirrorItem, 0, len(items))
		for _, it := range items {
			src, err := netip.ParseAddr(it.Src)
			if err != nil {
				continue
			}
			in = append(in, logs.MirrorItem{Kind: it.Kind, At: it.At, Src: src, Dest: it.Dest})
		}
		return svc.MatchMirror(ctx, in)
	}
}
