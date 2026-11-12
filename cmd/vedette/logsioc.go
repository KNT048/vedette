package main

import (
	"context"
	"slices"
	"strings"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/response"
)

// logsFeeds is logs' Feeds port (L4, D-213): the listing of an address or a domain in the indicators of the feeds module, read in the box
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
	var l logs.Listing
	for _, s := range rec.Sightings {
		if !s.Enabled { // a feed that was switched off is not pulled and not pruned: its listings are stale
			continue
		}
		l.Feeds = append(l.Feeds, s.SourceName)
		l.Confidence = max(l.Confidence, s.Confidence)
		if s.Subdomains && kind == "domain" { // the feed lists the name with all of its subdomains (hagezi TIF, D-228)
			l.SubFeeds = append(l.SubFeeds, s.SourceName)
			l.SubConfidence = max(l.SubConfidence, s.Confidence)
		}
	}
	return l, len(l.Feeds) > 0, nil // an indicator that no enabled feed lists is not a hit
}

func (f logsFeeds) On() bool { return f.d.Reg == nil || f.d.Reg.Enabled("feeds") }

func (f logsFeeds) Listed(ctx context.Context) (bool, error) {
	svc, err := feedsService(*f.d)
	if err != nil {
		return false, err
	}
	return svc.Store().IOCListed(ctx)
}

// Subdomains says whether a switched-on feed lists names with all of their subdomains (D-228); logs skips the parent walk without one (D-425).
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
// response.go (#376, D-337); Connection stays empty (a set one would make the hit read as a connection read).
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
