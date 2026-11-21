package feeds

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Vendor exploitation claims: what Microsoft, Cisco and Fortinet themselves say about exploitation of their products' CVEs. Each
// claim becomes one feeds_signal row (kind exploited, source = the feed), qualifying at once: a vendor stating it is enough. The box
// reads the whole of what each vendor publishes, never one CVE it holds: Microsoft's list of the CVEs it flags "Exploited: Yes",
// and every Cisco and Fortinet advisory the vendor published or changed (each vendor's advisory feed), each
// advisory's CSAF document read for its exploitation statement. Every box sends the same requests, so they say nothing about the
// devices it watches. Only facts are kept: the CVE id, the date of the claim, the advisory's link and its id.

// The built-in vendor feeds.
const (
	msrcFeedID     = "msrc"
	ciscoFeedID    = "cisco-psirt"
	fortinetFeedID = "fortinet-psirt"
)

// The decoders of the vendor feeds.
const (
	DecoderMSRC     Decoder = "msrc"           // parseMSRCExploited: the Security Update Guide's CVEs with exploited = Yes
	DecoderCisco    Decoder = "cisco-psirt"    // parseCiscoFeed, then parseCSAF of each advisory (ciscoClaims)
	DecoderFortinet Decoder = "fortinet-psirt" // parseFortiGuardFeed, then parseCSAF of each advisory (fortinetClaims)
)

// The licence lines of the vendor feeds (THIRD_PARTY_NOTICES.md has the terms read).
const (
	msrcNotice     = "Facts from Microsoft's Security Update Guide (the Exploited flag), Microsoft Terms of Use. Not endorsed by Microsoft."
	ciscoNotice    = "Facts from Cisco's public security advisories (CSAF), Cisco Terms of Use. Each claim links its advisory."
	fortinetNotice = "Facts from Fortinet's public PSIRT advisories (CSAF), Fortinet Terms of Use. Each claim links its advisory."
)

// vendorClaimFeed reports a feed of exploitation claims: a vendor's advisories or a prose source (textClaimFeed).
func vendorClaimFeed(id string) bool {
	return id == msrcFeedID || id == ciscoFeedID || id == fortinetFeedID || textClaimFeed(id)
}

// vendorTimeout bounds one pull of a vendor feed: a first pull reads about 50 advisories one by one.
const vendorTimeout = 30 * time.Minute

// vendorPause is the wait between two advisory documents of one vendor, so a first pull never bursts at the vendor's site.
var vendorPause = 500 * time.Millisecond

// claimSlack: a claim new to the box but dated more than this before the box's last good pull of the same feed was not there at that
// pull (the box read the same list then), so its date is the box's own sighting, not the date the vendor gives (an advisory edited
// later keeps its first publication date). Within it, a vendor's day-only date ("2026-11-10T00:00:00") is taken as it is.
const claimSlack = 24 * time.Hour

// claimDoc is one document of a vendor feed as read now: its link (feeds_signal.url), a small JSON detail for display, and the CVEs
// it claims are exploited with the date it gives each claim. A source whose terms do not let the box keep links (Rapid7) stores no
// link: its document is known by Key ("post:" and a digest of the link, also its detail {"post": …}), so a post that takes a claim
// back still removes it.
type claimDoc struct {
	URL    string
	Key    string // the document's identity when it differs from URL ("" means URL)
	Detail string
	Claims []vendorClaim
}

// key is the document's identity.
func (d claimDoc) key() string { return cmp.Or(d.Key, d.URL) }

// postKeyPrefix marks the identity of a document stored without its link.
const postKeyPrefix = "post:"

// unlinkedDoc is a post of a source that keeps no links: no URL, its identity a digest of its link.
func unlinkedDoc(link string) claimDoc {
	sum := sha256.Sum256([]byte(link))
	digest := hex.EncodeToString(sum[:8])
	return claimDoc{Key: postKeyPrefix + digest, Detail: unlinkedDetail(digest)}
}

// unlinkedDetail is the detail of a row kept without its link: the digest that tells its post.
func unlinkedDetail(digest string) string {
	detail, _ := json.Marshal(map[string]string{"post": digest}) // one string: never fails
	return string(detail)
}

// heldDocKey is the identity of the document a held row came from: its link, or the digest of a post kept without its link.
func heldDocKey(url string, detail sql.NullString) string {
	if url != "" || !detail.Valid {
		return url
	}
	var d struct {
		Post string `json:"post"`
	}
	if json.Unmarshal([]byte(detail.String), &d) != nil || d.Post == "" {
		return ""
	}
	return postKeyPrefix + d.Post
}

type vendorClaim struct {
	CVE  string
	Date time.Time
	Flag bool // read from a structured field (Microsoft's Exploited flag, a CSAF exploit_status threat), not from a sentence form
}

// vendorRead is what one pull of a vendor feed read.
type vendorRead struct {
	Docs []claimDoc
	// Whole: the documents are the feed's whole list (Microsoft's), so a CVE none of them claims any more loses its row. Otherwise
	// (Cisco, Fortinet) only the documents read now are compared: a CVE such a document no longer claims loses the row it gave.
	Whole bool
	// Claimed: for each CVE, the links of every advisory the box knows to claim it now (read now or before; Cisco, Fortinet). A row
	// whose advisory no longer claims its CVE moves to another of them instead of going.
	Claimed map[string][]string
	// Unclassified: sentences about exploitation in no known form (the first in the advisory UnclassifiedIn): counted on the pull's
	// note, never read as claims, never rejected rows.
	Unclassified   int
	UnclassifiedIn string
	Stats
}

// heldClaim is a feeds_signal row of a vendor feed as the box holds it before a pull.
type heldClaim struct {
	firstSeen string
	url       string
	key       string // the document it came from (heldDocKey)
}

// applyVendorClaims writes the claims of one pull of a vendor feed and returns how many CVEs the feed now flags. A CVE seen before
// keeps its first_seen and its link (the box's own first sighting does not move); a new one is dated by the vendor's date of the
// claim, or by now when that date is older than the last good pull (prevGood, zero for a first pull) by more than claimSlack.
func applyVendorClaims(ctx context.Context, tx *sql.Tx, now, prevGood time.Time, source string, r vendorRead) (int, error) {
	held := map[string]heldClaim{}
	rows, err := tx.QueryContext(ctx, `SELECT cve, first_seen, url, detail FROM feeds_signal WHERE source = ? AND kind = ?`, source, SignalExploited)
	if err != nil {
		return 0, fmt.Errorf("feeds: read claims: %w", err)
	}
	for rows.Next() {
		var (
			cve    string
			h      heldClaim
			detail sql.NullString
		)
		if err := rows.Scan(&cve, &h.firstSeen, &h.url, &detail); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("feeds: read claims: %w", err)
		}
		h.key = heldDocKey(h.url, detail)
		held[cve] = h
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("feeds: read claims: %w", err)
	}

	// each CVE once: the earliest date any document gives it, the first document's link
	type want struct {
		date        time.Time
		url, detail string
	}
	// docDetail is a document's detail as stored: NULL when it has none
	docDetail := func(d string) any {
		if d == "" {
			return sql.NullString{}
		}
		return d
	}
	wanted, order := map[string]*want{}, []string{}
	claimedBy := map[string]map[string]bool{} // document link → the CVEs it claims now
	for _, d := range r.Docs {
		claimedBy[d.key()] = map[string]bool{}
		for _, c := range d.Claims {
			claimedBy[d.key()][c.CVE] = true
			w := wanted[c.CVE]
			if w == nil {
				wanted[c.CVE] = &want{c.Date, d.URL, d.Detail}
				order = append(order, c.CVE)
			} else if c.Date.Before(w.date) {
				w.date = c.Date
			}
		}
	}
	stamp := store.FormatTS(now)
	for i, cve := range order {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		w := wanted[cve]
		if h, had := held[cve]; had {
			url, detail := h.url, any(nil)
			if claims, read := claimedBy[h.key]; read && !claims[cve] { // its document no longer claims it: the claiming document's
				url, detail = w.url, docDetail(w.detail)
			}
			if detail == nil {
				_, err = tx.ExecContext(ctx, `UPDATE feeds_signal SET last_seen = ? WHERE cve = ? AND kind = ? AND source = ?`, stamp, cve, SignalExploited, source)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE feeds_signal SET last_seen = ?, url = ?, detail = ? WHERE cve = ? AND kind = ? AND source = ?`,
					stamp, url, detail, cve, SignalExploited, source)
			}
			if err != nil {
				return 0, fmt.Errorf("feeds: store claim: %w", err)
			}
			continue
		}
		first := w.date
		if first.After(now) || (!prevGood.IsZero() && first.Before(prevGood.Add(-claimSlack))) {
			first = now
		}
		var detail any
		if w.detail != "" {
			detail = w.detail
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url, detail)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`, cve, SignalExploited, source, store.FormatTS(first), stamp, stamp, w.url, detail); err != nil {
			return 0, fmt.Errorf("feeds: store claim: %w", err)
		}
	}
	for cve, h := range held {
		if wanted[cve] != nil {
			continue
		}
		if _, read := claimedBy[h.key]; !r.Whole && !read {
			continue // the document that gave it was not read this time: it stands
		}
		if others := r.Claimed[cve]; len(others) > 0 { // another advisory still claims it: the row stays, with that link
			url, detail := others[0], any(sql.NullString{}) // a post has no detail
			switch {
			case strings.HasPrefix(url, postKeyPrefix): // a post kept without its link
				url, detail = "", unlinkedDetail(strings.TrimPrefix(url, postKeyPrefix))
			case !textClaimFeed(source):
				b, err := json.Marshal(map[string]string{"advisory": lastPart(url)})
				if err != nil {
					return 0, fmt.Errorf("feeds: store claim: %w", err)
				}
				detail = string(b)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_signal SET url = ?, detail = ?, last_seen = ? WHERE cve = ? AND kind = ? AND source = ?`,
				url, detail, stamp, cve, SignalExploited, source); err != nil {
				return 0, fmt.Errorf("feeds: store claim: %w", err)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_signal WHERE cve = ? AND kind = ? AND source = ?`, cve, SignalExploited, source); err != nil {
			return 0, fmt.Errorf("feeds: drop claim: %w", err)
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_signal WHERE source = ? AND kind = ?`, source, SignalExploited).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count claims: %w", err)
	}
	return n, nil
}
