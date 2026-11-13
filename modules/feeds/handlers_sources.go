package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

func noSuchFeed() error { return apierr.New(http.StatusNotFound, apierr.CodeNotFound, "No such feed.") }

// ---------- S-FEED-4: the list of feeds and their settings

// FeedsGetFeedsSources implements GET /feeds/sources: the built-in feeds in display order, then the custom ones.
func (h *FeedHandlers) FeedsGetFeedsSources(ctx context.Context) (*oas.FeedsGetFeedsSourcesOK, error) {
	rows, err := h.s.sources(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]feedDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, toFeedDTO(h.s.live(r)))
	}
	return convert[oas.FeedsGetFeedsSourcesOK](map[string]any{"items": items})
}

// FeedsPutFeedsSourcesID implements PUT /feeds/sources/{id}: on or off, the schedule, a mirror address. A
// built-in feed with an empty url goes back to its default address.
func (h *FeedHandlers) FeedsPutFeedsSourcesID(ctx context.Context, req *oas.FeedsPutFeedsSourcesIDReq, params oas.FeedsPutFeedsSourcesIDParams) (*oas.FeedsPutFeedsSourcesIDOK, error) {
	if err := h.s.ready(ctx); err != nil {
		return nil, err
	}
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var row sourceRow
	err = h.s.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := sourceTx(ctx, tx, params.ID)
		if errors.Is(err, ErrNotFound) {
			return noSuchFeed()
		}
		if err != nil {
			return err
		}
		enabled, hours, url := cur.Enabled, cur.IntervalHours, cur.URL
		var parts []string
		if v, ok := req.Enabled.Get(); ok {
			enabled = v
			parts = append(parts, map[bool]string{true: "enabled", false: "disabled"}[v])
		}
		if v, ok := req.IntervalHours.Get(); ok {
			if err := CheckInterval(v); err != nil {
				return apiError(err)
			}
			hours = v
			parts = append(parts, fmt.Sprintf("every %d h", v))
		}
		if v, ok := req.URL.Get(); ok {
			v = strings.TrimSpace(v)
			if v == "" && cur.Builtin {
				v = *cur.DefaultURL
			}
			if err := CheckURL(v); err != nil {
				return apiError(err)
			}
			if err := CheckDest(v, h.s.boxAddrs()); err != nil {
				return apiError(err)
			}
			if cur.ID == "first-epss" && strings.ContainsAny(v, "?#") { // EPSSBatchURLs adds the query itself
				return apierr.New(http.StatusBadRequest, "invalid_url", "The EPSS address must not carry a query string.")
			}
			url = v
			parts = append(parts, "address changed")
		}
		if err := updateSettings(ctx, tx, cur.ID, enabled, hours, url, url != cur.URL); err != nil {
			return err
		}
		if err := h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.update", Target: cur.Name, Detail: strings.Join(parts, ", ")}); err != nil {
			return err
		}
		row, err = sourceTx(ctx, tx, cur.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if row.ID == nvdFeedID && !row.Enabled {
		h.s.dropNVDRun()
	}
	return convert[oas.FeedsPutFeedsSourcesIDOK](toFeedDTO(row))
}

// ---------- S-FEED-4/5: custom feeds

// checkCustom applies the boundary rules of INV-2, 5, 6 and 17 to a custom feed body, in the order of the GUI
// mock (name, address, format, authentication, parsing rules, then an address another feed already uses). prev is the feed being edited, nil on create; box is
// the box's own addresses (CheckDest). It trims the text fields and treats an empty secret as "not sent" (keep the
// stored one, INV-6).
func checkCustom(ctx context.Context, tx *sql.Tx, in *feedInput, prev *sourceRow, own ownAddrs) error {
	in.Name, in.URL = strings.TrimSpace(in.Name), strings.TrimSpace(in.URL)
	if in.Auth.Secret != nil && *in.Auth.Secret == "" {
		in.Auth.Secret = nil
	}
	skip := ""
	if prev != nil {
		skip = prev.ID
	}
	others, err := customNames(ctx, tx, skip)
	if err != nil {
		return err
	}
	if err := CheckName(in.Name, others); err != nil {
		return apiError(err)
	}
	if err := CheckURL(in.URL); err != nil {
		return apiError(err)
	}
	if err := CheckDest(in.URL, own); err != nil {
		return apiError(err)
	}
	if err := CheckInterval(in.IntervalHours); err != nil {
		return apiError(err)
	}
	if err := CheckKindFormat(in.Kind, in.Parser.Format); err != nil {
		return apiError(err)
	}
	header, user := "", ""
	if in.Auth.HeaderName != nil {
		header = *in.Auth.HeaderName
	}
	if in.Auth.Username != nil {
		user = *in.Auth.Username
	}
	hasStored := prev != nil && prev.SecretID != nil && in.Auth.Type != AuthNone
	if err := CheckAuth(in.Auth.Type, header, user, in.Auth.Secret, hasStored); err != nil {
		return apiError(err)
	}
	if err := CheckParser(in.Kind, in.Parser); err != nil {
		return apiError(err)
	}
	return checkDuplicateURL(ctx, tx, in.URL, skip) // last, like duplicate_name of a valid body: it depends on the other feeds
}

// checkDuplicateURL refuses a custom feed address that another feed, built-in or custom, already pulls (D-420 (2)):
// the second feed would fetch the same list again and list every indicator twice. The message names that feed.
func checkDuplicateURL(ctx context.Context, tx *sql.Tx, addr, skip string) error {
	rows, err := tx.QueryContext(ctx, `SELECT name, url FROM feeds_source WHERE id != ?`, skip)
	if err != nil {
		return fmt.Errorf("feeds: read addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, u string
		if err := rows.Scan(&name, &u); err != nil {
			return fmt.Errorf("feeds: read addresses: %w", err)
		}
		if sameAddress(addr, u) {
			return apiError(fail(ErrDuplicateURL, "The feed %q already uses this address.", name))
		}
	}
	return rows.Err()
}

// boxAddrs is Vedette itself as the pull sees it now (INV-17, D-446): unknown host addresses leave the container's own
// interfaces and gateway, which are always checked.
func (s *Service) boxAddrs() ownAddrs {
	own, _ := (&destGuard{box: s.Fetcher.BoxAddrs, gateway: s.Fetcher.Gateway, self: s.Fetcher.Self}).ownAddrs()
	return own
}

// customRow builds the stored row of a custom feed body (the GUI mock's toCustom). The secret columns are set by saveSecret.
func customRow(id string, in feedInput, created time.Time) sourceRow {
	r := sourceRow{ID: id, Name: in.Name, Kind: in.Kind, Format: in.Parser.Format, URL: in.URL, Enabled: in.Enabled, IntervalHours: in.IntervalHours,
		Auth: in.Auth.Type, Parser: &in.Parser, CreatedAt: created, Status: "never"}
	switch in.Auth.Type {
	case AuthHeader:
		r.HeaderName = in.Auth.HeaderName
	case AuthBasic:
		u := strings.TrimSpace(*in.Auth.Username)
		r.Username = &u
	}
	return r
}

// saveSecret stores the credential of a custom feed through core/secrets and fills the secret columns of r.
// It returns the id of a secret to delete after the row stopped pointing at it (auth switched to none).
func (s *Service) saveSecret(ctx context.Context, tx *sql.Tx, prev *sourceRow, in feedInput, r *sourceRow) (drop *string, err error) {
	switch {
	case in.Auth.Type == AuthNone:
		if prev != nil {
			drop = prev.SecretID
		}
	case in.Auth.Secret != nil && prev != nil && prev.SecretID != nil:
		l4, err := s.Secrets.Replace(ctx, tx, *prev.SecretID, secretPurpose, []byte(*in.Auth.Secret), true)
		if err != nil {
			return nil, fmt.Errorf("feeds: replace secret: %w", err)
		}
		r.SecretID, r.SecretLast4 = prev.SecretID, &l4
	case in.Auth.Secret != nil:
		id, l4, err := s.Secrets.Seal(ctx, tx, secretPurpose, []byte(*in.Auth.Secret), true)
		if err != nil {
			return nil, fmt.Errorf("feeds: seal secret: %w", err)
		}
		r.SecretID, r.SecretLast4 = &id, &l4
	case prev != nil:
		r.SecretID, r.SecretLast4 = prev.SecretID, prev.SecretLast4 // sent empty: keep the stored secret
	}
	return drop, nil
}

// FeedsPostFeedsCustom implements POST /feeds/custom (PRE-5, POST-5).
func (h *FeedHandlers) FeedsPostFeedsCustom(ctx context.Context, req *oas.FeedsPostFeedsCustomReq) (*oas.FeedsPostFeedsCustomCreated, error) {
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var in feedInput
	if err := into(req, &in); err != nil {
		return nil, err
	}
	var row sourceRow
	err = h.s.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := checkCustom(ctx, tx, &in, nil, h.s.boxAddrs()); err != nil {
			return err
		}
		row = customRow(store.NewID("cf"), in, h.s.now())
		if _, err := h.s.saveSecret(ctx, tx, nil, in, &row); err != nil {
			return err
		}
		if err := insertCustom(ctx, tx, row); err != nil {
			return err
		}
		return h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.add_custom", Target: row.Name, Detail: fmt.Sprintf("%s, %s", row.Kind, row.Format)})
	})
	if err != nil {
		return nil, err
	}
	return convert[oas.FeedsPostFeedsCustomCreated](toFeedDTO(row))
}

// FeedsPutFeedsCustomID implements PUT /feeds/custom/{id}. Changing the kind removes what the feed loaded.
func (h *FeedHandlers) FeedsPutFeedsCustomID(ctx context.Context, req *oas.FeedsPutFeedsCustomIDReq, params oas.FeedsPutFeedsCustomIDParams) (*oas.FeedsPutFeedsCustomIDOK, error) {
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var in feedInput
	if err := into(req, &in); err != nil {
		return nil, err
	}
	var out sourceRow
	err = h.s.DB.Write(ctx, func(tx *sql.Tx) error {
		prev, err := sourceTx(ctx, tx, params.ID)
		if errors.Is(err, ErrNotFound) || (err == nil && prev.Builtin) {
			return noSuchFeed()
		}
		if err != nil {
			return err
		}
		if err := checkCustom(ctx, tx, &in, &prev, h.s.boxAddrs()); err != nil {
			return err
		}
		row := customRow(prev.ID, in, prev.CreatedAt)
		drop, err := h.s.saveSecret(ctx, tx, &prev, in, &row)
		if err != nil {
			return err
		}
		if err := updateCustom(ctx, tx, row); err != nil {
			return err
		}
		if drop != nil {
			if err := h.s.Secrets.Delete(ctx, tx, *drop); err != nil {
				return fmt.Errorf("feeds: delete secret: %w", err)
			}
		}
		if prev.Kind != in.Kind {
			if err := purgeLoaded(ctx, tx, prev.ID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET last_fetch = NULL, last_success = NULL, failures = 0, records = NULL, status = 'never', error = NULL WHERE id = ?`, prev.ID); err != nil {
				return fmt.Errorf("feeds: reset pull state: %w", err)
			}
		}
		if err := h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.edit_custom", Target: row.Name}); err != nil {
			return err
		}
		out, err = sourceTx(ctx, tx, prev.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return convert[oas.FeedsPutFeedsCustomIDOK](toFeedDTO(out))
}

// FeedsDeleteFeedsCustomID implements DELETE /feeds/custom/{id} (INV-4): the feed, its secret and everything it
// loaded go. A built-in feed answers 404, like the GUI mock.
func (h *FeedHandlers) FeedsDeleteFeedsCustomID(ctx context.Context, params oas.FeedsDeleteFeedsCustomIDParams) error {
	p, err := actor(ctx)
	if err != nil {
		return err
	}
	return h.s.DB.Write(ctx, func(tx *sql.Tx) error {
		prev, err := sourceTx(ctx, tx, params.ID)
		if errors.Is(err, ErrNotFound) || (err == nil && prev.Builtin) {
			return apierr.New(http.StatusNotFound, apierr.CodeNotFound, "No such feed (built-in feeds cannot be deleted).")
		}
		if err != nil {
			return err
		}
		if err := deleteCustom(ctx, tx, prev.ID); err != nil {
			return err
		}
		if prev.SecretID != nil {
			if err := h.s.Secrets.Delete(ctx, tx, *prev.SecretID); err != nil {
				return fmt.Errorf("feeds: delete secret: %w", err)
			}
		}
		return h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.delete_custom", Target: prev.Name})
	})
}

// FeedsPostFeedsParseTest implements POST /feeds/parse-test (S-FEED-5, INV-7): the rules run on the caller's
// sample, or on the built-in sample of the format. It reads and writes nothing: no database, no network.
func (h *FeedHandlers) FeedsPostFeedsParseTest(ctx context.Context, req *oas.FeedsPostFeedsParseTestReq) (*oas.FeedsPostFeedsParseTestOK, error) {
	var in struct {
		Kind   Kind    `json:"kind"`
		Parser Parser  `json:"parser"`
		Sample *string `json:"sample"`
	}
	if err := into(req, &in); err != nil {
		return nil, err
	}
	if err := CheckKindFormat(in.Kind, in.Parser.Format); err != nil {
		return nil, apiError(err)
	}
	if err := CheckParser(in.Kind, in.Parser); err != nil {
		return nil, apiError(err)
	}
	// A sample that was sent counts, even an empty one (0 records, like the GUI mock); only an absent sample
	// means the built-in one.
	text, label, _ := SampleFor(in.Kind, in.Parser.Format)
	if label == "" {
		label = "Sample"
	}
	if in.Sample != nil {
		text = *in.Sample
		if text != "" {
			label = "Your sample"
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res := Result{Records: []Record{}, Stats: Stats{Reasons: []Reason{}, Rejects: []Reject{}}}
	if text != "" {
		var err error
		if res, err = ParseFeed(ctx, []byte(text), in.Kind, in.Parser); err != nil {
			return nil, apiError(err)
		}
	}
	pre := res.Preview()
	return convert[oas.FeedsPostFeedsParseTestOK](map[string]any{
		"sample": text, "sample_label": label, "columns": FieldIDs(in.Kind), "records": pre.Records,
		"accepted": res.Accepted, "rejected": res.Rejected, "reasons": res.Reasons, "rejects": res.Rejects, "truncated": res.Truncated,
	})
}

// FeedsPostFeedsSourcesIDFetch implements POST /feeds/sources/{id}/fetch (INV-8): pull the feed now, straight from
// its source. A feed that is off is 409 feed_disabled; a pull that fails is a 200 with status error on the feed.
func (h *FeedHandlers) FeedsPostFeedsSourcesIDFetch(ctx context.Context, params oas.FeedsPostFeedsSourcesIDFetchParams) (*oas.FeedsPostFeedsSourcesIDFetchOK, error) {
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var row sourceRow
	if h.s.busy(params.ID) { // a pull is running: say how far it got instead of starting or waiting for another (W3-1)
		row, err = h.s.st.source(ctx, params.ID)
		row = h.s.live(row)
	} else {
		row, err = h.s.pull(ctx, params.ID, p.Email)
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, noSuchFeed()
	case errors.Is(err, ErrFeedDisabled):
		return nil, apierr.New(http.StatusConflict, "feed_disabled", "Turn the feed on before fetching it.")
	case err != nil:
		return nil, err
	}
	return convert[oas.FeedsPostFeedsSourcesIDFetchOK](toFeedDTO(row))
}
