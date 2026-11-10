package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// The API types of ogen repeat one shape per operation (five of them describe a Feed). The handlers build one
// JSON-tagged value per shape in api/openapi.json and convert it with convert/into: encoding/json on both
// sides, and ogen's decoder checks every enum and format of what the module built.

func convert[T any](src any) (*T, error) {
	var dst T
	if err := into(src, &dst); err != nil {
		return nil, err
	}
	return &dst, nil
}

func into(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("feeds: encode response: %w", err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("feeds: convert response: %w", err)
	}
	return nil
}

func parseDate(s string) (time.Time, error) { return time.Parse("2006-01-02", s) }

type vulnDTO struct {
	CVE            string   `json:"cve"`
	Vendor         string   `json:"vendor"`
	Product        string   `json:"product"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RequiredAction string   `json:"required_action"`
	Links          []string `json:"links"`
	DateAdded      string   `json:"date_added"`
	DueDate        *string  `json:"due_date"`
	Ransomware     bool     `json:"ransomware"`
	EPSS           *float64 `json:"epss"`
	EPSS7dAgo      *float64 `json:"epss_7d_ago"`
	HasTemplate    bool     `json:"has_template"`
	Display        string   `json:"display"`
}

func toVulnDTO(v VulnRow) vulnDTO {
	d := vulnDTO{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Description: v.Description, RequiredAction: v.RequiredAction,
		Links: v.Links, DateAdded: v.DateAdded, Ransomware: v.Ransomware, EPSS: v.EPSS, EPSS7dAgo: v.EPSS7dAgo, HasTemplate: v.HasTemplate,
		Display: DisplayOf(v.Vendor, v.Product)}
	if v.DueDate != "" {
		due := v.DueDate
		d.DueDate = &due
	}
	return d
}

type feedAuthDTO struct {
	Type        string  `json:"type"`
	HeaderName  *string `json:"header_name"`
	Username    *string `json:"username"`
	SecretLast4 *string `json:"secret_last4"`
}

type feedDTO struct {
	ID            string      `json:"id"`
	Builtin       bool        `json:"builtin"`
	Name          string      `json:"name"`
	Kind          Kind        `json:"kind"`
	Format        Format      `json:"format"`
	URL           string      `json:"url"`
	DefaultURL    *string     `json:"default_url"`
	Enabled       bool        `json:"enabled"`
	IntervalHours int         `json:"interval_hours"`
	Auth          feedAuthDTO `json:"auth"`
	Parser        *Parser     `json:"parser"`
	LastFetch     *time.Time  `json:"last_fetch"`
	Records       *int        `json:"records"`
	Status        string      `json:"status"`
	Error         *string     `json:"error"`
	License       *string     `json:"license"`
	AnsweredBy    *string     `json:"answered_by"`
}

// toFeedDTO is the Feed of the API (contract.ts Feed). The secret never leaves core/secrets: only secret_last4.
func toFeedDTO(r sourceRow) feedDTO {
	d := feedDTO{ID: r.ID, Builtin: r.Builtin, Name: r.Name, Kind: r.Kind, Format: r.Format, URL: r.URL, DefaultURL: r.DefaultURL,
		Enabled: r.Enabled, IntervalHours: r.IntervalHours, LastFetch: r.LastFetch, Records: r.Records, Status: r.Status, Error: r.Error,
		License: r.License, AnsweredBy: r.AnsweredBy, Parser: r.Parser,
		Auth: feedAuthDTO{Type: string(r.Auth), HeaderName: r.HeaderName, Username: r.Username, SecretLast4: r.SecretLast4}}
	if r.Builtin {
		d.Parser = nil
		d.Auth = feedAuthDTO{Type: string(AuthNone)}
	}
	return d
}

// feedInput is the body of POST/PUT /feeds/custom (contract.ts FeedInput).
type feedInput struct {
	Name          string `json:"name"`
	Kind          Kind   `json:"kind"`
	URL           string `json:"url"`
	Enabled       bool   `json:"enabled"`
	IntervalHours int    `json:"interval_hours"`
	Auth          struct {
		Type       AuthType `json:"type"`
		HeaderName *string  `json:"header_name"`
		Username   *string  `json:"username"`
		Secret     *string  `json:"secret"`
	} `json:"auth"`
	Parser Parser `json:"parser"`
}

// apiError maps what the library and the module return to the API error of the GUI mock (codes of
// API_CONVENTIONS 3.3). The sentence is the library's Detail: written for the user, no internals.
func apiError(err error) error {
	var fe *Error
	detail := ""
	if errors.As(err, &fe) {
		detail = fe.Detail
	}
	e := func(status int, code, def string) error {
		if detail == "" {
			detail = def
		}
		return apierr.New(status, code, detail)
	}
	switch {
	case errors.Is(err, ErrInvalidURL):
		return e(http.StatusBadRequest, "invalid_url", "Enter a full address such as https://example.com/feed.json.")
	case errors.Is(err, ErrInvalidInterval):
		return e(http.StatusBadRequest, "invalid_body", "Check the values and try again.")
	case errors.Is(err, ErrInvalidFormat):
		return e(http.StatusBadRequest, "invalid_format", "This format does not fit this kind of feed.")
	case errors.Is(err, ErrInvalidName):
		return e(http.StatusBadRequest, "invalid_name", "Enter a name of up to 60 characters.")
	case errors.Is(err, ErrDuplicateName):
		return e(http.StatusBadRequest, "duplicate_name", "A feed with this name already exists.")
	case errors.Is(err, ErrInvalidAuth), errors.Is(err, ErrInvalidSecret):
		return e(http.StatusBadRequest, "invalid_auth", "Check the authentication settings.")
	case errors.Is(err, ErrTooLarge):
		return e(http.StatusRequestEntityTooLarge, "too_large", "The data is larger than 5 MB.")
	case errors.Is(err, ErrBadConfig):
		return e(http.StatusBadRequest, "bad_config", "The parsing rules are not valid.")
	case errors.Is(err, ErrBadSample):
		return e(http.StatusBadRequest, "bad_sample", "The sample text could not be read with this parser.")
	case errors.Is(err, ErrNotFound):
		return apierr.New(http.StatusNotFound, apierr.CodeNotFound, "No such feed.")
	}
	return err
}
